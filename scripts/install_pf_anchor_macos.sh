#!/bin/bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer with administrator privileges." >&2
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
PF_CONF="/etc/pf.conf"
ANCHOR_FILE="/etc/pf.anchors/dozor"
LOAD_LINE='load anchor "dozor" from "/etc/pf.anchors/dozor"'
ANCHOR_LINE='anchor "dozor"'
STAMP="$(date '+%Y%m%d-%H%M%S')"
PF_BACKUP="/etc/pf.conf.dozor.backup.${STAMP}"
ANCHOR_BACKUP="/etc/pf.anchors/dozor.backup.${STAMP}"
HAD_ANCHOR=0
CHANGED=0

rollback_on_error() {
    result=$?
    trap - EXIT
    if [[ "$result" -ne 0 && "$CHANGED" -eq 1 ]]; then
        if [[ -f "$PF_BACKUP" ]]; then
            cp -p "$PF_BACKUP" "$PF_CONF"
        fi
        if [[ "$HAD_ANCHOR" -eq 1 && -f "$ANCHOR_BACKUP" ]]; then
            cp -p "$ANCHOR_BACKUP" "$ANCHOR_FILE"
        else
            rm -f "$ANCHOR_FILE"
        fi
        /sbin/pfctl -nf "$PF_CONF" || true
        /sbin/pfctl -f "$PF_CONF" || true
    fi
    exit "$result"
}
trap rollback_on_error EXIT

if [[ ! -f "$PF_CONF" || ! -f "$PROJECT_ROOT/config/dozor-pf.conf" ]]; then
    echo "Missing /etc/pf.conf or project config/dozor-pf.conf." >&2
    exit 1
fi

if [[ -e "$ANCHOR_FILE" ]]; then
    HAD_ANCHOR=1
    cp -p "$ANCHOR_FILE" "$ANCHOR_BACKUP"
fi
cp -p "$PF_CONF" "$PF_BACKUP"
install -o root -g wheel -m 644 "$PROJECT_ROOT/config/dozor-pf.conf" "$ANCHOR_FILE"
CHANGED=1

if grep -Fqx "$ANCHOR_LINE" "$PF_CONF"; then
    if ! grep -Fqx "$LOAD_LINE" "$PF_CONF"; then
        echo "A partial Dozor anchor already exists in /etc/pf.conf; refusing to add duplicates." >&2
        exit 1
    fi
else
    if grep -Fq 'anchor "dozor' "$PF_CONF" || grep -Fq 'load anchor "dozor' "$PF_CONF"; then
        echo "A conflicting Dozor anchor already exists in /etc/pf.conf." >&2
        exit 1
    fi
    temp_conf="$(mktemp /etc/pf.conf.dozor.XXXXXX)"
    if ! awk -v anchor="$ANCHOR_LINE" -v load="$LOAD_LINE" '
        /^anchor "com\.apple\/\*"$/ && !inserted {
            print anchor
            print load
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 1 }
    ' "$PF_CONF" > "$temp_conf"; then
        rm -f "$temp_conf"
        echo 'Could not find the macOS com.apple anchor point in /etc/pf.conf.' >&2
        exit 1
    fi
    chown root:wheel "$temp_conf"
    chmod 644 "$temp_conf"
    mv "$temp_conf" "$PF_CONF"
fi

/sbin/pfctl -nf "$PF_CONF"
/sbin/pfctl -f "$PF_CONF"

CHANGED=0
trap - EXIT
echo "Dozor PF anchor installed and loaded."
echo "Backup of /etc/pf.conf: $PF_BACKUP"
if [[ "$HAD_ANCHOR" -eq 1 ]]; then
    echo "Backup of previous anchor: $ANCHOR_BACKUP"
fi
