#!/bin/bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this remover with administrator privileges." >&2
    exit 1
fi

PF_CONF="/etc/pf.conf"
ANCHOR_FILE="/etc/pf.anchors/dozor"
LOAD_LINE='load anchor "dozor" from "/etc/pf.anchors/dozor"'
ANCHOR_LINE='anchor "dozor"'
STAMP="$(date '+%Y%m%d-%H%M%S')"
PF_BACKUP="/etc/pf.conf.dozor-remove.backup.${STAMP}"
ANCHOR_BACKUP="/etc/pf.anchors/dozor-remove.backup.${STAMP}"
CHANGED=0

rollback_on_error() {
    result=$?
    trap - EXIT
    if [[ "$result" -ne 0 && "$CHANGED" -eq 1 ]]; then
        cp -p "$PF_BACKUP" "$PF_CONF"
        if [[ -f "$ANCHOR_BACKUP" ]]; then
            cp -p "$ANCHOR_BACKUP" "$ANCHOR_FILE"
        fi
        /sbin/pfctl -nf "$PF_CONF" || true
        /sbin/pfctl -f "$PF_CONF" || true
    fi
    exit "$result"
}
trap rollback_on_error EXIT

cp -p "$PF_CONF" "$PF_BACKUP"
if [[ -f "$ANCHOR_FILE" ]]; then
    cp -p "$ANCHOR_FILE" "$ANCHOR_BACKUP"
fi
CHANGED=1

# Clear only Dozor's temporary table entries, if PF is currently active.
/sbin/pfctl -a dozor -t dozor_blocked -T flush || true

temp_conf="$(mktemp /etc/pf.conf.dozor-remove.XXXXXX)"
awk -v anchor="$ANCHOR_LINE" -v load="$LOAD_LINE" '$0 != anchor && $0 != load { print }' \
    "$PF_CONF" > "$temp_conf"
chown root:wheel "$temp_conf"
chmod 644 "$temp_conf"
mv "$temp_conf" "$PF_CONF"

/sbin/pfctl -nf "$PF_CONF"
/sbin/pfctl -f "$PF_CONF"
rm -f "$ANCHOR_FILE"

CHANGED=0
trap - EXIT
echo "Dozor PF anchor removed. Backup of /etc/pf.conf: $PF_BACKUP"
