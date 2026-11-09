#!/usr/bin/env python3
"""Generate and check Dozor's offline signature/behavior demo PCAPs."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


EXPECTED = {
    "ips_block_demo.pcap": ("WEB_XSS_SCRIPT", 1),
    "port_scan_demo.pcap": ("PORT_SCAN", 20),
    "host_scan_demo.pcap": ("HOST_SCAN", 20),
    "syn_rate_demo.pcap": ("SYN_FLOOD", 100),
    "udp_rate_demo.pcap": ("UDP_RATE", 200),
    "distributed_udp_demo.pcap": ("UDP_DISTRIBUTED_RATE", 1000),
}


def main() -> int:
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=project / "build" / "dozor")
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    if not binary.is_file():
        parser.error(f"Dozor executable not found: {binary}")

    generator = project / "demo" / "generate_demo_pcaps.py"
    subprocess.run([sys.executable, str(generator)], check=True)

    failed = False
    for filename, (rule_id, expected_packets) in EXPECTED.items():
        pcap = project / "tests" / filename
        result = subprocess.run([str(binary), "--pcap", str(pcap)],
                                text=True, capture_output=True)
        match = re.search(r"^Read: (\d+), IPv4 TCP/UDP: (\d+)$",
                          result.stdout, re.MULTILINE)
        events = re.findall(r"^\[(?:ALERT|BLOCK|BEHAVIOR)\] ([A-Z0-9_]+)$",
                            result.stdout, re.MULTILINE)
        ok = (result.returncode == 0 and match is not None and
              tuple(map(int, match.groups())) == (expected_packets, expected_packets) and
              events == [rule_id])
        if rule_id == "WEB_XSS_SCRIPT":
            ok = ok and "[IPS simulation] Would block 192.0.2.44" in result.stdout
        print(f"{'PASS' if ok else 'FAIL'} {filename}: expected {rule_id}, "
              f"{expected_packets} packets")
        if not ok:
            failed = True
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            print(result.stdout, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
