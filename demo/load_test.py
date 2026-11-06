#!/usr/bin/env python3
"""Offline load tests for Dozor's current PCAP CLI. Python 3.9+, stdlib only."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct
import subprocess
import sys
import tempfile
import time

PROFILES = ('tcp-small', 'udp-small', 'mixed', 'large-payload', 'many-flows', 'non-ipv4')
SUMMARY = re.compile(rb'^Read: (\d+), IPv4 TCP/UDP: (\d+)\s*$', re.MULTILINE)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(kind, index, payload_size, many_flows=False):
    ethernet = bytes.fromhex('020000000002020000000001')
    if kind == 'arp':
        arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
        arp += bytes.fromhex('020000000001c0000201') + b'\0' * 6 + bytes([192, 0, 2, 2])
        return (ethernet + b'\x08\x06' + arp).ljust(60, b'\0')
    src = bytes([192, 0, 2, 1])
    dst = bytes([198, 51, 100, 2])
    sport = 49152 + index % 16384 if many_flows else 53000
    if many_flows:
        src = bytes([10, (index >> 16) & 255, (index >> 8) & 255, index & 255])
    payload = (b'dozor-demo-' * ((payload_size + 10) // 11))[:payload_size]
    proto = 6 if kind == 'tcp' else 17
    if kind == 'tcp':
        transport = struct.pack('!HHIIBBHHH', sport, 8080, index & 0xffffffff, 0, 0x50, 0x18, 65535, 0, 0)
    else:
        transport = struct.pack('!HHHH', sport, 9999, 8 + len(payload), 0)
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(transport) + len(payload))
    check = checksum(pseudo + transport + payload)
    offset = 16 if kind == 'tcp' else 6
    transport = transport[:offset] + struct.pack('!H', check or 65535) + transport[offset + 2:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport) + len(payload), index & 65535, 0x4000, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return (ethernet + b'\x08\x00' + ip + transport + payload).ljust(60, b'\0')


def generate(path, profile, count):
    parsed = 0
    frame_bytes = 0
    digest = hashlib.sha256()
    with path.open('wb') as output:
        def write(data):
            output.write(data)
            digest.update(data)
        write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            kind = 'udp' if profile == 'udp-small' else 'tcp'
            if profile == 'mixed':
                kind = ('tcp', 'udp', 'arp')[i % 3]
            if profile == 'non-ipv4':
                kind = 'arp'
            packet = frame(kind, i, 1400 if profile == 'large-payload' else 16, profile == 'many-flows')
            write(struct.pack('<IIII', 1700000000 + i // 1000000, i % 1000000, len(packet), len(packet)))
            write(packet)
            parsed += kind != 'arp'
            frame_bytes += len(packet)
    return {'packets': count, 'ipv4_tcp_udp': parsed, 'frame_bytes': frame_bytes,
            'pcap_bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def run_once(binary, pcap, expected, timeout, directory):
    # File-backed output avoids retaining one output line per packet in RAM.
    start = time.perf_counter()
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            process = subprocess.run([str(binary), '--pcap', str(pcap)], stdout=stdout,
                                     stderr=stderr, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {'ok': False, 'error': 'timeout', 'seconds': time.perf_counter() - start}
        elapsed = time.perf_counter() - start
        size = stdout.tell()
        stdout.seek(max(0, size - 65536))
        summaries = SUMMARY.findall(stdout.read())
        stderr.seek(0)
        error = stderr.read(4096).decode('utf-8', errors='replace')
    observed = list(map(int, summaries[-1])) if summaries else None
    ok = process.returncode == 0 and observed == [expected['packets'], expected['ipv4_tcp_udp']] and not error
    return {'ok': ok, 'returncode': process.returncode, 'seconds': elapsed,
            'packets_per_second': expected['packets'] / elapsed,
            'frame_mbit_per_second': expected['frame_bytes'] * 8 / elapsed / 1e6,
            'stdout_bytes': size, 'observed_counts': observed, 'stderr': error,
            'error': None if ok else 'exit code, counters or stderr check failed'}


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('must be positive and finite')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'build/dozor')
    parser.add_argument('--profiles', nargs='+', choices=PROFILES, default=list(PROFILES))
    parser.add_argument('--packets', nargs='+', type=positive_int, default=[10000, 100000])
    parser.add_argument('--repeat', type=positive_int, default=3)
    parser.add_argument('--warmup', type=int, choices=range(0, 11), default=1)
    parser.add_argument('--timeout', type=positive_float, default=120)
    parser.add_argument('--min-pps', type=positive_float, help='optional minimum median throughput')
    parser.add_argument('--report', type=Path, default=Path('load-results.json'))
    args = parser.parse_args()
    binary = args.binary.expanduser().resolve()
    if not binary.is_file():
        parser.error('binary does not exist: %s' % binary)
    report = {'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'repeat': args.repeat, 'warmup': args.warmup, 'timeout': args.timeout,
              'min_pps': args.min_pps, 'cases': []}
    with tempfile.TemporaryDirectory(prefix='dozor-load-') as temporary:
        directory = Path(temporary)
        for profile in args.profiles:
            for count in args.packets:
                pcap = directory / 'input.pcap'
                expected = generate(pcap, profile, count)
                warmups = [run_once(binary, pcap, expected, args.timeout, directory) for _ in range(args.warmup)]
                runs = [run_once(binary, pcap, expected, args.timeout, directory) for _ in range(args.repeat)]
                rates = [run['packets_per_second'] for run in runs if run['ok']]
                median = statistics.median(rates) if rates else None
                ok = all(run['ok'] for run in warmups + runs)
                if args.min_pps is not None:
                    ok = ok and median is not None and median >= args.min_pps
                case = {'profile': profile, 'input': expected, 'warmups': warmups, 'runs': runs,
                        'median_pps': median, 'ok': ok}
                report['cases'].append(case)
                print('%s %s packets=%d median_pps=%s' % ('PASS' if ok else 'FAIL', profile, count,
                      '%.0f' % median if median is not None else 'n/a'), flush=True)
    report['ok'] = all(case['ok'] for case in report['cases'])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Report: %s' % args.report.resolve())
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print('ERROR: %s' % error, file=sys.stderr)
        sys.exit(2)
