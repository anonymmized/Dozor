#!/usr/bin/env python3
"""Generate harmless offline PCAPs for signature and behavior demonstrations."""

import argparse
from pathlib import Path
import struct

BASE_TIME = 1_800_000_000
ETHERNET = bytes.fromhex("0200000000020200000000010800")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(src_ip: str, dst_ip: str, proto: str, payload: bytes,
          src_port: int, dst_port: int, flags: int = 0, ident: int = 1) -> bytes:
    source = bytes(map(int, src_ip.split(".")))
    destination = bytes(map(int, dst_ip.split(".")))

    if proto == "TCP":
        transport = struct.pack("!HHIIHHHH", src_port, dst_port, ident, 0,
                                0x5000 | flags, 65535, 0, 0)
        protocol_number = 6
        pseudo = source + destination + struct.pack("!BBH", 0, protocol_number,
                                                     len(transport) + len(payload))
        value = checksum(pseudo + transport + payload)
        transport = transport[:16] + struct.pack("!H", value) + transport[18:]
    else:
        protocol_number = 17
        transport = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        pseudo = source + destination + struct.pack("!BBH", 0, protocol_number,
                                                     len(transport) + len(payload))
        value = checksum(pseudo + transport + payload) or 0xFFFF
        transport = transport[:6] + struct.pack("!H", value)

    total_length = 20 + len(transport) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, ident & 0xFFFF,
                     0x4000, 64, protocol_number, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return (ETHERNET + ip + transport + payload).ljust(60, b"\0")


def write_pcap(path: Path, packets: list[tuple[int, bytes]]) -> None:
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for offset_us, packet in packets:
            seconds, microseconds = divmod(offset_us, 1_000_000)
            output.write(struct.pack("<IIII", BASE_TIME + seconds, microseconds,
                                     len(packet), len(packet)))
            output.write(packet)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "tests")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    block_packet = frame("192.0.2.44", "198.51.100.10", "TCP",
                         b"GET /demo HTTP/1.1\r\nHost: example.invalid\r\n\r\n<script>alert(1)</script>",
                         53000, 8080, flags=0x18)
    write_pcap(args.out_dir / "ips_block_demo.pcap", [(0, block_packet)])

    scan_packets = [
        (index * 100_000,
         frame("192.0.2.60", "198.51.100.10", "TCP", b"", 53000,
               1000 + index, flags=0x02, ident=index + 1))
        for index in range(20)
    ]
    write_pcap(args.out_dir / "port_scan_demo.pcap", scan_packets)

    host_scan_packets = [
        (index * 100_000,
         frame("192.0.2.61", f"198.51.100.{100 + index}", "TCP", b"",
               53000, 443, flags=0x02, ident=index + 1))
        for index in range(20)
    ]
    write_pcap(args.out_dir / "host_scan_demo.pcap", host_scan_packets)

    syn_flood_packets = [
        (index * 5_000,
         frame("192.0.2.62", "198.51.100.40", "TCP", b"", 53000,
               443, flags=0x02, ident=index + 1))
        for index in range(100)
    ]
    write_pcap(args.out_dir / "syn_rate_demo.pcap", syn_flood_packets)

    udp_rate_packets = [
        (index * 4_000,
         frame("192.0.2.70", "198.51.100.20", "UDP", b"demo", 53000,
               9999, ident=index + 1))
        for index in range(200)
    ]
    write_pcap(args.out_dir / "udp_rate_demo.pcap", udp_rate_packets)

    distributed_packets = []
    for index in range(1000):
        source = f"198.18.{index // 256}.{index % 256}"
        packet = frame(source, "198.51.100.30", "UDP", b"demo", 53000,
                       9999, ident=index + 1)
        distributed_packets.append((index * 800_000 // 999, packet))
    write_pcap(args.out_dir / "distributed_udp_demo.pcap", distributed_packets)

    print(f"Created six offline demo PCAPs in {args.out_dir.resolve()}")


if __name__ == "__main__":
    main()
