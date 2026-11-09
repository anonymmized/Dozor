# Dozor IDS/IPS

Dozor is a C++20 prototype that reads offline PCAP files or captures packets from a live interface. It parses Ethernet, IPv4, TCP and UDP, detects content signatures and traffic patterns, and can ask macOS PF to block an IPv4 source address when a rule has `action: block`.

## How it is organized

1. `capture.cpp` reads PCAP or passes live raw packets to the application.
2. `parser.cpp` converts a packet into `PacketInfo`.
3. `engine.cpp` loads `rules/signatures.yaml` and `rules/behavior.yaml`, then checks packet payloads and rolling behavior windows.
4. `app.cpp` prints alerts and, during live capture, connects block actions to the IPS block list and PF.
5. `ips.cpp` stores IP addresses and expiry times in `state/blocked_ips.csv`; `firewall.cpp` updates the `dozor_blocked` table in the PF `dozor` anchor.

## Build

Requires CMake, a C++20 compiler, PcapPlusPlus and yaml-cpp.

```sh
cmake -S . -B build
cmake --build build
```

Rule paths are embedded at build time, so the executable can be started from another working directory.

## Run

Analyze one or more PCAP files. This mode never changes the host firewall; `block` actions are printed as simulations.

```sh
./build/dozor --pcap tests/all_scenarios.pcap
python3 demo/generate_demo_pcaps.py
./build/dozor --pcap tests/ips_block_demo.pcap
./build/dozor --pcap tests/port_scan_demo.pcap
./build/dozor --pcap tests/host_scan_demo.pcap
./build/dozor --pcap tests/syn_rate_demo.pcap
./build/dozor --pcap tests/udp_rate_demo.pcap
./build/dozor --pcap tests/distributed_udp_demo.pcap
```

List interfaces and capture live traffic:

```sh
./build/dozor --intlist
sudo ./build/dozor --int en0
```

Press Enter to stop live capture. Choose the interface name shown by `--intlist`. Live packet capture and PF modification require administrator privileges. A matching `action: block` rule blocks inbound packets from that IPv4 source for one hour while Dozor is running. The saved block list is re-applied on the next run while its expiry time is still in the future.

## Connect the PF anchor on macOS

Live blocking needs the project's rules loaded into a named PF anchor. Dozor does not edit the system PF configuration automatically.

1. From the project root, install the anchor. The script saves a timestamped backup of `/etc/pf.conf`, adds only the Dozor anchor beside the Apple anchor, checks the resulting syntax and loads it. It rolls back on an error.

   ```sh
   sudo bash scripts/install_pf_anchor_macos.sh
   ```

2. Start live capture with `sudo ./build/dozor --int en0`.

The project anchor contains only a persistent table and a rule that drops incoming packets whose source is in that table. Dozor takes a PF enable reference while capturing and releases it on clean shutdown; the OS keeps PF enabled if another system component still holds a reference. Dozor adds/removes addresses with `pfctl` table commands. Press Enter to stop capture cleanly; Dozor removes temporary entries from PF while retaining unexpired timestamps in its block-list file for the next run. PF is system-wide: only enable this for a demo when you understand the effect on the Mac's network traffic. To remove the integration, run `sudo bash scripts/remove_pf_anchor_macos.sh`; it backs up the current PF file, flushes only Dozor's table, removes the two Dozor lines and reloads the remaining rules.

## Detection rules

Signature rules match a protocol, optional destination ports and a byte sequence in one packet's TCP/UDP payload. `case_insensitive` controls ASCII case folding. `action` is `alert` or `block`; blocking is only applied in live mode.

Behavior rules aggregate packets within a sliding time window. The current YAML profile covers port scanning, horizontal host scanning, SYN rate, UDP rate and distributed UDP rate. Window boundaries are `(t - window, t]`; duplicate events are suppressed during a 10-second cooldown.

## Prototype limits

- The parser currently detects IPv4 TCP/UDP and does not reassemble fragmented IP packets or TCP streams. A signature split across TCP segments will not match.
- Payload signatures and behavior thresholds are educational indicators, not proof that a host is compromised or generating a denial-of-service attack.
- Live prevention currently uses macOS PF, IPv4 source addresses and inbound filtering. PCAP mode is analysis-only.
- The load benchmark measures offline PCAP processing, not live capture loss or end-to-end network latency.

See [demo/README.md](demo/README.md) for the demo and load-measurement commands.
