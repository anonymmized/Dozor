# Dozor demo and load measurements

Run these commands from the project root after building with CMake.

## Detection demo

Create six synthetic PCAPs. The generator only writes files; it does not send network traffic.

```sh
python3 demo/generate_demo_pcaps.py
python3 demo/check_demo.py
./build/dozor --pcap tests/ips_block_demo.pcap
./build/dozor --pcap tests/port_scan_demo.pcap
./build/dozor --pcap tests/host_scan_demo.pcap
./build/dozor --pcap tests/syn_rate_demo.pcap
./build/dozor --pcap tests/udp_rate_demo.pcap
./build/dozor --pcap tests/distributed_udp_demo.pcap
```

Expected rule IDs are `WEB_XSS_SCRIPT`, `PORT_SCAN`, `HOST_SCAN`, `SYN_FLOOD`, `UDP_RATE` and `UDP_DISTRIBUTED_RATE`. Together these cover the signature action and all five behavior rules. PCAP mode prints block actions as simulations and never modifies PF. It also prints `Read: N, IPv4 TCP/UDP: M` so packet totals are easy to check.

To demonstrate real blocking, set up the macOS PF `dozor` anchor as described in the root README, then run live capture with administrator privileges on a test network. The synthetic PCAPs are for offline testing only.

## PCAP processing speed

The benchmark creates temporary PCAPs and checks that Dozor reports the correct number of packets. It does not transmit traffic.

```sh
# Quick check
python3 demo/load_test.py --profiles tcp-small udp-small mixed --packets 1000 --repeat 1 --warmup 0 --report /tmp/dozor-load.json

# More repeatable local measurements
python3 demo/load_test.py --packets 10000 100000 --repeat 3 --warmup 1 --report demo/load-results-local.json

# Include large payloads and many flows
python3 demo/load_test.py --profiles large-payload many-flows --packets 100000 1000000 --repeat 3 --warmup 1 --timeout 300 --report demo/load-results-stress.json
```

The report includes packets per second and estimated Ethernet frame throughput. File-cache and disk speed affect measurements; compare runs on the same machine and with the same options. These numbers do not represent live capture loss, packet latency or PF filtering speed.
