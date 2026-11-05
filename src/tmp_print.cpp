#include "types.hpp"
#include <iostream>
#include <iomanip>

void printPacketInfo(const PacketInfo& info) {
    const auto old_flags = std::cout.flags();
    const auto old_fill = std::cout.fill();

    std::cout << std::dec << std::boolalpha;

    auto field = [](const char* name, const auto& value) {
        std::cout << name << ": " << value << '\n';
    };

    auto bytes = [](const char* name, const auto& data) {
        std::cout << name << " [" << data.size() << " bytes]: ";

        for (auto byte : data) {
            std::cout << std::hex << std::setfill('0')
                      << std::setw(2) << static_cast<unsigned>(byte) << ' ';
        }

        std::cout << std::dec << '\n';
    };

    std::cout << "\n--- PacketInfo ---\n";

    field("timestamp_us", info.timestamp_us);
    field("captured_size", info.captured_size);
    field("original_size", info.original_size);
    field("link_type", info.link_type);

    if (info.ethernet) {
        const auto& eth = *info.ethernet;

        field("ethernet.src_mac", eth.src_mac);
        field("ethernet.dst_mac", eth.dst_mac);
        field("ethernet.ether_type", eth.ether_type);
    } else {
        std::cout << "ethernet: absent\n";
    }

    if (info.ipv4) {
        const auto& ip = *info.ipv4;

        field("ipv4.src_ip", ip.src_ip);
        field("ipv4.dst_ip", ip.dst_ip);
        field("ipv4.ttl", static_cast<unsigned>(ip.ttl));
        field("ipv4.protocol", static_cast<unsigned>(ip.protocol));
        field("ipv4.header_size", static_cast<unsigned>(ip.header_size));
        field("ipv4.total_len", ip.total_len);
        field("ipv4.ip_id", ip.ip_id);
        field("ipv4.dont_fragment", ip.dont_fragment);
        field("ipv4.more_fragments", ip.more_fragments);
        field("ipv4.fragment_offset", ip.fragment_offset);
        field("ipv4.checksum", ip.checksum);
        bytes("ipv4.options", ip.options);
    } else {
        std::cout << "ipv4: absent\n";
    }

    if (info.tcp) {
        const auto& tcp = *info.tcp;

        field("tcp.src_port", tcp.src_port);
        field("tcp.dst_port", tcp.dst_port);
        field("tcp.seq_number", tcp.seq_number);
        field("tcp.ack_number", tcp.ack_number);
        field("tcp.flags", tcp.flags);
        field("tcp.window_size", tcp.window_size);
        field("tcp.header_size", static_cast<unsigned>(tcp.header_size));
        field("tcp.checksum", tcp.checksum);
        field("tcp.urg_pointer", tcp.urg_pointer);
        bytes("tcp.options", tcp.options);
    } else {
        std::cout << "tcp: absent\n";
    }

    if (info.udp) {
        const auto& udp = *info.udp;

        field("udp.src_port", udp.src_port);
        field("udp.dst_port", udp.dst_port);
        field("udp.length", udp.length);
        field("udp.checksum", udp.checksum);
    } else {
        std::cout << "udp: absent\n";
    }

    bytes("payload", info.payload);

    std::cout.flags(old_flags);
    std::cout.fill(old_fill);
}
