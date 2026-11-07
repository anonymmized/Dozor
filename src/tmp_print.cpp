#include <iostream>
#include <iomanip>
#include "tmp_print.hpp"

void printAlert(const Alert& alert) {
    std::cout << "[ALERT] " << alert.rule_id << '\n'
              << "  Time: " << alert.timestamp_us << " us\n"
              << "  Message: " << alert.message << '\n'
              << "  Source: "
              << (alert.src_ip.empty() ? "-" : alert.src_ip) << ':';

    if (alert.src_port)
        std::cout << *alert.src_port;
    else
        std::cout << '-';

    std::cout << "\n  Destination: "
              << (alert.dst_ip.empty() ? "-" : alert.dst_ip) << ':';

    if (alert.dst_port)
        std::cout << *alert.dst_port;
    else
        std::cout << '-';

    std::cout << "\n\n";
}

void printPacketInfo(const PacketInfo& info) {
    const auto old_flags = std::cout.flags();
    const auto old_fill = std::cout.fill();

    std::cout << std::dec << std::boolalpha;
    std::cout << "\n--- PacketInfo ---\n";

    std::cout << "timestamp_us: " << info.timestamp_us << '\n'
              << "captured_size: " << info.captured_size << '\n'
              << "original_size: " << info.original_size << '\n'
              << "link_type: " << info.link_type << '\n';

    auto printBytes = [](const char* name,
                         const std::vector<std::uint8_t>& bytes) {
        std::cout << name << " [" << bytes.size() << " bytes]: ";
        for (const auto byte : bytes) {
            std::cout << std::hex << std::setfill('0')
                      << std::setw(2) << static_cast<unsigned>(byte) << ' ';
        }
        std::cout << std::dec << '\n';
    };

    if (info.ethernet) {
        std::cout << "ethernet.src_mac: " << info.ethernet->src_mac << '\n'
                  << "ethernet.dst_mac: " << info.ethernet->dst_mac << '\n'
                  << "ethernet.ether_type: " << info.ethernet->ether_type << '\n';
    } else {
        std::cout << "ethernet: absent\n";
    }

    if (info.ipv4) {
        const auto& ip = *info.ipv4;
        std::cout << "ipv4.src_ip: " << ip.src_ip << '\n'
                  << "ipv4.dst_ip: " << ip.dst_ip << '\n'
                  << "ipv4.ttl: " << static_cast<unsigned>(ip.ttl) << '\n'
                  << "ipv4.protocol: " << static_cast<unsigned>(ip.protocol) << '\n'
                  << "ipv4.header_size: " << static_cast<unsigned>(ip.header_size) << '\n'
                  << "ipv4.total_len: " << ip.total_len << '\n'
                  << "ipv4.ip_id: " << ip.ip_id << '\n'
                  << "ipv4.dont_fragment: " << ip.dont_fragment << '\n'
                  << "ipv4.more_fragments: " << ip.more_fragments << '\n'
                  << "ipv4.fragment_offset: " << ip.fragment_offset << '\n'
                  << "ipv4.checksum: " << ip.checksum << '\n';
        printBytes("ipv4.options", ip.options);
    } else {
        std::cout << "ipv4: absent\n";
    }

    if (info.tcp) {
        const auto& tcp = *info.tcp;
        std::cout << "tcp.src_port: " << tcp.src_port << '\n'
                  << "tcp.dst_port: " << tcp.dst_port << '\n'
                  << "tcp.seq_number: " << tcp.seq_number << '\n'
                  << "tcp.ack_number: " << tcp.ack_number << '\n'
                  << "tcp.flags: " << tcp.flags << '\n'
                  << "tcp.window_size: " << tcp.window_size << '\n'
                  << "tcp.header_size: " << static_cast<unsigned>(tcp.header_size) << '\n'
                  << "tcp.checksum: " << tcp.checksum << '\n'
                  << "tcp.urg_pointer: " << tcp.urg_pointer << '\n';
        printBytes("tcp.options", tcp.options);
    } else {
        std::cout << "tcp: absent\n";
    }

    if (info.udp) {
        const auto& udp = *info.udp;
        std::cout << "udp.src_port: " << udp.src_port << '\n'
                  << "udp.dst_port: " << udp.dst_port << '\n'
                  << "udp.length: " << udp.length << '\n'
                  << "udp.checksum: " << udp.checksum << '\n';
    } else {
        std::cout << "udp: absent\n";
    }

    printBytes("payload", info.payload);

    std::cout.flags(old_flags);
    std::cout.fill(old_fill);
}
