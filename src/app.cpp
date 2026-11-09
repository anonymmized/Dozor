#include "app.hpp"

#include "capture.hpp"
#include "config.hpp"
#include "engine.hpp"
#include "firewall.hpp"
#include "ips.hpp"
#include "parser.hpp"
#include "tmp_print.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
    class FirewallSessionCleanup {
    public:
        FirewallSessionCleanup(Firewall& firewall, IPS& ips, std::mutex& mutex)
            : firewall(firewall), ips(ips), mutex(mutex) {}

        ~FirewallSessionCleanup() {
            std::lock_guard<std::mutex> lock(mutex);
            std::vector<std::string> addresses = ips.activeIps();
            const auto expired = ips.expiredIps();
            addresses.insert(addresses.end(), expired.begin(), expired.end());
            for (const auto& ip : addresses) {
                try {
                    firewall.unblockIp(ip);
                } catch (const std::exception& error) {
                    std::cerr << "[IPS] Could not remove temporary PF block for "
                              << ip << ": " << error.what() << '\n';
                }
            }
            try {
                firewall.disable();
            } catch (const std::exception& error) {
                std::cerr << "[IPS] Could not release PF enable reference: "
                          << error.what() << '\n';
            }
        }

    private:
        Firewall& firewall;
        IPS& ips;
        std::mutex& mutex;
    };
}

void App::run() {
    if (cmd.mode == Modes::InterfaceList) {
        printAvailableInterfaces();
        return;
    }

    if (cmd.mode == Modes::Pcap) {
        std::uint64_t packets_read = 0;
        std::uint64_t ipv4_tcp_udp_packets = 0;
        for (const auto& file : cmd.content) {
            Engine engine; // Independent PCAP files have independent behavior windows.
            forEachPcapPacket(file, [&](const PacketInfo& packet) {
                ++packets_read;
                if (packet.ipv4 && (packet.tcp || packet.udp)) {
                    ++ipv4_tcp_udp_packets;
                }
                for (const auto& alert : engine.process(packet)) {
                    printAlert(alert);
                    if (alert.action == "block" && !alert.src_ip.empty()) {
                        std::cout << "[IPS simulation] Would block "
                                  << alert.src_ip << " (offline PCAP mode)\n";
                    }
                }
            });
        }
        std::cout << "Read: " << packets_read
                  << ", IPv4 TCP/UDP: " << ipv4_tcp_udp_packets << '\n';
        return;
    }

    Engine engine;

    if (cmd.mode != Modes::Interface || cmd.content.empty()) {
        throw std::runtime_error("No network interface was provided");
    }

    IPS ips(BLOCKLIST_PATH);
    Firewall firewall;
    std::mutex firewall_mutex;
    FirewallSessionCleanup firewall_cleanup(firewall, ips, firewall_mutex);
    firewall.enable();

    // Apply saved bans when starting capture and remove bans whose timer expired.
    {
        std::lock_guard<std::mutex> lock(firewall_mutex);
        for (const auto& ip : ips.expiredIps()) {
            firewall.unblockIp(ip);
            ips.removeIp(ip);
        }
        for (const auto& ip : ips.activeIps()) {
            firewall.blockIp(ip);
        }
    }

    auto removeExpired = [&]() {
        std::lock_guard<std::mutex> lock(firewall_mutex);
        for (const auto& ip : ips.expiredIps()) {
            firewall.unblockIp(ip);
            ips.removeIp(ip);
            std::cout << "[IPS] Unblocked expired address " << ip << '\n';
        }
    };

    std::jthread expiry_worker([&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            try {
                removeExpired();
            } catch (const std::exception& error) {
                std::cerr << "[IPS] Expiry cleanup failed: " << error.what() << '\n';
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    captureInterface(cmd.content.front(), [&](pcpp::RawPacket& raw_packet) {
        const PacketInfo packet = parsePacket(raw_packet);
        if (packet.ipv4 && ips.isBlocked(packet.ipv4->src_ip)) {
            return;
        }

        for (const auto& alert : engine.process(packet)) {
            printAlert(alert);
            if (alert.action != "block" || alert.src_ip.empty()) {
                continue;
            }

            std::lock_guard<std::mutex> lock(firewall_mutex);
            firewall.blockIp(alert.src_ip);
            try {
                ips.blockIp(alert.src_ip);
            } catch (...) {
                // Keep firewall and saved blocklist in sync if persistence fails.
                try {
                    firewall.unblockIp(alert.src_ip);
                } catch (const std::exception& rollback_error) {
                    std::cerr << "[IPS] Could not roll back firewall block: "
                              << rollback_error.what() << '\n';
                }
                throw;
            }
            std::cout << "[IPS] Blocked " << alert.src_ip << " for one hour\n";
        }
    });
}
