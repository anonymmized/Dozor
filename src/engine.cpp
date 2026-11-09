#include "engine.hpp"
#include "config.hpp"
#include <yaml-cpp/yaml.h>
#include <stdexcept>
#include <algorithm>
#include <limits>
#include <utility>

namespace {
    std::uint8_t normalizeByte(std::uint8_t byte, bool case_insensitive) {
        if (case_insensitive && byte >= 'A' && byte <= 'Z') {
            return static_cast<std::uint8_t>(byte + ('a' - 'A'));
        }
        return byte;
    }

    template <typename Map, typename Key>
    void decrementCount(Map& counts, const Key& key) {
        const auto it = counts.find(key);
        if (it == counts.end()) {
            return;
        }
        if (--it->second == 0) {
            counts.erase(it);
        }
    }

    void addSample(BehaviorWindow& window, BehaviorSample sample) {
        ++window.dst_port_counts[sample.dst_port];
        ++window.src_ip_counts[sample.src_ip];
        ++window.dst_ip_counts[sample.dst_ip];
        window.samples.push_back(std::move(sample));
    }

    void removeOldestSample(BehaviorWindow& window) {
        const auto& sample = window.samples.front();
        decrementCount(window.dst_port_counts, sample.dst_port);
        decrementCount(window.src_ip_counts, sample.src_ip);
        decrementCount(window.dst_ip_counts, sample.dst_ip);
        window.samples.pop_front();
    }

    std::vector<SignatureRule> load_signatures() {
        const YAML::Node root = YAML::LoadFile(SIGNATURES_PATH.string());
        const YAML::Node entries = root["signatures"];
        if (!entries || !entries.IsSequence()) {
            throw std::runtime_error("Missing signatures list in YAML");
        }
        std::vector<SignatureRule> rules;
        for (const auto& entry : entries) {
            SignatureRule rule;
            rule.id = entry["id"].as<std::string>();
            rule.protocol = entry["protocol"].as<std::string>();
            rule.dst_ports = entry["dst_ports"].as<std::vector<std::uint16_t>>();
            rule.contains = entry["contains"].as<std::string>();
            rule.case_insensitive = entry["case_insensitive"]
                ? entry["case_insensitive"].as<bool>()
                : false;
            rule.action = entry["action"] ? entry["action"].as<std::string>() : "alert";
            if (rule.action != "alert" && rule.action != "block") {
                throw std::runtime_error("Unsupported action in signature rule " + rule.id);
            }
            const auto pattern_size = rule.contains.size();
            rule.skip_table.fill(pattern_size);
            for (std::size_t i = 0; i + 1 < pattern_size; ++i) {
                const auto byte = normalizeByte(
                    static_cast<std::uint8_t>(rule.contains[i]), rule.case_insensitive);
                rule.skip_table[byte] = pattern_size - i - 1;
            }
            rules.push_back(rule);
        }
        return rules;
    }

    std::vector<BehaviorRule> load_behaviors() {
        const YAML::Node root = YAML::LoadFile(BEHAVIOR_PATH.string());
        const YAML::Node entries = root["behaviors"];
        if (!entries || !entries.IsSequence()) {
            throw std::runtime_error("Missing behaviors list in YAML");
        }

        std::vector<BehaviorRule> rules;
        for (const auto& entry : entries) {
            BehaviorRule rule;
            rule.id = entry["id"].as<std::string>();
            rule.protocol = entry["protocol"].as<std::string>();
            rule.group_by = entry["group_by"].as<std::vector<std::string>>();
            rule.window_us = entry["window_seconds"].as<std::int64_t>() * 1'000'000;
            if (entry["cooldown_seconds"]) {
                rule.cooldown_us = entry["cooldown_seconds"].as<std::int64_t>() * 1'000'000;
            }
            if (entry["min_packets"]) {
                rule.min_packets = entry["min_packets"].as<std::size_t>();
            }
            if (entry["min_unique_dst_ports"]) {
                rule.min_unique_dst_ports = entry["min_unique_dst_ports"].as<std::size_t>();
            }
            if (entry["min_unique_dst_ips"]) {
                rule.min_unique_dst_ips = entry["min_unique_dst_ips"].as<std::size_t>();
            }
            if (entry["min_unique_src_ips"]) {
                rule.min_unique_src_ips = entry["min_unique_src_ips"].as<std::size_t>();
            }
            if (entry["tcp_syn_only"]) {
                rule.tcp_syn_only = entry["tcp_syn_only"].as<bool>();
            }
            if (entry["tcp_syn_without_ack"]) {
                rule.tcp_syn_without_ack = entry["tcp_syn_without_ack"].as<bool>();
            }
            if (entry["action"]) {
                rule.action = entry["action"].as<std::string>();
            }
            if (rule.action != "alert" && rule.action != "block") {
                throw std::runtime_error("Unsupported action in behavior rule " + rule.id);
            }
            if (rule.window_us <= 0 || rule.cooldown_us < 0 || rule.group_by.empty()) {
                throw std::runtime_error("Invalid behavior rule: " + rule.id);
            }
            rules.push_back(std::move(rule));
        }
        return rules;
    }

    std::string groupKey(const PacketInfo& packet, const BehaviorRule& rule) {
        std::string key;
        for (const auto& field : rule.group_by) {
            key.push_back('\x1f');
            if (field == "src_ip") {
                key += packet.ipv4->src_ip;
            } else if (field == "dst_ip") {
                key += packet.ipv4->dst_ip;
            } else if (field == "dst_port") {
                key += std::to_string(packet.tcp ? packet.tcp->dst_port : packet.udp->dst_port);
            } else {
                throw std::runtime_error("Unsupported group_by field in behavior rule " + rule.id + ": " + field);
            }
        }
        return key;
    }

    bool behaviorMatches(const PacketInfo& packet, const BehaviorRule& rule) {
        if (!packet.ipv4) {
            return false;
        }
        if (rule.protocol == "TCP") {
            if (!packet.tcp) {
                return false;
            }
            constexpr std::uint16_t syn = 0x02;
            constexpr std::uint16_t ack = 0x10;
            if (rule.tcp_syn_only && ((packet.tcp->flags & syn) == 0 || (packet.tcp->flags & ack) != 0)) {
                return false;
            }
            if (rule.tcp_syn_without_ack && ((packet.tcp->flags & syn) == 0 || (packet.tcp->flags & ack) != 0)) {
                return false;
            }
            return true;
        }
        if (rule.protocol == "UDP") {
            return packet.udp.has_value();
        }
        throw std::runtime_error("Unsupported protocol in behavior rule " + rule.id + ": " + rule.protocol);
    }

    Alert makeBehaviorAlert(const PacketInfo& packet,
                            const BehaviorRule& rule,
                            const BehaviorWindow& window) {
        Alert alert{};
        alert.timestamp_us = packet.timestamp_us;
        alert.rule_id = rule.id;
        alert.action = rule.action;
        alert.behavioral = true;
        alert.src_ip = packet.ipv4->src_ip;
        alert.dst_ip = packet.ipv4->dst_ip;
        if (packet.tcp) {
            alert.src_port = packet.tcp->src_port;
            alert.dst_port = packet.tcp->dst_port;
        } else if (packet.udp) {
            alert.src_port = packet.udp->src_port;
            alert.dst_port = packet.udp->dst_port;
        }

        if (rule.min_unique_dst_ports > 0) {
            alert.message = std::to_string(window.dst_port_counts.size()) + " unique destination ports in " +
                            std::to_string(rule.window_us / 1'000'000) + " seconds";
        } else if (rule.min_unique_dst_ips > 0) {
            alert.message = std::to_string(window.dst_ip_counts.size()) + " unique destination IPs in " +
                            std::to_string(rule.window_us / 1'000'000) + " seconds";
        } else {
            alert.message = std::to_string(window.samples.size()) + " packets in " +
                            std::to_string(rule.window_us / 1'000'000) + " seconds";
        }
        return alert;
    }

    bool thresholdReached(const BehaviorRule& rule, const BehaviorWindow& window) {
        if (rule.min_packets > 0 && window.samples.size() < rule.min_packets) {
            return false;
        }
        if (rule.min_unique_dst_ports > 0) {
            if (window.dst_port_counts.size() < rule.min_unique_dst_ports) return false;
        }
        if (rule.min_unique_dst_ips > 0) {
            if (window.dst_ip_counts.size() < rule.min_unique_dst_ips) return false;
        }
        if (rule.min_unique_src_ips > 0) {
            if (window.src_ip_counts.size() < rule.min_unique_src_ips) return false;
        }
        return rule.min_packets > 0 || rule.min_unique_dst_ports > 0 ||
               rule.min_unique_dst_ips > 0 || rule.min_unique_src_ips > 0;
    }

    bool matchesFilters(const PacketInfo& packet, const SignatureRule& rule) {
        std::uint16_t dst_port;
        if (rule.protocol == "TCP") {
            if (!packet.tcp) {
                return false;
            }
            dst_port = packet.tcp->dst_port;
        } else if (rule.protocol == "UDP") {
            if (!packet.udp) {
                return false;
            }
            dst_port = packet.udp->dst_port;
        } else {
            return false;
        }
        return rule.dst_ports.empty() || std::find(rule.dst_ports.begin(), rule.dst_ports.end(), dst_port) != rule.dst_ports.end();
    }

    bool containsPayload(const PacketInfo& packet, const SignatureRule& rule) {
        const auto pattern_size = rule.contains.size();
        if (pattern_size == 0 || packet.payload.size() < pattern_size) {
            return false;
        }

        std::size_t offset = 0;
        while (offset <= packet.payload.size() - pattern_size) {
            std::size_t index = pattern_size;
            while (index > 0) {
                const auto actual = normalizeByte(packet.payload[offset + index - 1], rule.case_insensitive);
                const auto expected = normalizeByte(
                    static_cast<std::uint8_t>(rule.contains[index - 1]), rule.case_insensitive);
                if (actual != expected) {
                    break;
                }
                --index;
            }
            if (index == 0) {
                return true;
            }
            const auto last = normalizeByte(packet.payload[offset + pattern_size - 1], rule.case_insensitive);
            offset += rule.skip_table[last];
        }
        return false;
    }

    Alert makeAlert(const PacketInfo& packet, const SignatureRule& rule) {
        Alert alert{};
        alert.timestamp_us = packet.timestamp_us;
        alert.rule_id = rule.id;
        alert.message = "Matched payload pattern: " + rule.contains;
        alert.action = rule.action;
        if (packet.ipv4) {
            alert.src_ip = packet.ipv4->src_ip;
            alert.dst_ip = packet.ipv4->dst_ip;
        }
        if (packet.tcp) {
            alert.src_port = packet.tcp->src_port;
            alert.dst_port = packet.tcp->dst_port;
        } else if (packet.udp) {
            alert.src_port = packet.udp->src_port;
            alert.dst_port = packet.udp->dst_port;
        }
        return alert;
    }
};

Engine::Engine() {
    signatures = load_signatures();
    behaviors = load_behaviors();
    behavior_windows.resize(behaviors.size());
}

std::vector<Alert> Engine::process(const PacketInfo& packet) {
    std::vector<Alert> alerts;
    ++packets_processed;
    if (packets_processed % 256 == 0) {
        for (std::size_t index = 0; index < behaviors.size(); ++index) {
            const auto cutoff = packet.timestamp_us - behaviors[index].window_us;
            auto& windows = behavior_windows[index];
            for (auto it = windows.begin(); it != windows.end();) {
                auto& window = it->second;
                while (!window.samples.empty() && window.samples.front().timestamp_us <= cutoff) {
                    removeOldestSample(window);
                }
                const bool cooldown_expired =
                    window.last_alert_us == std::numeric_limits<std::int64_t>::min() ||
                    packet.timestamp_us - window.last_alert_us >= behaviors[index].cooldown_us;
                if (window.samples.empty() && cooldown_expired) {
                    it = windows.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
    for (const auto& rule : signatures) {
        if (!matchesFilters(packet, rule)) {
            continue;
        }
        if (!containsPayload(packet, rule)) {
            continue;
        }
        alerts.push_back(makeAlert(packet, rule));
    }

    for (std::size_t index = 0; index < behaviors.size(); ++index) {
        const auto& rule = behaviors[index];
        if (!behaviorMatches(packet, rule)) {
            continue;
        }
        const auto key = groupKey(packet, rule);
        auto& window = behavior_windows[index][key];
        const auto cutoff = packet.timestamp_us - rule.window_us;
        while (!window.samples.empty() && window.samples.front().timestamp_us <= cutoff) {
            removeOldestSample(window);
        }

        const auto dst_port = packet.tcp ? packet.tcp->dst_port : packet.udp->dst_port;
        addSample(window, {packet.timestamp_us, packet.ipv4->src_ip,
                           packet.ipv4->dst_ip, dst_port});

        if (!thresholdReached(rule, window)) {
            continue;
        }
        if (window.last_alert_us != std::numeric_limits<std::int64_t>::min() &&
            packet.timestamp_us - window.last_alert_us < rule.cooldown_us) {
            continue;
        }
        window.last_alert_us = packet.timestamp_us;
        alerts.push_back(makeBehaviorAlert(packet, rule, window));
    }
    return alerts;
}
