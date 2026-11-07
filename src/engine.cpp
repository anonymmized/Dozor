#include "engine.hpp"
#include "config.hpp"
#include <yaml-cpp/yaml.h>
#include <stdexcept>
#include <algorithm>

namespace {
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
            rule.case_insensitive = entry["case_insensitive"].as<bool>();
            rules.push_back(rule);
        }
        return rules;
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
        if (rule.contains.empty()) {
            return false;
        }
        auto lowerAscii = [](unsigned char c) {
            if (c >= 'A' && c <= 'Z') {
                return static_cast<unsigned char>(c + ('a' - 'A'));
            }
            return c;
        };
        auto equal = [&rule, &lowerAscii](std::uint8_t byte, char expected) {
            auto actual = static_cast<unsigned char>(byte);
            auto pattern = static_cast<unsigned char>(expected);
            if (rule.case_insensitive) {
                actual = lowerAscii(actual);
                pattern = lowerAscii(pattern);
            }
            return actual == pattern;
        };
        return std::search(packet.payload.begin(), packet.payload.end(), rule.contains.begin(), rule.contains.end(), equal) != packet.payload.end();
    }

    Alert makeAlert(const PacketInfo& packet, const SignatureRule& rule) {
        Alert alert{};
        alert.timestamp_us = packet.timestamp_us;
        alert.rule_id = rule.id;
        alert.message = "Matched payload pattern: " + rule.contains;
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
}

std::vector<Alert> Engine::process(const PacketInfo& packet) {
    std::vector<Alert> alerts;
    for (const auto& rule : signatures) {
        if (!matchesFilters(packet, rule)) {
            continue;
        }
        if (!containsPayload(packet, rule)) {
            continue;
        }
        alerts.push_back(makeAlert(packet, rule));
    }
    return alerts;
}
