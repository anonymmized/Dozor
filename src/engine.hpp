#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <array>
#include <deque>
#include <limits>
#include <unordered_map>

#include "types.hpp"

struct SignatureRule {
    std::string id;
    std::string protocol;
    std::vector<std::uint16_t> dst_ports;
    std::string contains;
    std::string action = "alert";
    bool case_insensitive = false;
    std::array<std::size_t, 256> skip_table{};
};

struct BehaviorRule {
    std::string id;
    std::string protocol;
    std::vector<std::string> group_by;
    std::int64_t window_us = 0;
    std::int64_t cooldown_us = 10'000'000;
    std::size_t min_packets = 0;
    std::size_t min_unique_dst_ports = 0;
    std::size_t min_unique_dst_ips = 0;
    std::size_t min_unique_src_ips = 0;
    bool tcp_syn_only = false;
    bool tcp_syn_without_ack = false;
    std::string action = "alert";
};

struct BehaviorSample {
    std::int64_t timestamp_us;
    std::string src_ip;
    std::string dst_ip;
    std::uint16_t dst_port;
};

struct BehaviorWindow {
    std::deque<BehaviorSample> samples;
    std::unordered_map<std::uint16_t, std::size_t> dst_port_counts;
    std::unordered_map<std::string, std::size_t> src_ip_counts;
    std::unordered_map<std::string, std::size_t> dst_ip_counts;
    std::int64_t last_alert_us = std::numeric_limits<std::int64_t>::min();
};

struct Alert {
    std::int64_t timestamp_us;
    std::string rule_id;
    std::string message;
    std::string src_ip;
    std::string dst_ip;
    std::string action = "alert";
    bool behavioral = false;
    std::optional<std::uint16_t> src_port;
    std::optional<std::uint16_t> dst_port;
};

class Engine {
private:
    std::vector<SignatureRule> signatures;
    std::vector<BehaviorRule> behaviors;
    std::vector<std::unordered_map<std::string, BehaviorWindow>> behavior_windows;
    std::uint64_t packets_processed = 0;
public:
    Engine();
    std::vector<Alert> process(const PacketInfo& packet);
};
