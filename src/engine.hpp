#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "types.hpp"

struct SignatureRule {
    std::string id;
    std::string protocol;
    std::vector<std::uint16_t> dst_ports;
    std::string contains;
    bool case_insensitive;
};

struct Alert {
    std::int64_t timestamp_us;
    std::string rule_id;
    std::string message;
    std::string src_ip;
    std::string dst_ip;
    std::optional<std::uint16_t> src_port;
    std::optional<std::uint16_t> dst_port;
};

class Engine {
private:
    std::vector<SignatureRule> signatures;
public:
    Engine();
    std::vector<Alert> process(const PacketInfo& packet);
};
