#pragma once

#include <optional>
#include <string>

class Firewall {
public:
    void enable() const;
    void disable() const;
    void blockIp(const std::string& ip) const;
    void unblockIp(const std::string& ip) const;

private:
    mutable std::optional<std::string> enable_token;
};
