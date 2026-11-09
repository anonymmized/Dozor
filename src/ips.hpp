#pragma once

#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class IPS {
public:
    explicit IPS(std::filesystem::path file_path);

    bool isBlocked(const std::string& ip) const;
    void blockIp(const std::string& ip,
                 std::chrono::seconds duration = std::chrono::seconds{3600});
    std::vector<std::string> activeIps() const;
    std::vector<std::string> expiredIps() const;
    void removeIp(const std::string& ip);

private:
    using Clock = std::chrono::system_clock;

    void load();
    void saveLocked() const;

    std::filesystem::path file_path;
    std::unordered_map<std::string, Clock::time_point> blocked_until;
    mutable std::mutex mutex;
};
