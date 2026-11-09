#include "ips.hpp"

#include <fstream>
#include <stdexcept>
#include <utility>

IPS::IPS(std::filesystem::path path) : file_path(std::move(path)) {
    load();
}

void IPS::load() {
    blocked_until.clear();
    if (!std::filesystem::exists(file_path)) {
        return;
    }
    std::ifstream input(file_path);
    if (!input) {
        throw std::runtime_error("Cannot read blocklist: " + file_path.string());
    }
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) {
            continue;
        }
        const auto comma = line.find(',');
        if (comma == std::string::npos || comma == 0) {
            throw std::runtime_error("Invalid blocklist entry at line " + std::to_string(line_number));
        }
        const std::string ip = line.substr(0, comma);
        const std::string time_text = line.substr(comma + 1);

        std::size_t parsed_chars = 0;
        long long timestamp = 0;

        try {
            timestamp = std::stoll(time_text, &parsed_chars);
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid expiration time at blocklist line " + std::to_string(line_number));
        }
        if (parsed_chars != time_text.size()) {
            throw std::runtime_error("Invalid expiration time at blocklist line " + std::to_string(line_number));
        }
        const auto new_blocked_until = Clock::time_point{std::chrono::seconds{timestamp}};
        auto [it, inserted] = blocked_until.try_emplace(ip, new_blocked_until);
        if (!inserted && it->second < new_blocked_until) {
            it->second = new_blocked_until;
        }
    }
}

bool IPS::isBlocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex);
    const auto it = blocked_until.find(ip);
    return it != blocked_until.end() && it->second > Clock::now();
}

void IPS::blockIp(const std::string& ip, std::chrono::seconds duration) {
    if (ip.empty() || duration <= std::chrono::seconds::zero()) {
        throw std::invalid_argument("IP and positive duration are required");
    }
    std::lock_guard<std::mutex> lock(mutex);
    const auto new_expiration = Clock::now() + duration;
    auto [it, inserted] = blocked_until.try_emplace(ip, new_expiration);
    if (!inserted && it->second < new_expiration) {
        it->second = new_expiration;
    }
    saveLocked();
}

std::vector<std::string> IPS::activeIps() const {
    std::lock_guard<std::mutex> lock(mutex);
    std::vector<std::string> ips;
    const auto now = Clock::now();
    for (const auto& [ip, expiration] : blocked_until) {
        if (expiration > now) {
            ips.push_back(ip);
        }
    }
    return ips;
}

std::vector<std::string> IPS::expiredIps() const {
    std::lock_guard<std::mutex> lock(mutex);
    std::vector<std::string> ips;
    const auto now = Clock::now();
    for (const auto& [ip, expiration] : blocked_until) {
        if (expiration <= now) {
            ips.push_back(ip);
        }
    }
    return ips;
}

void IPS::removeIp(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex);
    if (blocked_until.erase(ip) > 0) {
        saveLocked();
    }
}

void IPS::saveLocked() const {
    if (!file_path.parent_path().empty()) {
        std::filesystem::create_directories(file_path.parent_path());
    }
    std::ofstream output(file_path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Cannot write blocklist: " + file_path.string());
    }
    const auto now = Clock::now();
    for (const auto& [ip, expiration] : blocked_until) {
        if (expiration <= now) {
            continue;
        }
        const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(expiration.time_since_epoch()).count();
        output << ip << ',' << timestamp << '\n';
    }
    if (!output) {
        throw std::runtime_error("Failed writing blocklist: " + file_path.string());
    }
}
