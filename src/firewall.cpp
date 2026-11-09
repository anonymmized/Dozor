#include "firewall.hpp"

#include <arpa/inet.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

extern char** environ;

namespace {
    void validateIPv4(const std::string& ip) {
        in_addr address{};
        if (inet_pton(AF_INET, ip.c_str(), &address) != 1) {
            throw std::invalid_argument("Invalid IPv4 address: " + ip);
        }
    }

    void runPfctl(const std::vector<std::string>& arguments) {
        std::vector<std::string> command{"/sbin/pfctl"};
        command.insert(command.end(), arguments.begin(), arguments.end());
        std::vector<char*> argv;
        for (auto& argument : command) {
            argv.push_back(argument.data());
        }
        argv.push_back(nullptr);
        pid_t child = 0;
        const int spawn_error = posix_spawn(&child, command[0].c_str(), nullptr, nullptr, argv.data(), environ);
        if (spawn_error != 0) {
            throw std::runtime_error("Cannot start pfctl: " + std::string(std::strerror(spawn_error)));
        }
        int status = 0;
        pid_t result;

        do {
            result = waitpid(child, &status, 0);
        } while (result == -1 && errno == EINTR);

        if (result == -1) {
            throw std::runtime_error("Cannot wait for pfctl: " + std::string(std::strerror(errno)));
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("pfctl failed; check PF configuration and admin privileges");
        }
    }

    std::string runPfctlAndCapture(const std::vector<std::string>& arguments) {
        int pipe_fds[2];
        if (pipe(pipe_fds) == -1) {
            throw std::runtime_error("Cannot create pipe for pfctl output: " +
                                     std::string(std::strerror(errno)));
        }

        posix_spawn_file_actions_t actions;
        int error = posix_spawn_file_actions_init(&actions);
        if (error != 0) {
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            throw std::runtime_error("Cannot initialize pfctl process: " +
                                     std::string(std::strerror(error)));
        }

        error = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
        if (error == 0) {
            error = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDERR_FILENO);
        }
        if (error == 0) {
            error = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
        }
        if (error == 0) {
            error = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
        }
        if (error != 0) {
            posix_spawn_file_actions_destroy(&actions);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            throw std::runtime_error("Cannot configure pfctl output: " +
                                     std::string(std::strerror(error)));
        }

        std::vector<std::string> command{"/sbin/pfctl"};
        command.insert(command.end(), arguments.begin(), arguments.end());
        std::vector<char*> argv;
        for (auto& argument : command) {
            argv.push_back(argument.data());
        }
        argv.push_back(nullptr);

        pid_t child = 0;
        const int spawn_error = posix_spawn(&child, command[0].c_str(), &actions,
                                            nullptr, argv.data(), environ);
        posix_spawn_file_actions_destroy(&actions);
        close(pipe_fds[1]);
        if (spawn_error != 0) {
            close(pipe_fds[0]);
            throw std::runtime_error("Cannot start pfctl: " +
                                     std::string(std::strerror(spawn_error)));
        }

        std::string output;
        char buffer[512];
        ssize_t bytes_read;
        int read_error = 0;
        do {
            bytes_read = read(pipe_fds[0], buffer, sizeof(buffer));
            if (bytes_read > 0) {
                output.append(buffer, static_cast<std::size_t>(bytes_read));
            } else if (bytes_read == -1 && errno == EINTR) {
                continue;
            } else if (bytes_read == -1) {
                read_error = errno;
                break;
            }
        } while (bytes_read != 0);
        close(pipe_fds[0]);

        int status = 0;
        pid_t result;
        do {
            result = waitpid(child, &status, 0);
        } while (result == -1 && errno == EINTR);
        if (result == -1) {
            throw std::runtime_error("Cannot wait for pfctl: " +
                                     std::string(std::strerror(errno)));
        }
        if (read_error != 0) {
            throw std::runtime_error("Cannot read pfctl output: " +
                                     std::string(std::strerror(read_error)));
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("pfctl failed to enable PF: " + output);
        }
        return output;
    }
}

void Firewall::enable() const {
    if (enable_token) {
        return;
    }

    const std::string output = runPfctlAndCapture({"-E"});
    const auto marker = output.find("Token");
    const auto colon = marker == std::string::npos ? marker : output.find(':', marker);
    if (colon == std::string::npos) {
        throw std::runtime_error("pfctl -E did not return an enable token: " + output);
    }
    const auto start = output.find_first_of("0123456789", colon + 1);
    if (start == std::string::npos) {
        throw std::runtime_error("pfctl -E returned an invalid enable token: " + output);
    }
    const auto end = output.find_first_not_of("0123456789", start);
    const auto token = output.substr(start, end == std::string::npos ? end : end - start);
    enable_token = token;
}

void Firewall::disable() const {
    if (!enable_token) {
        return;
    }
    runPfctl({"-X", *enable_token});
    enable_token.reset();
}

void Firewall::blockIp(const std::string& ip) const {
    validateIPv4(ip);
    runPfctl({"-a", "dozor", "-t", "dozor_blocked", "-T", "add", ip});
}

void Firewall::unblockIp(const std::string& ip) const {
    validateIPv4(ip);
    runPfctl({"-a", "dozor", "-t", "dozor_blocked", "-T", "delete", ip});
}
