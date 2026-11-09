#include "cmd_parse.hpp"
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <filesystem>
#include <net/if.h>
#include <unordered_set>

namespace {
    std::vector<std::string> dump_line(int argc, char** argv) {
        std::vector<std::string> dumped_vector;
        for (int i = 2; i < argc; i++) {
            dumped_vector.push_back(argv[i]);
        }
        return dumped_vector;
    }

    void checkPaths(const std::vector<std::string>& paths) {
        if (paths.empty()) {
            throw std::invalid_argument("There is no files passed");
        }
        for (const auto& path : paths) {
            if (!std::filesystem::is_regular_file(path)) {
                throw std::invalid_argument("The file " + path + " is not exist");
            }
        }
    }

    void checkInterfaces(const std::vector<std::string>& interfaces) {
        std::unordered_set<std::string> available_interfaces;
        struct if_nameindex* sys_interfaces = if_nameindex();
        if (!sys_interfaces) {
            throw std::runtime_error("Failed to get interfaces");
        }
        for (struct if_nameindex* it = sys_interfaces; it->if_index != 0; ++it) {
            available_interfaces.insert(it->if_name);
        }
        if_freenameindex(sys_interfaces);
        for (const auto& interface : interfaces) {
            if (!available_interfaces.contains(interface)) {
                throw std::invalid_argument("The interface " + interface + " is not set in the system");
            }
        }
    }
};

CmdContent parseCommandLine(int argc, char** argv) {
    if (argc < 2) {
        throw std::invalid_argument("Usage: dozor --pcap <file...> | --int <interface> | --intlist");
    }
    static const std::unordered_map<std::string, Modes> mode_map{
        {"--pcap", Modes::Pcap},
        {"--int", Modes::Interface},
        {"-il", Modes::InterfaceList},
        {"--intlist", Modes::InterfaceList}
    };
    const auto it = mode_map.find(argv[1]);
    if (it == mode_map.end()) {
        //print_help_page();
        throw std::invalid_argument("Unknown mode: " + std::string(argv[1]));
    }
    CmdContent cmd{};
    cmd.mode = it->second;

    if (cmd.mode == Modes::Pcap) {
        cmd.content = dump_line(argc, argv);
        checkPaths(cmd.content);
    }
    if (cmd.mode == Modes::Interface) {
        cmd.content = dump_line(argc, argv);
        if (cmd.content.size() != 1) {
            throw std::invalid_argument("--int accepts exactly one interface name");
        }
        checkInterfaces(cmd.content);
    }
    if (cmd.mode == Modes::InterfaceList) {
        if (argc != 2) {
            throw std::invalid_argument("--intlist does not accept arguments");
        }
        return cmd;
    }
    return cmd;
}
