#include "cmd_parse.hpp"
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <filesystem>

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
};

CmdContent parseCommandLine(int argc, char** argv) {
    if (argc < 3) {
        throw std::invalid_argument("Not anough arguments");
    }
    static const std::unordered_map<std::string, Modes> mode_map{
        {"--pcap", Modes::Pcap},
        {"--int", Modes::Interface}
    };
    CmdContent cmd;
    const auto it = mode_map.find(argv[1]);
    if (it == mode_map.end()) {
        //print_help_page();
        throw std::invalid_argument("Unknown mode: " + std::string(argv[1]));
    }
    cmd.mode = it->second;
    if (cmd.mode == Modes::Pcap) {
        cmd.content = dump_line(argc, argv);
        checkPaths(cmd.content);
    }
    if (cmd.mode == Modes::Interface) {
        cmd.content = dump_line(argc, argv);
        // сделать проверку интерфейсов
    }
    return cmd;
}
