#pragma once

#include <string>
#include <vector>

enum class Modes {
    Pcap,
    Interface,
    InterfaceList
};

struct CmdContent {
    Modes mode;
    std::vector<std::string> content;
};

CmdContent parseCommandLine(int argc, char** argv);
