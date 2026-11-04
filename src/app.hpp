#pragma once

#include "cmd_parse.hpp"

class App {
private:
    CmdContent cmd;
public:
    App(int argc, char** argv) {
        cmd = parseCommandLine(argc, argv);
    }
    void run();
};
