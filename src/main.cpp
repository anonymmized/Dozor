#include <iostream>
#include "app.hpp"

int main(int argc, char** argv) {
    
    try {
        App app(argc, argv);
        app.run();
    } catch (std::exception& e) {
        std::cerr << "[ERROR] " << e.what();
    }
}
