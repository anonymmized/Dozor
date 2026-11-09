#include <iostream>
#include "app.hpp"

int main(int argc, char** argv) {
    
    try {
        App app(argc, argv);
        app.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return 1;
    }
}
