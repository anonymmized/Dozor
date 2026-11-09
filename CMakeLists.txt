cmake_minimum_required(VERSION 3.16)
project(dozor LANGUAGES CXX)
find_package(PcapPlusPlus REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)

add_executable(dozor 
    src/main.cpp
    src/app.cpp
    src/cmd_parse.cpp
    src/capture.cpp
    src/parser.cpp
    src/tmp_print.cpp
    src/engine.cpp
    src/ips.cpp
    src/firewall.cpp)
target_compile_features(dozor PRIVATE cxx_std_20)
target_include_directories(dozor PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(dozor PRIVATE PcapPlusPlus::Pcap++ yaml-cpp::yaml-cpp)
target_compile_definitions(dozor PRIVATE "DOZOR_RULES_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/rules\"")
