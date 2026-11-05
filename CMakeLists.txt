cmake_minimum_required(VERSION 3.16)
project(dozor LANGUAGES CXX)
find_package(PcapPlusPlus REQUIRED)

add_executable(dozor 
    src/main.cpp
    src/app.cpp
    src/cmd_parse.cpp
    src/capture.cpp
    src/parser.cpp
    src/tmp_print.cpp)
target_compile_features(dozor PRIVATE cxx_std_17)
target_include_directories(dozor PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(dozor PRIVATE PcapPlusPlus::Pcap++)
