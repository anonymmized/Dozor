#pragma once

#include "types.hpp"
#include "engine.hpp"

#include <vector>
#include <string>

std::vector<PacketInfo> parsePcapFile(const std::string& pcap_file);
void captureInterface(const std::string& interface_name, Engine& engine);
