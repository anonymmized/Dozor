#pragma once

#include "types.hpp"

#include <RawPacket.h>

#include <functional>
#include <vector>
#include <string>

using PacketHandler = std::function<void(pcpp::RawPacket&)>;
using ParsedPacketHandler = std::function<void(const PacketInfo&)>;

std::vector<PacketInfo> parsePcapFile(const std::string& pcap_file);
void forEachPcapPacket(const std::string& pcap_file, const ParsedPacketHandler& handler);
void captureInterface(const std::string& interface_name, const PacketHandler& handler);
void printAvailableInterfaces();
