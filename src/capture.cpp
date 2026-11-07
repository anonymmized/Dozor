#include "capture.hpp"
#include "parser.hpp"
#include "tmp_print.hpp"

#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <iostream>
#include <stdexcept>


namespace {
    void onPacketArrives(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice*, void* cookie) {
        auto& packets = *static_cast<std::vector<PacketInfo>*>(cookie);
        packets.push_back(parsePacket(*raw_packet));
    } 
};

std::vector<PacketInfo> captureInterface(const std::string& interface_name) {
    std::vector<PacketInfo> packets;
    auto* device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interface_name);
    
    if (!device) {
        throw std::runtime_error("Unknown interface: " + interface_name);
    }
    if (!device->open()) {
        throw std::runtime_error("Cannot open interface: " + interface_name);
    }
    if (!device->startCapture(onPacketArrives, &packets)) {
        device->close();
        throw std::runtime_error("Cannot start capture on: " + interface_name);
    }
    
    std::cout << "Capturing on " << interface_name << ". Press Enter to stop\n";
    std::string line;
    std::getline(std::cin, line);
    device->stopCapture();
    device->close();
    return packets;
}

std::vector<PacketInfo> parsePcapFile(const std::string& pcap_file) {
    pcpp::PcapFileReaderDevice reader(pcap_file);
    if (!reader.open()) {
        throw std::runtime_error("Cannot open file: " + pcap_file);
    }
    std::vector<PacketInfo> packets;
    pcpp::RawPacket raw_packet;
    while (reader.getNextPacket(raw_packet)) {
        packets.push_back(parsePacket(raw_packet));
    }
    reader.close();
    return packets;
}

void printAvailableInterfaces() {
    const auto& devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    if (devices.empty()) {
        std::cout << "No network interfaces found\n";
        return;
    }
    std::cout << "Available network interfaces:\n";
    for (const auto& device : devices) {
        std::cout << "- " << device->getName() << " | IPv4: " << device->getIPv4Address().toString();
        const auto description = device->getDesc();
        if (!description.empty()) {
            std::cout << " | " << description;
        }
        std::cout << '\n';
    }
}
