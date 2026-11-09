#include "capture.hpp"
#include "parser.hpp"
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    struct CaptureContext {
        const PacketHandler& handler;
    };

    void onPacketArrives(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice*, void* cookie) {
        auto& context = *static_cast<CaptureContext*>(cookie);
        try {
            context.handler(*raw_packet);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Packet handler failed: " << e.what() << '\n';
        }
    }
}

void captureInterface(const std::string& interface_name, const PacketHandler& handler) {
    auto* device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interface_name);

    if (!device) {
        throw std::runtime_error("Unknown interface: " + interface_name);
    }

    if (!device->open()) {
        throw std::runtime_error("Cannot open interface: " + interface_name);
    }

    CaptureContext context{handler};

    if (!device->startCapture(onPacketArrives, &context)) {
        device->close();
        throw std::runtime_error("Cannot start capture on: " + interface_name);
    }

    std::cout << "Capturing on " << interface_name << ". Press Enter to stop\n";

    std::string line;
    std::getline(std::cin, line);

    device->stopCapture();
    device->close();
}

std::vector<PacketInfo> parsePcapFile(const std::string& pcap_file) {
    std::vector<PacketInfo> packets;
    forEachPcapPacket(pcap_file, [&packets](const PacketInfo& packet) {
        packets.push_back(packet);
    });
    return packets;
}

void forEachPcapPacket(const std::string& pcap_file, const ParsedPacketHandler& handler) {
    pcpp::PcapFileReaderDevice reader(pcap_file);

    if (!reader.open()) {
        throw std::runtime_error("Cannot open file: " + pcap_file);
    }

    pcpp::RawPacket raw_packet;

    while (reader.getNextPacket(raw_packet)) {
        const PacketInfo packet = parsePacket(raw_packet);
        handler(packet);
    }

    reader.close();
}

void printAvailableInterfaces() {
    const auto& devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    if (devices.empty()) {
        std::cout << "No network interfaces found\n";
        return;
    }

    std::cout << "Available network interfaces:\n";

    for (const auto* device : devices) {
        std::cout << "- " << device->getName() << " | IPv4: " << device->getIPv4Address().toString();

        const auto description = device->getDesc();
        if (!description.empty()) {
            std::cout << " | " << description;
        }

        std::cout << '\n';
    }
}
