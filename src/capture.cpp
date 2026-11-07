#include "engine.hpp"
#include "capture.hpp"
#include "parser.hpp"
#include "tmp_print.hpp"

#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <iostream>
#include <stdexcept>


namespace {
    void onPacketArrives(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice*, void* cookie) {
        auto& engine = *static_cast<Engine*>(cookie);
        try {
            auto packet = parsePacket(*raw_packet);
            for (const auto& alert : engine.process(packet)) {
                printAlert(alert);
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Packet processing failed: " << e.what() << '\n';
        }
    } 
};

void captureInterface(const std::string& interface_name, Engine& engine) {
    auto* device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interface_name);
    if (!device) {
        throw std::runtime_error("Unknown interface: " + interface_name);
    }
    if (!device->open()) {
        throw std::runtime_error("Cannot open interface: " + interface_name);
    }
    if (!device->startCapture(onPacketArrives, &engine)) {
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
