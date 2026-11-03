#include <iostream>
#include <string>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

int main(int argc, char** argv) {
    if (argc != 3 || std::string(argv[1]) != "--pcap") {
        std::cerr << "Usage: dozor --pcap file.pcap\n";
        return 1;
    }   
    pcpp::PcapFileReaderDevice reader(argv[2]);
    if (!reader.open()) {
        std::cerr << "Cannot open file: " << argv[2] << '\n';
        return 1;
    }

    pcpp::RawPacket rawPacket;
    std::size_t total = 0;
    std::size_t parsed = 0;
    
    while (reader.getNextPacket(rawPacket)) {
        ++total;
        pcpp::Packet packet(&rawPacket);
        auto* ip = packet.getLayerOfType<pcpp::IPv4Layer>();
        if (ip == nullptr) {
            continue;
        }
        auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
        auto* udp = packet.getLayerOfType<pcpp::UdpLayer>();
        if (tcp == nullptr && udp == nullptr) {
            continue;
        }
        const char* protocol = tcp ? "TCP" : "UDP";
        const auto srcPort = tcp ? tcp->getSrcPort() : udp->getSrcPort();
        const auto dstPort = tcp ? tcp->getDstPort() : udp->getDstPort();
        const auto payloadSize = tcp ? tcp->getLayerPayloadSize() : udp->getLayerPayloadSize();
        std::cout << protocol << ' ' << ip->getSrcIPAddress().toString() << ':' << srcPort 
            << " -> " << ip->getDstIPAddress().toString() << ':' << dstPort << " | payload: " << payloadSize << " bytes\n";
        ++parsed;
    }
    reader.close();
    std::cout << "Read: " << total << ", IPv4 TCP/UDP: " << parsed << '\n';
    return 0;
}
