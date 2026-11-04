#include "parser.hpp"
#include "types.hpp"
#include "capture.hpp"

#include <vector>
#include <PcapFileDevice.h>
#include <stdexcept>

std::vector<PacketInfo> parsePcapFile(const std::string& pcap_file) {
    pcpp::PcapFileReaderDevice reader(pcap_file);
    if (!reader.open()) {
        throw std::runtime_error("The file " + pcap_file  + " was not opened");
    }
    pcpp::RawPacket rawPacket;
    std::vector<PacketInfo> packetsInfo;
    while (reader.getNextPacket(rawPacket)) {
        packetsInfo.push_back(parsePacket(rawPacket));
    }
    reader.close();
    return packetsInfo;
}
