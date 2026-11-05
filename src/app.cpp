#include "app.hpp"
#include "types.hpp"
#include "parser.hpp"
#include "tmp_print.hpp"

#include <PcapFileDevice.h>
#include <vector>
#include <string>
#include <stdexcept>

void App::run() {
    if (cmd.mode == Modes::Pcap) {
        std::vector<PacketInfo> parsedFiles{};
        for (const auto& file : cmd.content) {
            pcpp::PcapFileReaderDevice reader(file);
            if (!reader.open()) {
                throw std::runtime_error("Cannot open file: " + file);
            }
            pcpp::RawPacket rawPacket;
            while (reader.getNextPacket(rawPacket)) {
                auto info = parsePacket(rawPacket);
                printPacketInfo(info);
                parsedFiles.push_back(info);
            }
            reader.close();
        }
    }
}
