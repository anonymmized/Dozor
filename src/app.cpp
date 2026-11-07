#include "app.hpp"
#include "types.hpp"
#include "parser.hpp"
#include "engine.hpp"
#include "tmp_print.hpp"
#include "signature.hpp"

#include <PcapFileDevice.h>
#include <vector>
#include <string>
#include <stdexcept>

void App::run() {
    if (cmd.mode == Modes::Pcap) {
        Engine engine;
        for (const auto& file : cmd.content) {
            pcpp::PcapFileReaderDevice reader(file);
            if (!reader.open()) {
                throw std::runtime_error("Cannot open file: " + file);
            }
            pcpp::RawPacket rawPacket;
            while (reader.getNextPacket(rawPacket)) {
                auto info = parsePacket(rawPacket);
                auto alerts = engine.process(info);
                for (const auto& alert : alerts) {
                    printAlert(alert);
                }
                //printPacketInfo(info);
            }
            reader.close();
        }
    }
}
