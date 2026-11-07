#include "app.hpp"
#include "types.hpp"
#include "parser.hpp"
#include "engine.hpp"
#include "tmp_print.hpp"
#include "signature.hpp"
#include "capture.hpp"

#include <PcapFileDevice.h>
#include <vector>
#include <string>
#include <stdexcept>

void App::run() {
    Engine engine;
    if (cmd.mode == Modes::Pcap) {
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
    } else if (cmd.mode == Modes::Interface) {
        captureInterface(cmd.content.front(), engine);
    }
}
