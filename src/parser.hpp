#pragma once

#include "types.hpp"
#include <RawPacket.h>

PacketInfo parsePacket(pcpp::RawPacket& raw_packet);
