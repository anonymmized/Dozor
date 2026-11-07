#include "signature.hpp"
#include <algorithm>
#include <string_view>

bool matchesSignature(const PacketInfo& packet) {
    constexpr std::string_view signature = "IDS_DEMO_SIGNATURE";
    const auto found = std::search(packet.payload.begin(), packet.payload.end(), signature.begin(), signature.end());
    return found != packet.payload.end();
}
