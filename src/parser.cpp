#include "types.hpp"

#include <PcapFileDevice.h>
#include <EthLayer.h>
#include <SystemUtils.h>
#include <IPv4Layer.h>

namespace {
    EthernetInfo parse_ethernet(pcpp::EthLayer* eth) {
        EthernetInfo eth_info;
        eth_info.src_mac = eth->getSourceMac().toString();
        eth_info.dst_mac = eth->getDestMac().toString();
        eth_info.ether_type = pcpp::netToHost16(eth->getEthHeader()->etherType);
        return eth_info;
    }

    IPv4Info parse_ipv4(pcpp::IPv4Layer* ipv4) {
        IPv4Info data;
        const auto* header = ipv4->getIPv4Header();
        const auto header_size = header->internetHeaderLength * 4u;
        if (header_size >= 20 && header_size <= ipv4->getDataLen()) {
            data.src_ip = ipv4->getSrcIPAddress().toString();
            data.dst_ip = ipv4->getDstIPAddress().toString();
            data.ttl = header->timeToLive;
            data.protocol = header->protocol;
            data.header_size = header_size;
            data.total_len = pcpp::netToHost16(header->totalLength);
            data.ip_id = pcpp::netToHost16(header->ipId);
            data.checksum = pcpp::netToHost16(header->headerChecksum);
            
            const auto fragment = pcpp::netToHost16(header->fragmentOffset);
            data.dont_fragment = (fragment & 0x4000) != 0;
            data.more_fragments = (fragment & 0x2000) != 0;
            data.fragment_offset = fragment & 0x1FFF;
            data.options.assign(ip->getData() + 20, ip->getData() + header_size);
        }
        return data;
    }
};

PacketInfo parsePacket(const pcpp::RawPacket& raw_packet) {
    PacketInfo info;

    // первые 4 поля структуры
    const auto ts = raw_packet.getPacketTimeStamp();
    info.timestamp_us = static_cast<std::int64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
    info.captured_size = static_cast<std::uint32_t>(raw_packet.getRawDataLen());
    info.original_size = static_cast<std::uint32_t>(raw_packet.getFrameLength());
    info.link_type = static_cast<std::int32_t>(raw_packet.getLinkLayerType());
    
    pcpp::Packet packet(&raw_packet);

    // PacketInfo.ethernet
    auto* eth = packet.getLayerOfType<pcpp::EthLayer>();
    if (eth) {
        info.ethernet = parse_ethernet(eth);
    }
    
    // PacketInfo.ipv4
    auto* ip = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ip) {
        info.ipv4 = parse_ipv4(ip);
    } 
    // PacketInfo.tcp
    auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();

    // PacketInfo.udp
    auto* udp = packet.getLayerOfType<pcpp::UdpLayer>();
}
