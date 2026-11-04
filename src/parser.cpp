#include "types.hpp"

#include <PcapFileDevice.h>
#include <EthLayer.h>
#include <SystemUtils.h>
#include <IPv4Layer.h>
#include <Packet.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

namespace {
    EthernetInfo parse_ethernet(const pcpp::EthLayer* eth) {
        EthernetInfo eth_info;
        eth_info.src_mac = eth->getSourceMac().toString();
        eth_info.dst_mac = eth->getDestMac().toString();
        eth_info.ether_type = pcpp::netToHost16(eth->getEthHeader()->etherType);
        return eth_info;
    }

    std::optional<IPv4Info> parse_ipv4(const pcpp::IPv4Layer* ipv4) {
        const auto* header = ipv4->getIPv4Header();
        const auto header_size = header->internetHeaderLength * 4u;
        if (header_size >= 20 && header_size <= ipv4->getDataLen()) {
            IPv4Info data;
            data.src_ip = ipv4->getSrcIPAddress().toString();
            data.dst_ip = ipv4->getDstIPAddress().toString();
            data.ttl = header->timeToLive;
            data.protocol = header->protocol;
            data.header_size = header_size;
            data.total_len = pcpp::netToHost16(header->totalLength);
            if (data.total_len < header_size || data.total_len > ipv4->getDataLen()) {
                return std::nullopt;
            }
            data.ip_id = pcpp::netToHost16(header->ipId);
            data.checksum = pcpp::netToHost16(header->headerChecksum);
            
            const auto fragment = pcpp::netToHost16(header->fragmentOffset);
            data.dont_fragment = (fragment & 0x4000) != 0;
            data.more_fragments = (fragment & 0x2000) != 0;
            data.fragment_offset = fragment & 0x1FFF;
            data.options.assign(ipv4->getData() + 20, ipv4->getData() + header_size);
            return data;
        }
        return std::nullopt;
    }

    std::optional<TcpInfo> parse_tcp(const pcpp::TcpLayer* tcp) {
        if (!tcp || tcp->getDataLen() < 20) {
            return std::nullopt;
        }
        const auto* header = tcp->getTcpHeader();
        const auto header_size = header->dataOffset * 4u;
        if (header_size < 20 || header_size > tcp->getDataLen()) {
            return std::nullopt;
        }
        TcpInfo data;
        data.src_port = tcp->getSrcPort();
        data.dst_port = tcp->getDstPort();
        data.seq_number = pcpp::netToHost32(header->sequenceNumber);
        data.ack_number = pcpp::netToHost32(header->ackNumber);
        data.window_size = pcpp::netToHost16(header->windowSize);
        data.header_size = static_cast<std::uint8_t>(header_size);
        data.checksum = pcpp::netToHost16(header->headerChecksum);
        data.urg_pointer = pcpp::netToHost16(header->urgentPointer);
        const auto* bytes = tcp->getData();
        data.flags = static_cast<std::uint16_t>((bytes[12] & 0x01u) << 8) | bytes[13];
        data.options.assign(bytes + 20, bytes + header_size);
        return data;
    }

    std::optional<UdpInfo> parse_udp(const pcpp::UdpLayer* udp) {
        if (!udp || udp->getDataLen() < 8) {
            return std::nullopt;
        }
        const auto* header = udp->getUdpHeader();
        const auto length = pcpp::netToHost16(header->length);
        if (length < 8 || length > udp->getDataLen()) {
            return std::nullopt;
        }
        UdpInfo data;
        data.src_port = udp->getSrcPort();
        data.dst_port = udp->getDstPort();
        data.length = length;
        data.checksum = pcpp::netToHost16(header->headerChecksum);
        return data;
    }
};

PacketInfo parsePacket(pcpp::RawPacket& raw_packet) {
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
    
    if (!info.ipv4 || info.ipv4->more_fragments || info.ipv4->fragment_offset != 0) {
        return info;
    }
    // PacketInfo.tcp
    auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcp) {
        info.tcp = parse_tcp(tcp);
    }
    if (info.tcp) {
        const auto* payload = tcp->getLayerPayload();
        const auto size = tcp->getLayerPayloadSize();
        if (size > 0) {
            info.payload.assign(payload, payload + size);
        }
    }

    // PacketInfo.udp
    auto* udp = packet.getLayerOfType<pcpp::UdpLayer>();
    if (udp) {
        info.udp = parse_udp(udp);
    }
    if (info.udp) {
        const auto* data = udp->getLayerPayload();
        const auto size = info.udp->length - 8;
        if (size > 0) {
            info.payload.assign(data, data + size);
        }
    }
    return info;
}
