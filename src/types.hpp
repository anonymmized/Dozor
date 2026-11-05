#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct EthernetInfo {
    /*
       Сведения о заголовке Ethernet кадра включают в себя: 
         порт отправителя
         порт получателя 
         код протокола внутри, может быть например 0x0800 - IPv4 или 0x0806 - arp
    */
    std::string src_mac; 
    std::string dst_mac; 
    std::uint16_t ether_type = 0;
};

struct IPv4Info {
    /*
       Сведения о заголовке пакета IPv4:
         src_ip/dst_ip - ip адрес отправителя и получателя
         ttl - оставшееся число переходов через маршрутизаторы
         protocol - протокол внутри ip пакета 6 - tcp или 17 - udp и тп
         header_size - размер заголовка IPv4 в байтах
         total_len - общий размер ip пакета
         ip_id - идентификатор ipv4 пакета общий для всех его фрагментов
         dont_fragment - запрет фрагментации пакета
         more_fragments - true-если после этого фрагмента есть следующие
         fragment_offset - смещение фрагмента отн. начала в блоках по 8 байт
         checksum - контрольная сумма только заголовка ipv4
         options - байты доп. опций заголовка если они есть
    */
    std::string src_ip; 
    std::string dst_ip; 
    
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint8_t header_size = 0;
    std::uint16_t total_len = 0;
    std::uint16_t ip_id = 0;

    bool dont_fragment = false;
    bool more_fragments = false;
    std::uint16_t fragment_offset = 0;

    std::uint16_t checksum = 0;
    std::vector<std::uint8_t> options;
};

struct TcpInfo {
    /*
        Сведения о заголовке tcp сегмента
          src_port/dst_port - порт отправителя и получателя
          seq_number - номер начала передаваемых данных
          ack_number - номер следующего ожидаемого байта от другой стороны
          flags - битовая маска управляющих флагов syn,ack,fin,rst и тп
          window_size - сколько данных сторона готова принять
          header_size - размер tcp заголовка в байтах включая опции
          checksum - контрольная сумма заголовка
          urgent_pointer - указатель на срочные данные (при флаге urg)
          options - байты дополнительных опций tcp заголовка
    */
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;

    std::uint32_t seq_number = 0;
    std::uint32_t ack_number = 0;

    std::uint16_t flags = 0;
    std::uint16_t window_size = 0;
    std::uint8_t header_size = 0;
    std::uint16_t checksum = 0;
    std::uint16_t urg_pointer = 0;

    std::vector<std::uint8_t> options;
};

struct UdpInfo {
    /*
        Сведения о заголовке udp сегмента:
          src_port/dst_port - порт отправителя и получателя
          length - общая длина заголовка
          checksum - контрольная сумма заголовка
    */
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length = 0;
    std::uint16_t checksum = 0;
};

struct PacketInfo {
    /*
        Общая структура разобранного пакета
          timestamp_us - время пакета из источника захвата в микросекундах
          captured_size - количество фактически полученных байтов
          original_size - исходный размер кадра по сведениям захвата
          link_type - тип канального уровня захвата например ethernet
          ethernet - если есть, то сведения ethernet
          ipv4 - если есть, то сведения ipv4
          tcp - если есть, то сведения tcp
          udp - если есть, то сведения udp
          payload - собственная копия полезных данных tcp или udp
    */
    std::int64_t timestamp_us = 0;
    std::uint32_t captured_size = 0;
    std::uint32_t original_size = 0;
    std::int32_t link_type = 0;
    
    std::optional<EthernetInfo> ethernet;
    std::optional<IPv4Info> ipv4;
    std::optional<TcpInfo> tcp;
    std::optional<UdpInfo> udp;
    std::vector<std::uint8_t> payload;
};
