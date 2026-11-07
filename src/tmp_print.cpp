#include <iostream>
#include "tmp_print.hpp"

void printAlert(const Alert& alert) {
    std::cout << "[ALERT] " << alert.rule_id << '\n'
              << "  Time: " << alert.timestamp_us << " us\n"
              << "  Message: " << alert.message << '\n'
              << "  Source: "
              << (alert.src_ip.empty() ? "-" : alert.src_ip) << ':';

    if (alert.src_port)
        std::cout << *alert.src_port;
    else
        std::cout << '-';

    std::cout << "\n  Destination: "
              << (alert.dst_ip.empty() ? "-" : alert.dst_ip) << ':';

    if (alert.dst_port)
        std::cout << *alert.dst_port;
    else
        std::cout << '-';

    std::cout << "\n\n";
}
