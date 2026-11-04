#include "../src/ips.hpp";

#include <iostream>

int main(int args, char** argv) {
  if (args != 2) {
    std::cerr << "Usage: ips_cli <ip>\n";
    return 1;
  }
  if (!ipsInit()) {
    std::cerr << "Cannot set up nftables\n";
    return 1;
  }
  return ipsBlock(argv[1]) ? 0 : 1;
}
