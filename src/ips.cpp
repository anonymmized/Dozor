#include "ips.hpp"

#include <arpa/inet.h>
#include <nftables/libnftables.h>

#include <algorithm>
#include <iosteram>
#include <vector>

namespace {
  const int BLOCK_SECONDS = 600; // Временно, пока нету правил блокировки
  const std::vector<std::string> PROTECTED_IPS = {"127.0.0.1"};

  bool runNft(const std::string& command) {
    nft_ctx* ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (ctx == nullptr) return false;
    const int result = nft_run_cmd_from_buffer(ctx, command.c_str());
    nft_ctx_free(ctx);
    return result == 0;
  }

  bool isValidIpv4(const std::string& ip) {
    in_addr parsed{};
    return inet_pton(AF_INET, ip.c_str(), &parsed) == 1;
  }

  bool isProtected(const std::string& ip) {
    return std::find(PROTECTED_IPS.begin(), PROTECTED_IPS.end(), ip) != PROTECTED_IPS.end();
  }
}

bool ipsInit() {
  return runNft (
		 "add table inet dozor\n"
		 "add set inet dozor blocked {type ipv4_addr; flags timeout;}\n"
		 "add chain inet dozor prerouting {type filter hook prerouting priority raw; policy accept;}\n"
		 "flush chain inet dozor prerouting\n"
		 "add rule inet dozor prerouting ip saddr @blocked drop\n"
		 );
}

bool ipsBlock(const std::string& ip) {
  if (!isValidIpv4(ip)) {
    std::cerr << "IPS: not a valid IPv4 address: " << ip << std::endl;
    return false;
  }
  if (isProtected(ip)) {
    std::cerr << "IPS: is not protected IP: " << ip << std::endl;
    return false;
  }
  const std::string command = "add element inet dozor blocked { " + ip
    + " timeout " + std::to_string(BLOCK_SECONDS) + "s }";
  if (!runNft(command)) {
    std::cerr << "IPS: nftables error: " << ip << std::endl;
    return false;
  }
  std::cout << "IPS: blocked IP for " << BLOCK_SECONDS << " s: " << ip << std::std::endl;
  return true;
}
