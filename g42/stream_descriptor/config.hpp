#ifndef CONFIG_HPP
#define CONFIG_HPP

#define TUN0 "tun1" // TODO we use vpn?
#define IPV6SERVER "fd42::1"
#define SERVER 1
#define IPV6CLIENT "fd42::2"
#define CLIENT 0
#define CS_PORT 9042
//#define BUFFER_SIZE ETH_FRAME_LEN
#define BUFFER_SIZE 65535
#define TUN_MTU 1304
#define SSL_TCP 0
#define SSL_UDP 1
#define PCAP_FILE "g42_tun"

#endif // CONFIG_HPP
