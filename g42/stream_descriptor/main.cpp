#include <boost/asio/io_service.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/signal_set.hpp>

#include <asio/dtls.hpp>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pfplog.hpp"
#include "dbgstr.hpp"

#ifdef PCAPPLUSPLUS
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#endif

#define TUN0 "tun1" // TODO we use vpn?
#define IPV6SERVER "fd42::1"
#define SERVER 1
#define IPV6CLIENT "fd42::2"
#define CLIENT 0
#define CS_PORT 9042
#define BUFFER_SIZE 65535
#define MTU 9000
#define SSL_TCP 0
#define SSL_UDP 1
#define PCAP_FILE "g42_tun"

#ifdef PCAPPLUSPLUS
struct PacketStats {
	int ethPacketCount;
	int ipv4PacketCount;
	int ipv6PacketCount;
	int tcpPacketCount;
	int udpPacketCount;
	int dnsPacketCount;
	int httpPacketCount;
	int sslPacketCount;

	void clear() {
		ethPacketCount = 0;
		ipv4PacketCount = 0;
		ipv6PacketCount = 0;
		tcpPacketCount = 0;
		udpPacketCount = 0;
		tcpPacketCount = 0;
		dnsPacketCount = 0;
		httpPacketCount = 0;
		sslPacketCount = 0;
	}

	PacketStats() { clear(); }

	void consumePacket(pcpp::Packet& packet) {
		if (packet.isPacketOfType(pcpp::Ethernet))
			ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6))
			ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP))
			tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			udpPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL))
			sslPacketCount++;
	}

	void printToConsole() {
		printf("Ethernet packet count: %d\n", ethPacketCount);
		printf("IPv4     packet count: %d\n", ipv4PacketCount);
		printf("IPv6     packet count: %d\n", ipv6PacketCount);
		printf("TCP      packet count: %d\n", tcpPacketCount);
		printf("UDP      packet count: %d\n", udpPacketCount);
		printf("DNS      packet count: %d\n", dnsPacketCount);
		printf("HTTP     packet count: %d\n", httpPacketCount);
		printf("SSL      packet count: %d\n", sslPacketCount);
	}
};
#endif

void usage() {
	pfp_fact("'-s' - Server, '-c [host]' - Client, '-t' - SSL TCP, '-u' - SSL UDP");
}

bool client_verify_cb(bool preverified, boost::asio::ssl::verify_context& ctx) {
	char subject_name[256];
	X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	pfp_fact("*** Verifying : " << subject_name);
	return preverified;
}

bool generateCookie(std::string &cookie, const boost::asio::ip::udp::endpoint& ep) {
	cookie = "deafbeefcafe";
	pfp_fact("Cookie generated for endpoint: " << ep << " is " << cookie);
	return true;
}

bool verifyCookie(const std::string &cookie, const boost::asio::ip::udp::endpoint& ep) {
	pfp_fact("Cookie provided for endpoint: " << ep << " is " << cookie);
	return (cookie == "deafbeefcafe");
}

#ifdef PCAPPLUSPLUS
void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	PacketStats* stats = (PacketStats*)cookie;
	pcpp::Packet parsedPacket(packet);
	stats->consumePacket(parsedPacket);
}
#endif

typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> dtls_sock;
typedef std::shared_ptr<dtls_sock> dtls_sock_ptr;
typedef std::array<unsigned char,1500> buffer_ptr;

void listen_udp(boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> & acceptor, dtls_sock_ptr socket, buffer_ptr buffer, boost::asio::io_context & io_sys_context, int s_loop_idx, int s_tun_in, int s_tun_out, int s_socket_in, int s_socket_out, boost::system::error_code & error, boost::asio::posix::stream_descriptor & sd);

int main(int argc, char *argv[])
{
	int tun_fd = -1, cs = -1, ssl_tcp_udp = -1, write_to_pcap_file = -1, if_index, s, option, delete_flag = 1;
	int s_socket_in = 0, s_socket_out = 0, s_tun_in = 0, s_tun_out = 0, s_loop_idx = 0;

	char remote_ip[16] = { 0 }, pcap_file[16] = { 0 };

	uid_t owner;
	gid_t group;

	while((option = getopt(argc, argv, "sc:tuw")) > 0) {
		switch(option) {
			case 's':
				cs = SERVER;
				break;
			case 'c':
				cs = CLIENT;
				strncpy(remote_ip,optarg,15);
				break;
			case 't':
				ssl_tcp_udp = SSL_TCP;
				break;
			case 'u':
				ssl_tcp_udp = SSL_UDP;
				break;
			case 'w':
				write_to_pcap_file = 1;
				break;
		}
	}

	if (cs == -1 || ssl_tcp_udp == -1) {
		usage();
		exit(2);
	}

	unsigned int tun_exists = if_nametoindex(TUN0);
	if (tun_exists == 0) { // we dont have tun with TUN0 name
		tun_fd = open("/dev/net/tun", O_RDWR);
		if (tun_fd < 0) {
			pfp_fact("Tun open : " << strerror(errno));
			return tun_fd;
		} else {
			pfp_fact("Tun open with fd=" << tun_fd);
		}

		// set type
		struct ifreq if_tun = { 0 };
		if_tun.ifr_flags = IFF_TUN | IFF_NO_PI;
		//if_tun.ifr_flags = IFF_TAP | IFF_NO_PI;
		memcpy(&if_tun.ifr_name, TUN0, IFNAMSIZ);
		if (ioctl(tun_fd, TUNSETIFF, &if_tun) < 0) {
			pfp_fact("Tun ioctl : " << strerror(errno));
			return tun_fd;
		} else {
			pfp_fact("Tun ioctl : ok");
			if_index = if_nametoindex(TUN0);
		}

		pfp_fact("Tun ifindex : " << if_index);

		// XXX queue ?
//		struct ifreq if_queue = { 0 };
//		if_queue.ifr_ifindex = if_index;
//		if_queue.ifr_flags = IFF_ATTACH_QUEUE;
//		memcpy(&if_queue.ifr_name, TUN0, IFNAMSIZ);
//		if (ioctl(tun_fd, TUNSETQUEUE, &if_queue) < 0) {
//			pfp_fact("Tun attach queue : " << strerror(errno));
//		} else {
//			pfp_fact("Tun attach queue : OK");
//		}

		s = socket(AF_INET6, SOCK_DGRAM, 0);
		if (s < 0) {
			pfp_fact("socket AF_INET6 : " << strerror(errno));
			return s;
		} else {
			pfp_fact("socket AF_INET6 : " << s);
		}

		// XXX TODO if we dont have up and running tun, we try to configure in loop
		while (1) {
			struct ifreq if_up = { 0 };
			memcpy(&if_up.ifr_name, TUN0, IFNAMSIZ);
			if_up.ifr_ifindex = if_index;
			if (ioctl(s, SIOCGIFFLAGS, &if_up) < 0) {
				pfp_fact("Tun get flags : " << strerror(errno));
			} else {
				pfp_fact("Tun get flags : OK");
			}
			if (!(if_up.ifr_flags & IFF_UP) && !(if_up.ifr_flags & IFF_RUNNING)) {
				struct ifreq if_flag_up_running = { 0 };
				memcpy(&if_flag_up_running.ifr_name, TUN0, IFNAMSIZ);
				if_flag_up_running.ifr_flags |= IFF_UP | IFF_RUNNING;
				if_flag_up_running.ifr_ifindex = if_index;
				if (ioctl(s, SIOCSIFFLAGS, &if_flag_up_running) < 0) {
					pfp_fact("Tun flags to UP : " << strerror(errno));
				} else {
					pfp_fact("Tun flags to UP : ok");
				}
			} else {
				pfp_fact("We have setting UP flags on " << TUN0);
				break;
			}
			sleep(1);
		}

		// info mac
		struct ifreq if_mac = { 0 };
		if_mac.ifr_ifindex = if_index;
		memcpy(&if_mac.ifr_name, TUN0, IFNAMSIZ);
		if (ioctl(s, SIOCGIFHWADDR, &if_mac) < 0) {
			pfp_fact("Tun hwaddr : " << strerror(errno));
		} else {
			pfp_fact("Tun hwaddr = " << n_pfp::dbgstr_hex(if_mac.ifr_hwaddr.sa_data, IFHWADDRLEN));
		}

		// ipv6
		struct in6_ifreq ifr6 = { 0 };
		struct sockaddr_in6 sai = { 0 };
		sai.sin6_family = AF_INET6;
		sai.sin6_port = 0;
		int ipv6_addr_type;

		if (cs == SERVER) { // ipv6 S
			ipv6_addr_type = inet_pton(AF_INET6, IPV6SERVER, (void *)&sai.sin6_addr);
			if(ipv6_addr_type <= 0) {
				pfp_fact("Bad server address to convert : " << IPV6SERVER);
				return -1;
			} else {
				pfp_fact("Server address : " << IPV6SERVER);
			}
		}

		if (cs == CLIENT) { // ipv6 C
			ipv6_addr_type = inet_pton(AF_INET6, IPV6CLIENT, (void *)&sai.sin6_addr);
			if(ipv6_addr_type <= 0) {
				pfp_fact("Bad client address to convert : " << IPV6CLIENT);
				return -1;
			} else {
				pfp_fact("Client address : " << IPV6CLIENT);
			}
		}

		// set addr ipv6 type SERVER/CLIENT
		ifr6.ifr6_prefixlen = 16;
		memcpy((char *) &ifr6.ifr6_addr, (char *) &sai.sin6_addr, sizeof(struct in6_addr));
		ifr6.ifr6_ifindex = if_index;
		if (ioctl(s, SIOCSIFADDR, &ifr6) < 0) {
			pfp_fact("Tun set IPv6 : " << strerror(errno));
		} else {
			pfp_fact("Tun set IPv6 : ok");
		}

		// set MTU
		struct ifreq if_mtu = { 0 };
		if_mtu.ifr_ifindex = if_index;
		if_mtu.ifr_mtu = MTU;
		memcpy(&if_mtu.ifr_name, TUN0, IFNAMSIZ);
		if (ioctl(s, SIOCSIFMTU, &if_mtu) < 0) {
			pfp_fact("Tun mtu : " << strerror(errno));
		} else {
			pfp_fact("Tun mtu = " << if_mtu.ifr_mtu);
		}

		// XXX TODO whaT?
		if (delete_flag) {
			/* remove persistent status */
			if (ioctl(tun_fd, TUNSETPERSIST, 0) < 0) {
				pfp_fact("disabling TUNSETPERSIST : " << strerror(errno));
				exit(1);
			}
			pfp_fact("Set " << TUN0 << " nonpersistent");
		} else {
			if (owner == -1 && group == -1) {
				owner = geteuid();
			}
			if (owner != -1) {
				if (ioctl(tun_fd, TUNSETOWNER, owner) < 0) {
					pfp_fact("TUNSETOWNER : " << strerror(errno));
					exit(1);
				}
			}
			if (group != -1) {
				if (ioctl(tun_fd, TUNSETGROUP, group) < 0) {
					pfp_fact("TUNSETGROUP : " << strerror(errno));
					exit(1);
				}
			}
			if (ioctl(tun_fd, TUNSETPERSIST, 1) < 0) {
				pfp_fact("enabling TUNSETPERSIST : " << strerror(errno));
				exit(1);
			}
			pfp_fact("Set " << TUN0 << " persistent");
			if(owner != -1)
					pfp_fact("owned by uid " << owner);
			if(group != -1)
					pfp_fact("owned by gid " << group);
		}
	} else {
		pfp_fact("Interface " << TUN0 << " exists");
	}

#ifdef PCAPPLUSPLUS
	// open .pcap file depend from -w flag
	pcpp::PcapNgFileWriterDevice pcapWriter(PCAP_FILE);
	if (write_to_pcap_file == 1) {
		pcapWriter.open();
	}
	if (!pcapWriter.isOpened()) {
		pfp_fact("Cannot open .pcap file for writing - -w flag ?");
	} else {
		pfp_fact("Open .pcap for writing : OK");
	}

	std::string tun_dev(TUN0);
	pcpp::PcapLiveDevice* dev;
	if (write_to_pcap_file == 1) { // open TUN0 dev depend from -w flag
		dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(tun_dev);
		if (dev == NULL) {
			pfp_fact("PCAP++ Cannot find interface name " << TUN0);
		} else {
			if (!dev->open()) {
				pfp_fact("PCAP++ Device " << TUN0 << " not opened ");
			} else {
				pfp_fact("PCAP++ Device " << TUN0 << " opened : OK");
			}
		}
	} else {
		pfp_fact("PCAP++ -w flag not set, so we dont open device");
	}

	PacketStats packet_stats;

	pcpp::RawPacketVector packetVec;

	// CTF depend from -w flag
	if (write_to_pcap_file == 1) {
		pfp_fact("PCAP++ start async capturing...");
		dev->startCapture(packetVec);
		if (dev->captureActive()) {
			pfp_fact("PCAP++ capturing is activate");
		}
	}
#endif

	boost::asio::io_context io_sys_context;
#ifdef PCAPPLUSPLUS
// install the CTRL+... handler
// io_sys_context.run();
//	boost::asio::signal_set signal_(io_sys_context, SIGINT );
//	signal_.async_wait([write_to_pcap_file,&dev,&pcapWriter,&packetVec,&packet_stats](const boost::system::error_code & error , int signal_number) {
//		if (!error) {
//			if (signal_number == 2) { // CTRL+C
//				pfp_fact("Handling signal CTRL+C");
//				if (write_to_pcap_file == 1) {
//					pfp_fact("PCAP++ -w flag active, stop capturing ...");
//					dev->stopCapture();
//					if (!dev->captureActive()) {
//						pfp_fact("PCAP++ capturing is offline");
//						pfp_fact("PCAP++ parse " << packetVec.size() << " packets");
//						for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++) {
//							pcpp::Packet parsedPacket(*iter);
//							packet_stats.consumePacket(parsedPacket);
//						}
//						packet_stats.printToConsole();
//						pfp_fact("PCAP++ -w flag is set so we write to file : " << PCAP_FILE << "");
//						pfp_fact("PCAP++ write " << packetVec.size() << " packets");
//						if (pcapWriter.writePackets(packetVec)) {
//							pcap_stat pcap_s;
//							pcapWriter.getStatistics(pcap_s);
//							pfp_fact("PCAP++ has writted to .pcap file : " << pcap_s.ps_recv << " packets");
//						} else {
//							pfp_fact("PCAP++ problem with writting to .pcap file");
//						}
//					} else {
//						pfp_fact("PCAP++ error with offline capturing - still capture ???");
//					}
//				} else {
//					pfp_fact("PCAP++ -w flag off, so we dont parse packets");
//				}
//				exit(signal_number);
//			}
//		} else {
//			pfp_fact("Error in signal_set async_wait signal : " << error.message());
//		}
//	});
#endif

	boost::asio::posix::stream_descriptor sd(io_sys_context, tun_fd);

	boost::system::error_code ec;
	boost::system::error_code error;

	if (cs == SERVER) { // server mode
		if (ssl_tcp_udp == SSL_TCP) { // s tcp mode
			pfp_fact("SERVER TCP...");
			typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_tcp;
			boost::asio::ssl::context m_ssl_context_tcp(boost::asio::ssl::context::sslv23);

			boost::system::error_code ec_1;
			m_ssl_context_tcp.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use, ec_1);
			if (ec_1) {
				pfp_fact("TCP SSL set context : " << ec_1.message());
			} else {
				pfp_fact("TCP SSL set context : OK");
			}
			boost::system::error_code ec_2;
			m_ssl_context_tcp.set_password_callback([](std::size_t ml, boost::asio::ssl::context::password_purpose purpose) -> std::string {
				return "text"; // TODO set password
			}, ec_2);
			if (ec_2) {
				pfp_fact("TCP SSL set password callback : " << ec_2.message());
			} else {
				pfp_fact("TCP SSL set password callback : OK");
			}
			boost::system::error_code ec_3;
			m_ssl_context_tcp.use_certificate_chain_file("server.pem", ec_3);
			if (ec_3) {
				pfp_fact("TCP SSL use certificate file : " << ec_3.message());
			} else {
				pfp_fact("TCP SSL use certificate file : OK");
			}
			boost::system::error_code ec_4;
			m_ssl_context_tcp.use_private_key_file("server.pem", boost::asio::ssl::context::pem, ec_4);
			if (ec_4) {
				pfp_fact("TCP SSL use private file : " << ec_4.message());
			} else {
				pfp_fact("TCP SSL use private file : OK");
			}
			boost::system::error_code ec_5;
			m_ssl_context_tcp.use_tmp_dh_file("dh2048.pem", ec_5);
			if (ec_5) {
				pfp_fact("TCP SSL use tmp dh file : " << ec_5.message());
			} else {
				pfp_fact("TCP SSL use tmp dh file : OK");
			}

			boost::asio::ip::tcp::endpoint ep;
			ssl_socket_tcp socket_tcp(io_sys_context, m_ssl_context_tcp);
			boost::asio::ip::tcp::acceptor acceptor(io_sys_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), CS_PORT));
			acceptor.accept(socket_tcp.lowest_layer(), ep, error);
			if (!error) {
				pfp_fact("TCP Accept from : " << ep.address().to_string());
			} else {
				pfp_fact("TCP Accept error : " << error.message());
			}
			socket_tcp.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true));
			socket_tcp.handshake(boost::asio::ssl::stream_base::server, error);
			if (error) {
				pfp_fact("TCP Server handshake : " << error.message());
			} else {
				pfp_fact("TCP Server handshake : OK");
				while(1) {
					pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");
					unsigned char request1[BUFFER_SIZE];
					boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
					socket_tcp.async_read_some(mb1, [&s_socket_in,&s_tun_out,&sd,&mb1] (const boost::system::error_code& error, std::size_t bytes_transferred) {
						if (!error) {
							pfp_fact("Read " << bytes_transferred << " bytes from socket");
							s_socket_in += bytes_transferred;
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
							boost::system::error_code ec;
							size_t sd_ws = sd.write_some(mb, ec);
							if (!ec) {
								pfp_fact("Write " << sd_ws << " bytes to fd=" << sd.native_handle());
								s_tun_out += sd_ws;
							} else {
								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
							}
						} else {
							pfp_fact("Error on read from socket : " << error.message());
						}
					});
					unsigned char request2[BUFFER_SIZE];
					boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
					sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&socket_tcp,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
						if (!error) {
							pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
							s_tun_in += bytes_transferred;
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
							boost::system::error_code ec;
							size_t s_ws = socket_tcp.write_some(mb, ec);
							if (!ec) {
								pfp_fact("Write " << s_ws << " bytes to socket");
								s_socket_out += s_ws;
							} else {
								pfp_fact("Error on write to socket : " << ec.message());
							}
						} else {
							pfp_fact("Error on read from " << TUN0 << " : " << error.message());
						}
					});
					io_sys_context.run();
					io_sys_context.restart();
				} // loop
			} // handshake ok
		} // SERVER SSL_TCP

		if (ssl_tcp_udp == SSL_UDP) { // s udp mode
			pfp_fact("SERVER UDP...");
			typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> ssl_socket_udp;
			boost::asio::ssl::dtls::context m_ssl_context_udp(boost::asio::ssl::dtls::context::dtls_server);

			boost::system::error_code ec_1;
			m_ssl_context_udp.set_options(boost::asio::ssl::dtls::context::cookie_exchange, ec_1);
			if (ec_1) {
				pfp_fact("UDP SSL set options : " << ec_1.message());
			} else {
				pfp_fact("UDP SSL set options : OK");
			}
			boost::system::error_code ec_2;
			m_ssl_context_udp.set_password_callback([](std::size_t ml, boost::asio::ssl::context::password_purpose purpose) -> std::string {
				return "text"; // TODO set password
			}, ec_2);
			if (ec_2) {
				pfp_fact("UDP SSL set password callback : " << ec_2.message());
			} else {
				pfp_fact("UDP SSL set password callback : OK");
			}
			boost::system::error_code ec_3;
			m_ssl_context_udp.use_certificate_file("server.pem", boost::asio::ssl::context_base::pem, ec_3);
			if (ec_3) {
				pfp_fact("UDP SSL use certificate file : " << ec_3.message());
			} else {
				pfp_fact("UDP SSL use certificate file : OK");
			}
			boost::system::error_code ec_4;
			m_ssl_context_udp.use_private_key_file("server.pem", boost::asio::ssl::context_base::pem, ec_4);
			if (ec_4) {
				pfp_fact("UDP SSL use private file : " << ec_4.message());
			} else {
				pfp_fact("UDP SSL use private file : OK");
			}
			boost::system::error_code ec_5;
			m_ssl_context_udp.use_tmp_dh_file("dh2048.pem", ec_5);
			if (ec_5) {
				pfp_fact("UDP SSL use tmp dh file : " << ec_5.message());
			} else {
				pfp_fact("UDP SSL use tmp dh file : OK");
			}

			boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v4(), CS_PORT);
			boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> acceptor(io_sys_context, ep);
			acceptor.set_option(boost::asio::socket_base::reuse_address(true));
			acceptor.set_cookie_generate_callback(generateCookie);
			acceptor.set_cookie_verify_callback(verifyCookie);
			acceptor.bind(ep, error);
			if (!error) {
				pfp_fact("UDP Bind to : " << acceptor.local_endpoint().address().to_string());
			} else {
				pfp_fact("UDP Bind error : " << error.message());
			}

			dtls_sock_ptr socket(new dtls_sock(acceptor.get_executor(), m_ssl_context_udp));
			//ssl_socket_udp socket_udp(io_sys_context, m_ssl_context_udp);
			buffer_ptr buffer;

			buffer.fill(0);
			//pfp_fact("buffer before listen : " << n_pfp::dbgstr_hex2(buffer.data(), buffer.size(), 64));
			listen_udp(acceptor, socket, buffer, io_sys_context, s_loop_idx, s_tun_in,s_tun_out, s_socket_in, s_socket_out, error, sd);

			//io_sys_context.run(); // TODO herE?
			if (error) {
				pfp_fact("UDP async_accept : " << error.message());
			} else {
				pfp_fact("UDP async_accept : OK");
			}
		} // SSL_UDP
	} // CS SERVER

	if (cs == CLIENT) { // client mode
		if (ssl_tcp_udp == SSL_TCP) { // c tcp mode
			pfp_fact("CLIENT TCP...");
			boost::asio::ip::tcp::resolver resolver(io_sys_context);
			boost::asio::ip::tcp::resolver::query query(remote_ip, std::to_string(CS_PORT));
			boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
			pfp_fact("TCP Client connect to : " << query.host_name() << ":" << query.service_name());

			typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_tcp;
			boost::asio::ssl::context m_ssl_context_tcp(boost::asio::ssl::context::sslv23);

			m_ssl_context_tcp.load_verify_file("server.pem", ec);
			if (ec) {
				pfp_fact("TCP SSL load verify file : " << ec.message());
			} else {
				pfp_fact("TCP SSL load verify file : OK");
			}
			m_ssl_context_tcp.use_certificate_chain_file("server.pem", ec);
			if (ec) {
				pfp_fact("TCP SSL use certificate chain file : " << ec.message());
			} else {
				pfp_fact("TCP SSL use certificate chain file : OK");
			}
			m_ssl_context_tcp.use_private_key_file("server.pem", boost::asio::ssl::context::pem, ec);
			if (ec) {
				pfp_fact("TCP SSL use private key file : " << ec.message());
			} else {
				pfp_fact("TCP SSL use private key file : OK");
			}
			m_ssl_context_tcp.use_tmp_dh_file("dh2048.pem", ec);
			if (ec) {
				pfp_fact("TCP SSL use tmp dh file : " << ec.message());
			} else {
				pfp_fact("TCP SSL use tmp dh file : OK");
			}

			ssl_socket_tcp client(io_sys_context, m_ssl_context_tcp);

			boost::asio::connect(client.lowest_layer(), it, ec);
			if (ec) {
				pfp_fact("TCP Conect error to " << it->host_name() << " : " << ec.message());
			} else {
				pfp_fact("TCP Connected to : " << it->host_name());
			}

			client.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true));

			client.set_verify_mode(boost::asio::ssl::verify_peer, ec);
			if (ec) {
				pfp_fact("TCP Client set verify mode : " << ec.message());
			} else {
				pfp_fact("TCP Client set verify mode : OK");
			}
			client.set_verify_callback(client_verify_cb, ec);
			if (ec) {
				pfp_fact("TCP Client set verify callback : " << ec.message());
			} else {
				pfp_fact("TCP Client set verify callback : OK");
			}

			client.handshake(boost::asio::ssl::stream_base::client, ec);
			if (ec) {
				pfp_fact("TCP Client handshake : " << ec.message());
			} else {
				pfp_fact("TCP Client handshake : OK");

				while (1) {
					pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");

					unsigned char request1[BUFFER_SIZE];
					boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
					client.async_read_some(mb1, [&s_socket_in,&s_tun_out,&sd,&mb1] (const boost::system::error_code& error, std::size_t bytes_transferred) {
						if (!error) {
							pfp_fact("Read " << bytes_transferred << " bytes from socket");
							s_socket_in += bytes_transferred;
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
							boost::system::error_code ec;
							size_t sd_ws = sd.write_some(mb, ec);
							if (!ec) {
								pfp_fact("Write " << sd_ws << " bytes to fd=" << sd.native_handle());
								s_tun_out += sd_ws;
							} else {
								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
							}
						} else {
							pfp_fact("Error on read from socket : " << error.message());
						}
					});

					unsigned char request2[BUFFER_SIZE];
					boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
					sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&client,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
						if (!error) {
							pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
							s_tun_in += bytes_transferred;
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
							boost::system::error_code ec;
							size_t ws2 = client.write_some(mb, ec);
							if (!ec) {
								pfp_fact("Write " << ws2 << " bytes to socket");
								s_socket_out += ws2;
							} else {
								pfp_fact("Error on write to socket : " << ec.message());
							}
						} else {
							pfp_fact("Error on read from " << TUN0 << " : " << error.message());
						}
					});

					io_sys_context.run();
					io_sys_context.restart();
				} // loop
			} // tcp client handshake ok
		} // client SSL_TCP

		if (ssl_tcp_udp == SSL_UDP) { // c udp mode
			pfp_fact("CLIENT UDP...");
			boost::asio::ip::udp::resolver resolver(io_sys_context);
			boost::asio::ip::udp::resolver::query query(remote_ip, std::to_string(CS_PORT));
			boost::asio::ip::udp::resolver::iterator it = resolver.resolve(query, ec);
			if (ec) {
				pfp_fact("UDP Client cannot resolve the query " << query.host_name() << "/" << query.service_name() << " : " << ec.message());
			} else {
				pfp_fact("UDP Client resolver resolv the : " << it->endpoint().address().to_string() << ":" << it->endpoint().port());
				typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> ssl_socket_udp;
				boost::asio::ssl::dtls::context m_ssl_context_udp(boost::asio::ssl::dtls::context::dtls_client);

				m_ssl_context_udp.load_verify_file("server.pem", ec);
				if (ec) {
					pfp_fact("UDP SSL load verify file : " << ec.message());
				} else {
					pfp_fact("UDP SSL load verify file : OK");
				}
				m_ssl_context_udp.use_certificate_chain_file("server.pem", ec);
				if (ec) {
					pfp_fact("UDP SSL use certificate chain file : " << ec.message());
				} else {
					pfp_fact("UDP SSL use certificate chain file : OK");
				}
				m_ssl_context_udp.use_private_key_file("server.pem", boost::asio::ssl::context::pem, ec);
				if (ec) {
					pfp_fact("UDP SSL use private key file : " << ec.message());
				} else {
					pfp_fact("UDP SSL use private key file : OK");
				}
				m_ssl_context_udp.use_tmp_dh_file("dh2048.pem", ec);
				if (ec) {
					pfp_fact("UDP SSL use tmp dh file : " << ec.message());
				} else {
					pfp_fact("UDP SSL use tmp dh file : OK");
				}

				ssl_socket_udp client(io_sys_context, m_ssl_context_udp);

				client.set_verify_mode(boost::asio::ssl::verify_peer, ec);
				if (ec) {
					pfp_fact("UDP Client set verify mode : " << ec.message());
				} else {
					pfp_fact("UDP Client set verify mode : OK");
				}
				client.set_verify_callback(client_verify_cb, ec);
				if (ec) {
					pfp_fact("UDP Client set verify callback : " << ec.message());
				} else {
					pfp_fact("UDP Client set verify callback : OK");
				}

				client.lowest_layer().connect(it->endpoint(), ec);
				if (ec) {
					pfp_fact("UDP Conect error to " << it->host_name() << " : " << ec.message());
				} else {
					pfp_fact("UDP Connected to : " << it->host_name());
				}

				std::array<char, 1500> buffer_data{0};
				boost::asio::const_buffer buffer(buffer_data.data(), buffer_data.size());

				client.async_handshake(boost::asio::ssl::stream_base::handshake_type::client, buffer,\
				[&buffer_data,&s_loop_idx,&s_socket_in,&s_socket_out,&s_tun_in,&s_tun_out,&sd,&client,&io_sys_context]\
				(const boost::system::error_code & error, size_t bytes_transferred){
					if (error) {
						pfp_fact("UDP Client async handshake failed : " << error.message());
					} else {
						pfp_fact("UDP Client handshake : OK");
						while (1) {
							pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");

							unsigned char request2[BUFFER_SIZE];
							boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
							sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&client,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
								if (!error) {
									pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
									s_tun_in += bytes_transferred;
									boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
									client.async_send(mb, [&s_socket_out](const boost::system::error_code & error, size_t bytes_transferred){
										if (!error) {
											pfp_fact("Write " << bytes_transferred << " bytes to socket");
											s_socket_out += bytes_transferred;
										} else {
											pfp_fact("Error on write to socket : " << error.message());
										}
									});
								} else {
									pfp_fact("Error on read from " << TUN0 << " : " << error.message());
								}
							});

							unsigned char request1[BUFFER_SIZE];
							boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
							client.async_receive(mb1, [&s_socket_in,&s_tun_out,&mb1,&sd](const boost::system::error_code &error, size_t bytes_transferred){
								if (!error) {
									pfp_fact("Read " << bytes_transferred << " bytes from socket");
									s_socket_in += bytes_transferred;
									boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
									boost::system::error_code ec;
									sd.async_write_some(mb, [&s_tun_out,&sd](const boost::system::error_code &error, size_t bytes_transferred){
										if (!error) {
											pfp_fact("Write " << bytes_transferred << " bytes to fd=" << sd.native_handle());
											s_tun_out += bytes_transferred;
										} else {
											pfp_fact("Error on write to " << TUN0 << " : " << error.message());
										}
									});
								} else {
									pfp_fact("Error on read from socket : " << error.message());
								}
							});
							io_sys_context.run();
							io_sys_context.restart();
						}; // loop
					}
				});
				io_sys_context.run(); // TODO hehre?
			}
		} // SSL_UDP
	} // CS_CLIENT
} // main

void listen_udp(boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> & acceptor, dtls_sock_ptr socket, buffer_ptr buffer, boost::asio::io_context & io_sys_context, int s_loop_idx, int s_tun_in, int s_tun_out, int s_socket_in, int s_socket_out, boost::system::error_code & error, boost::asio::posix::stream_descriptor & sd) {
	boost::system::error_code ec;
	boost::asio::mutable_buffer mb = boost::asio::buffer(buffer.data(), buffer.size());
	acceptor.async_accept(*socket, mb, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&mb](const boost::asio::error_code &ec, size_t size) {
		if(ec) {
			pfp_fact("UDP in async - Error in Accept: " << ec.message());
		} else {
			pfp_fact("UDP in async - Accept: OK");
			//pfp_fact("async_accept size is : " << size);
			//pfp_fact("async_accept buffer  : " << n_pfp::dbgstr_hex(mb.data(), mb.size())); // TODO cookie at 60 byte?
			boost::asio::mutable_buffers_1 cb = boost::asio::mutable_buffers_1(buffer.data(), buffer.size());
			socket.get()->async_handshake(boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket>::server, cb, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&cb](const boost::system::error_code &error, size_t size) {
				if (error) {
					pfp_fact("UDP Server async_handshake : " << error.message());
				} else {
					pfp_fact("UDP Server async_handshake : OK");
					//pfp_fact("async_handshake size is : " << size);
					//pfp_fact("async_handshake buffer  : " << n_pfp::dbgstr_hex2(cb.data(), cb.size(), 64));
						pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");
						boost::system::error_code ec;

//						unsigned char request1[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//						socket.get()->async_receive(mb1, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&mb1](const boost::asio::error_code &error, size_t bytes_transferred) {
//							if (!error) {
//								pfp_fact("Read " << bytes_transferred << " bytes from socket");
//								s_socket_in += bytes_transferred;
//								boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
//								sd.async_write_some(mb, [&s_tun_out,&sd](const boost::asio::error_code & ec, size_t bytes_transferred){
//									if (!ec) {
//										pfp_fact("Write " << bytes_transferred << " bytes to fd=" << sd.native_handle());
//										s_tun_out += bytes_transferred;
//									} else {
//										pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//									}
//								});
//							} else {
//								pfp_fact("Error on read from socket : " << error.message());
//							}
//						});

						// read socket / write tun
						unsigned char request1[BUFFER_SIZE];
						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
						size_t s_read = socket.get()->receive(mb1, ec);
						if (ec) {
							pfp_fact("socket receive error: " << ec.message());
						} else {
							pfp_fact("Read " << s_read << " bytes from socket");
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1, s_read);
							size_t sd_write = sd.write_some(mb, ec);
							if (!ec) {
								pfp_fact("Write " << sd_write << " bytes to fd=" << sd.native_handle());
							} else {
								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
							}
						}

						// read socket / write tun async
//						unsigned char request1[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//						size_t socket_read = socket.get()->receive(mb1, ec);
//						if (ec) {
//							pfp_fact("socket error: " << ec.message());
//						} else {
//							pfp_fact("Read " << socket_read << " bytes from socket");
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), socket_read);
//							sd.async_write_some(mb, [&s_tun_out,&sd](const boost::asio::error_code & ec, size_t bytes_transferred){
//								if (!ec) {
//									pfp_fact("Write " << bytes_transferred << " bytes to fd=" << sd.native_handle());
//									s_tun_out += bytes_transferred;
//								} else {
//									pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//								}
//							});
//						}

						// read async socket / write tun
//						unsigned char request1[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//						socket.get()->async_receive(mb1, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&mb1](const boost::asio::error_code &error, size_t bytes_transferred) {
//							pfp_fact("Read " << bytes_transferred << " bytes from socket");
//							boost::system::error_code ec;
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1, bytes_transferred);
//							size_t sd_write = sd.write_some(mb, ec);
//							if (ec) {
//								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//							} else {
//								pfp_fact("Write " << sd_write << " bytes to fd=" << sd.native_handle());
//							}
//							socket.get()->shutdown(ec);
//							if (ec) {
//								pfp_fact("socket async_receive socket shutdown : " << ec.message());
//							} else {
//								pfp_fact("socket async_receive socket shutdown : OK");
//							}
//							socket->async_shutdown([socket](const boost::asio::error_code & error){
//								if (error) {
//									pfp_fact("async_shutdown : " << error.message());
//								} else {
//									pfp_fact("async_shutdown : OK");
//								}
//							});
//						});

//						unsigned char request2[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
//						sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&socket,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
//							if (!error) {
//								pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
//								s_tun_in += bytes_transferred;
//								boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
//								socket.get()->async_send(mb, [&socket,&s_socket_out](const boost::asio::error_code &ec, size_t size){
//									if (!ec) {
//										pfp_fact("Write " << size << " bytes to socket");
//										s_socket_out += size;
//									} else {
//										pfp_fact("Error on write to socket : " << ec.message());
//									}
//								});

//							} else {
//								pfp_fact("Error on read from " << TUN0 << " : " << error.message());
//							}
//						});

						// read tun / write socket
						unsigned char request2[BUFFER_SIZE];
						boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
						size_t tun_read = sd.read_some(mb2, ec);
						if (ec) {
							pfp_fact(TUN0 << " read_some error: " << ec.message());
						} else {
							pfp_fact("Read " << tun_read << " bytes from fd=" << sd.native_handle());
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2, tun_read);
							size_t s_write = socket.get()->send(mb, ec);
							if (!ec) {
								pfp_fact("Write " << s_write << " bytes to socket");
							} else {
								pfp_fact("Error on write to socket : " << ec.message());
							}
						}

						// read tun / write socket async
//						unsigned char request2[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb2 = boost::asio::mutable_buffer(request2, BUFFER_SIZE);
//						size_t sd_read = sd.read_some(mb2, ec);
//						if (ec) {
//							pfp_fact("sd error : " << ec.message());
//						} else {
//							pfp_fact("Read " << sd_read << " bytes from fd=" << sd.native_handle());
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), sd_read);
//							socket.get()->async_send(mb, [](const boost::asio::error_code &ec, size_t size){
//								if (!ec) {
//									pfp_fact("Write " << size << " bytes to socket");
//								} else {
//									pfp_fact("Error on write to socket : " << ec.message());
//								}
//							});
//						}

						// read async tun / write socket
//						unsigned char request2[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb2 = boost::asio::mutable_buffer(request2, BUFFER_SIZE);
//						sd.async_read_some(mb2, [&mb2, &sd, &socket](const boost::asio::error_code &error, size_t bytes_transferred) {
//							if (error) {
//								pfp_fact("Error on read from " << TUN0 << " : " << error.message());
//							} else {
//								pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
//								boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
//								boost::system::error_code ec;
//								size_t write_socket = socket.get()->send(mb, ec);
//								if (ec) {
//									pfp_fact("Error on write to socket : " << ec.message());
//								} else {
//									pfp_fact("Write " << write_socket << " bytes to socket");
//								}
//								socket.get()->shutdown(ec);
//								if (ec) {
//									pfp_fact(TUN0 << " async_receive socket shutdown : " << ec.message());
//								} else {
//									pfp_fact(TUN0 << " async_receive socket shutdown : OK");
//								}
//								socket->async_shutdown([socket](const boost::asio::error_code & error){
//									if (error) {
//										pfp_fact("async_shutdown : " << error.message());
//									} else {
//										pfp_fact("async_shutdown : OK");
//									}
//								});
//							}
//						});
						socket->async_shutdown([socket](const boost::asio::error_code & error){
						if (error) {
							pfp_fact("async_shutdown : " << error.message());
						} else {
							pfp_fact("async_shutdown : OK");
						}
					});
//					socket.get()->shutdown(ec);
//					if (ec) {
//						pfp_fact(TUN0 << " async_receive socket shutdown : " << ec.message());
//					} else {
//						pfp_fact(TUN0 << " async_receive socket shutdown : OK");
//					}
				}
			});
		}
	}, ec);
	if (ec) {
		pfp_fact("async_accept : " << ec.message());
	} else {
		pfp_fact("async_accept : OK");
	}

	io_sys_context.run();
	io_sys_context.restart();

	listen_udp(acceptor, socket, buffer, io_sys_context, s_loop_idx, s_tun_in, s_tun_out, s_socket_in, s_socket_out, error, sd);
}