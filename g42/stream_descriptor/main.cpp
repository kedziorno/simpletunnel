//#include <boost/asio/io_service.hpp>
//#include <boost/asio/connect.hpp>
//#include <boost/asio/ip/tcp.hpp>
//#include <boost/asio/ip/udp.hpp>
//#include <boost/asio/ssl.hpp>
//#include <boost/asio/posix/stream_descriptor.hpp>
//#include <boost/asio/signal_set.hpp>
//#include <boost/asio/socket_base.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <asio/dtls.hpp>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pfplog.hpp"
#include "dbgstr.hpp"
#include "tun_device.hpp"
#include "tcp_ssl_context.hpp"
#include "udp_dtls_context.hpp"
#include "config.hpp"
#include "server_tcp.hpp"
#include "server_udp.hpp"
#include "client_tcp.hpp"
#include "client_udp.hpp"

#ifdef PCAPPLUSPLUS
#include "RawPacket.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#endif

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

struct PacketArrivedData {
	pcpp::PcapNgFileWriterDevice* pcapWriter;
};

void PacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	pcpp::Packet parsedPacket(packet);

	PacketArrivedData* data  = (PacketArrivedData*)cookie;

	if (data->pcapWriter != NULL) {
		data->pcapWriter->writePacket(*packet);
	}
}

void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	PacketStats* stats = (PacketStats*)cookie;
	pcpp::Packet parsedPacket(packet);
	stats->consumePacket(parsedPacket);
}
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

//typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> dtls_sock;
//typedef std::shared_ptr<dtls_sock> dtls_sock_ptr;
typedef std::array<unsigned char,BUFFER_SIZE> buffer_ptr;
typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> ssl_socket_udp;
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_tcp;

//void listen_udp(boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> & acceptor, dtls_sock_ptr socket, buffer_ptr buffer, boost::asio::io_context & io_sys_context, int s_loop_idx, int s_tun_in, int s_tun_out, int s_socket_in, int s_socket_out, boost::system::error_code & error, boost::asio::posix::stream_descriptor & sd);
void listen_udp(boost::asio::ssl::dtls::context & m_ssl_context_udp, boost::asio::io_context & io_sys_context, int s_loop_idx, int s_tun_in, int s_tun_out, int s_socket_in, int s_socket_out, boost::system::error_code & error, boost::asio::posix::stream_descriptor & sd);

int tun_fd = -1;

int main(int argc, char *argv[])
{
	int cs = -1, ssl_tcp_udp = -1, write_to_pcap_file = -1, if_index, s, option, delete_flag = 1;
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

	std::string ipv6address;
	if (cs == SERVER) { // ipv6 S
		ipv6address = IPV6SERVER;
	}

	if (cs == CLIENT) { // ipv6 C
		ipv6address = IPV6CLIENT;
	}

	tun_device tun(TUN0, IFF_TUN, IFF_UP | IFF_RUNNING, ipv6address, TUN_MTU);

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
			//pcpp::PcapLiveDevice::DeviceConfiguration dev_conf;
			//dev_conf.direction = pcpp::PcapLiveDevice::PcapDirection::PCPP_INOUT;
			//dev_conf.mode = pcpp::PcapLiveDevice::DeviceMode::Normal;
			//if (!dev->open(dev_conf)) {
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
		//PacketArrivedData data;
		//data.pcapWriter = &pcapWriter;
		//dev->startCapture(PacketArrive, &data);
		dev->startCapture(packetVec);
		if (dev->captureActive()) {
			pfp_fact("PCAP++ capturing is activate");
		}
	}
#endif

	boost::asio::io_context io_sys_context;
#ifdef PCAPPLUSPLUS
	//install the CTRL+... handler
	boost::asio::signal_set signal_(io_sys_context.get_executor(), SIGINT);
	signal_.async_wait([write_to_pcap_file,&dev,&pcapWriter,&packetVec,&packet_stats](const boost::system::error_code & error , int signal_number) {
		if (!error) {
			if (signal_number == 2) { // CTRL+C
				pfp_fact("Handling signal CTRL+C");
				if (write_to_pcap_file == 1) {
					pfp_fact("PCAP++ -w flag active, stop capturing ...");
					dev->stopCapture();
					if (!dev->captureActive()) {
						pfp_fact("PCAP++ capturing is offline");
						pfp_fact("PCAP++ parse " << packetVec.size() << " packets");
						for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++) {
							pcpp::Packet parsedPacket(*iter);
							packet_stats.consumePacket(parsedPacket);
						}
						packet_stats.printToConsole();
						pfp_fact("PCAP++ -w flag is set so we write to file : " << PCAP_FILE << "");
						pfp_fact("PCAP++ write " << packetVec.size() << " packets");
						if (pcapWriter.writePackets(packetVec)) {
							pcap_stat pcap_s;
							pcapWriter.getStatistics(pcap_s);
							pfp_fact("PCAP++ has writted to .pcap file : " << pcap_s.ps_recv << " packets");
						} else {
							pfp_fact("PCAP++ problem with writting to .pcap file");
						}
					} else {
						pfp_fact("PCAP++ error with offline capturing - still capture ???");
					}
					pfp_fact("PCAP++ closing device " << TUN0);
					dev->close();
				} else {
					pfp_fact("PCAP++ -w flag off, so we dont parse packets");
				}
				exit(signal_number);
			}
		} else {
			pfp_fact("Error in signal_set async_wait signal : " << error.message());
		}
	});
	//io_sys_context.run_one();
#endif

	// ok
	boost::asio::io_context ioc2;
	boost::asio::posix::stream_descriptor sd(ioc2, 0);

	boost::system::error_code ec;
	boost::system::error_code error;

	if (cs == SERVER) { // server mode
		if (ssl_tcp_udp == SSL_TCP) {

			pfp_fact("SERVER TCP...");
			tcp_ssl_context tcp_ctx;
			server_tcp server(io_sys_context, tcp_ctx.get_ssl_context(), tun.get_file_descriptor());
			server.run();
		}

		if (ssl_tcp_udp == SSL_UDP) { // s udp mode
			pfp_fact("SERVER UDP...");
//			typedef boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> ssl_socket_udp;

			udp_dtls_context udp_ctx;
			server_udp server(io_sys_context, udp_ctx.get_udp_context(), tun.get_file_descriptor());
			server.run();

//			boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v4(), CS_PORT);
//			boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> acceptor(io_sys_context, ep);
//			acceptor.set_option(boost::asio::socket_base::reuse_address(true));
//			acceptor.set_cookie_generate_callback(generateCookie);
//			acceptor.set_cookie_verify_callback(verifyCookie);
//			acceptor.bind(ep, error);
//			if (!error) {
//				pfp_fact("UDP Bind to : " << acceptor.local_endpoint().address().to_string());
//			} else {
//				pfp_fact("UDP Bind error : " << error.message());
//			}

//			dtls_sock_ptr socket(new dtls_sock(acceptor.get_executor(), m_ssl_context_udp));
//			//ssl_socket_udp socket_udp(io_sys_context, m_ssl_context_udp);
//			buffer_ptr buffer;

//			buffer.fill(0);
//			//pfp_fact("buffer before listen : " << n_pfp::dbgstr_hex2(buffer.data(), buffer.size(), 64));
//			listen_udp(acceptor, socket, buffer, io_sys_context, s_loop_idx, s_tun_in,s_tun_out, s_socket_in, s_socket_out, error, sd);

			// 000000000000
			//listen_udp(udp_ctx.get_udp_context(), io_sys_context, s_loop_idx, s_tun_in,s_tun_out, s_socket_in, s_socket_out, error, sd);

			//io_sys_context.run(); // TODO herE?
//			if (error) {
//				pfp_fact("UDP async_accept : " << error.message());
//			} else {
//				pfp_fact("UDP async_accept : OK");
//			}
		} // SSL_UDP
	} // CS SERVER

	if (cs == CLIENT) { // client mode
		if (ssl_tcp_udp == SSL_TCP) { // c tcp mode
			pfp_fact("CLIENT TCP...");
//			boost::asio::ip::tcp::resolver resolver(io_sys_context);
//			boost::asio::ip::tcp::resolver::query query(remote_ip, std::to_string(CS_PORT));
//			boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
//			pfp_fact("TCP Client want connect to : " << query.host_name() << ":" << query.service_name());

//			typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_tcp;

			tcp_ssl_context tcp_ctx;
			client_tcp client(io_sys_context, tcp_ctx.get_ssl_context(), tun.get_file_descriptor(), remote_ip);
			client.run();

//			ssl_socket_tcp client(io_sys_context, tcp_ctx.get_ssl_context());

//			boost::asio::connect(client.lowest_layer(), it, ec);
//			if (ec) {
//				pfp_fact("TCP Conect error to " << it->host_name() << " : " << ec.message());
//			} else {
//				pfp_fact("TCP Connected to : " << it->host_name());
//			}

//			client.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true));

//			client.set_verify_mode(boost::asio::ssl::verify_peer, ec);
//			if (ec) {
//				pfp_fact("TCP Client set verify mode : " << ec.message());
//			} else {
//				pfp_fact("TCP Client set verify mode : OK");
//			}
//			client.set_verify_callback(client_verify_cb, ec);
//			if (ec) {
//				pfp_fact("TCP Client set verify callback : " << ec.message());
//			} else {
//				pfp_fact("TCP Client set verify callback : OK");
//			}

//			client.handshake(boost::asio::ssl::stream_base::client, ec);
//			if (ec) {
//				pfp_fact("TCP Client handshake : " << ec.message());
//			} else {
//				pfp_fact("TCP Client handshake : OK");

//				while (1) {
//					io_sys_context.reset();
//					pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");

//					std::array<unsigned char, BUFFER_SIZE> request1;
//					request1.fill(0);
//					boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//					client.async_read_some(mb1, [&s_socket_in,&s_tun_out,&sd,&mb1] (const boost::system::error_code& error, std::size_t bytes_transferred) {
//						if (!error) {
//							pfp_fact("Read " << bytes_transferred << " bytes from socket");
//							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb1.data(), bytes_transferred));
//							s_socket_in += bytes_transferred;
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
//							boost::system::error_code ec;
//							size_t sd_ws = sd.write_some(mb, ec);
//							if (!ec) {
//								pfp_fact("Write " << sd_ws << " bytes to fd=" << sd.native_handle());
//								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), sd_ws));
//								s_tun_out += sd_ws;
//							} else {
//								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//							}
//						} else {
//							pfp_fact("Error on read from socket : " << error.message());
//						}
//					});

////					std::array<unsigned char, BUFFER_SIZE> request1;
////					request1.fill(0);
////					boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
////					size_t rsl = client.read_some(mb1, ec);
////					if (ec) {
////						pfp_fact("Error read_some on socket : " << ec.message());
////					} else {
////						pfp_fact("read_some " << rsl << " bytes from socket");
////						size_t sd_ws = sd.write_some(mb1, ec);
////						if (!ec) {
////							pfp_fact("Write " << sd_ws << " bytes to fd=" << sd.native_handle());
////						} else {
////							pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
////						}
////					}

//					std::array<unsigned char, BUFFER_SIZE> request2;
//					request2.fill(0);
//					boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
//					sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&client,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
//						if (!error) {
//							pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
//							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb2.data(), bytes_transferred));
//							s_tun_in += bytes_transferred;
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
//							boost::system::error_code ec;
//							size_t ws2 = client.write_some(mb, ec);
//							if (!ec) {
//								pfp_fact("Write " << ws2 << " bytes to socket");
//								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), ws2));
//								s_socket_out += ws2;
//							} else {
//								pfp_fact("Error on write to socket : " << ec.message());
//							}
//						} else {
//							pfp_fact("Error on read from " << TUN0 << " : " << error.message());
//						}
//					});

////					std::array<unsigned char, BUFFER_SIZE> request2;
////					request2.fill(0);
////					boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
////					size_t sdrl = sd.read_some(mb2, ec);
////					if (ec) {
////						pfp_fact("Error on read_some on tun : " << ec.message());
////					} else {
////						pfp_fact("read_some " << sdrl << " bytes from socket");
////						size_t s_ws = client.write_some(mb2, ec);
////						if (!ec) {
////							pfp_fact("Write " << s_ws << " bytes to socket");
////						} else {
////							pfp_fact("Error on write to socket : " << ec.message());
////						}
////					}

//					io_sys_context.run();
//					io_sys_context.restart();
//				} // loop
//			} // tcp client handshake ok

		if (ssl_tcp_udp == SSL_UDP) { // c udp mode
			pfp_fact("CLIENT UDP...");
//			boost::asio::ip::udp::resolver resolver(io_sys_context);
//			boost::asio::ip::udp::resolver::query query(remote_ip, std::to_string(CS_PORT));
//			boost::asio::ip::udp::resolver::iterator it = resolver.resolve(query, ec);
//			if (ec) {
//				pfp_fact("UDP Client cannot resolve the query " << query.host_name() << "/" << query.service_name() << " : " << ec.message());
//			} else {
//				pfp_fact("UDP Client resolver resolv the : " << it->endpoint().address().to_string() << ":" << it->endpoint().port());

				udp_dtls_context udp_ctx;
				client_udp client(io_sys_context, udp_ctx.get_udp_context(), tun.get_file_descriptor(), remote_ip);
				client.run();

//				std::array<char, BUFFER_SIZE> buffer_data{0};
//				boost::asio::const_buffer buffer(buffer_data.data(), buffer_data.size());

//				ssl_socket_udp client(io_sys_context, udp_ctx.get_udp_context());

//				client.set_verify_mode(boost::asio::ssl::verify_peer, ec);
//				if (ec) {
//					pfp_fact("UDP Client set verify mode : " << ec.message());
//				} else {
//					pfp_fact("UDP Client set verify mode : OK");
//				}
//				client.set_verify_callback(client_verify_cb, ec);
//				if (ec) {
//					pfp_fact("UDP Client set verify callback : " << ec.message());
//				} else {
//					pfp_fact("UDP Client set verify callback : OK");
//				}

//				client.lowest_layer().connect(it->endpoint(), ec);
//				if (ec) {
//					pfp_fact("UDP Client Conect error to " << it->host_name() << " : " << ec.message());
//				} else {
//					pfp_fact("UDP Client Connected to : " << it->host_name());
//				}
//				client.async_handshake(boost::asio::ssl::stream_base::handshake_type::client, buffer,[&buffer_data,&s_loop_idx,&s_socket_in,&s_socket_out,&s_tun_in,&s_tun_out,&sd,&client,&io_sys_context](const boost::system::error_code & error, size_t bytes_transferred){
//					if (error) {
//						pfp_fact("UDP Client async handshake failed : " << error.message());
//					} else {
//						boost::system::error_code ec;

//						pfp_fact("UDP Client handshake : OK");
//						pfp_fact("UDP Client bytes : " << bytes_transferred);

//						while (1) {
//						io_sys_context.reset();
//						pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");

//							// tun async read / socket async write
////							unsigned char request2[BUFFER_SIZE];
////							boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
////							sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&client,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
////								if (!error) {
////									pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
////									s_tun_in += bytes_transferred;
////									boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
////									client.async_send(mb, [&s_socket_out](const boost::system::error_code & error, size_t bytes_transferred){
////										if (!error) {
////											pfp_fact("Write " << bytes_transferred << " bytes to socket");
////											s_socket_out += bytes_transferred;
////										} else {
////											pfp_fact("Error on write to socket : " << error.message());
////										}
////									});
////								} else {
////									pfp_fact("Error on read from " << TUN0 << " : " << error.message());
////								}
////							});

//							// read tun / write socket
//							unsigned char request2[BUFFER_SIZE];
//							boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
//							size_t tun_read = sd.read_some(mb2, ec);
//							if (ec) {
//								pfp_fact(TUN0 << " read_some error: " << ec.message());
//							} else {
//								pfp_fact("Read " << tun_read << " bytes from fd=" << sd.native_handle());
//								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb2.data(), tun_read));
//								boost::asio::mutable_buffer mb = boost::asio::buffer(mb2, tun_read);
//								size_t s_write = client.send(mb, ec);
//								if (!ec) {
//									pfp_fact("Write " << s_write << " bytes to socket");
//									pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), s_write));
//								} else {
//									pfp_fact("Error on write to socket : " << ec.message());
//								}
//							}

//							// socket async read / tun async write
////							unsigned char request1[BUFFER_SIZE];
////							boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
////							client.async_receive(mb1, [&s_socket_in,&s_tun_out,&mb1,&sd](const boost::system::error_code &error, size_t bytes_transferred){
////								if (!error) {
////									pfp_fact("Read " << bytes_transferred << " bytes from socket");
////									s_socket_in += bytes_transferred;
////									boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
////									boost::system::error_code ec;
////									sd.async_write_some(mb, [&s_tun_out,&sd](const boost::system::error_code &error, size_t bytes_transferred){
////										if (!error) {
////											pfp_fact("Write " << bytes_transferred << " bytes to fd=" << sd.native_handle());
////											s_tun_out += bytes_transferred;
////										} else {
////											pfp_fact("Error on write to " << TUN0 << " : " << error.message());
////										}
////									});
////								} else {
////									pfp_fact("Error on read from socket : " << error.message());
////								}
////							});

//							// read socket / write tun
//							unsigned char request1[BUFFER_SIZE];
//							boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//							size_t s_read = client.receive(mb1, ec);
//							if (ec) {
//								pfp_fact("socket receive error: " << ec.message());
//							} else {
//								pfp_fact("Read " << s_read << " bytes from socket");
//								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb1.data(), s_read));
//								boost::asio::mutable_buffer mb = boost::asio::buffer(mb1, s_read);
//								size_t sd_write = sd.write_some(mb, ec);
//								if (!ec) {
//									pfp_fact("Write " << sd_write << " bytes to fd=" << sd.native_handle());
//									pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), sd_write));
//								} else {
//									pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//								}
//							}
//							//io_sys_context.restart();
//							io_sys_context.run_one(ec);
//							if (ec) {
//								pfp_fact("io run: " << ec.message());
//							} else {
//								pfp_fact("io run : OK");
//							}
//							//io_sys_context.reset();
//					}; // loop
//					}
//				});
//				io_sys_context.run();
//			}
		} // SSL_UDP
	} // CS_CLIENT
} // main
}


// void listen_udp(boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> & acceptor, dtls_sock_ptr socket, buffer_ptr buffer, boost::asio::io_context & io_sys_context, int s_loop_idx, int s_tun_in, int s_tun_out, int s_socket_in, int s_socket_out, boost::system::error_code & error, boost::asio::posix::stream_descriptor & sd)
//void listen_udp(boost::asio::ssl::dtls::context & m_ssl_context_udp, boost::asio::io_context & io_sys_context, int s_loop_idx, int s_tun_in, int s_tun_out, int s_socket_in, int s_socket_out, boost::system::error_code & error, boost::asio::posix::stream_descriptor & sd) {
//	boost::system::error_code ec;
//	buffer_ptr buffer;
//	boost::asio::mutable_buffer mb = boost::asio::buffer(buffer.data(), buffer.size());
//		boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v4(), CS_PORT);
//		boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> acceptor(io_sys_context, ep);
//		acceptor.set_option(boost::asio::socket_base::reuse_address(true));
//		acceptor.set_cookie_generate_callback(generateCookie);
//		acceptor.set_cookie_verify_callback(verifyCookie);
//		acceptor.bind(ep, ec);

//		if (!ec) {
//			pfp_fact("UDP Bind to : " << acceptor.local_endpoint().address().to_string());
//		} else {
//			pfp_fact("UDP Bind error : " << ec.message());
//		}

//		//dtls_sock_ptr socket(new dtls_sock(acceptor.get_executor(), m_ssl_context_udp));
//		ssl_socket_udp socket(io_sys_context, m_ssl_context_udp);

//		buffer.fill(0);
//		//pfp_fact("buffer before listen : " << n_pfp::dbgstr_hex2(buffer.data(), buffer.size(), 64));
//	acceptor.async_accept(socket, mb, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&mb](const boost::asio::error_code &ec, size_t size) {
//		if(ec) {
//			pfp_fact("UDP in async - Error in Accept: " << ec.message());
//		} else {
//			pfp_fact("UDP in async - Accept: OK");
//			//pfp_fact("async_accept size is : " << size);
//			//pfp_fact("async_accept buffer  : " << n_pfp::dbgstr_hex(mb.data(), mb.size())); // TODO cookie at 60 byte?
//			boost::asio::mutable_buffers_1 cb = boost::asio::mutable_buffers_1(buffer.data(), buffer.size());
//			socket.async_handshake(boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket>::server, cb, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&cb](const boost::system::error_code &error, size_t size) {
//				if (error) {
//					pfp_fact("UDP Server async_handshake : " << error.message());
//				} else {
//					pfp_fact("UDP Server async_handshake : OK");
//					boost::system::error_code ec;
//					//pfp_fact("async_handshake size is : " << size);
//					//pfp_fact("async_handshake buffer  : " << n_pfp::dbgstr_hex2(cb.data(), cb.size(), 64));

//					while (1) {
//						io_sys_context.reset();
//					pfp_fact("Loop [" << ++s_loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << s_tun_in << "/" << s_tun_out << "/" << s_socket_in << "/" << s_socket_out << ")");

////						pfp_fact("non-blocking : " << sd.non_blocking());
////						sd.non_blocking(true);
////						pfp_fact("non-blocking : " << sd.non_blocking());

////						boost::asio::posix::descriptor_base::bytes_readable command(true);
////						sd.io_control(command, ec);
////						if (ec) {
////							pfp_fact("Error on io_control : " << ec.message());
////						} else {
////							std::size_t bytes_readable = command.get();
////							pfp_fact("asd : " << bytes_readable);
////						}

////						unsigned char request1[BUFFER_SIZE];
////						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
////						socket.async_receive(mb1, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&mb1](const boost::asio::error_code &error, size_t bytes_transferred) {
////							if (!error) {
////								pfp_fact("Read " << bytes_transferred << " bytes from socket");
////								s_socket_in += bytes_transferred;
////								boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
////								sd.async_write_some(mb, [&s_tun_out,&sd](const boost::asio::error_code & ec, size_t bytes_transferred){
////									if (!ec) {
////										pfp_fact("Write " << bytes_transferred << " bytes to fd=" << sd.native_handle());
////										s_tun_out += bytes_transferred;
////									} else {
////										pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
////									}
////								});
////							} else {
////								pfp_fact("Error on read from socket : " << error.message());
////							}
////						});

//						// read socket / write tun
//						unsigned char request1[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//						size_t s_read = socket.receive(mb1, ec);
//						if (ec) {
//							pfp_fact("socket receive error: " << ec.message());
//						} else {
//							pfp_fact("Read " << s_read << " bytes from socket");
//							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb1.data(), s_read));
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1, s_read);
//							size_t sd_write = sd.write_some(mb, ec);
//							if (!ec) {
//								pfp_fact("Write " << sd_write << " bytes to fd=" << sd.native_handle());
//								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), sd_write));
////								struct timeval tp;
////								gettimeofday(&tp, NULL);
////								pcpp::RawPacket rp(static_cast<const uint8_t*>(mb.data()), sd_write, tp, false);
////								packetVec.pushBack(&rp);
//							} else {
//								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//							}
//						}

//						// read socket / write tun async
////						unsigned char request1[BUFFER_SIZE];
////						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
////						size_t socket_read = socket.get()->receive(mb1, ec);
////						if (ec) {
////							pfp_fact("socket error: " << ec.message());
////						} else {
////							pfp_fact("Read " << socket_read << " bytes from socket");
////							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), socket_read);
////							sd.async_write_some(mb, [&s_tun_out,&sd](const boost::asio::error_code & ec, size_t bytes_transferred){
////								if (!ec) {
////									pfp_fact("Write " << bytes_transferred << " bytes to fd=" << sd.native_handle());
////									s_tun_out += bytes_transferred;
////								} else {
////									pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
////								}
////							});
////						}

//						// read async socket / write tun
////						unsigned char request1[BUFFER_SIZE];
////						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
////						socket.get()->async_receive(mb1, [&io_sys_context,&s_loop_idx,&s_tun_in,&s_tun_out,&s_socket_in,&s_socket_out,&error,&socket,&sd,&buffer,&mb1](const boost::asio::error_code &error, size_t bytes_transferred) {
////							pfp_fact("Read " << bytes_transferred << " bytes from socket");
////							boost::system::error_code ec;
////							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1, bytes_transferred);
////							size_t sd_write = sd.write_some(mb, ec);
////							if (ec) {
////								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
////							} else {
////								pfp_fact("Write " << sd_write << " bytes to fd=" << sd.native_handle());
////							}
////							socket.get()->shutdown(ec);
////							if (ec) {
////								pfp_fact("socket async_receive socket shutdown : " << ec.message());
////							} else {
////								pfp_fact("socket async_receive socket shutdown : OK");
////							}
////							socket->async_shutdown([socket](const boost::asio::error_code & error){
////								if (error) {
////									pfp_fact("async_shutdown : " << error.message());
////								} else {
////									pfp_fact("async_shutdown : OK");
////								}
////							});
////						});

////						unsigned char request2[BUFFER_SIZE];
////						boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
////						sd.async_read_some(mb2, [&s_tun_in,&s_socket_out,&sd,&socket,&mb2] (const boost::system::error_code& error, std::size_t bytes_transferred) {
////							if (!error) {
////								pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
////								s_tun_in += bytes_transferred;
////								boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
////								socket.async_send(mb, [&socket,&s_socket_out](const boost::asio::error_code &ec, size_t size){
////									if (!ec) {
////										pfp_fact("Write " << size << " bytes to socket");
////										s_socket_out += size;
////									} else {
////										pfp_fact("Error on write to socket : " << ec.message());
////									}
////								});
////							} else {
////								pfp_fact("Error on read from " << TUN0 << " : " << error.message());
////							}
////						});

//						// read tun / write socket
//						unsigned char request2[BUFFER_SIZE];
//						boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
//						size_t tun_read = sd.read_some(mb2, ec);
//						if (ec) {
//							pfp_fact(TUN0 << " read_some error: " << ec.message());
//						} else {
//							pfp_fact("Read " << tun_read << " bytes from fd=" << sd.native_handle());
//							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb2.data(), tun_read));
//							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2, tun_read);
//							size_t s_write = socket.send(mb, ec);
//							if (!ec) {
//								pfp_fact("Write " << s_write << " bytes to socket");
//								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), s_write));
////								struct timeval tp;
////								gettimeofday(&tp, NULL);
////								pcpp::RawPacket rp(static_cast<const uint8_t*>(mb.data()), s_write, tp, false);
////								packetVec.pushBack(&rp);
//							} else {
//								pfp_fact("Error on write to socket : " << ec.message());
//							}
//						}

//						// read tun / write socket async
////						unsigned char request2[BUFFER_SIZE];
////						boost::asio::mutable_buffer mb2 = boost::asio::mutable_buffer(request2, BUFFER_SIZE);
////						size_t sd_read = sd.read_some(mb2, ec);
////						if (ec) {
////							pfp_fact("sd error : " << ec.message());
////						} else {
////							pfp_fact("Read " << sd_read << " bytes from fd=" << sd.native_handle());
////							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), sd_read);
////							socket.get()->async_send(mb, [](const boost::asio::error_code &ec, size_t size){
////								if (!ec) {
////									pfp_fact("Write " << size << " bytes to socket");
////								} else {
////									pfp_fact("Error on write to socket : " << ec.message());
////								}
////							});
////						}

//						// read async tun / write socket
////						unsigned char request2[BUFFER_SIZE];
////						boost::asio::mutable_buffer mb2 = boost::asio::mutable_buffer(request2, BUFFER_SIZE);
////						sd.async_read_some(mb2, [&mb2, &sd, &socket](const boost::asio::error_code &error, size_t bytes_transferred) {
////							if (error) {
////								pfp_fact("Error on read from " << TUN0 << " : " << error.message());
////							} else {
////								pfp_fact("Read " << bytes_transferred << " bytes from fd=" << sd.native_handle());
////								boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
////								boost::system::error_code ec;
////								size_t write_socket = socket.get()->send(mb, ec);
////								if (ec) {
////									pfp_fact("Error on write to socket : " << ec.message());
////								} else {
////									pfp_fact("Write " << write_socket << " bytes to socket");
////								}
////								socket.get()->shutdown(ec);
////								if (ec) {
////									pfp_fact(TUN0 << " async_receive socket shutdown : " << ec.message());
////								} else {
////									pfp_fact(TUN0 << " async_receive socket shutdown : OK");
////								}
////								socket->async_shutdown([socket](const boost::asio::error_code & error){
////									if (error) {
////										pfp_fact("async_shutdown : " << error.message());
////									} else {
////										pfp_fact("async_shutdown : OK");
////									}
////								});
////							}
////						});
////						socket->async_shutdown([socket](const boost::asio::error_code & error){
////						if (error) {
////							pfp_fact("async_shutdown : " << error.message());
////						} else {
////							pfp_fact("async_shutdown : OK");
////						}
////					});
//						//io_sys_context.reset();
//						io_sys_context.run_one(ec);
//						if (ec) {
//							pfp_fact("io run: " << ec.message());
//						} else {
//							pfp_fact("io run : OK");
//						}
//						//io_sys_context.restart();
//					}; // loop
//				}
//			});
//		}
//	}, ec);
//	if (ec) {
//		pfp_fact("async_accept : " << ec.message());
//	} else {
//		pfp_fact("async_accept : OK");
//	}

//	io_sys_context.run();
//	//listen_udp(acceptor, socket, buffer, io_sys_context, s_loop_idx, s_tun_in, s_tun_out, s_socket_in, s_socket_out, error, sd);

//	//	socket.get()->shutdown(ec);
//	//	if (ec) {
//	//		pfp_fact(TUN0 << " async_receive socket shutdown : " << ec.message());
//	//	} else {
//	//		pfp_fact(TUN0 << " async_receive socket shutdown : OK");
//	//	}

//}
