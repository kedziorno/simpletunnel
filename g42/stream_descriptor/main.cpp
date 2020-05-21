#include <boost/asio/signal_set.hpp>

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
	(void)dev;
	pcpp::Packet parsedPacket(packet);

	PacketArrivedData* data  = (PacketArrivedData*)cookie;

	if (data->pcapWriter != NULL) {
		data->pcapWriter->writePacket(*packet);
	}
}

void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	(void)dev;
	PacketStats* stats = (PacketStats*)cookie;
	pcpp::Packet parsedPacket(packet);
	stats->consumePacket(parsedPacket);
}
#endif

void usage() {
	pfp_fact("'-s' - Server, '-c [host]' - Client, '-t' - SSL TCP, '-u' - SSL UDP");
}

int main(int argc, char *argv[])
{
	int cs = -1, ssl_tcp_udp = -1, write_to_pcap_file = -1, option;

	char remote_ip[16] = { 0 };

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

	if (cs == SERVER) { // server mode
		if (ssl_tcp_udp == SSL_TCP) {
			pfp_fact("SERVER TCP...");
			tcp_ssl_context tcp_ctx;
			server_tcp server(io_sys_context, tcp_ctx.get_ssl_context(), tun.get_file_descriptor());
			server.run();
		}

		if (ssl_tcp_udp == SSL_UDP) { // s udp mode
			pfp_fact("SERVER UDP...");
			udp_dtls_context udp_ctx;
			server_udp server(io_sys_context, udp_ctx.get_udp_context(), tun.get_file_descriptor());
			server.run();
		} // SSL_UDP
	} // CS SERVER

	if (cs == CLIENT) { // client mode
		if (ssl_tcp_udp == SSL_TCP) { // c tcp mode
			pfp_fact("CLIENT TCP...");
			tcp_ssl_context tcp_ctx;
			client_tcp client(io_sys_context, tcp_ctx.get_ssl_context(), tun.get_file_descriptor(), remote_ip);
			client.run();
		}

		if (ssl_tcp_udp == SSL_UDP) { // c udp mode
			pfp_fact("CLIENT UDP...");
			udp_dtls_context udp_ctx;
			client_udp client(io_sys_context, udp_ctx.get_udp_context(), tun.get_file_descriptor(), remote_ip);
			client.run();
		} // SSL_UDP
	} // CS_CLIENT
} // main
