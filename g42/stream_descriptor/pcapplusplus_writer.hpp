#ifndef PCAPPLUSPLUS_WRITER_HPP
#define PCAPPLUSPLUS_WRITER_HPP

#include "RawPacket.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

class pcapplusplus_writer
{
public:
	pcapplusplus_writer();
	pcapplusplus_writer(const std::string & name_capture_network_device, const std::string & file_name_to_write, boost::asio::io_context & io_context);

	void open_file();
	void open_device();
	void start_capturing();
	void install_signal_handler();

private:
	void PacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);
	void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);

	struct PacketArrivedData {
		pcpp::PcapNgFileWriterDevice* pcapWriter;
	};

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

	PacketStats m_packets_statistics;
private:
	std::shared_ptr<boost::asio::io_context> m_io_context;
	std::string m_name_capture_network_device;
	std::string m_file_name_to_write;
	pcpp::PcapNgFileWriterDevice m_pcapng_file_writer_device;
	std::unique_ptr<pcpp::PcapLiveDevice*> m_pcap_live_device;
	pcpp::RawPacketVector m_packet_vector;
	std::unique_ptr<boost::asio::signal_set> m_signal_set;
};

#endif // PCAPPLUSPLUS_WRITER_HPP
