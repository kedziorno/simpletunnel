#include "pcapplusplus_writer.hpp"

#include "pfplog.hpp"

pcapplusplus_writer::pcapplusplus_writer(const std::string & name_capture_network_device, const std::string & file_name_to_write)
	:
			m_name_capture_network_device(name_capture_network_device),
			m_file_name_to_write(file_name_to_write),
			m_pcapng_file_writer_device(m_file_name_to_write.c_str())
{

}

void pcapplusplus_writer::open_file()
{
	m_pcapng_file_writer_device.open();
	if (!m_pcapng_file_writer_device.isOpened()) {
		pfp_fact("Cannot open .pcap file for writing");
	} else {
		pfp_fact("Open .pcap for writing : OK");
	}
}

void pcapplusplus_writer::open_device()
{
	m_pcap_live_device = std::make_unique<pcpp::PcapLiveDevice*>();
	*m_pcap_live_device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(m_name_capture_network_device);
	if (!m_pcap_live_device) {
		pfp_fact("PCAP++ Cannot find interface name " << m_name_capture_network_device);
	} else {
		if (!(*m_pcap_live_device.get())->open()) {
			pfp_fact("PCAP++ Device " << m_name_capture_network_device << " not opened ");
		} else {
			pfp_fact("PCAP++ Device " << m_name_capture_network_device << " opened : OK");
		}
	}
}

void pcapplusplus_writer::start_capturing()
{
	pfp_fact("PCAP++ start async capturing...");
	(*m_pcap_live_device.get())->startCapture(m_packet_vector);
	if ((*m_pcap_live_device.get())->captureActive()) {
		pfp_fact("PCAP++ capturing is activate");
	}
}

void pcapplusplus_writer::install_signal_handler(boost::asio::signal_set & signal_set)
{
	signal_set.async_wait([&](const boost::system::error_code & error , int signal_number) {
		if (!error) {
			if (signal_number == 2) { // CTRL+C
				pfp_fact("Handling signal CTRL+C");
				pfp_fact("PCAP++ -w flag active, stop capturing ...");
				(*m_pcap_live_device.get())->stopCapture();
				if (!(*m_pcap_live_device.get())->captureActive()) {
					pfp_fact("PCAP++ capturing is offline");
					pfp_fact("PCAP++ parse " << m_packet_vector.size() << " packets");
					for (pcpp::RawPacketVector::ConstVectorIterator iter = m_packet_vector.begin(); iter != m_packet_vector.end(); iter++) {
						pcpp::Packet parsedPacket(*iter);
						m_packets_statistics.consumePacket(parsedPacket);
					}
					m_packets_statistics.printToConsole();
					pfp_fact("PCAP++ -w flag is set so we write to file : " << m_file_name_to_write << "");
					pfp_fact("PCAP++ write " << m_packet_vector.size() << " packets");
					if (m_pcapng_file_writer_device.writePackets(m_packet_vector)) {
						pcap_stat pcap_s;
						m_pcapng_file_writer_device.getStatistics(pcap_s);
						pfp_fact("PCAP++ has writted to .pcap file : " << pcap_s.ps_recv << " packets");
					} else {
						pfp_fact("PCAP++ problem with writting to .pcap file");
					}
				} else {
					pfp_fact("PCAP++ error with offline capturing - still capture ???");
				}
				pfp_fact("PCAP++ close file " << m_pcapng_file_writer_device.getFileName());
				m_pcapng_file_writer_device.close();
				pfp_fact("PCAP++ closing device " << m_name_capture_network_device);
				(*m_pcap_live_device.get())->close();
				exit(signal_number);
			} else {
				pfp_fact("PCAP++ close file " << m_pcapng_file_writer_device.getFileName());
				m_pcapng_file_writer_device.close();
				pfp_fact("Unrecognized signal number : " << signal_number);
				(*m_pcap_live_device.get())->close();
				exit(signal_number);
			}
		} else {
			pfp_fact("Error in signal_set async_wait signal : " << error.message());
		}
	});
}

void pcapplusplus_writer::PacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	(void)dev;
	pcpp::Packet parsedPacket(packet);

	PacketArrivedData* data  = (PacketArrivedData*)cookie;

	if (data->pcapWriter != NULL) {
		data->pcapWriter->writePacket(*packet);
	}
}

void pcapplusplus_writer::onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	(void)dev;
	PacketStats* stats = (PacketStats*)cookie;
	pcpp::Packet parsedPacket(packet);
	stats->consumePacket(parsedPacket);
}
