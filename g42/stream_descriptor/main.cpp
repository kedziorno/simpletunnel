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
#include "pcapplusplus_writer.hpp"

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

	boost::asio::io_context io_sys_context;

//	pcapplusplus_writer pcppw(TUN0, PCAP_FILE, io_sys_context);
//	if (write_to_pcap_file == 1) {
//		pfp_fact("Flag -w is set, so we install CTRL+C handler and capture packets");
//		pcppw.install_signal_handler();
//	}

	if (cs == SERVER) {
		if (ssl_tcp_udp == SSL_TCP) {
			pfp_fact("SERVER TCP...");
			tcp_ssl_context tcp_ctx(boost::asio::ssl::context::sslv23_server);
			server_tcp server(io_sys_context, tcp_ctx.get_ssl_context(), tun.get_file_descriptor());
			server.run();
		}

		if (ssl_tcp_udp == SSL_UDP) {
			pfp_fact("SERVER UDP...");
			udp_dtls_context udp_ctx(boost::asio::ssl::dtls::context::dtls_server);
			server_udp server(io_sys_context, udp_ctx.get_udp_context(), tun.get_file_descriptor());
			server.run();
		}
	}

	if (cs == CLIENT) {
		if (ssl_tcp_udp == SSL_TCP) {
			pfp_fact("CLIENT TCP...");
			tcp_ssl_context tcp_ctx(boost::asio::ssl::context::sslv23_client);
			client_tcp client(io_sys_context, tcp_ctx.get_ssl_context(), tun.get_file_descriptor(), remote_ip);
			client.run();
		}

		if (ssl_tcp_udp == SSL_UDP) {
			pfp_fact("CLIENT UDP...");
			udp_dtls_context udp_ctx(boost::asio::ssl::dtls::context::dtls_client);
			client_udp client(io_sys_context, udp_ctx.get_udp_context(), tun.get_file_descriptor(), remote_ip);
			client.run();
		}
	}

	io_sys_context.run();

}
