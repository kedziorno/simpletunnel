#ifndef SERVER_UDP_HPP
#define SERVER_UDP_HPP

#include <asio/dtls.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include "unused_code.hpp"

class server_udp
{
public:
	server_udp();
	server_udp(boost::asio::io_context &io_context, boost::asio::ssl::dtls::context &dtls_context, int tun_descriptor);

	void run();

private:
	static bool generateCookie(std::string &cookie, const boost::asio::ip::udp::endpoint& ep) {
		cookie = "deafbeefcafe";
		pfp_fact("Cookie generated for endpoint: " << ep << " is " << cookie);
		return true;
	}

	static bool verifyCookie(const std::string &cookie, const boost::asio::ip::udp::endpoint& ep) {
		pfp_fact("Cookie provided for endpoint: " << ep << " is " << cookie);
		return (cookie == "deafbeefcafe");
	}

private:
	boost::system::error_code m_error_code;
	std::shared_ptr<boost::asio::io_context> m_io_context;
	std::shared_ptr<boost::asio::ssl::dtls::context> m_dtls_context;
	boost::asio::ip::udp::endpoint m_endpoint;
	boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> m_socket_udp_dtls;
	boost::asio::ssl::dtls::acceptor<boost::asio::ip::udp::socket> m_acceptor;
	std::unique_ptr<boost::asio::posix::stream_descriptor> m_stream_descriptor;

	struct statistics {
		size_t tun_in;
		size_t tun_out;
		size_t socket_in;
		size_t socket_out;
	};

	statistics m_statistics;
};

#endif // SERVER_UDP_HPP
