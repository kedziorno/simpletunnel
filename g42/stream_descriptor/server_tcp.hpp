#ifndef SERVER_TCP_HPP
#define SERVER_TCP_HPP

#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include "tun_device.hpp"

class server_tcp
{
public:
	server_tcp();
	server_tcp(boost::asio::io_context &io_context, boost::asio::ssl::context &tls_context, int tun_descriptor);

	void run();

private:
	boost::system::error_code m_error_code;
	boost::asio::ip::tcp::endpoint m_endpoint;
	std::shared_ptr<boost::asio::io_context> m_io_context;
	std::shared_ptr<boost::asio::ssl::context> m_tls_context;
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket_tcp_ssl;
	boost::asio::ip::tcp::acceptor m_acceptor;
	std::unique_ptr<boost::asio::posix::stream_descriptor> m_stream_descriptor;

	struct statistics {
		size_t tun_in;
		size_t tun_out;
		size_t socket_in;
		size_t socket_out;
	};

	statistics m_statistics;
};

#endif // SERVER_TCP_HPP
