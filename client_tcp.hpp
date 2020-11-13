#ifndef CLIENT_TCP_HPP
#define CLIENT_TCP_HPP

#include "unused_code.hpp"

#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>

class client_tcp
{
public:
	client_tcp();
	client_tcp(boost::asio::io_context &io_context, boost::asio::ssl::context &tls_context, int tun_descriptor, const std::string & remote_ip);

	void run();

private:
	static bool client_verify_cb(bool preverified, boost::asio::ssl::verify_context& ctx) {
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		pfp_fact("*** Verifying : " << subject_name);
		return preverified;
	}

private:
	boost::system::error_code m_error_code;
	std::shared_ptr<boost::asio::io_context> m_io_context;
	std::shared_ptr<boost::asio::ssl::context> m_tcp_ssl_context;
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket_tcp_ssl;
	boost::asio::ip::tcp::resolver m_resolver;
	std::unique_ptr<boost::asio::posix::stream_descriptor> m_stream_descriptor;

	struct statistics {
		size_t tun_in;
		size_t tun_out;
		size_t socket_in;
		size_t socket_out;
	};

	statistics m_statistics;
};

#endif // CLIENT_TCP_HPP
