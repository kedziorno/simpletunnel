#ifndef CLIENT_UDP_HPP
#define CLIENT_UDP_HPP

#include "pfplog.hpp"

#include <asio/dtls.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>

class client_udp
{
public:
	client_udp();
	client_udp(boost::asio::io_context &io_context, boost::asio::ssl::dtls::context &dtls_context, int tun_descriptor, const std::string & remote_ip);

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
	std::shared_ptr<boost::asio::ssl::dtls::context> m_udp_dtls_context;
	boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket> m_socket_udp_dtls;
	boost::asio::ip::udp::resolver m_resolver;
	std::unique_ptr<boost::asio::posix::stream_descriptor> m_stream_descriptor;

	struct statistics {
		size_t tun_in;
		size_t tun_out;
		size_t socket_in;
		size_t socket_out;
	};

	statistics m_statistics;
};

#endif // CLIENT_UDP_HPP
