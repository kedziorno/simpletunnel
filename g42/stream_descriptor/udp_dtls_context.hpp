#ifndef UDP_DTLS_CONTEXT_HPP
#define UDP_DTLS_CONTEXT_HPP

#include <boost/asio/ip/udp.hpp>
#include <asio/dtls.hpp>

class udp_dtls_context
{
public:
	udp_dtls_context();

	boost::asio::ssl::dtls::context & get_udp_context();

private:
	void set_options();
	void set_password_callback();
	void use_certificate_file();
	void use_private_key_file();
	void use_tmp_dh_file();

	void throw_after_error_code(const std::string & message);

private:
	boost::system::error_code m_error_code;
	boost::asio::ssl::dtls::context m_udp_dtls_context;
};

#endif // UDP_DTLS_CONTEXT_HPP
