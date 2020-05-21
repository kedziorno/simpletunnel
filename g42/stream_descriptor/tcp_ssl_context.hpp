#ifndef TCP_SSL_CONTEXT_HPP
#define TCP_SSL_CONTEXT_HPP

#include <boost/asio/ssl/context.hpp>

class tcp_ssl_context
{
public:
	tcp_ssl_context();

	boost::asio::ssl::context & get_ssl_context();

private:
	void tcp_ssl_set_options();
	void tcp_ssl_set_password_callback();
	void tcp_ssl_use_certificate_chain_file();
	void tcp_ssl_use_private_key_file();
	void tcp_ssl_use_tmp_dh_file();

	void throw_after_error_code(const std::string & message);

private:
	boost::system::error_code m_error_code;
	boost::asio::ssl::context m_tcp_ssl_context;
};

#endif // TCP_SSL_CONTEXT_HPP
