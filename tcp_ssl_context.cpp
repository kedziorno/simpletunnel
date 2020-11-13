#include "tcp_ssl_context.hpp"

#include "unused_code.hpp"

tcp_ssl_context::tcp_ssl_context(const boost::asio::ssl::context::method & context_type)
	:
			m_tcp_ssl_context(context_type)
{
	set_options();
	set_password_callback();
	use_certificate_chain_file();
	use_private_key_file();
	use_tmp_dh_file();
	use_verify_key_file();
}

boost::asio::ssl::context & tcp_ssl_context::get_ssl_context()
{
	return m_tcp_ssl_context;
}

void tcp_ssl_context::set_options() {
	m_tcp_ssl_context.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use, m_error_code);
	throw_after_error_code(__func__);
}

void tcp_ssl_context::set_password_callback()
{
	m_tcp_ssl_context.set_password_callback([](std::size_t ml, boost::asio::ssl::context::password_purpose purpose) -> std::string {
		(void)ml;
		(void)purpose;
		return "text"; // TODO set password
	}, m_error_code);
	throw_after_error_code(__func__);
}

void tcp_ssl_context::use_certificate_chain_file()
{
	m_tcp_ssl_context.use_certificate_chain_file("server.pem", m_error_code);
	throw_after_error_code(__func__);
}

void tcp_ssl_context::use_private_key_file()
{
	m_tcp_ssl_context.use_private_key_file("server.pem", boost::asio::ssl::context::pem, m_error_code);
	throw_after_error_code(__func__);
}

void tcp_ssl_context::use_tmp_dh_file()
{
	m_tcp_ssl_context.use_tmp_dh_file("dh2048.pem", m_error_code);
	throw_after_error_code(__func__);
}

void tcp_ssl_context::use_verify_key_file()
{
	m_tcp_ssl_context.load_verify_file("server.pem", m_error_code);
	throw_after_error_code(__func__);
}

void tcp_ssl_context::throw_after_error_code(const std::string & message)
{
	if (m_error_code) {
		pfp_throw_error_runtime_oss(message << " : " << m_error_code.message());
	} else {
		pfp_fact(message << ":" << "OK");
	}
}
