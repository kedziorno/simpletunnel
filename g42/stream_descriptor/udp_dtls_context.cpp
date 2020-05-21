#include "udp_dtls_context.hpp"

#include "pfplog.hpp"

udp_dtls_context::udp_dtls_context()
	:
			m_udp_dtls_context(boost::asio::ssl::dtls::context::dtls_server)
{
	set_options();
	set_password_callback();
	use_certificate_file();
	use_private_key_file();
	use_tmp_dh_file();
}

boost::asio::ssl::dtls::context & udp_dtls_context::get_udp_context()
{
	return m_udp_dtls_context;
}

void udp_dtls_context::set_options()
{
	m_udp_dtls_context.set_options(boost::asio::ssl::dtls::context::cookie_exchange, m_error_code);
	throw_after_error_code(__func__);
}

void udp_dtls_context::set_password_callback()
{
	m_udp_dtls_context.set_password_callback([](std::size_t ml, boost::asio::ssl::context::password_purpose purpose) -> std::string {
		(void)ml;
		(void)purpose;
		return "text"; // TODO set password
	}, m_error_code);
	throw_after_error_code(__func__);
}

void udp_dtls_context::use_certificate_file()
{
	m_udp_dtls_context.use_certificate_file("server.pem", boost::asio::ssl::context_base::pem, m_error_code);
	throw_after_error_code(__func__);
}

void udp_dtls_context::use_private_key_file()
{
	m_udp_dtls_context.use_private_key_file("server.pem", boost::asio::ssl::context_base::pem, m_error_code);
	throw_after_error_code(__func__);
}

void udp_dtls_context::use_tmp_dh_file()
{
	m_udp_dtls_context.use_tmp_dh_file("dh2048.pem", m_error_code);
	throw_after_error_code(__func__);
}

void udp_dtls_context::use_verify_key_file()
{
	m_udp_dtls_context.load_verify_file("server.pem", m_error_code);
	throw_after_error_code(__func__);
}

void udp_dtls_context::throw_after_error_code(const std::string & message)
{
	if (m_error_code) {
		pfp_throw_error_runtime_oss(message << " : " << m_error_code.message());
	} else {
		pfp_fact(message << ":" << "OK");
	}
}
