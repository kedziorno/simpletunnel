#include "config.hpp"
#include "client_tcp.hpp"
#include "pfplog.hpp"
#include "dbgstr.hpp"

#include <boost/asio/connect.hpp>
#include <boost/exception/all.hpp>

client_tcp::client_tcp(boost::asio::io_context &io_context, boost::asio::ssl::context &tls_context, int tun_descriptor, const std::string & remote_ip)
	:
			m_io_context(&io_context),
			m_tcp_ssl_context(&tls_context),
			m_socket_tcp_ssl(*m_io_context, *m_tcp_ssl_context),
			m_resolver(*m_io_context)
{
	try {
		m_stream_descriptor = std::make_unique<boost::asio::posix::stream_descriptor>(*m_io_context, tun_descriptor);
	} catch(boost::exception & be) {
		pfp_fact("Exception : " << boost::diagnostic_information(be));
	}

	boost::asio::ip::tcp::resolver::query query(remote_ip.c_str(), std::to_string(CS_PORT));
	boost::asio::ip::tcp::resolver::iterator it = m_resolver.resolve(query);
	pfp_fact("Want connect to : " << query.host_name() << ":" << query.service_name());

	boost::asio::connect(m_socket_tcp_ssl.lowest_layer(), it, m_error_code);
	if (m_error_code) {
		pfp_fact("Conect error to " << it->host_name() << " : " << m_error_code.message());
	} else {
		pfp_fact("Connected to : " << it->host_name());
	}

	m_socket_tcp_ssl.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true));

	m_socket_tcp_ssl.set_verify_mode(boost::asio::ssl::verify_peer, m_error_code);
	if (m_error_code) {
		pfp_fact("Set verify mode : " << m_error_code.message());
	} else {
		pfp_fact("Set verify mode : OK");
	}

	m_socket_tcp_ssl.set_verify_callback(client_verify_cb, m_error_code);
	if (m_error_code) {
		pfp_fact("Set verify callback : " << m_error_code.message());
	} else {
		pfp_fact("Set verify callback : OK");
	}
}

void client_tcp::run()
{
//	m_socket_tcp_ssl.handshake(boost::asio::ssl::stream_base::client, m_error_code);
	m_socket_tcp_ssl.async_handshake(boost::asio::ssl::stream_base::client, [&](const boost::system::error_code & error_code){
		if (error_code) {
			pfp_fact("Handshake : failed , " << m_error_code.message());
		} else {
			pfp_fact("Handshake : OK");
			size_t loop_idx = 0;
			while (1) {
				m_io_context.get()->reset();
				pfp_fact("Loop [" << ++loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << m_statistics.tun_in << "/" << m_statistics.tun_out << "/" << m_statistics.socket_in << "/" << m_statistics.socket_out << ")");

				std::array<unsigned char, BUFFER_SIZE> request1;
				request1.fill(0);
				boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
				m_socket_tcp_ssl.async_read_some(mb1, [&] (const boost::system::error_code& error, std::size_t bytes_transferred) {
					if (!error) {
						pfp_fact("Read " << bytes_transferred << " bytes from socket");
						pfp_fact("dump : " << n_pfp::dbgstr_hex(mb1.data(), bytes_transferred));
						m_statistics.socket_in += bytes_transferred;
						boost::asio::mutable_buffer mb = boost::asio::buffer(mb1.data(), bytes_transferred);
						boost::system::error_code ec;
						size_t sd_ws = m_stream_descriptor.get()->write_some(mb, ec);
						if (!ec) {
							pfp_fact("Write " << sd_ws << " bytes to fd=" << m_stream_descriptor.get()->native_handle());
							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), sd_ws));
							m_statistics.tun_out += sd_ws;
						} else {
							pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
						}
					} else {
						pfp_fact("Error on read from socket : " << error.message());
					}
				});

				std::array<unsigned char, BUFFER_SIZE> request2;
				request2.fill(0);
				boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
				m_stream_descriptor.get()->async_read_some(mb2, [&] (const boost::system::error_code& error, std::size_t bytes_transferred) {
					if (!error) {
						pfp_fact("Read " << bytes_transferred << " bytes from fd=" << m_stream_descriptor.get()->native_handle());
						pfp_fact("dump : " << n_pfp::dbgstr_hex(mb2.data(), bytes_transferred));
						m_statistics.tun_in += bytes_transferred;
						boost::asio::mutable_buffer mb = boost::asio::buffer(mb2.data(), bytes_transferred);
						boost::system::error_code ec;
						size_t ws2 = m_socket_tcp_ssl.write_some(mb, ec);
						if (!ec) {
							pfp_fact("Write " << ws2 << " bytes to socket");
							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), ws2));
							m_statistics.socket_out += ws2;
						} else {
							pfp_fact("Error on write to socket : " << ec.message());
						}
					} else {
						pfp_fact("Error on read from " << TUN0 << " : " << error.message());
					}
				});

				m_io_context.get()->run();
				m_io_context.get()->restart();
			}
		}
	});
	m_io_context.get()->run();
}
