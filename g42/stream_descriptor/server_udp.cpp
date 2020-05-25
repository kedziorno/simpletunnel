#include "server_udp.hpp"
#include "config.hpp"
#include "pfplog.hpp"
#include "dbgstr.hpp"
#include <boost/exception/all.hpp>

server_udp::server_udp(boost::asio::io_context &io_context, boost::asio::ssl::dtls::context &dtls_context, int tun_descriptor)
	:
			m_io_context(&io_context),
			m_dtls_context(&dtls_context),
			m_endpoint(boost::asio::ip::udp::v4(), CS_PORT),
			m_socket_udp_dtls(*m_io_context, *m_dtls_context),
			m_acceptor(*m_io_context, m_endpoint)
{
	try {
		m_stream_descriptor = std::make_unique<boost::asio::posix::stream_descriptor>(*m_io_context, tun_descriptor);
	} catch(boost::exception & be) {
		pfp_fact("Exception : " << boost::diagnostic_information(be));
	}

	m_acceptor.set_option(boost::asio::socket_base::reuse_address(true));
	m_acceptor.set_cookie_generate_callback(generateCookie);
	m_acceptor.set_cookie_verify_callback(verifyCookie);
	m_acceptor.bind(m_endpoint, m_error_code);
	if (m_error_code) {
		pfp_fact("Bind error : " << m_error_code.message());
	} else {
		pfp_fact("Bind to : " << m_acceptor.local_endpoint().address().to_string());
	}
}

void server_udp::run()
{
	std::array<unsigned char,BUFFER_SIZE> buffer;
	boost::asio::mutable_buffer mb = boost::asio::buffer(buffer.data(), buffer.size());
	m_acceptor.async_accept(m_socket_udp_dtls, mb, [&](const boost::asio::error_code &ec, size_t size) {
		(void)size;
		if(ec) {
			pfp_fact("Error in async_accept : " << ec.message());
		} else {
			pfp_fact("UDP in async - Accept : OK");
			boost::asio::mutable_buffers_1 cb = boost::asio::mutable_buffers_1(buffer.data(), buffer.size());
			m_socket_udp_dtls.async_handshake(boost::asio::ssl::dtls::socket<boost::asio::ip::udp::socket>::server, cb, [&](const boost::system::error_code &error, size_t size) {
				(void)size;
				if (error) {
					pfp_fact("UDP Server async_handshake : " << error.message());
				} else {
					pfp_fact("UDP Server async_handshake : OK");
					boost::system::error_code ec;
					size_t loop_idx = 0;
					while (1) {
						m_io_context.get()->reset();
					pfp_fact("Loop [" << ++loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << m_statistics.tun_in << "/" << m_statistics.tun_out << "/" << m_statistics.socket_in << "/" << m_statistics.socket_out << ")");

						// read socket / write tun
						unsigned char request1[BUFFER_SIZE];
						boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
						size_t s_read = m_socket_udp_dtls.receive(mb1, ec);
						if (ec) {
							pfp_fact("socket receive error: " << ec.message());
						} else {
							pfp_fact("Read " << s_read << " bytes from socket");
							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb1.data(), s_read));
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb1, s_read);
							size_t sd_write = m_stream_descriptor.get()->write_some(mb, ec);
							if (!ec) {
								pfp_fact("Write " << sd_write << " bytes to fd=" << m_stream_descriptor.get()->native_handle());
								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), sd_write));
							} else {
								pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
							}
						}

						// read tun / write socket
						unsigned char request2[BUFFER_SIZE];
						boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
						size_t tun_read = m_stream_descriptor.get()->read_some(mb2, ec);
						if (ec) {
							pfp_fact(TUN0 << " read_some error: " << ec.message());
						} else {
							pfp_fact("Read " << tun_read << " bytes from fd=" << m_stream_descriptor.get()->native_handle());
							pfp_fact("dump : " << n_pfp::dbgstr_hex(mb2.data(), tun_read));
							boost::asio::mutable_buffer mb = boost::asio::buffer(mb2, tun_read);
							size_t s_write = m_socket_udp_dtls.send(mb, ec);
							if (!ec) {
								pfp_fact("Write " << s_write << " bytes to socket");
								pfp_fact("dump : " << n_pfp::dbgstr_hex(mb.data(), s_write));
							} else {
								pfp_fact("Error on write to socket : " << ec.message());
							}
						}
						m_io_context.get()->run_for(std::chrono::milliseconds(100));
					};
				}
			});
		}
	}, m_error_code);
	if (m_error_code) {
		pfp_fact("async_accept : " << m_error_code.message());
	} else {
		pfp_fact("async_accept : OK");
	}
	m_io_context.get()->run();
}
