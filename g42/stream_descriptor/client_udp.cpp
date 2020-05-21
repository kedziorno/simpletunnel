#include "config.hpp"
#include "client_udp.hpp"
#include "pfplog.hpp"
#include "dbgstr.hpp"

#include <boost/asio/connect.hpp>
#include <boost/exception/all.hpp>


client_udp::client_udp(boost::asio::io_context &io_context, boost::asio::ssl::dtls::context &dtls_context, int tun_descriptor, const std::string & remote_ip)
	:
			m_io_context(&io_context),
			m_udp_dtls_context(&dtls_context),
			m_socket_udp_dtls(*m_io_context, *m_udp_dtls_context),
			m_resolver(*m_io_context)
{
	try {
		m_stream_descriptor = std::make_unique<boost::asio::posix::stream_descriptor>(*m_io_context, tun_descriptor);
	} catch(boost::exception & be) {
		pfp_fact("Exception : " << boost::diagnostic_information(be));
	}

	boost::asio::ip::udp::resolver::query query(remote_ip.c_str(), std::to_string(CS_PORT));
	boost::asio::ip::udp::resolver::iterator it = m_resolver.resolve(query);
	pfp_fact("Want connect to : " << query.host_name() << ":" << query.service_name());

	m_socket_udp_dtls.set_verify_mode(boost::asio::ssl::verify_peer, m_error_code);
	if (m_error_code) {
		pfp_fact("Set verify mode : " << m_error_code.message());
	} else {
		pfp_fact("Set verify mode : OK");
	}

	m_socket_udp_dtls.set_verify_callback(client_verify_cb, m_error_code);
	if (m_error_code) {
		pfp_fact("Set verify callback : " << m_error_code.message());
	} else {
		pfp_fact("Set verify callback : OK");
	}

	m_socket_udp_dtls.lowest_layer().connect(it->endpoint(), m_error_code);
	if (m_error_code) {
		pfp_fact("Conect error to " << it->host_name() << " : " << m_error_code.message());
	} else {
		pfp_fact("Connected to : " << it->host_name());
	}


}

void client_udp::run() {
	std::array<char, BUFFER_SIZE> buffer_data;
	buffer_data.fill(0);
	boost::asio::const_buffer buffer(buffer_data.data(), buffer_data.size());
	m_socket_udp_dtls.async_handshake(boost::asio::ssl::stream_base::handshake_type::client, buffer, [&](const boost::system::error_code & error, size_t bytes_transferred){
		if (error) {
			pfp_fact("async_handshake failed : " << error.message());
		} else {
			pfp_fact("Handshake : OK");
			pfp_fact("UDP Client bytes : " << bytes_transferred);
			boost::system::error_code ec;
			size_t loop_idx = 0;
			while (1) {
			m_io_context.get()->reset();
			pfp_fact("Loop [" << ++loop_idx << "] : (tun_in/tun_out/socket_in/socket_out) -> (" << m_statistics.tun_in << "/" << m_statistics.tun_out << "/" << m_statistics.socket_in << "/" << m_statistics.socket_out << ")");

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

				m_io_context.get()->run_one(ec);
				if (ec) {
					pfp_fact("io run: " << ec.message());
				} else {
					pfp_fact("io run : OK");
				}
		};
		}
	});
	m_io_context.get()->run();
}

