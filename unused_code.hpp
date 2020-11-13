#ifndef UNUSED_CODE_HPP
#define UNUSED_CODE_HPP

//std::array<unsigned char, BUFFER_SIZE> request1;
//request1.fill(0);
//boost::asio::mutable_buffer mb1 = boost::asio::buffer(request1, BUFFER_SIZE);
//size_t rsl = socket_tcp.read_some(mb1, ec);
//if (ec) {
//	pfp_fact("Error read_some on socket : " << ec.message());
//} else {
//	pfp_fact("read_some " << rsl << " bytes from socket");
//	size_t sd_ws = sd.write_some(mb1, ec);
//	if (!ec) {
//		pfp_fact("Write " << sd_ws << " bytes to fd=" << sd.native_handle());
//	} else {
//		pfp_fact("Error on write to " << TUN0 << " : " << ec.message());
//	}
//}

//std::array<unsigned char, BUFFER_SIZE> request2;
//request2.fill(0);
//boost::asio::mutable_buffer mb2 = boost::asio::buffer(request2, BUFFER_SIZE);
//size_t sdrl = sd.read_some(mb2, ec);
//if (ec) {
//	pfp_fact("Error on read_some on tun : " << ec.message());
//} else {
//	pfp_fact("read_some " << sdrl << " bytes from socket");
//	size_t s_ws = socket_tcp.write_some(mb2, ec);
//	if (!ec) {
//		pfp_fact("Write " << s_ws << " bytes to socket");
//	} else {
//		pfp_fact("Error on write to socket : " << ec.message());
//	}

#endif // UNUSED_CODE_HPP
