#ifndef TUN_DEVICE_HPP
#define TUN_DEVICE_HPP

#include <string>

#define DEFAULT_TUN_NAME "tun0"

class tun_device
{
public:
	tun_device();
	tun_device(const std::string & name, int type, int flags, const std::string & ipv6address, int mtu);

	int get_file_descriptor();

private:
	void open_socket_inet6_dgram();
	void tun_open(const std::string & name);
	void tun_set_type(int type);
	void tun_set_flags(int flags);
	void tun_get_mac();
	void tun_set_ipv6(const std::string & ipv6address);
	void tun_set_mtu(int mtu);

private:
	std::string m_name;
	int m_fd;
	int m_type;
	int m_flags;
	int m_ifindex;
	int m_socket_inet6_dgram;
	int m_mtu;
	std::string m_ipv6_address;
};

#endif // TUN_DEVICE_HPP
