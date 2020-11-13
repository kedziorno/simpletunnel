#include "tun_device.hpp"
#include "unused_code.hpp"

tun_device::tun_device()
	:
			m_name(DEFAULT_TUN_NAME),
			m_fd(-1),
			m_type(IFF_TUN),
			m_flags(IFF_UP | IFF_RUNNING),
			m_ifindex(-1),
			m_socket_inet6_dgram(-1),
			m_mtu(0),
			m_ipv6_address("")
{
	open_socket_inet6_dgram();
	tun_open(m_name);
	tun_set_type(m_type);
	tun_set_flags(m_flags);
	tun_get_mac();
	tun_set_ipv6(m_ipv6_address);
	tun_set_mtu(m_mtu);
	close(m_socket_inet6_dgram);
}

tun_device::tun_device(const std::string &device_name, int type, int flags, const std::string &ipv6address, int mtu)
	:
			m_name(device_name),
			m_fd(-1),
			m_type(type),
			m_flags(flags),
			m_ifindex(-1),
			m_socket_inet6_dgram(-1),
			m_mtu(mtu),
			m_ipv6_address(ipv6address)
{
	open_socket_inet6_dgram();
	tun_open(m_name);
	tun_set_type(m_type);
	tun_set_flags(m_flags);
	tun_get_mac();
	tun_set_ipv6(m_ipv6_address);
	tun_set_mtu(m_mtu);
	close(m_socket_inet6_dgram);
}

int tun_device::get_file_descriptor()
{
	return m_fd;
}

void tun_device::open_socket_inet6_dgram()
{
	m_socket_inet6_dgram = socket(AF_INET6, SOCK_DGRAM, 0);
	if (m_socket_inet6_dgram < 0) {
		pfp_throw_error_runtime_oss("socket AF_INET6 : " << strerror(errno));
	} else {
		pfp_fact("socket AF_INET6 : " << m_socket_inet6_dgram);
	}
}

void tun_device::tun_open(const std::string &name)
{
	m_name = name;
	unsigned int tun_exists = if_nametoindex(m_name.c_str());
	if (tun_exists == 0) { // we dont have tun with TUN0 name
		m_fd = open("/dev/net/tun", O_RDWR);
		if (m_fd < 0) {
			pfp_throw_error_runtime_oss("Tun open : " << strerror(errno));
		} else {
			pfp_fact("Tun open with fd=" << m_fd);
		}
	}
}

void tun_device::tun_set_type(int type)
{
	m_type = type;
	struct ifreq if_tun;
	memset(&if_tun, 0, sizeof(struct ifreq));
	if_tun.ifr_flags = m_type;
	memcpy(&if_tun.ifr_name, m_name.c_str(), IFNAMSIZ);
	if (ioctl(m_fd, TUNSETIFF, &if_tun) < 0) {
		pfp_throw_error_runtime_oss("Tun ioctl : " << strerror(errno));
	} else {
		pfp_fact("Tun ioctl : ok");
		m_ifindex = if_nametoindex(m_name.c_str());
	}
	pfp_fact("Tun ifindex : " << m_ifindex);
}

void tun_device::tun_set_flags(int flags)
{
	m_flags = flags;
	while (1) {
		struct ifreq if_up;
		memset(&if_up, 0, sizeof(struct ifreq));
		memcpy(&if_up.ifr_name, m_name.c_str(), IFNAMSIZ);
		if_up.ifr_ifindex = m_ifindex;
		if (ioctl(m_socket_inet6_dgram, SIOCGIFFLAGS, &if_up) < 0) {
			pfp_throw_error_runtime_oss("Tun get flags : " << strerror(errno));
		} else {
			pfp_fact("Tun get flags : OK");
			break;
		}
		if (!(if_up.ifr_flags & m_flags)) {
			struct ifreq if_flag_up_running;
			memset(&if_flag_up_running, 0, sizeof(struct ifreq));
			memcpy(&if_flag_up_running.ifr_name, m_name.c_str(), IFNAMSIZ);
			if_flag_up_running.ifr_flags |= m_flags;
			if_flag_up_running.ifr_ifindex = m_ifindex;
			if (ioctl(m_socket_inet6_dgram, SIOCSIFFLAGS, &if_flag_up_running) < 0) {
				pfp_throw_error_runtime_oss("Tun flags to UP : " << strerror(errno));
			} else {
				pfp_fact("Tun flags to UP : ok");
				break;
			}
		} else {
			pfp_fact("We have setting UP flags on " << m_name);
			break;
		}
		sleep(1);
	}
}

void tun_device::tun_get_mac()
{
	struct ifreq if_mac;
	memset(&if_mac, 0, sizeof(struct ifreq));
	if_mac.ifr_ifindex = m_ifindex;
	memcpy(&if_mac.ifr_name, m_name.c_str(), IFNAMSIZ);
	if (ioctl(m_socket_inet6_dgram, SIOCGIFHWADDR, &if_mac) < 0) {
		pfp_throw_error_runtime_oss("Tun hwaddr : " << strerror(errno));
	} else {
		pfp_fact("Tun hwaddr = " << n_pfp::dbgstr_hex(if_mac.ifr_hwaddr.sa_data, IFHWADDRLEN));
	}
}

void tun_device::tun_set_ipv6(const std::string &ipv6address)
{
	struct in6_ifreq ifr6;
	memset(&ifr6, 0, sizeof(struct in6_ifreq));
	struct sockaddr_in6 sai;
	memset(&sai, 0, sizeof(struct sockaddr_in6));
	sai.sin6_family = AF_INET6;
	sai.sin6_port = 0;
	int ipv6_addr_type;

	ipv6_addr_type = inet_pton(AF_INET6, ipv6address.c_str(), (void *)&sai.sin6_addr);
	if(ipv6_addr_type <= 0) {
		pfp_throw_error_runtime_oss("Bad server address to convert : " << ipv6address);
	} else {
		pfp_fact("Server address : " << ipv6address);
	}

	ifr6.ifr6_prefixlen = 16;
	memcpy((char *) &ifr6.ifr6_addr, (char *) &sai.sin6_addr, sizeof(struct in6_addr));
	ifr6.ifr6_ifindex = m_ifindex;
	if (ioctl(m_socket_inet6_dgram, SIOCSIFADDR, &ifr6) < 0) {
		pfp_throw_error_runtime_oss("Tun set IPv6 : " << strerror(errno));
	} else {
		pfp_fact("Tun set IPv6 : ok");
	}
}

void tun_device::tun_set_mtu(int mtu)
{
	m_mtu = mtu;
	struct ifreq if_mtu;
	memset(&if_mtu, 0, sizeof(struct ifreq));
	if_mtu.ifr_ifindex = m_ifindex;
	if_mtu.ifr_mtu = m_mtu;
	memcpy(&if_mtu.ifr_name, m_name.c_str(), IFNAMSIZ);
	if (ioctl(m_socket_inet6_dgram, SIOCSIFMTU, &if_mtu) < 0) {
		pfp_throw_error_runtime_oss("Tun mtu : " << strerror(errno));
	} else {
		pfp_fact("Tun mtu = " << if_mtu.ifr_mtu);
	}
}

/*
{
	if (delete_flag) {
		if (ioctl(tun_fd, TUNSETPERSIST, 0) < 0) {
			pfp_fact("disabling TUNSETPERSIST : " << strerror(errno));
			exit(1);
		}
		pfp_fact("Set " << TUN0 << " nonpersistent");
	} else {
		if (owner == -1 && group == -1) {
			owner = geteuid();
		}
		if (owner != -1) {
			if (ioctl(tun_fd, TUNSETOWNER, owner) < 0) {
				pfp_fact("TUNSETOWNER : " << strerror(errno));
				exit(1);
			}
		}
		if (group != -1) {
			if (ioctl(tun_fd, TUNSETGROUP, group) < 0) {
				pfp_fact("TUNSETGROUP : " << strerror(errno));
				exit(1);
			}
		}
		if (ioctl(tun_fd, TUNSETPERSIST, 1) < 0) {
			pfp_fact("enabling TUNSETPERSIST : " << strerror(errno));
			exit(1);
		}
		pfp_fact("Set " << TUN0 << " persistent");
		if(owner != -1)
				pfp_fact("owned by uid " << owner);
		if(group != -1)
				pfp_fact("owned by gid " << group);
	}
}
{
	struct ifreq if_queue = { 0 };
	if_queue.ifr_ifindex = if_index;
	if_queue.ifr_flags = IFF_ATTACH_QUEUE;
	memcpy(&if_queue.ifr_name, TUN0, IFNAMSIZ);
	if (ioctl(tun_fd, TUNSETQUEUE, &if_queue) < 0) {
	pfp_fact("Tun attach queue : " << strerror(errno));
	} else {
	pfp_fact("Tun attach queue : OK");
	}
}
*/
