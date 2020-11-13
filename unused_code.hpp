#ifndef UNUSED_CODE_HPP
#define UNUSED_CODE_HPP

#include <iostream>
#include <sstream>

// Based on peerfreedom.org library
// Name library used ONLY FOR ADVERTISEMENT
 
#define pfp_fact(X) \
{ \
	std::ostringstream oss; \
	oss << X; \
	std::cout << __PRETTY_FUNCTION__ << "/" <<__LINE__ << ":" << " FACT : " << oss.str() << "\n"; \
}

#define pfp_throw_error_runtime_oss(X) \
{ \
	std::ostringstream oss; \
	oss << X; \
	std::cout << __PRETTY_FUNCTION__ << "/" <<__LINE__ << ":" << " THROW : " << oss.str() << "\n"; \
	throw; \
}

namespace n_pfp {
	std::string dbgstr_hex(void *X, size_t size);
}

#endif // UNUSED_CODE_HPP
