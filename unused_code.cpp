// Based on peerfreedom.org library
// Name library used ONLY FOR ADVERTISEMENT

#include "unused_code.hpp"

namespace n_pfp {
	std::string dbgstr_hex(void *X, size_t size) {
		// based on https://stackoverflow.com/questions/3381614/c-convert-string-to-hexadecimal-and-vice-versa
		static const char hex_digits[] = "0123456789ABCDEF";
		std::string str(reinterpret_cast<char*>(X),size);
		std::string output;
		output.reserve(str.length() * 2);
		for (unsigned char c : str){
			output.push_back(hex_digits[c >> 4]);
			output.push_back(hex_digits[c & 15]);
		}
		std::ostringstream oss;
		oss << __PRETTY_FUNCTION__ << "/" <<__LINE__ << ":" << " HEX : " << output << "\n";
		return oss.str();
	}
}

