if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
	message(FATAL_ERROR "Not Linux System")
endif()

if(NOT CMAKE_CXX_COMPILER_LOADED)
	message(FATAL_ERROR "Compiler C++ not found")
endif()

find_package(PkgConfig)

pkg_check_modules (LIBPCAP REQUIRED libpcap)
if (NOT LIBPCAP_FOUND)
	message(FATAL_ERROR "libpcap not found")
else()
	message(STATUS "LIBPCAP FOUND -> ${LIBPCAP_FOUND}")
	#message(STATUS "LIBPCAP LIBRARIES ${LIBPCAP_LIBRARIES}")
	#message(STATUS "LIBPCAP LINK_LIBRARIES ${LIBPCAP_LINK_LIBRARIES}")
	#message(STATUS "LIBPCAP LIBRARY_DIRS ${LIBPCAP_LIBRARY_DIRS}")
	#message(STATUS "LIBPCAP INCLUDE_DIRS ${LIBPCAP_INCLUDE_DIRS}")
endif()

pkg_check_modules (PCAPPLUSPLUS REQUIRED PcapPlusPlus)
if (NOT PCAPPLUSPLUS_FOUND)
	message(FATAL_ERROR "PCAPPLUSPLUS not found")
else()
	message(STATUS "PCAPPLUSPLUS FOUND -> ${PCAPPLUSPLUS_FOUND}")
	#message(STATUS "PCAPPLUSPLUS LIBRARIES ${PCAPPLUSPLUS_LIBRARIES}")
	#message(STATUS "PCAPPLUSPLUS LINK_LIBRARIES ${PCAPPLUSPLUS_LINK_LIBRARIES}")
	#message(STATUS "PCAPPLUSPLUS LIBRARY_DIRS ${PCAPPLUSPLUS_LIBRARY_DIRS}")
	#message(STATUS "PCAPPLUSPLUS INCLUDE_DIRS ${PCAPPLUSPLUS_INCLUDE_DIRS}")
endif()
