cmake_minimum_required (VERSION 3.21)

project(TestProject)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/test)
#list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_LIST_DIR}/test")

# Include the lwip library
add_subdirectory("lwip" EXCLUDE_FROM_ALL)
add_subdirectory("mbedtls" EXCLUDE_FROM_ALL)

# lwip
include_directories(.)
include_directories(arch)
include_directories(lwip/src/include)

# mbedtls
include_directories(mbedtls/library)
include_directories(mbedtls/tests/include)
include_directories(mbedtls/tf-psa-crypto/core)

#add_definitions( -DNO_SYS=0 )
#add_definitions( -DLWIP_PROVIDE_ERRNO=1 )

find_package(PCAP REQUIRED)

# Create the main executable
add_executable(TestProject
    "test/main.c"
    test/echo_server.c
    test/netif.c test/pcap.c
    test/socket_echo_server.c
    test/mbedtls_net_sockets.c
    test/ssl_server.c
    arch/sys_arch.c
    # mbedtls/tests/src/certs.c
    #    test/pcapif.c
)

target_link_libraries(TestProject
    PRIVATE mbedtls
    PRIVATE lwipcore
    PRIVATE lwipallapps
    ${PCAP_LIBRARY}
)
