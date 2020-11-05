cmake_minimum_required(VERSION 3.9)
project(hashing VERSION 1.0.0 DESCRIPTION "Hash functions library")

set(hashing_src
   src/ripemd160.c
   src/sha2.c
   src/sha3.c
   src/hmac_sha2.c
   src/hmac_sha3.c
)

add_library(hashing ${hashing_src})

target_include_directories(hashing PRIVATE include)

set_target_properties(hashing PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/hmac_sha2.h;include/hmac_sha3.h;include/ripemd160.h;include/sha2.h;include/sha3.h"
)

add_executable(test_sha2 misc/test_sha2.c)
add_executable(test_sha3 misc/test_sha3.c)
add_executable(test_ripemd160 misc/test_ripemd160.c)

target_include_directories(test_sha2 PRIVATE include)
target_include_directories(test_sha3 PRIVATE include)
target_include_directories(test_ripemd160 PRIVATE include)

target_link_libraries(test_sha2 hashing)
target_link_libraries(test_sha3 hashing)
target_link_libraries(test_ripemd160 hashing)

include(GNUInstallDirs)
install(TARGETS hashing
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(hashing.pc.in hashing.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/hashing.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
