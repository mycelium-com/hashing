cmake_minimum_required(VERSION 3.9)
project(hashing VERSION 1.0.0 DESCRIPTION "Hash functions library")

include(GNUInstallDirs)

set(hashing_src
        src/ripemd160.c
        src/sha2.c
        src/sha3.c
        src/hmac_sha2.c
        src/hmac_sha3.c
        )

if (NOT TARGET hashing)
    add_library(hashing ${hashing_src})
    target_include_directories(hashing PRIVATE include)

    set_target_properties(hashing PROPERTIES
            VERSION ${PROJECT_VERSION}
            POSITION_INDEPENDENT_CODE 1
            PUBLIC_HEADER "include/hmac_sha2.h;include/hmac_sha3.h;include/ripemd160.h;include/sha2.h;include/sha3.h"
            )

    install(TARGETS hashing
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()


if(NOT TARGET test_sha2)
    add_executable(test_sha2 misc/test_sha2.c)
    target_include_directories(test_sha2 PRIVATE include)
    target_link_libraries(test_sha2 hashing)
endif()

if(NOT TARGET test_sha3)
    add_executable(test_sha3 misc/test_sha3.c)
    target_include_directories(test_sha3 PRIVATE include)
    target_link_libraries(test_sha3 hashing)
endif()

if(NOT TARGET test_ripemd160)
    add_executable(test_ripemd160 misc/test_ripemd160.c)
    target_include_directories(test_ripemd160 PRIVATE include)
    target_link_libraries(test_ripemd160 hashing)
endif()

if(NOT TARGET test_sha2_hmac)
    add_executable(test_sha2_hmac misc/test_sha2_hmac.c)
    target_include_directories(test_sha2_hmac PRIVATE include)
    target_link_libraries(test_sha2_hmac hashing)
endif()

if(NOT TARGET test_sha3_hmac)
    add_executable(test_sha3_hmac misc/test_sha3_hmac.c)
    target_include_directories(test_sha3_hmac PRIVATE include)
    target_link_libraries(test_sha3_hmac hashing)
endif()

configure_file(hashing.pc.in hashing.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/hashing.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
