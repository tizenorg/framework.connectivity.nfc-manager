CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(tests C)

SET(NFC_CLIENT_TEST "nfc-client-test")

include_directories(${CMAKE_SOURCE_DIR}/src/clientlib/include)
include_directories(${CMAKE_SOURCE_DIR}/src/commonlib/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(tests_pkgs REQUIRED glib-2.0)

FOREACH(flag ${tests_pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fpie")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")
ADD_EXECUTABLE(${NFC_CLIENT_TEST}
		main.c
		net_nfc_test_manager.c
		net_nfc_test_tag.c
		net_nfc_test_ndef.c
		net_nfc_test_test.c
		net_nfc_test_p2p.c
		net_nfc_test_transceive.c
		net_nfc_test_handover.c
		net_nfc_test_client.c
		net_nfc_test_jewel.c
		net_nfc_test_tag_mifare.c
		net_nfc_test_tag_felica.c
		net_nfc_test_llcp.c
		net_nfc_test_snep.c
		net_nfc_test_se.c
		)

TARGET_LINK_LIBRARIES(${NFC_CLIENT_TEST} ${tests_pkgs_LD_FLAGS} nfc)
LINK_DIRECTORIES(${CMAKE_BUILD_DIR}/src/clientlib
		${CMAKE_BUILD_DIR}/src/commonlib)
