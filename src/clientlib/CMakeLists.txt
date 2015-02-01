CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(nfc-client-lib C)

#SET(NFC_CLIENT_LIB "nfc-client-lib")
SET(NFC_CLIENT_LIB "nfc")
SET(VERSION_MAJOR 1)
SET(VERSION ${VERSION_MAJOR}.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src/commonlib)
include_directories(${CMAKE_SOURCE_DIR}/src/commonlib/include)
include_directories(${CMAKE_SOURCE_DIR}/src/manager/include)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} CLIENT_SRCS)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

INCLUDE(FindPkgConfig)
pkg_check_modules(clientlib_pkges REQUIRED security-server dlog ecore-x vconf)

FOREACH(flag ${clientlib_pkges_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

MESSAGE("CHECK MODULE in MANAGER ${clientlib_pkges_LDFLAGS}")

# this for NFC flag

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -pipe -fomit-frame-pointer -Wall -Wno-trigraphs -Werror-implicit-function-declaration  -fno-strict-aliasing -Wl,-zdefs -fvisibility=hidden")

SET(ARM_CFLAGS "${ARM_CLAGS} -mapcs -mno-sched-prolog -mabi=aapcs-linux -Uarm -fno-common -fpic")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror-implicit-function-declaration -Wl,-z,nodelete")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

FIND_PROGRAM(UNAME NAMES uname)
EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" MATCHES "^arm.*")
	ADD_DEFINITIONS("-DTARGET")
	MESSAGE("add -DTARGET")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARM_CFLAGS}")
ENDIF()

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_LIBRARY(${NFC_CLIENT_LIB} SHARED ${CLIENT_SRCS})
SET_TARGET_PROPERTIES(${NFC_CLIENT_LIB} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${NFC_CLIENT_LIB} PROPERTIES VERSION ${VERSION})
TARGET_LINK_LIBRARIES(${NFC_CLIENT_LIB} ${clientlib_pkges_LDFLAGS} nfc-common-lib)

LINK_DIRECTORIES(${CMAKE_BUILD_DIR}/src/commonlib)


SET(CLIENT_HEADER
	${CMAKE_SOURCE_DIR}/src/commonlib/include/net_nfc_typedef.h
	include/net_nfc.h
	include/net_nfc_data.h
	include/net_nfc_target_info.h
	include/net_nfc_ndef_message.h
	include/net_nfc_ndef_record.h
	include/net_nfc_sign_record.h
	include/net_nfc_ndef_message_handover.h
	include/net_nfc_client_context.h
	include/net_nfc_client_manager.h
	include/net_nfc_client_system_handler.h
	include/net_nfc_client_transceive.h
	include/net_nfc_client_tag.h
	include/net_nfc_client_ndef.h
	include/net_nfc_client_llcp.h
	include/net_nfc_client_p2p.h
	include/net_nfc_client_snep.h
	include/net_nfc_client_handover.h
	include/net_nfc_client_se.h
	include/net_nfc_client_tag_felica.h
	include/net_nfc_client_tag_jewel.h
	include/net_nfc_tag_mifare.h
	include/net_nfc_client_test.h
)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/nfc.pc.in ${CMAKE_CURRENT_SOURCE_DIR}/nfc.pc)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/nfc.pc DESTINATION lib/pkgconfig)

INSTALL(TARGETS ${NFC_CLIENT_LIB} DESTINATION lib)

FOREACH(hfile ${CLIENT_HEADER})
		INSTALL(FILES ${hfile} DESTINATION include/nfc)
ENDFOREACH(hfile)
