CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#PROJECT(nfc C)
PROJECT(nfc-client-lib C)

#SET(NFC_CLIENT_LIB "nfc-client-lib")
SET(NFC_CLIENT_LIB "nfc")
SET(VERSION_MAJOR 1)
SET(VERSION ${VERSION_MAJOR}.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../commonlib/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../manager/include)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} CLIENT_SRCS)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

INCLUDE(FindPkgConfig)
pkg_check_modules(clientlib_pkges REQUIRED security-server dbus-glib-1 dlog ecore vconf)

FOREACH(flag ${clientlib_pkges_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

MESSAGE("CHECK MODULE in MANAGER ${clientlib_pkges_LDFLAGS}")

# this for NFC flag

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -pipe -fomit-frame-pointer -Wall -Wno-trigraphs -Werror-implicit-function-declaration  -fno-strict-aliasing -Wl,-zdefs -fvisibility=hidden")

SET(ARM_CFLAGS "${ARM_CLAGS} -mapcs -mno-sched-prolog -mabi=aapcs-linux -Uarm -fno-common -fpic")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror-implicit-function-declaration")

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
#ADD_DEFINITIONS("-DSLP_DEBUG")

ADD_DEFINITIONS("-DNFC_FIRMWARE_UPDATE")
ADD_DEFINITIONS("-DNFC_DEBUG_USE_DLOG -D_GNU_SOURCE")
ADD_DEFINITIONS("-DUSE_UNIX_DOMAIN")
ADD_DEFINITIONS("-DUSE_IPC_EPOLL -DUSE_EPOLL_TIMEOUT")
ADD_DEFINITIONS("-DLLCP_MODE")
ADD_DEFINITIONS("-DNFC_APP_SUPPORTED")
ADD_DEFINITIONS("-DSAVE_TARGET_INFO_IN_CC")
#ADD_DEFINITIONS("-DSECURITY_SERVER")
#ADD_DEFINITIONS("-DG_MAIN_LOOP")
#ADD_DEFINITIONS("-DUSE_ECORE_MAIN_LOOP")
ADD_DEFINITIONS("-DUSE_GLIB_MAIN_LOOP")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_LIBRARY(${NFC_CLIENT_LIB} SHARED ${CLIENT_SRCS})
SET_TARGET_PROPERTIES(${NFC_CLIENT_LIB} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${NFC_CLIENT_LIB} PROPERTIES VERSION ${VERSION})
TARGET_LINK_LIBRARIES(${NFC_CLIENT_LIB} ${clientlib_pkges_LDFLAGS} "-L${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_tmp/src/commonlib/" "-lnfc-common-lib")

SET(CLIENT_HEADER
	../commonlib/include/net_nfc_typedef.h
	include/net_nfc.h
	include/net_nfc_target_info.h
	include/net_nfc_tag.h
	include/net_nfc_tag_jewel.h
	include/net_nfc_tag_mifare.h
	include/net_nfc_tag_felica.h
	include/net_nfc_llcp.h
	include/net_nfc_ndef_record.h
	include/net_nfc_ndef_message.h
	include/net_nfc_ndef_message_handover.h
	include/net_nfc_sign_record.h
	include/net_nfc_data.h
	include/net_nfc_exchanger.h
	include/net_nfc_internal_se.h
	include/net_nfc_test.h
	../manager/include/nfc-service-glue.h
	../manager/include/net_nfc_manager_dbus.h
)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/nfc.pc.in ${CMAKE_CURRENT_SOURCE_DIR}/nfc.pc)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/nfc.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)

INSTALL(TARGETS ${NFC_CLIENT_LIB} DESTINATION ${LIB_INSTALL_DIR})

FOREACH(hfile ${CLIENT_HEADER})
        INSTALL(FILES ${hfile} DESTINATION include/nfc)
ENDFOREACH(hfile)

