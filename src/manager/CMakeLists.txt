CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#PROJECT(nfc C)
PROJECT(nfc-manager-daemon C)

SET(NFC_MANAGER_DAEMON "nfc-manager-daemon")

include_directories(${CMAKE_SOURCE_DIR}/src/commonlib/)
include_directories(${CMAKE_SOURCE_DIR}/src/commonlib/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/addons/include)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/ MANAGER_SRCS)
AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/addons MANAGER_SRCS)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

IF (TIZEN_TELEPHONY_ENABLED)
	MESSAGE("-DENABLE_TELEPHONY")
	ADD_DEFINITIONS(-DENABLE_TELEPHONY)
ENDIF (TIZEN_TELEPHONY_ENABLED)

INCLUDE(FindPkgConfig)
pkg_check_modules(manager_pkges REQUIRED aul glib-2.0 gio-unix-2.0 security-server vconf dlog tapi appsvc libcurl bluetooth-api capi-network-bluetooth openssl deviced feedback capi-media-wav-player ecore-x mm-keysound syspopup-caller notification capi-network-wifi capi-network-wifi-direct capi-system-info sqlite3)

FOREACH(flag ${manager_pkges_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

MESSAGE("CHECK MODULE in MANAGER ${manager_pkges_LDFLAGS}")

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

# for addons
#ADD_DEFINITIONS("-DADDON_HCE_NDEF")
#ADD_DEFINITIONS("-DADDON_HCE_PPSE")

ADD_DEFINITIONS("-DPREFIX=\"${PREFIX}\"")
ADD_DEFINITIONS("-DNFC_MANAGER_MODULEDIR=\"${MODULEDIR}\"")

ADD_DEFINITIONS("-DUSE_FULL_URI")
#ADD_DEFINITIONS("-DESE_ALWAYS_ON")
#ADD_DEFINITIONS("-DEMERGENCY_MODE")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")

ADD_EXECUTABLE(${NFC_MANAGER_DAEMON} ${MANAGER_SRCS})

TARGET_LINK_LIBRARIES(${NFC_MANAGER_DAEMON} ${manager_pkges_LDFLAGS} pthread dl rt nfc-common-lib nfc)
LINK_DIRECTORIES(${CMAKE_BUILD_DIR}/src/commonlib ${CMAKE_BUILD_DIR}/src/clientlib)
INSTALL(TARGETS ${NFC_MANAGER_DAEMON} DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.tizen.NetNfcService.service DESTINATION share/dbus-1/services)
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/sounds DESTINATION share/nfc-manager-daemon)
