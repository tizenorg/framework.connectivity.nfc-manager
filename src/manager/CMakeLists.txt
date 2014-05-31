CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#PROJECT(nfc C)
PROJECT(nfc-manager-daemon C)

SET(NFC_MANAGER_DAEMON "nfc-manager-daemon")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../commonlib/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/ MANAGER_SRCS)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

INCLUDE(FindPkgConfig)
pkg_check_modules(manager_pkges REQUIRED aul glib-2.0 gobject-2.0 security-server dbus-glib-1 vconf dlog tapi appsvc libcurl bluetooth-api heynoti smartcard-service smartcard-service-common libssl pmapi svi capi-media-wav-player pkgmgr pkgmgr-info ecore-x)

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

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
#ADD_DEFINITIONS("-DSLP_DEBUG")
ADD_DEFINITIONS("-DCLIENT_IPC_THREAD")

ADD_DEFINITIONS("-DNFC_FIRMWARE_UPDATE")
ADD_DEFINITIONS("-DNFC_DEBUG_USE_DLOG -D_GNU_SOURCE")
ADD_DEFINITIONS("-DUSE_UNIX_DOMAIN")
ADD_DEFINITIONS("-DUSE_IPC_EPOLL -DUSE_EPOLL_TIMEOUT")
ADD_DEFINITIONS("-DLLCP_MODE")
ADD_DEFINITIONS("-DNFC_APP_SUPPORTED")
ADD_DEFINITIONS("-DBROADCAST_MESSAGE")
ADD_DEFINITIONS("-DSAVE_TARGET_INFO_IN_CC")
#ADD_DEFINITIONS("-DSECURITY_SERVER")
#ADD_DEFINITIONS("-DG_MAIN_LOOP")
#ADD_DEFINITIONS("-DUSE_ECORE_MAIN_LOOP")
ADD_DEFINITIONS("-DUSE_GLIB_MAIN_LOOP")
ADD_DEFINITIONS("-DUSE_FULL_URI")
# add temporary
ADD_DEFINITIONS("-D_TIZEN_OPEN")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")
FIND_PROGRAM(DBUS_BINDING_TOOL NAMES dbus-binding-tool)
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=nfc_service ${CMAKE_CURRENT_SOURCE_DIR}/nfc-service.xml --mode=glib-client --output=${CMAKE_CURRENT_SOURCE_DIR}/include/nfc-service-glue.h")
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=nfc_service ${CMAKE_CURRENT_SOURCE_DIR}/nfc-service.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/include/nfc-service-binding.h")

ADD_EXECUTABLE(${NFC_MANAGER_DAEMON} ${MANAGER_SRCS})


TARGET_LINK_LIBRARIES(${NFC_MANAGER_DAEMON} ${manager_pkges_LDFLAGS} "-lpthread -lrt -pie -ldl -L${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_tmp/src/commonlib/ -lnfc-common-lib -L${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_tmp/src/clientlib/ -lnfc")

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.tizen.nfc_service.service DESTINATION share/dbus-1/services)
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/sounds DESTINATION /usr/share/nfc-manager-daemon)
INSTALL(TARGETS ${NFC_MANAGER_DAEMON} DESTINATION bin)


