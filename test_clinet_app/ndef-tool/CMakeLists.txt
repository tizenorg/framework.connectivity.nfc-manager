CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(ndef-tool C)

SET(NDEF_TOOL "ndef-tool")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/commonlib/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/clientlib/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/ TOOL_SRC)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

INCLUDE(FindPkgConfig)
pkg_check_modules(tool_pkgs REQUIRED glib-2.0 gobject-2.0)

FOREACH(flag ${tool_pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# this for NFC flag

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -pipe -fomit-frame-pointer -Wall -Wno-trigraphs -Werror-implicit-function-declaration  -fno-strict-aliasing -Wl,-zdefs -fvisibility=hidden")

SET(ARM_CFLAGS "${ARM_CLAGS} -mapcs -mno-sched-prolog -mabi=aapcs-linux -Uarm -fno-common -fpic")

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

ADD_EXECUTABLE(${NDEF_TOOL} ${TOOL_SRC})

TARGET_LINK_LIBRARIES(${NDEF_TOOL} ${tool_pkgs_LDFLAGS} "-lpthread -lrt -pie -ldl" "-L${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_tmp/src/clientlib -L${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_tmp/src/commonlib" "-lnfc" "-lnfc-common-lib")


INSTALL(TARGETS ${NDEF_TOOL} DESTINATION bin)


