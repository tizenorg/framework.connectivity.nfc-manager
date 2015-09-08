CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET (this_target hce_plugin)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/cmake_build_tmp/output)
include_directories(${CMAKE_SOURCE_DIR}/src/commonlib/include)
include_directories(${CMAKE_SOURCE_DIR}/src/clientlib/include)
#include_directories(${CMAKE_SOURCE_DIR}/src/clientlib)

#INCLUDE(FindPkgConfig)
#pkg_check_modules(pkg REQUIRED glib-2.0 dlog libxml-2.0)
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED
		glib-2.0
		pkgmgr-info
		libxml-2.0
		dlog
)

FOREACH(flag ${pkgs_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET (${this_target}_SOURCE_FILES
    pkgmgr_plugin_hce.c
    )

ADD_DEFINITIONS("-DDLOG_ERROR_ENABLED")
ADD_DEFINITIONS("-DLOG_TAG=\"HCE_PLUGIN\"")
SET(EXTRA_CFLAGS  "${EXTRA_CFLAGS} -Wall" )

SET(CMAKE_C_FLAGS_PROFILING    " -g -pg")
SET(CMAKE_CXX_FLAGS_PROFILING  " -std=c++0x -g -pg")
SET(CMAKE_C_FLAGS_DEBUG        " -g")
SET(CMAKE_CXX_FLAGS_DEBUG      " -std=c++0x -g")
SET(CMAKE_C_FLAGS_RELEASE      " -g")
SET(CMAKE_CXX_FLAGS_RELEASE    " -std=c++0x -g")
SET(CMAKE_C_FLAGS_CCOV         " -g --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       " -std=c++0x -g --coverage")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -std=gnu99")

## Create Library
ADD_LIBRARY (${this_target} SHARED ${${this_target}_SOURCE_FILES} )
## SET LINKER FLAGS
#SET(CMAKE_SHARED_LINKER_FLAGS -Wl,--no-undefined)

TARGET_LINK_LIBRARIES(${this_target} ${pkg_LDFLAGS} nfc)

INSTALL(TARGETS ${this_target} DESTINATION "/usr/etc/package-manager/parserlib/metadata")

