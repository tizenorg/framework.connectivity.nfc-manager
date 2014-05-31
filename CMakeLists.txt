CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

MESSAGE("build nfc-common-lib and nfc-manager")

ADD_SUBDIRECTORY(src/commonlib)
ADD_SUBDIRECTORY(src/clientlib)
ADD_SUBDIRECTORY(src/manager)
ADD_SUBDIRECTORY(test_clinet_app/ndef-tool)

