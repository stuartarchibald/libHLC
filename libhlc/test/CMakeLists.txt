#
# Copyright (c) 2016 , Continuum Analytics, Inc.
# All rights reserved.
#

add_executable(test_hlc test_hlc.cpp)

# set link dir
link_directories(${libhlc_BINARY_DIR})

# include include/
target_include_directories(test_hlc PUBLIC ${CMAKE_SOURCE_DIR}/include ${BIN_INCLUDE_DIR})

# set linkage
target_link_libraries(test_hlc
                     HLC
                     gtest
                     gtest_main
                     pthread
                     )

get_target_property(TEST_LOC test_hlc LOCATION)
add_test(test_hlc ${TEST_LOC})
