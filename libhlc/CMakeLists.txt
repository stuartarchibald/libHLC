#
# Copyright (c) 2016 , Continuum Analytics, Inc.
# All rights reserved.
#

set(LIBHLC_SOURCES hlc.cpp)

add_library(
            HLC
            SHARED
            ${LIBHLC_SOURCES}
            )

# llvm components needed (will get mapped to libs for linking)
# See `llvm-config --components` for a list of available components.
llvm_map_components_to_libnames(
llvm_libs # this name is magic, it is the variable in which the
          # component linker info is stored.
amdgpu
amdgpuasmparser
amdgpucodegen
core
native
objcarcopts
)

#Link against LLVM libraries
target_link_libraries(HLC ${llvm_libs})

# set library properties
set_target_properties(HLC PROPERTIES
                     VERSION   ${libHLC_VERSION}
                     SOVERSION ${libHLC_SOVERSION})
