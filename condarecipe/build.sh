#!/bin/bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RELEASE -DLLVM_DIR=${LLVM_MAINLINE}/lib/cmake/llvm/
make
mkdir ${PREFIX}/lib
cp "libhlc/libHLC.so" "${PREFIX}/lib"
cp "libhlc/test/builtins-hsail.opt.bc" "${PREFIX}/lib"
cp "libhlc/test/hsail-amdgpu-wrapper.ll" "${PREFIX}/lib"
ctest -V
