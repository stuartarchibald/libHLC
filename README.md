# What is libHLC?
`libHLC` is a stand-alone library that provides access to the LLVM toolchain
for targetting AMD dGPUs with Heterogeneous System Architecture (HSA) support.

WARNING: This library is experimental and under development.

# Build Instructions

To build libHLC, LLVM mainline is needed (build instructions below).

## Prerequisites
 * A C++ compiler with C++11 support.
 * CMake 2.8.12+.
 * To test libHLC or use `conda build` valgrind is required.

## Build LLVM mainline
This builds llvm mainline from source, note the inclusion of the `lld` tool,
this is required to patch the binaries produced by libHLC.
```bash
git clone https://github.com/llvm-mirror/llvm.git
cd llvm/tools && git clone http://llvm.org/git/lld.git
cd ..
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="AMDGPU;X86"
make -j 8
```

## Build libHLC
```bash
git clone https://github.com/numba/libHLC.git
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RELEASE  -DLLVM_DIR=<path_to_llvm_mainline_from_above>/build/lib/cmake/llvm/
make
```
Optionally test the build (requires valgrind):
```bash
ctest -V
```

## Conda build
A conda package for libHLC can be built as follows, first build LLVM mainline
as above, then:
```bash
export LLVM_MAINLINE=<path_to_llvm_mainline_from_above>/build
conda build condarecipe
```

