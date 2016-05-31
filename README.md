# Build Instructions

## Build LLVM mainline
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
```
git clone https://github.com/numba/libHLC.git
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RELEASE  -DLLVM_DIR=<path_to_llvm_mainline_from_above>/build/lib/cmake/llvm/
make -j 2
# optionally test the build
ctest -V
```
