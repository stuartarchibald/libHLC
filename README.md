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

The `llvm-config` binary is in `build/bin` from above.

```bash
LLVMCONFIG=<path-to-llvm-config-binary> conda build condarecipe
```
