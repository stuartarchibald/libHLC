CXX=g++
LLVMCONFIG=llvm-config
CXXFLAGS=`$(LLVMCONFIG) --cxxflags` -Wall
LDFLAGS=`$(LLVMCONFIG) --system-libs --ldflags --libs all` -lhsail -lLLVMHSAILUtil

all:
	$(CXX) -g $(CXXFLAGS) -g -shared -o libHLC.so hlc.cpp $(LDFLAGS)
