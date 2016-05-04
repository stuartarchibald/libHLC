CXX=g++
CXXFLAGS=`$(LLVMCONFIG) --cxxflags --system-libs` -Wall -std=c++11 -O0
LDFLAGS=`$(LLVMCONFIG) --ldflags --system-libs --libs all`

all:
	$(CXX) -g $(CXXFLAGS) -g -shared -o libHLC.so hlc.cpp $(LDFLAGS)
