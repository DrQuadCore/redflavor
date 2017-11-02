PREFIX ?= /usr/local
DESTLIB ?= $(PREFIX)/lib64
CUDA ?= /usr/local/cuda


CUDA_LIBPATH := -L$(CUDA)/lib64 -L$(CUDA)/lib -L/usr/lib64/nvidia -L/usr/lib/nvidia 
CUDA_LIBS    := -lcudart -lcuda 
LIBS         := -lpthread -ldl $(CUDA_LIBPATH) $(CUDA_LIBS)

CUDA_INC := -I$(CUDA)/include 
#INCS     := -I/usr/src/linux-headers-4.2.0-27/include/ $(CUDA_INC)
#NETWORK_INC := -I$
INCS     := $(CUDA_INC)

CPPFLAGS := $(INCS) 
CFLAGS := -O2 $(CPPFLAGS) $(INCS)
CXX := nvcc
#CXX := g++

SRCS := packet_man.cu
#SRCS := packet_man.cpp
EXES := $(SRCS:.cpp=).out


#all: driver exes
all: exes

exes: $(EXES)

arp.o: arp.c 
eth_out.o: eth_out.c 
packet_man.o: packet_man.cpp common.hpp

packet_man.out: packet_man.o arp.o eth_out.o
	$(CXX) -o $@ $^ $(LIBS)

clean:
	rm -f *.o $(EXES) && \
	$(MAKE) -C mydrv clean

.PHONY: driver clean all exes 
