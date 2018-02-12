PREFIX ?= /usr/local
DESTLIB ?= $(PREFIX)/lib64
CUDA ?= /usr/local/cuda

USE_GPU := 1
CUDA_LIBPATH := -L$(CUDA)/lib64 -L$(CUDA)/lib -L/usr/lib64/nvidia -L/usr/lib/nvidia 
CUDA_LIBS    := -lcudart -lcuda 
LIBS         := -lpthread -ldl $(CUDA_LIBPATH) $(CUDA_LIBS)

CUDA_INC := -I$(CUDA)/include 
#INCS     := -I/usr/src/linux-headers-4.2.0-27/include/ $(CUDA_INC)
#NETWORK_INC := -I$
INCS     := $(CUDA_INC)

ifeq ($(USE_GPU), 1)
CPPFLAGS := $(INCS) -D__USE_GPU__ 
CXX := nvcc
NVCC := nvcc
else
CPPFLAGS := $(INCS) 
CXX := g++
endif

CFLAGS := -O2 $(CPPFLAGS) $(INCS)

ifeq ($(USE_GPU), 1)
SRCS = serving_man.cu packet_man.cu
else
SRCS = packet_man.cpp
endif
#SRCS := packet_man.cpp
#EXES := $(SRCS:.cpp=).out
EXES = $(SRCS:.cu=).out

#all: driver exes
all : serving_man.out packet_man.out

ifeq ($(USE_GPU), 1)
serving_man.out: serving_man.cu arp.o eth_out.o icmp.o
	$(NVCC) -o $@ $^ $(LIBS) $(CPPFLAGS) -arch=compute_30
packet_man.out: packet_man.cu arp.o eth_out.o
	$(NVCC) -o $@ $^ $(LIBS) $(CPPFLAGS) -arch=compute_30
else
serving_man.out: serving_man.cu arp.o eth_out.o icmp.o
	$(CXX) -o $@ $^ $(LIBS) $(CPPFLAGS)
packet_man.out: packet_man.cpp arp.o eth_out.o
	$(CXX) -o $@ $^ $(LIBS) $(CPPFLAGS)
endif

exes: $(EXES)

icmp.o: icmp.cu icmp.cu.h
	$(NVCC) -c icmp.cu -arch=compute_30
#$(NVCC) -dc $@ $^ $(LIBS) $(CPPFLAGS) -arch=compute_30

arp.o: arp.c 
	$(CXX) -dc $@ $^ $(LIBS) $(CPPFLAGS) -arch=compute_30

eth_out.o: eth_out.c 

clean:
	rm -f *.o $(EXES) && \
	$(MAKE) -C mydrv clean

.PHONY: driver clean all exes 
