#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <memory.h>
#include <cuda_runtime_api.h>
#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <time.h>
#include <asm/types.h>


#include <linux/ip.h> // YHOON: struct iphdr
//#include <netinet/ip.h> // HONESTCHOI : struct iphdr
#define ETH_ALEN  6 // YHOON
#define ARP_PAD_LEN 18 // YHOON


#include <asm/types.h>
using namespace std;

#include "my_malloc.h"
#include "mydrv/mydrv.h"
#include "common.hpp"


#define OUT cout

enum mycopy_msg_level {
    MYCOPY_MSG_DEBUG = 1,
    MYCOPY_MSG_INFO,
    MYCOPY_MSG_WARN,
    MYCOPY_MSG_ERROR
};

struct my {
  int fd;
};


// YHOON
struct arphdr
{
  uint16_t ar_hrd;      /* hardware address format */
  uint16_t ar_pro;      /* protocol address format */
  uint8_t ar_hln;       /* hardware address length */
  uint8_t ar_pln;       /* protocol address length */
  uint16_t ar_op;       /* arp opcode */

  uint8_t ar_sha[ETH_ALEN]; /* sender hardware address */
  uint32_t ar_sip;      /* sender ip address */
  uint8_t ar_tha[ETH_ALEN]; /* targe hardware address */
  uint32_t ar_tip;      /* target ip address */

  uint8_t pad[ARP_PAD_LEN];
} __attribute__ ((packed));

static int my_msg_level = MYCOPY_MSG_ERROR;
static int my_enable_logging = 1;

static void my_msg(enum mycopy_msg_level lvl, const char* fmt, ...)
{
    if (-1 == my_enable_logging) {
        const char *env = getenv("MYCOPY_ENABLE_LOGGING");
        if (env)
            my_enable_logging = 1;
        else
            my_enable_logging = 0;

        env = getenv("MYCOPY_LOG_LEVEL");
        if (env)
            my_msg_level = atoi(env);
    }
    if (my_enable_logging) {
        if (lvl >= my_msg_level) {
            va_list ap;
            va_start(ap, fmt);
            vfprintf(stderr, fmt, ap);
        }
    }
}

#define my_dbg(FMT, ARGS...)  my_msg(MYCOPY_MSG_DEBUG, "DBG:  " FMT, ## ARGS)
#define my_dbgc(C, FMT, ARGS...)  do { static int my_dbg_cnt=(C); if (my_dbg_cnt) { my_dbg(FMT, ## ARGS); --my_dbg_cnt; }} while (0)
#define my_info(FMT, ARGS...) my_msg(MYCOPY_MSG_INFO,  "INFO: " FMT, ## ARGS)
#define my_warn(FMT, ARGS...) my_msg(MYCOPY_MSG_WARN,  "WARN: " FMT, ## ARGS)
#define my_err(FMT, ARGS...)  my_msg(MYCOPY_MSG_ERROR, "ERR:  " FMT, ## ARGS)


int my_pin_buffer(my_t g, unsigned long addr, size_t size, uint64_t p2p_token, uint32_t va_space, my_mh_t *handle)
{
    int ret = 0;
    int retcode;

    struct MYDRV_IOC_PIN_BUFFER_PARAMS params;
    params.addr = addr;
    params.size = size;
    params.p2p_token = p2p_token;
    params.va_space = va_space;
    params.handle = 0;

    // YHOON~ for test
    const char *myinode = "/dev/ixgbe";
    int fd = open(myinode, O_RDWR);
    uint64_t ptr = 1234;
    retcode = ioctl(fd, 0, &ptr);
    // ~YHOON

    retcode = ioctl(g->fd, MYDRV_IOC_PIN_BUFFER, &params);
    if (0 != retcode) {
        ret = errno;
        my_err("ioctl error (errno=%d)\n", ret);
    }
    *handle = params.handle;

    return ret;
}

my_t my_open()
{
    my_t m = NULL;
    const char *myinode = "/dev/mydrv";

    m = (my_t) calloc(1, sizeof(*m));
    if (!m) {
        //my_err("error while allocating memory\n");
        return NULL;
    }

    int fd = open(myinode, O_RDWR);
    if (-1 == fd ) {
        int ret = errno;
        //my_err("error opening driver (errno=%d/%s)\n", ret, strerror(ret));
        free(m);
        return NULL;
    }

    m->fd = fd;

    return m;
}


#if 0
__global__ void init_data(int size, unsigned char* h_mem, int* d_A)
#else
void init_data(int size, unsigned char* h_mem, int* d_A)
#endif
{
  //printf("[%s][%d]\n", __FUNCTION__, __LINE__);
  for(int i=0; i < size; i++) 
    h_mem[i] = 0;
  cudaMemcpy(d_A, h_mem, size, cudaMemcpyHostToDevice);
}

#if 0
__global__ void check_data(int size, unsigned char* h_mem, int* d_A)
#else
void check_data(int size, unsigned char* h_mem, int* d_A)
#endif
{
  printf("[%s][%d] BEGINS--------------------------------------------------------------------------------\n", __FUNCTION__, __LINE__);
  cudaMemcpy(h_mem, d_A, size, cudaMemcpyDeviceToHost);
#if 0
  for(int outer = 0; outer < size-4095; outer+=4096) {
	if(iter[outer+4095] != 0) {
      int inner = outer;
      while(iter[inner] != 0)
	    printf("%c", iter[inner++]);
	}
  }
#else
  int dirty_cnt = 0;
  const int DUMP_SIZE = 30;
  for(int i = 0; i < size; i++) {
    if((h_mem[i] == 0x08 && h_mem[i+1] == 0x06)) { // || (h_mem[i] == 0x00 && h_mem[i+1] == 0x08) ) {
      i = i+2;
      printf("\n\n\n[%s][%d] PACKET BEGINS-------------------------------------\n", __FUNCTION__, __LINE__);
      printf("[%s][%d] We found ethernet type 0x%02x%02x on %dth memory.\n", __FUNCTION__ , __LINE__, h_mem[i], h_mem[i+1],i);
      
      for(int packet_iter = i-20; packet_iter < (i+20+DUMP_SIZE); packet_iter++) {
        if((packet_iter-i) % 4 == 0)
          printf("\n");
        printf("%3d:0x%02x\t", packet_iter-i, h_mem[packet_iter]);
      }
      printf("\n");
      //struct iphdr* iph = reinterpret_cast<iphdr*>(h_mem+i+2);
      struct arphdr *arph = reinterpret_cast<arphdr*>(h_mem+i);
      //struct iphdr* iph = (struct iphdr *)(h_mem+i+2);
      //printf("[%s][%d] pid:[%x], protocol:[%x]\n", __FUNCTION__, __LINE__, iph->id, iph->protocol);
      //uint8_t *t = (uint8_t *)&iph->saddr;
      uint8_t *saddr = (uint8_t *)&arph->ar_sip;
      uint8_t *daddr = (uint8_t *)&arph->ar_tip;
      //printf("[%s][%d] src ip %u.%u.%u.%u\n", __FUNCTION__ ,__LINE__, t[0], t[1], t[2], t[3]);
      //printf("[%s][%d] src ip %x.%x.%x.%x\n", __FUNCTION__ ,__LINE__, t[0], t[1], t[2], t[3]);
      printf("[%s][%d] src ip %u.%u.%u.%u\n", __FUNCTION__ ,__LINE__, saddr[0], saddr[1], saddr[2], saddr[3]);
      printf("[%s][%d] dst ip %u.%u.%u.%u\n", __FUNCTION__ ,__LINE__, daddr[0], daddr[1], daddr[2], daddr[3]);
      //t = (uint8_t *)&iph->daddr;
      //printf("[%s][%d] dst ip %u.%u.%u.%u\n", __FUNCTION__ ,__LINE__, t[0], t[1], t[2], t[3]);
    }
  }
  for(int i = 0; i < size; i++) 
    if(h_mem[i] != 0) 
      dirty_cnt++;
#endif
  printf("[%s][%d] dirty_cnt:[%d]\n", __FUNCTION__ , __LINE__, dirty_cnt);
  printf("[%s][%d] ENDS\n", __FUNCTION__, __LINE__);
}


int main(int argc, char *argv[])
{
  printf("[%s][%d] 2\n", __FUNCTION__, __LINE__);
  int dev_id = 0;
  size_t _size = 50*1024*1024; //50*1024*1024;

  size_t size = (_size + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;

  int n_devices = 0;

  unsigned char* h_mem = (unsigned char*)malloc(size*sizeof(unsigned char)); 

  cudaGetDeviceCount(&n_devices);

  cudaDeviceProp prop;
  for (int n=0; n<n_devices; ++n) {
    cudaGetDeviceProperties(&prop,n);
    OUT << "GPU id:" << n << " name:" << prop.name 
      << " PCI domain: " << prop.pciDomainID 
      << " bus: " << prop.pciBusID 
      << " device: " << prop.pciDeviceID << endl;
  }
  OUT << "selecting device " << dev_id << endl;
  OUT << "_size: " << _size << "  size: " << size << endl;

  ASSERTRT(cudaSetDevice(dev_id));

  // Test
  void* dummy;
  ASSERTRT(cudaMalloc(&dummy, 0));

  int* d_A;
  ASSERTRT(cudaMalloc((void**)&d_A, size));
  OUT << "device ptr: " << hex << d_A << dec << endl;
  
  unsigned int flag = 1;
  ASSERTDRV(cuPointerSetAttribute(&flag, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr) d_A));

  my_t g = my_open();

  ASSERT_NEQ(g, (void*)0);

  my_mh_t mh;
  if (my_pin_buffer(g, (CUdeviceptr)d_A, size, 0, 0, &mh)  != 0)
    OUT << "NOT_EQ" << endl;

  //cudaMemcpy(&h_tmp, (int *)d_A, sizeof(int), cudaMemcpyDeviceToHost);
  //OUT << "after pinning: " << h_tmp << endl;

#if 0
  init_data<<< 1, 1 >>>(size, h_mem, d_A);
#else
  init_data(size, h_mem, d_A);
#endif
  
  int count = 0;
  while(count < 1000) {
#if 0
    check_data<<< 1,1 >>>(size, h_mem, d_A);
#else
    check_data(size, h_mem, d_A);
#endif 
    usleep(1*1000*1000);
    count++;
  }
  OUT << "END" << endl;
  cudaFree(d_A);

  return 0;
}
