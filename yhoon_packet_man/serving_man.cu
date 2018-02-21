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

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "icmp.cu.h"
#include "arp.h" 

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/in6.h>
#define ETH_ALEN  6 // YHOON
#define ARP_PAD_LEN 18 // YHOON
#define IP_HEADER_LEN 20

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif


#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
	((((unsigned long)(n) & 0xFF00)) << 8) | \
	((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
	((((unsigned long)(n) & 0xFF00)) << 8) | \
	((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		  ((((unsigned long)(n) & 0xFF000000)) >> 24))


#define cudaCheckErrors(msg) do { cudaError_t __err = cudaGetLastError(); if (__err != cudaSuccess) { \
			fprintf(stderr, "Fatal error: %s (%s at %s:%d)\n", \
					msg, cudaGetErrorString(__err), \
					__FILE__, __LINE__); \
				fprintf(stderr, "*** FAILED - ABORTING\n"); \
				exit(1); \
		} \
	} while (0)

#include <asm/types.h>
using namespace std;

#include "packet_man.h"
#include "mydrv/mydrv.h"
#include "common.hpp"


#define OUT cout


enum mycopy_msg_level {
    MYCOPY_MSG_DEBUG = 1,
    MYCOPY_MSG_INFO,
    MYCOPY_MSG_WARN,
    MYCOPY_MSG_ERROR
};

#define IXGBE_TDT(_i)   (0x06018 + ((_i) * 0x40))

//#define __USE_PKT_MONITOR__
#define NUM_PACKETS 500
#define THREADS_PER_TB 512 

#define RX_TB 0
#define PP_TB 1
#define TX_TB 2

struct my {
  int fd;
};

/*----------------------------------------------------------------------------*/
enum arp_hrd_format
{
	arp_hrd_ethernet = 1
};
/*----------------------------------------------------------------------------*/
enum arp_opcode
{
	arp_op_request = 1, 
	arp_op_reply = 2, 
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

#define DBGMSG 1

__device__ uint32_t d_curr_of_processing_queue = 0;
__device__ uint32_t d_processing_queue_size = 8 * 512;

void h_DumpARPPacket(struct arphdr *arph)
{
	uint8_t *t;

	printf("ARP header: \n");
	printf("Hardware type: %d (len: %d), "
			"protocol type: %d (len: %d), opcode: %d\n", 
			//ntohs(arph->ar_hrd), arph->ar_hln, 
			NTOHS(arph->ar_hrd), arph->ar_hln, 
			//ntohs(arph->ar_pro), arph->ar_pln, ntohs(arph->ar_op));
			NTOHS(arph->ar_pro), arph->ar_pln, NTOHS(arph->ar_op));
	t = (uint8_t *)&arph->ar_sip;
	printf("Sender IP: %u.%u.%u.%u, "
			"haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
			t[0], t[1], t[2], t[3], 
			arph->ar_sha[0], arph->ar_sha[1], arph->ar_sha[2], 
			arph->ar_sha[3], arph->ar_sha[4], arph->ar_sha[5]);
	t = (uint8_t *)&arph->ar_tip;
	printf("Target IP: %u.%u.%u.%u, "
			"haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
			t[0], t[1], t[2], t[3], 
			arph->ar_tha[0], arph->ar_tha[1], arph->ar_tha[2], 
			arph->ar_tha[3], arph->ar_tha[4], arph->ar_tha[5]);
}

__device__ void DumpARPPacket(struct arphdr *arph)
//void DumpARPPacket(struct arphdr *arph)
{
	uint8_t *t;

	printf("ARP header: \n");
	printf("Hardware type: %d (len: %d), "
			"protocol type: %d (len: %d), opcode: %d\n", 
			//ntohs(arph->ar_hrd), arph->ar_hln, 
			NTOHS(arph->ar_hrd), arph->ar_hln, 
			//ntohs(arph->ar_pro), arph->ar_pln, ntohs(arph->ar_op));
			NTOHS(arph->ar_pro), arph->ar_pln, NTOHS(arph->ar_op));
	t = (uint8_t *)&arph->ar_sip;
	printf("Sender IP: %u.%u.%u.%u, "
			"haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
			t[0], t[1], t[2], t[3], 
			arph->ar_sha[0], arph->ar_sha[1], arph->ar_sha[2], 
			arph->ar_sha[3], arph->ar_sha[4], arph->ar_sha[5]);
	t = (uint8_t *)&arph->ar_tip;
	printf("Target IP: %u.%u.%u.%u, "
			"haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
			t[0], t[1], t[2], t[3], 
			arph->ar_tha[0], arph->ar_tha[1], arph->ar_tha[2], 
			arph->ar_tha[3], arph->ar_tha[4], arph->ar_tha[5]);
}


__device__ uint8_t * EthernetOutput(uint8_t *buf, uint16_t h_proto, unsigned char* src_haddr, unsigned char* dst_haddr, uint16_t iplen)
{
	struct ethhdr *ethh;
	int i;

	ethh = (struct ethhdr *)buf;

#if 0
	printf("dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				dst_haddr[0], dst_haddr[1], 
				dst_haddr[2], dst_haddr[3], 
				dst_haddr[4], dst_haddr[5]);
	printf("src_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				src_haddr[0], src_haddr[1], 
				src_haddr[2], src_haddr[3], 
				src_haddr[4], src_haddr[5]);
#endif

	for (i = 0; i < ETH_ALEN; i++) {
		ethh->h_source[i] = src_haddr[i];
		ethh->h_dest[i] = dst_haddr[i];
	}
	ethh->h_proto = HTONS(h_proto);

	return (uint8_t *)(ethh + 1);
}

__device__ void DumpPacket(uint8_t *buf, int len)
//void DumpPacket(uint8_t *buf, int len)
{
  printf("<<<DumpPacket>>>----------------------------------------------------------------\n");
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct udphdr *udph;
	//struct tcphdr *tcph;
	uint8_t *t;

	ethh = (struct ethhdr *)buf;
	//if (ntohs(ethh->h_proto) != ETH_P_IP) {
	if (NTOHS(ethh->h_proto) != ETH_P_IP) {
		printf("%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
				ethh->h_source[0],
				ethh->h_source[1],
				ethh->h_source[2],
				ethh->h_source[3],
				ethh->h_source[4],
				ethh->h_source[5],
				ethh->h_dest[0],
				ethh->h_dest[1],
				ethh->h_dest[2],
				ethh->h_dest[3],
				ethh->h_dest[4],
				ethh->h_dest[5]);

		//printf("protocol %04hx  \n", ntohs(ethh->h_proto));
		printf("protocol %04hx  \n", NTOHS(ethh->h_proto));

    //if(ntohs(ethh->h_proto) == ETH_P_ARP)
    if(NTOHS(ethh->h_proto) == ETH_P_ARP)
      DumpARPPacket((struct arphdr *) (ethh + 1));
		goto done;
	}

	iph = (struct iphdr *)(ethh + 1);
	udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
	//tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);

	t = (uint8_t *)&iph->saddr;
	printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
		//printf("(%d)", ntohs(udph->source));
		printf("(%d)", NTOHS(udph->source));

	printf(" -> ");

	t = (uint8_t *)&iph->daddr;
	printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
		//printf("(%d)", ntohs(udph->dest));
		printf("(%d)", NTOHS(udph->dest));

	//printf(" IP_ID=%d", ntohs(iph->id));
	printf(" IP_ID=%d", NTOHS(iph->id));
	printf(" TTL=%d ", iph->ttl);

	switch (iph->protocol) {
	case IPPROTO_TCP:
		printf("TCP ");
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		break;
	default:
		printf("protocol %d ", iph->protocol);
		goto done;
	}
done:
	printf("len=%d\n", len);
  printf("<<<DumpPacket>>>-----------------------------------END--------------------------\n");

}


__device__ static int ARPOutput(uint8_t * d_tx_pkt_buffer, int opcode, uint32_t src_ip, uint32_t dst_ip, unsigned char *dst_haddr)
{
	if (!dst_haddr)
		return -1;

  //printf("\n\n\n[%s][%d] Enters\n", __FUNCTION__, __LINE__);
  // ckjung: 00:1b:21:bc:11:52
  uint8_t src_haddr[ETH_ALEN] = {0x00, 0x1b, 0x21, 0xbc, 0x11, 0x52};
	struct arphdr *arph = 
    (struct arphdr *)(uintptr_t)EthernetOutput(d_tx_pkt_buffer, ETH_P_ARP, src_haddr, dst_haddr, sizeof(struct arphdr));

	if (!arph) {
    printf("ERROR\n");
		return -1;
	}
	/* Fill arp header */
	arph->ar_hrd = HTONS(arp_hrd_ethernet);
	arph->ar_pro = HTONS(ETH_P_IP);
	arph->ar_hln = ETH_ALEN;
	arph->ar_pln = 4;
	arph->ar_op = HTONS(opcode);

	/* Fill arp body */
#if 0 // HONESTCHOI : TODO
	arph->ar_sip = CONFIG.eths[nif].ip_addr;
#endif 
	arph->ar_sip = src_ip;
	arph->ar_tip = dst_ip;

#if 0 // HONESTCHOI : TODO
	memcpy(arph->ar_sha, CONFIG.eths[nif].haddr, arph->ar_hln);
	if (target_haddr) {
		memcpy(arph->ar_tha, target_haddr, arph->ar_hln);
	} else {
		memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
	}
#endif
  for(int i=0; i<arph->ar_hln; i++) {
    arph->ar_sha[i] = src_haddr[i];
    arph->ar_tha[i] = dst_haddr[i];
  }
	//memcpy(arph->ar_sha, src_haddr, arph->ar_hln);
  //memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
	memset(arph->pad, 0, ARP_PAD_LEN);

#if 0
	DumpARPPacket(arph);
#endif

	return 0;
}

__device__ uint32_t offset_for_rx = 512 * 0x1000;
__device__ static volatile uint8_t *tx_tail_for_queue_zero;

__device__ static int ProcessARPRequest(struct arphdr *arph, uint8_t* d_tx_pkt_buffer)
{
  //printf("[%s][%d] Enters", __FUNCTION__, __LINE__);
	ARPOutput(d_tx_pkt_buffer, arp_op_reply, arph->ar_tip, arph->ar_sip, arph->ar_sha);
  return 0;
}

// TODO
__device__ static int ProcessARPReply(struct arphdr *arph)
{
  DumpARPPacket(arph);
	//unsigned char *temp;
	return 0;
}

__device__ int ProcessARPPacket(unsigned char* d_tx_pkt_buffer, unsigned char *pkt_data, int len)
{
	struct arphdr *arph = (struct arphdr *)(pkt_data + sizeof(struct ethhdr));

  switch (NTOHS(arph->ar_op)) {
    case arp_op_request:
      //printf("[%s][%d] arp_op_request\n", __FUNCTION__, __LINE__);
      ProcessARPRequest(arph, d_tx_pkt_buffer);
      break;

    case arp_op_reply:
      //printf("[%s][%d] arp_op_reply\n", __FUNCTION__, __LINE__);
      // TODO
      ProcessARPReply(arph);
      break;

    default:
      printf("[%s][%d] ERROR. KNOWN OP CODE (%d)\n", __FUNCTION__, __LINE__, NTOHS(arph->ar_op));
      DumpPacket(pkt_data, 1500);
      break;
  }

  return 1;
}
uint8_t * h_EthernetOutput(uint8_t *buf, uint16_t h_proto, unsigned char* src_haddr, unsigned char* dst_haddr, uint16_t iplen)
{
	struct ethhdr *ethh;
	int i;

	ethh = (struct ethhdr *)buf;

#if 1
	printf("dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				dst_haddr[0], dst_haddr[1], 
				dst_haddr[2], dst_haddr[3], 
				dst_haddr[4], dst_haddr[5]);
	printf("src_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				src_haddr[0], src_haddr[1], 
				src_haddr[2], src_haddr[3], 
				src_haddr[4], src_haddr[5]);
#endif

	for (i = 0; i < ETH_ALEN; i++) {
		ethh->h_source[i] = src_haddr[i];
		ethh->h_dest[i] = dst_haddr[i];
	}
	ethh->h_proto = HTONS(h_proto);

	return (uint8_t *)(ethh + 1);
}

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
    //params.buf_name = bname;

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
    //const char *myinode = "/dev/mydrv";
    const char *myinode = "/dev/ixgbe";

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
static inline uint32_t myrand(uint64_t *seed) 
{
	*seed = *seed * 1103515245 + 12345;
	return (uint32_t)(*seed >> 32);
}
#endif

int curr_num;
__device__ void d_check_data(int size, volatile int* d_pkt_buffer, volatile int* flag)
{
  printf("[%s][%d] \n", __FUNCTION__ , __LINE__);
  volatile unsigned char * d_mem = (volatile unsigned char*)d_pkt_buffer;
  d_mem += offset_for_rx;

  int pkt_cnt = 0;
  //const int DUMP_SIZE = 30;
  //__threadfence_system();
  //printf("[%s][%d] before waiting %d\n", __FUNCTION__ , __LINE__, *flag);
  //WAIT_ON_MEM_NE(d_mem[2093068], 0);
  //WAIT_ON_MEM(*flag, 1);
  //printf("[%s][%d] after waiting %d\n", __FUNCTION__ , __LINE__, *flag);

#if 1
  while(pkt_cnt < 30000) {
    //printf("[%s][%d] BEFORE WAIT_ON_MEM %d\n", __FUNCTION__ , __LINE__, threadIdx.x);
    int head_index = 12 + 0x1000*threadIdx.x; // + 0x1000*(THREADS_PER_TB * pkt_cnt);
    //WAIT_ON_MEM_NE(d_mem[head_index], 0);
    pkt_cnt++;
    if(*((uint16_t*)&d_mem[head_index]) == 0x0608 || *((uint16_t*)&d_mem[head_index]) == 0x0806 ) {
      printf("[%s][%d] Ethernet type 0x%02x%02x on %dth memory. (threadIdx.x:%d %dpkts)\n", __FUNCTION__ , __LINE__, d_mem[head_index], d_mem[head_index+1], head_index, threadIdx.x, pkt_cnt);
      *((uint16_t*)&d_mem[head_index]) = 0;     
    }
  }
#endif

}

#if 0
__device__ void wait_for_something(volatile int * something_finished)
{
  BEGIN_SINGLE_THREAD_PART {
    while(!*something_finished) {
    }
  }
}
#endif

__device__ unsigned long tail_val;
__device__ volatile int server_done;
#define NUM_TB 1 
#define NUM_THREADS 512 

__global__ void clean_buffer(unsigned char* buffer, unsigned char* buffer2, int size, char* bm_worked_thread, int* tb_status_table) 
{
  for(int i=0; i<size; i++) {
    buffer[i] = 0;
  }
  for(int i=0; i<4*size; i++) {
    buffer2[i] = 0;
  }
  for(int i=0; i<NUM_THREADS; i++) {
    bm_worked_thread[i] = 0;
    tb_status_table[i] = 0;
  }

}

//#define NUM_TURN 100
__device__ int NUM_TURN;
#define COMPILER_BARRIER() asm volatile("" ::: "memory")
#define cpu_to_le32(x) ((__le32)(__swab32)(x))

union ixgbe_adv_tx_desc {
	struct {
		__le64 buffer_addr; /* Address of descriptor's data buf */
		__le32 cmd_type_len;
		__le32 olinfo_status;
	} read;
	struct {
		__le64 rsvd; /* Reserved */
		__le32 nxtseq_seed;
		__le32 status;
	} wb;
};

#define __force
typedef unsigned int u32;

__device__ static inline __sum16 csum_fold(unsigned int csum)
{
	u32 sum = (__force u32)csum;;

	sum += (sum << 16);
	csum = (sum < csum);
	sum >>= 16;
	sum += csum;

	return (__force __sum16)~sum;
}

__device__ static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	const unsigned int *word = (const unsigned int*) iph;
	const unsigned int *stop = word + ihl;
	unsigned int csum = 0;
	int carry;

  uint32_t tmp = 0;
  memcpy(&tmp, (uint16_t*)&word[0], 4);
  csum = tmp;
  memcpy(&tmp, (uint16_t*)&word[1], 4);
	csum += tmp;
	carry = (csum < tmp);
	csum += carry;

  memcpy(&tmp, (uint16_t*)&word[2], 4);
	csum += tmp;
	carry = (csum < tmp);
	csum += carry;

  memcpy(&tmp, (uint16_t*)&word[3], 4);
	csum += tmp;
	carry = (csum < tmp);
	csum += carry;

	word += 4;
	do {
    memcpy(&tmp, (uint16_t*)word, 4);
		csum += tmp;
		carry = (csum < tmp);
		csum += carry;
		word++;
	} while (word != stop);

	return csum_fold(csum);
}


#define IP_NEXT_PTR(iph) ((uint8_t *)iph + (iph->ihl << 2))


__device__ void 
DumpICMPPacket(const char* type, struct icmphdr *icmph, uint32_t saddr, uint32_t daddr)
{
  uint8_t* _saddr = (uint8_t*) &saddr;
  uint8_t* _daddr = (uint8_t*) &daddr;

	printf("ICMP header: \n");
  printf("Type: %d, "
      "Code: %d, ID: %d, Sequence: %d\n", 
      icmph->icmp_type, icmph->icmp_code,
      NTOHS(ICMP_ECHO_GET_ID(icmph)), NTOHS(ICMP_ECHO_GET_SEQ(icmph)));

  printf("Sender IP: %u.%u.%u.%u\n",
      *_saddr++, *_saddr++, *_saddr++, *_saddr);
  printf("Target IP: %u.%u.%u.%u\n",
      *_daddr++, *_daddr++, *_daddr++, *_daddr);

  printf("%s--------------------------------------------\n", type);
  for(int i=0; i<64; i+=2) {
    printf("%x ", *(((uint8_t*)icmph) + i));
    printf("%x ", *(((uint8_t*)icmph) + i+1));
    if(i%20==0)
      printf("\n");
  }
  printf("\n--------------------------------------------\n");
}


__device__ void 
DumpICMPPacket(struct icmphdr *icmph, uint32_t saddr, uint32_t daddr)
{
  uint8_t* _saddr = (uint8_t*) &saddr;
  uint8_t* _daddr = (uint8_t*) &daddr;

	printf("ICMP header: \n");
  printf("Type: %d, "
      "Code: %d, ID: %d, Sequence: %d\n", 
      icmph->icmp_type, icmph->icmp_code,
      NTOHS(ICMP_ECHO_GET_ID(icmph)), NTOHS(ICMP_ECHO_GET_SEQ(icmph)));

  printf("Sender IP: %u.%u.%u.%u\n",
      *_saddr++, *_saddr++, *_saddr++, *_saddr);
  printf("Target IP: %u.%u.%u.%u\n",
      *_daddr++, *_daddr++, *_daddr++, *_daddr);

  printf("--------------------------------------------\n");
  for(int i=0; i<100; i+=2) {
    printf("%x ", *(((uint8_t*)icmph) + i));
    printf("%x ", *(((uint8_t*)icmph) + i+1));
    if(i%20==0)
      printf("\n");
  }
  printf("\n--------------------------------------------\n");
}

#if 0
__device__ void 
DumpICMPPacket(struct icmphdr *icmph, uint8_t* saddr, uint8_t* daddr)
{
	printf("ICMP header: \n");
  printf("Type: %d, "
      "Code: %d, ID: %d, Sequence: %d\n", 
      icmph->icmp_type, icmph->icmp_code,
      NTOHS(ICMP_ECHO_GET_ID(icmph)), NTOHS(ICMP_ECHO_GET_SEQ(icmph)));

  printf("Sender IP: %u.%u.%u.%u\n",
      *saddr++, *saddr++, *saddr++, *saddr);
  printf("Target IP: %u.%u.%u.%u\n",
      *daddr++, *daddr++, *daddr++, *daddr);
}
#endif

__device__ uint8_t *
IPOutputStandalone(unsigned char* d_tx_pkt_buffer, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen)
{
	struct iphdr *iph;
	int nif;
	unsigned char * haddr;
	int rc = -1;

// TODO: when daddr is not known yet.
// This should be done with handling arp reply
#if 0
	nif = GetOutputInterface(daddr);
	if (nif < 0)
		return NULL;

	haddr = GetDestinationHWaddr(daddr);
	if (!haddr) {
#if 0
		uint8_t *da = (uint8_t *)&daddr;
		TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
				"is not in ARP table!\n",
				da[0], da[1], da[2], da[3]);
#endif
		RequestARP(mtcp, daddr, nif, mtcp->cur_ts);
		return NULL;
	}
#endif

  //TODO for now, statically sets mac addrs
  uint8_t src_haddr[ETH_ALEN] = {0x00, 0x1b, 0x21, 0xbc, 0x11, 0x52};
  // hw addr for yoon
  uint8_t dst_haddr[ETH_ALEN] = {0x3c, 0xa3, 0x15, 0x04, 0x88, 0xd3};
	iph = (struct iphdr *)EthernetOutput(d_tx_pkt_buffer, ETH_P_IP, src_haddr, dst_haddr, payloadlen + IP_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = HTONS(IP_HEADER_LEN + payloadlen);

  // to avoid memory misalignment
  // maybe, __be16 is not recognized as 2bytes by cuda
  // maybe, we need to redevine ip header structure using __align__
	*(uint16_t*)(&(iph->id)) = HTONS(ip_id);

  // XXX ??? why undefined?
#define IP_DF   0x4000
	*(uint16_t*)(&(iph->frag_off)) = (uint16_t)HTONS(IP_DF);	// no fragmentation
	*(uint8_t*)&iph->ttl = 64;
	*(uint8_t*)&iph->protocol = protocol;
	//iph->saddr = saddr;
	memcpy((uint16_t*)&iph->saddr,&saddr,4);
	//*(uint32_t*)&iph->saddr = saddr;
	//*(uint32_t*)&iph->daddr = daddr;
	memcpy((uint16_t*)&iph->daddr,&daddr,4);

  __sum16 tmp = ip_fast_csum(iph, iph->ihl);
	//memcpy((uint16_t*)&iph->check, &tmp, 2);
  //iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);
	return (uint8_t *)(iph + 1);
}

__device__ static uint16_t
ICMPChecksum(uint16_t *icmph, int len)
{
	uint16_t ret = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;
	
	while (len > 1) {
		sum += *icmph++;
		len -= 2;
	}
	
	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
		sum += odd_byte;
	}
	
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret =  ~sum;
	return ret; 
}

__device__ static int
ICMPOutput(unsigned char* d_tx_pkt_buffer, uint32_t saddr, uint32_t daddr,
	   uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_id, uint16_t icmp_seq,
	   uint8_t *icmpd, uint16_t len)
{
	struct icmphdr *icmph;

	icmph = (struct icmphdr *)IPOutputStandalone(
      d_tx_pkt_buffer, IPPROTO_ICMP, 0, saddr, daddr, sizeof(struct icmphdr) + len);
	if (!icmph)
		return -1;
	/* Fill in the icmp header */
	icmph->icmp_type = icmp_type;
	icmph->icmp_code = icmp_code;
	icmph->icmp_checksum = 0;
	ICMP_ECHO_SET_ID(icmph, HTONS(icmp_id));
	ICMP_ECHO_SET_SEQ(icmph, HTONS(icmp_seq));
	
	/* Fill in the icmp data */
	if (len > 0)
		memcpy((void *)(icmph + 1), icmpd, len);
	
#if 1
	//DumpICMPPacket("ICMPChecksum", icmph, saddr, daddr);
	/* Calculate ICMP Checksum with header and data */
	icmph->icmp_checksum = 
		ICMPChecksum((uint16_t *)icmph, sizeof(struct icmphdr) + len);
#endif
	
	//DumpICMPPacket("TX", icmph, saddr, daddr);

#if 0
	if (ICMPChecksum((uint16_t *) icmph, 64) ) {
    printf("ICMPChecksum returns ERROR\n");
  }
#endif
	return 0;
}

__device__ static int 
ProcessICMPECHORequest(unsigned char* d_tx_pkt_buffer, struct iphdr *iph, int len)
{
	int ret = 0;
	struct icmphdr *icmph = (struct icmphdr *) IP_NEXT_PTR(iph);
	
	/* Check correctness of ICMP checksum and send ICMP echo reply */
  // TODO
#if 1 
	if (ICMPChecksum((uint16_t *) icmph, len - (iph->ihl << 2)) ) {
		ret = ERROR;
  }
	else 
#endif
  {
    // RESOLVING MISALINGED ERROR
    uint16_t* _saddr = (uint16_t*)&(iph->saddr);
    uint16_t* _daddr = (uint16_t*)&(iph->daddr);
    uint32_t saddr = 0;
    uint32_t daddr = 0;
    memcpy(&saddr, _saddr, 4);
    memcpy(&daddr, _daddr, 4);

    ICMPOutput(d_tx_pkt_buffer, daddr, saddr, ICMP_ECHOREPLY, 0, 
        NTOHS(ICMP_ECHO_GET_ID(icmph)), NTOHS(ICMP_ECHO_GET_SEQ(icmph)), 
        (uint8_t *) (icmph + 1),
        (uint16_t) (len - (iph->ihl << 2) - sizeof(struct icmphdr)) );
  }

  return ret;
}

__device__ int ProcessICMPPacket(unsigned char* d_tx_pkt_buffer, struct iphdr *iph, int len)
{
  //uint8_t* _saddr = (uint8_t*) &(iph->saddr);
  //uint8_t* _daddr = (uint8_t*) &(iph->daddr);
	struct icmphdr *icmph = (struct icmphdr *) IP_NEXT_PTR(iph);
	int i;
  // TODO : should we do the following?
#if 0
	int to_me = -1;
	
	/* process the icmp messages destined to me */
	for (i = 0; i < CONFIG.eths_num; i++) {
		if (iph->daddr == CONFIG.eths[i].ip_addr) {
			to_me = TRUE;
		}
	}
	
	if (!to_me)
		return TRUE;
#endif
	
  // need to re-align for cuda
#if 0
  uint16_t* _saddr = (uint16_t*)&(iph->saddr);
  uint16_t* _daddr = (uint16_t*)&(iph->daddr);
  uint32_t saddr = 0;
  uint32_t daddr = 0;
  memcpy(&saddr, _saddr, 4);
  memcpy(&daddr, _daddr, 4);
#endif

  switch (icmph->icmp_type) {
        case ICMP_ECHO:
          //printf("[%s][%d] [INFO] ICMP_ECHO received\n", __FUNCTION__, __LINE__);
          //DumpICMPPacket("RX", icmph, saddr, daddr);
          ProcessICMPECHORequest(d_tx_pkt_buffer, iph, len);
          break;
		
        case ICMP_DEST_UNREACH:
          printf("[INFO] ICMP Destination Unreachable message received\n");
          break;
		
        case ICMP_TIME_EXCEEDED:
          printf("[INFO] ICMP Time Exceeded message received\n");
          break;

        default:
          printf("[INFO] Unsupported ICMP message type %x received\n", icmph->icmp_type);
          break;
  }
  return TRUE;
}


__device__ inline int ProcessIPv4Packet(unsigned char* d_tx_pkt_buffer, unsigned char *pkt_data, int len)
{
  //printf("[%s][%d]\n",__FUNCTION__, __LINE__);
	/* check and process IPv4 packets */
	struct iphdr* iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	int ip_len = NTOHS(iph->tot_len);

	/* drop the packet shorter than ip header */
	if (ip_len < sizeof(struct iphdr))
    // TODO: define ERROR and FALSE
		//return ERROR;
    return -1;

  // TODO: should handle checksum and promiscuous mode
#if 0
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx, PKT_RX_IP_CSUM, iph);
	if (rc == -1 && ip_fast_csum(iph, iph->ihl))
		return ERROR;
#else
	UNUSED(rc);
	if (ip_fast_csum(iph, iph->ihl))
		return ERROR;
#endif

#if !PROMISCUOUS_MODE
	/* if not promiscuous mode, drop if the destination is not myself */
	if (iph->daddr != CONFIG.eths[ifidx].ip_addr)
		//DumpIPPacketToFile(stderr, iph, ip_len);
		return TRUE;
#endif
#endif 

	// see if the version is correct
	if (iph->version != 0x4 ) {
    // TODO: define ERROR and FALSE
		//return FALSE;
		return -1;
	}
	
  switch (iph->protocol) {
#if 0
		case IPPROTO_TCP:
			return ProcessTCPPacket(mtcp, cur_ts, ifidx, iph, ip_len);
#endif
		case IPPROTO_ICMP:
			return ProcessICMPPacket(d_tx_pkt_buffer, iph, ip_len);
		default:
			/* currently drop other protocols */
      // TODO: define FALSE
			return -1;
      //return FALSE
	}
  //return FALSE
}

__global__ void packet_processor(unsigned char* d_pkt_processing_queue, unsigned char* d_tx_pkt_buffer, int * tb_status_table, volatile int* num_turns, volatile uint8_t* io_addr)
{
  if(blockIdx.x == 0) {
    BEGIN_SINGLE_THREAD_PART {
    // can be placed somewhere else.
      tx_tail_for_queue_zero = io_addr + IXGBE_TDT(0);
      printf("[%s][%d] in pp. (%d, %d)\n", __FUNCTION__, __LINE__, readNoCache(&tb_status_table[PP_TB]), *num_turns );
    } END_SINGLE_THREAD_PART;
      
    while(*num_turns < NUM_TURN) {
      while(!readNoCache(&tb_status_table[PP_TB])) {
      } 
      // currently d_curr_of_processing_queue is fixed to zero.
      unsigned char* rx_packet = &d_pkt_processing_queue[d_curr_of_processing_queue * 512 * 0x1000 + 0x1000*threadIdx.x];
      unsigned char* tx_packet = &d_tx_pkt_buffer[0x1000*threadIdx.x];
      //__threadfence_system();
      if(*(uint16_t*)(rx_packet+12) != 0) {
        struct ethhdr *ethh = (struct ethhdr *)rx_packet;
        u_short ip_proto = NTOHS(ethh->h_proto);
        if (ip_proto == ETH_P_ARP) {
          ProcessARPPacket(tx_packet, rx_packet, 60);
          //printf("[%s][%d] %d thread setting tx packet for ARP\n", __FUNCTION__, __LINE__, threadIdx.x);
        } else if(ip_proto == ETH_P_IP) {
          // TODO: passing len from below
          ProcessIPv4Packet(tx_packet, rx_packet, 1500);
          //printf("[%s][%d] %d thread setting tx packet for IP\n", __FUNCTION__, __LINE__, threadIdx.x);
        } else {
          printf("[%s][%d] %d thread unknown protocol\n", __FUNCTION__, __LINE__, threadIdx.x);
        }
        //DumpPacket((uint8_t*)tx_packet, 60);
        *(uint16_t*)(rx_packet+12) = 0;
      } else {
        //printf("[%s][%d] %d thread not set\n", __FUNCTION__, __LINE__, threadIdx.x);
      }
      //__threadfence();

      tb_status_table[TX_TB] = 1; // set for tx 
      tb_status_table[PP_TB] = 0; // set for pp
    }

    BEGIN_SINGLE_THREAD_PART {
    // can be placed somewhere else.
      printf("[%s][%d] out pp.\n", __FUNCTION__, __LINE__);
    } END_SINGLE_THREAD_PART;
  }
}


__device__ int tx_curr = 0;

#if 0
__global__ void tx_handler(volatile unsigned char* d_pkt_buffer, int * tb_status_table, volatile uint8_t* io_addr, volatile union ixgbe_adv_tx_desc* tx_desc, volatile int* num_turns)
{
  BEGIN_SINGLE_THREAD_PART {
    while(*num_turns < NUM_TURN) {
      while(!readNoCache(&tb_status_table[TX_TB])) { } 
      //printf("TX [%2d,%2d]\n", blockIdx.x, threadIdx.x);
      tb_status_table[TX_TB]=0;

      //volatile unsigned char* tx_packet = &d_pkt_buffer[0x1000*threadIdx.x];
      //DumpPacket((uint8_t*)tx_packet, 60);
#if 1

      COMPILER_BARRIER();
      int tmp = tx_curr;
      //printf("+(%d) ",tmp);
      for(int i=0; i<512; i++) {
        int curr_index = (tmp+ i)%512;
        printf("(%d,%d) ",i, curr_index);

        if(*(uint16_t*)(d_pkt_buffer+ 0x1000*curr_index) != 0) {
          tx_curr = curr_index;
          printf("-(%d) ",tx_curr);
          //printf("%dth memory, tx handler finds a packet to send.\n", curr_index);
          //DumpPacket((uint8_t*)(d_pkt_buffer+0x1000*curr_index), 60);

          // TODO: currently, back to back. batching need to be implemented
          //printf("TX: Try to send packets using %dth tx_desc.\n",curr_index);
          //printf("tx_tail_for_queue_zero:%p\n", tx_tail_for_queue_zero);
          volatile union ixgbe_adv_tx_desc *desc = tx_desc + curr_index;
          //desc->read.olinfo_status = 0xf0002;
          COMPILER_BARRIER();
          struct ethhdr *ethh = (struct ethhdr *) (d_pkt_buffer + 0x1000*curr_index);
          u_short ip_proto = NTOHS(ethh->h_proto);
          if (ip_proto == ETH_P_ARP) {
            desc->read.cmd_type_len |= 60;
            // TODO
            desc->read.olinfo_status = 0xf0000;
          } else if(ip_proto == ETH_P_IP) {
            desc->read.cmd_type_len |= 98;
            // TODO
            // temporal value for ping msgs
            desc->read.olinfo_status = 0x188000;
            //printf("%p %p\n", &(desc->read.cmd_type_len), &(desc->read.olinfo_status));
          } else {
            desc->read.cmd_type_len |= 60;
            desc->read.olinfo_status = 0xf0000;
          }
          tx_tail_for_queue_zero = io_addr + IXGBE_TDT(0);
          *(uint16_t*)(d_pkt_buffer+ 0x1000*(curr_index-1)) = 0;
          *(volatile unsigned long*) tx_tail_for_queue_zero = (unsigned long)(curr_index + 1);
          //uint32_t curr_tx_index_q_zero = *(volatile unsigned int *)tx_tail_for_queue_zero;
          //printf("curr_tx_index_q_zero: %u\n", curr_tx_index_q_zero);

          // TODO cleaning sent data
          //*(uint16_t*)(d_pkt_buffer+ 0x1000*curr_index) = 0;
          //break;
        }
        //printf("\n");
      }
      COMPILER_BARRIER();
#endif
      //__threadfence_system();
    }
    printf("[%s][%d] out tx.\n", __FUNCTION__, __LINE__);
  } END_SINGLE_THREAD_PART;
}

#else

__global__ void tx_handler(volatile unsigned char* d_pkt_buffer, int * tb_status_table, volatile uint8_t* io_addr, volatile union ixgbe_adv_tx_desc* tx_desc, volatile int* num_turns)
{
  while(*num_turns < NUM_TURN) {
    BEGIN_SINGLE_THREAD_PART {
      while(!readNoCache(&tb_status_table[TX_TB])) { } 
      tb_status_table[TX_TB]=0;
    } END_SINGLE_THREAD_PART;
    __syncthreads();
#if 1
    int my_index = threadIdx.x;
    if(*(uint16_t*)(d_pkt_buffer+ 0x1000*my_index) != 0) {
      volatile union ixgbe_adv_tx_desc *desc = tx_desc + my_index;
      struct ethhdr *ethh = (struct ethhdr *) (d_pkt_buffer + 0x1000*my_index);
      u_short ip_proto = NTOHS(ethh->h_proto);
      if (ip_proto == ETH_P_ARP) {
        desc->read.cmd_type_len |= 60;
        // TODO
        desc->read.olinfo_status = 0xf0000;
      } else if(ip_proto == ETH_P_IP) {
        desc->read.cmd_type_len |= 98;
        // TODO
        // temporal value for ping msgs
        desc->read.olinfo_status = 0x188000;
        //printf("%p %p\n", &(desc->read.cmd_type_len), &(desc->read.olinfo_status));
      } else {
        desc->read.cmd_type_len |= 60;
        desc->read.olinfo_status = 0xf0000;
      }
      tx_tail_for_queue_zero = io_addr + IXGBE_TDT(0);
      // TODO: following code is wrong
      *(uint16_t*)(d_pkt_buffer+ 0x1000*(my_index-1)) = 0;
      *(volatile unsigned long*) tx_tail_for_queue_zero = (unsigned long)(my_index + 1);
    }
#endif
  }
  //printf("[%s][%d] out tx.\n", __FUNCTION__, __LINE__);
}
#endif

__global__ void rx_handler(volatile unsigned char* d_pkt_buffer, int * tb_status_table, char *bm_worked_thread, volatile int* num_turns, int fd, unsigned char* d_pkt_processing_queue) // bm: bitmap
{
  *num_turns = 0;
  //volatile unsigned char * d_mem = (volatile unsigned char*)d_pkt_buffer;
  tb_status_table[RX_TB] = 0;
  tb_status_table[PP_TB] = 0;
  tb_status_table[TX_TB] = 0;
  volatile unsigned char* rx_buf = d_pkt_buffer + offset_for_rx;

#if 0
  if(blockIdx.x == 0) {
#if 0
    BEGIN_SINGLE_THREAD_PART {
      printf("Entering rx_handler. (Block ID:%d)\n", blockIdx.x);
      int mem_index = 0; // why 12??
      while(*num_turns < NUM_TURN) { 
        if(readNoCache(((uint16_t*)&rx_buf[mem_index])) != 0 ) {
          //for(int i=0; i<120; i=i+2) {
          //  printf("%d:0x%02x%02x\n", i, rx_buf[mem_index+i],rx_buf[mem_index+i+1]);
          //}
          //printf("1[%2d,%2d] %d, %d\n", blockIdx.x, threadIdx.x, readNoCache((uint16_t*)&rx_buf[mem_index]), mem_index);
          //printf("Setting tb_status_table[1] = 1 %d(%d)\n", (uint16_t)rx_buf[mem_index], mem_index);
          tb_status_table[RX_TB] = 1;
        }
        mem_index += 0x1000;
        //__threadfence_system();

        if(mem_index >= offset_for_rx) {
          mem_index -= offset_for_rx;
        }
      }
    } END_SINGLE_THREAD_PART;
#else
    //printf("Entering rx_handler. (Block ID:%d)\n", blockIdx.x);
    int mem_index = 0x1000*threadIdx.x;
    while(*num_turns < NUM_TURN) { 
      if(readNoCache(((uint16_t*)&rx_buf[mem_index])) != 0 ) {
        //for(int i=0; i<120; i=i+2) {
        //  printf("%d:0x%02x%02x\n", i, rx_buf[mem_index+i],rx_buf[mem_index+i+1]);
        //}
        //printf("1[%2d,%2d] %d, %d\n", blockIdx.x, threadIdx.x, readNoCache((uint16_t*)&rx_buf[mem_index]), mem_index);
        //printf("Setting tb_status_table[1] = 1 %d(%d)\n", (uint16_t)rx_buf[mem_index], threadIdx.x);
        tb_status_table[RX_TB] = 1;
      }
    }
#endif
  } else {
    while(*num_turns < NUM_TURN) {
      while(!readNoCache(&tb_status_table[RX_TB])) { } 
      //__threadfence_system();
      int mem_index = 0x1000 * threadIdx.x;
      if(readNoCache((uint16_t*)&rx_buf[mem_index]) != 0) {
        //printf("RX [%2d,%2d] %d from %d\n", blockIdx.x, threadIdx.x, tb_status_table[blockIdx.x], *num_turns);
        //DumpPacket((uint8_t*)&rx_buf[mem_index], 60);
        memcpy(d_pkt_processing_queue + mem_index,(const void*)(rx_buf + mem_index), 0x1000);
        for(int i=mem_index; i<mem_index+0x1000; i++)
          rx_buf[i] = 0;
        bm_worked_thread[threadIdx.x] = 1;
      }
#if 1
      BEGIN_SINGLE_THREAD_PART {
        //printf("[%2d,%2d] %d from %d\n", blockIdx.x, threadIdx.x, tb_status_table[blockIdx.x], *num_turns);
        //__threadfence_system();
        tb_status_table[RX_TB] = 0; // set for rx
        tb_status_table[PP_TB] = 1; // set for pp
        (*num_turns)++;
        int num_worked_threads = 0;
        for(int i=0; i<NUM_THREADS; i++) {
          if(bm_worked_thread[i]) {
            num_worked_threads++;
            bm_worked_thread[i] = 0;
          }
        }
        //printf("RX [%2d,%2d] %d from %d, num_worked_threads:%d\n", blockIdx.x, threadIdx.x, tb_status_table[RX_TB], *num_turns, num_worked_threads);
      } END_SINGLE_THREAD_PART;
#endif
    }
  }
#else
  
  while(*num_turns < NUM_TURN) {
    //while(!readNoCache(&tb_status_table[RX_TB])) { } 
    //__threadfence_system();
    int mem_index = 0x1000 * threadIdx.x;
    if(readNoCache((uint16_t*)&rx_buf[mem_index]) != 0) {
      //DumpPacket((uint8_t*)&rx_buf[mem_index], 60);
      memcpy(d_pkt_processing_queue + mem_index, (const void*)(rx_buf + mem_index), 0x800);
#if 0
      clock_t start = clock();
      clock_t now;
      for (;;) {
        now = clock();
        clock_t cycles = now > start ? now - start : now + (0xffffffff - start);
        if (cycles >= 10000) {
          break;
        }
      }
#endif
      //printf("RX [%2d,%2d] status:%d num_turn:%d(%d) in buf:%x\n", blockIdx.x, threadIdx.x, tb_status_table[0], *num_turns, NUM_TURN, rx_buf[mem_index]);
      //for(int i=mem_index; i<mem_index+0x1000; i++) {
       // rx_buf[i] = 0;
      //}
      rx_buf[mem_index] = 0;
      rx_buf[mem_index+1] = 0;
      //bm_worked_thread[threadIdx.x] = 1;
      (*num_turns)++;
      tb_status_table[PP_TB] = 1; // set for pp
    }
    //__threadfence_system();
#if 0
    BEGIN_SINGLE_THREAD_PART {
      //printf("[%2d,%2d] %d from %d\n", blockIdx.x, threadIdx.x, tb_status_table[blockIdx.x], *num_turns);
      //__threadfence_system();
      //tb_status_table[RX_TB] = 0; // set for rx
      //tb_status_table[PP_TB] = 1; // set for pp
      int num_worked_threads = 0;
     // for(int i=0; i<NUM_THREADS; i++) {
     //   if(bm_worked_thread[i]) {
     //     num_worked_threads++;
     //     bm_worked_thread[i] = 0;
     //   }
     // }
      //printf("RX [%2d,%2d] %d from %d, num_worked_threads:%d\n", blockIdx.x, threadIdx.x, tb_status_table[RX_TB], *num_turns, num_worked_threads);
    } END_SINGLE_THREAD_PART;
#endif
  }

#endif
}




__global__ void doorbell_test(void * io_addr, void * desc, uint32_t curr, int* d_mem, int size)
{
  printf("[%s][%d]\n", __FUNCTION__, __LINE__);
  if (blockIdx.x == 0) {
    BEGIN_SINGLE_THREAD_PART {
      printf("[%s][%d] in doorbell_test First Block.\n", __FUNCTION__, __LINE__);
      if(desc == 0) {
        printf("[%s][%d]desc==NULL.\n", __FUNCTION__, __LINE__);
        return;
      }
      // ARP call
      uint8_t* pktBuf;
      pktBuf = (uint8_t *)malloc(60);

      // For now, static ip address 
      uint8_t src_tmp[] = {0x0a, 0x00, 0x00, 0x02};
      uint8_t dst_tmp[] = {0x0a, 0x00, 0x00, 0x01};
      uint32_t src_ip;                             
      memcpy(&src_ip, src_tmp, 4);                 
      uint32_t dst_ip;                             
      memcpy(&dst_ip, dst_tmp, 4);  
      unsigned char dst_haddr[ETH_ALEN];
      memset(dst_haddr, 0xFF, ETH_ALEN);

      for(int i=0; i< size/sizeof(int); i++) {
        d_mem[i] = 0;
      }

      for(int i=0; i< 512; i++) {
        memcpy(d_mem+4096*i/4, pktBuf, 60);
      }

      unsigned char *db[12];
      for(int i=0; i<12; i++)
        db[i] = ((unsigned char *)io_addr) + IXGBE_TDT(i);

      COMPILER_BARRIER();
      volatile union ixgbe_adv_tx_desc* tx_desc;
      tx_desc = (union ixgbe_adv_tx_desc*) desc;

      int num_packets = NUM_PACKETS;
      int index = curr;
      for(int i=0; i<curr; i++) {
        tx_desc++;
      }
      for(int i=0; i<num_packets; i++) {
        tx_desc->read.cmd_type_len |= 60;
        tx_desc->read.olinfo_status = 0xf0000;
        tx_desc++;
        index++;
        if(index == 512)
          tx_desc = (union ixgbe_adv_tx_desc*) desc;
      }
      tail_val = (unsigned long)((curr + num_packets) % 512);
      *(volatile unsigned long*)db[0] = tail_val;

      COMPILER_BARRIER();

      //__threadfence_system();
    } END_SINGLE_THREAD_PART;
    
  } else {
#ifndef __USE_PKT_MONITOR__
    // Second Block
    //printf("[%s][%d] in doorbell_test Second Block.\n", __FUNCTION__, __LINE__);
    //d_check_data(size, d_mem, flag);
#endif
  }
}

// YHOON~ for test
int tx_rx_ring_setup()
{
  const char *myinode = "/dev/ixgbe";
  int fd = open(myinode, O_RDWR);
  ioctl(fd, 1);
  return fd;
}

void yhoon_initializer(int fd, void *ixgbe_bar0_host_addr, ixgbe_adv_tx_desc* desc_addr, void **io_addr, void **tx_desc)
{
  const size_t IXGBE_BAR0_SIZE = 4096*8; // A rough calculation

  ixgbe_bar0_host_addr = mmap(0, IXGBE_BAR0_SIZE*5 , PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  ASSERTRT(cudaHostRegister(ixgbe_bar0_host_addr, IXGBE_BAR0_SIZE, cudaHostRegisterIoMemory));
  ASSERTRT(cudaHostGetDevicePointer((void**)io_addr, (void*)ixgbe_bar0_host_addr, 0));
  printf("io_addr: %p\n", *io_addr);

  desc_addr = (ixgbe_adv_tx_desc*)((unsigned char*)ixgbe_bar0_host_addr + IXGBE_BAR0_SIZE);
  ASSERTRT(cudaHostRegister(desc_addr, IXGBE_BAR0_SIZE * 4, cudaHostRegisterIoMemory));
  //ASSERTRT(cudaMalloc(&tx_desc, IXGBE_BAR0_SIZE * 4));
  ASSERTRT(cudaHostGetDevicePointer((void**)tx_desc, (void*)desc_addr, 0));
  printf("tx_desc: %p\n", *tx_desc);

}

void yhoon_finalizer(void* ixgbe_bar0_host_addr, ixgbe_adv_tx_desc* desc_addr)
{
  const size_t IXGBE_BAR0_SIZE = 4096*8; // A rough calculation
  cudaHostUnregister(desc_addr);
  cudaHostUnregister(ixgbe_bar0_host_addr);
  munmap(ixgbe_bar0_host_addr, IXGBE_BAR0_SIZE*5);
}


void yhoon_xmit_arp(int *d_mem, int size, int fd)
{
  printf("[%s][%d]START---yhoon_xmit_arp------------HOST.\n", __FUNCTION__, __LINE__);
  printf("[%s][%d] sizeof tx_desc:%lu \n", __FUNCTION__, __LINE__, sizeof(union ixgbe_adv_tx_desc));
  // sample code for copying address to drivers
  //uint64_t ptr = 1234;
  //ioctl(fd, 0, &ptr);

  //printf("cpu_to_le32 test:%x\n", htonl(60));

  void* dBAR;
  const size_t IXGBE_BAR0_SIZE = 4096*8; // A rough calculation
  void* ixgbe_bar0_host_addr = mmap(0, IXGBE_BAR0_SIZE*5 , PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  ASSERTRT(cudaHostRegister(ixgbe_bar0_host_addr, IXGBE_BAR0_SIZE, cudaHostRegisterIoMemory));
  ASSERTRT(cudaHostGetDevicePointer((void**)&dBAR, (void*)ixgbe_bar0_host_addr, 0));

  unsigned char *db[12];
  for(int i=0; i<1; i++) {
    db[i] = ((unsigned char *)ixgbe_bar0_host_addr) + IXGBE_TDT(i);
#if 0
    printf("db[%d]: %d\n", i, *(volatile unsigned int *)db[i]);
#endif
  }

  ixgbe_adv_tx_desc* desc = (ixgbe_adv_tx_desc*)((unsigned char*)ixgbe_bar0_host_addr + IXGBE_BAR0_SIZE);
  ASSERTRT(cudaHostRegister(desc, IXGBE_BAR0_SIZE * 4, cudaHostRegisterIoMemory));
  //cudaHostRegister(desc, sizeof(ixgbe_adv_tx_desc), cudaHostRegisterIoMemory);
  void* tx_desc;
  ASSERTRT(cudaMalloc(&tx_desc, IXGBE_BAR0_SIZE * 4));
  if(cudaSuccess != cudaHostGetDevicePointer((void**)&tx_desc, (void*)desc, 0)) {
    cudaCheckErrors("cudaHostGetDevicePointer fails");
  }

	cudaStream_t cuda_stream2;
  ASSERT_CUDA(cudaStreamCreate(&cuda_stream2));

  uint32_t curr_tx_index_q_zero = *(volatile unsigned int *)db[0];
  printf("curr_tx_index_q_zero: %u\n", curr_tx_index_q_zero);
  doorbell_test<<< 1, 1, 0, cuda_stream2 >>>(dBAR, tx_desc, curr_tx_index_q_zero, d_mem, size);

  //if(cudaSuccess != cudaDeviceSynchronize())
	//  cudaCheckErrors("doorbell_sync_error!");

  curr_num = curr_tx_index_q_zero;
  cudaHostUnregister(desc);
  cudaHostUnregister(ixgbe_bar0_host_addr);
  munmap(ixgbe_bar0_host_addr, IXGBE_BAR0_SIZE*5);

  // ~YHOON
  printf("[%s][%d]END-----yhoon_xmit_arp------------HOST.\n", __FUNCTION__, __LINE__);
}

void check_data(int size, unsigned char* h_mem, int* d_A)
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
  uint32_t offset_for_rx = 512 * 4096;
  //const int DUMP_SIZE = 30;
  for(int i = offset_for_rx; i < size; i++) {
    if(*((uint16_t*)&h_mem[i]) == 0x0608 || *((uint16_t*)&h_mem[i]) == 0x0008 ) {//(h_mem[i] == 0x08 && h_mem[i+1] == 0x00) ) {
      i = i;
      //printf("\n%s][%d] PACKET BEGINS-------------------------------------\n", __FUNCTION__, __LINE__);
      printf("[%s][%d] We found ethernet type 0x%02x%02x on %dth memory.\n", __FUNCTION__ , __LINE__, h_mem[i], h_mem[i+1],i-offset_for_rx);
      printf("[%s][%d] We found ethernet type 0x%04x on %dth memory.\n", __FUNCTION__ , __LINE__, *((uint16_t*)&h_mem[i]), i-offset_for_rx);
    } else if (h_mem[i] == 0xAB || h_mem[i] == 0xBA) {
      for(int packet_iter = i; packet_iter < (i+20); packet_iter++) {
        if((packet_iter-i) % 4 == 0)
          printf("\n");
        printf("%3d:0x%02x\t", packet_iter-i, h_mem[packet_iter]);
      }
	}
  }
  for(int i = 0; i < size; i++) 
    if(h_mem[i] != 0) 
      dirty_cnt++;
#endif
  printf("[%s][%d] dirty_cnt:[%d]\n", __FUNCTION__ , __LINE__, dirty_cnt);
  printf("[%s][%d] ENDS\n\n\n\n", __FUNCTION__, __LINE__);
}

__global__ void init_data(int num_turn)
{
  NUM_TURN = num_turn;  
}

int main(int argc, char *argv[])
{
  int num_turn = 10;
#if 1
  if(argc != 1) {
    num_turn = atoi(argv[1]);
  }
#endif

  printf("[%s][%d] main\n", __FUNCTION__, __LINE__);
  int dev_id = 0;
  size_t _pkt_buffer_size = 2*512*4096; // 4MB, for rx,tx ring

  // CKJUNG, meaning of this?
  size_t pkt_buffer_size = (_pkt_buffer_size + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;
  printf("[%s][%d]____CKJUNG__pkt_buffer_size: %lu\n", __FUNCTION__, __LINE__, pkt_buffer_size);

  int n_devices = 0;

  ASSERTRT(cudaGetDeviceCount(&n_devices));

  cudaDeviceProp prop;
  for (int n=0; n<n_devices; ++n) {
    cudaGetDeviceProperties(&prop,n);
    OUT << "GPU id:" << n << " name:" << prop.name 
      << " PCI domain: " << prop.pciDomainID 
      << " bus: " << prop.pciBusID 
      << " device: " << prop.pciDeviceID << endl;
  }
  OUT << "selecting device " << dev_id << endl;
  OUT << "_pkt_buffer_size: " << _pkt_buffer_size << "  pkt_buffer_size: " << pkt_buffer_size << endl;

  ASSERTRT(cudaSetDevice(dev_id));
  ASSERTRT(cudaSetDeviceFlags(cudaDeviceMapHost));

  unsigned char* d_pkt_buffer;
  unsigned char* d_pkt_processing_queue;
  ASSERTRT(cudaMalloc((void**)&d_pkt_buffer, pkt_buffer_size));
  ASSERTRT(cudaMalloc((void**)&d_pkt_processing_queue, 4*pkt_buffer_size));
  ASSERTRT(cudaMemset(d_pkt_buffer, 0, pkt_buffer_size));
  ASSERTRT(cudaMemset(d_pkt_processing_queue, 0, 4*pkt_buffer_size));
 
  unsigned int flag = 1;
  ASSERTDRV(cuPointerSetAttribute(&flag, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr) d_pkt_buffer));

  my_t g = my_open();

  ASSERT_NEQ(g, (void*)0);

  my_mh_t mh;
  if (my_pin_buffer(g, (CUdeviceptr)d_pkt_buffer, pkt_buffer_size, 0, 0, &mh)  != 0)
    OUT << "NOT_EQ" << endl;

#if 0
  int *h_tmp = (int*) malloc(sizeof(int) * pkt_buffer_size);
  for(int i=0; i<pkt_buffer_size; i++)
    h_tmp[i] = 0;

  cudaMemcpy((void *)d_pkt_buffer, (const void*)h_tmp, pkt_buffer_size * sizeof(int), cudaMemcpyHostToDevice);

  for(int i=512*4096; i<512*4096*2; i++) {
    if(h_tmp[i] != 0) {
      printf("I%d %c\n", i, (uint16_t)h_tmp[i]);
    }
  }
  cudaMemcpy((void*)h_tmp, (const void *)d_pkt_buffer, pkt_buffer_size * sizeof(int), cudaMemcpyDeviceToHost);

  for(int i=512*4096; i<512*4096*2; i++) {
    if(h_tmp[i] != 0) {
      printf("O%d %c\n", i, (uint16_t)h_tmp[i]);
    }
  }
#endif 

  void *ixgbe_bar0_host_addr = 0, *io_addr=0, *tx_desc=0;
  ixgbe_adv_tx_desc* desc_addr=0;
  int fd = tx_rx_ring_setup();
  yhoon_initializer(fd, ixgbe_bar0_host_addr, desc_addr, &io_addr, &tx_desc);
  init_data<<< 1,1>>> (num_turn);

	cudaStream_t cuda_stream1;
  //ASSERT_CUDA(cudaStreamCreate(&cuda_stream1));
  ASSERT_CUDA(cudaStreamCreateWithFlags(&cuda_stream1,cudaStreamNonBlocking));
	cudaStream_t cuda_stream2;
  //ASSERT_CUDA(cudaStreamCreate(&cuda_stream2));
  ASSERT_CUDA(cudaStreamCreateWithFlags(&cuda_stream2,cudaStreamNonBlocking));
	cudaStream_t cuda_stream3;
  //ASSERT_CUDA(cudaStreamCreate(&cuda_stream3));
  ASSERT_CUDA(cudaStreamCreateWithFlags(&cuda_stream3,cudaStreamNonBlocking));

	int *dev_tb_status_table, *num_turns;
  char *bm_worked_thread;
	ASSERT_CUDA(cudaMalloc(&dev_tb_status_table, NUM_THREADS * sizeof(*dev_tb_status_table)));
	ASSERT_CUDA(cudaMemset(dev_tb_status_table, 0, NUM_THREADS* sizeof(*dev_tb_status_table)));
  ASSERTRT(cudaMalloc((void**)&num_turns, sizeof(int)));
  ASSERTRT(cudaMalloc((void**)&bm_worked_thread, NUM_THREADS * sizeof(char)));

  clean_buffer<<< 1, 1 >>> (d_pkt_buffer, d_pkt_processing_queue, pkt_buffer_size, bm_worked_thread, dev_tb_status_table);

  if(cudaSuccess != cudaDeviceSynchronize())
	  cudaCheckErrors("cudaDeviceSynchronize Error"); 

#if 1
  printf("PP\n");
  packet_processor<<< NUM_TB, NUM_THREADS, 0, cuda_stream2 >>> (d_pkt_processing_queue, d_pkt_buffer, dev_tb_status_table, num_turns, (volatile uint8_t *)io_addr);
  //usleep(1*1000*1000);
  printf("RX\n");
  rx_handler<<< NUM_TB, NUM_THREADS, 0, cuda_stream1 >>> (d_pkt_buffer, dev_tb_status_table, bm_worked_thread, num_turns, fd, d_pkt_processing_queue);
  //usleep(1*1000*1000);
  printf("TX\n");
  tx_handler<<< NUM_TB, NUM_THREADS, 0, cuda_stream3 >>> (d_pkt_buffer, dev_tb_status_table, (volatile uint8_t*)io_addr, (volatile union ixgbe_adv_tx_desc*) tx_desc, num_turns);
#endif

  // call ixgbe_xmit_yhoon in ixgbe_main.c
  //yhoon_xmit_arp(d_pkt_buffer, pkt_buffer_size, fd);

#if 0
  int one = 1;
  usleep(1*1000*1000);
  cudaMemcpyToSymbol(server_done, &one, sizeof(int));

  unsigned char* h_mem = (unsigned char*)malloc(pkt_buffer_size*sizeof(unsigned char)); 
  cudaMemcpy(d_pkt_buffer, h_mem, pkt_buffer_size, cudaMemcpyHostToDevice);
  int count = 0;
  while(count < 1000) {
    check_data(pkt_buffer_size, h_mem, d_pkt_buffer);
    usleep(1*1000*1000);
    count++;
  }
#endif

 
  if(cudaSuccess != cudaDeviceSynchronize())
	  cudaCheckErrors("cudaDeviceSynchronize Error"); 
  cudaStreamDestroy(cuda_stream1);
  cudaStreamDestroy(cuda_stream2);
  cudaStreamDestroy(cuda_stream3);
  yhoon_finalizer(ixgbe_bar0_host_addr, desc_addr);

  ASSERT_CUDA(cudaFree(dev_tb_status_table));
  ASSERT_CUDA(cudaFree(d_pkt_buffer));
  return 0;
}

#undef IP_NEXT_PTR
