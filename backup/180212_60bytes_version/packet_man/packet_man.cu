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
#include "arp.h" 

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/in6.h>
#define ETH_ALEN  6 // YHOON
#define ARP_PAD_LEN 18 // YHOON

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


#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
enum mycopy_msg_level {
    MYCOPY_MSG_DEBUG = 1,
    MYCOPY_MSG_INFO,
    MYCOPY_MSG_WARN,
    MYCOPY_MSG_ERROR
};

#define IXGBE_TDT(_i)   (0x06018 + ((_i) * 0x40))

#define NUM_PACKETS 50
#define THREADS_PER_TB 512 

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

void h_DumpPacket(uint8_t *buf, int len)
{
  printf("<<<h_DumpPacket>>>\n");
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
      h_DumpARPPacket((struct arphdr *) (ethh + 1));
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


__device__ uint8_t * EthernetOutput(uint8_t *buf, uint16_t h_proto, unsigned char* src_haddr, unsigned char* dst_haddr, uint16_t iplen)
//uint8_t * EthernetOutput(uint8_t *buf, uint16_t h_proto, unsigned char* src_haddr, unsigned char* dst_haddr, uint16_t iplen)
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

static int h_ARPOutput(uint8_t * buf, int opcode, uint32_t src_ip, uint32_t dst_ip, unsigned char *dst_haddr)
{
	if (!dst_haddr)
		return -1;
  printf("ARPOUTPUT\n");
	/* Allocate a buffer */

#if 1
  uint8_t src_haddr[ETH_ALEN];
  // ckjung: 00:1b:21:bc:11:52
  src_haddr[0] = 0x00;
  src_haddr[1] = 0x1b;
  src_haddr[2] = 0x21;
  src_haddr[3] = 0xbc;
  src_haddr[4] = 0x11;
  src_haddr[5] = 0x52;

	struct arphdr *arph = (struct arphdr *)(uintptr_t)h_EthernetOutput(
    buf, ETH_P_ARP, src_haddr, dst_haddr, sizeof(struct arphdr));

	if (!arph) {
    printf("ERROR\n");
		return -1;
	}
#else 
	struct arphdr *arph = NULL;
#endif
	/* Fill arp header */
	arph->ar_hrd = HTONS(arp_hrd_ethernet);
	arph->ar_pro = HTONS(ETH_P_IP);
	//arph->ar_pro = htons(0x0800);
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
	memcpy(arph->ar_sha, src_haddr, arph->ar_hln);
  memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
	memset(arph->pad, 0, ARP_PAD_LEN);

#if DBGMSG
//	DumpARPPacket(arph);
#endif

	return 0;
}

__device__ static int ARPOutput(uint8_t * buf, int opcode, uint32_t src_ip, uint32_t dst_ip, unsigned char *dst_haddr)
//static int ARPOutput(uint8_t * buf, int opcode, uint32_t src_ip, uint32_t dst_ip, unsigned char *dst_haddr)
{
	if (!dst_haddr)
		return -1;
  printf("ARPOUTPUT\n");
	/* Allocate a buffer */

#if 1
  uint8_t src_haddr[ETH_ALEN];
  // ckjung: 00:1b:21:bc:11:52
  src_haddr[0] = 0x00;
  src_haddr[1] = 0x1b;
  src_haddr[2] = 0x21;
  src_haddr[3] = 0xbc;
  src_haddr[4] = 0x11;
  src_haddr[5] = 0x52;

	struct arphdr *arph = (struct arphdr *)(uintptr_t)EthernetOutput(
    buf, ETH_P_ARP, src_haddr, dst_haddr, sizeof(struct arphdr));

	if (!arph) {
    printf("ERROR\n");
		return -1;
	}
#else 
	struct arphdr *arph = NULL;
#endif
	/* Fill arp header */
	arph->ar_hrd = HTONS(arp_hrd_ethernet);
	arph->ar_pro = HTONS(ETH_P_IP);
	//arph->ar_pro = htons(0x0800);
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
	memcpy(arph->ar_sha, src_haddr, arph->ar_hln);
  memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
	memset(arph->pad, 0, ARP_PAD_LEN);

#if DBGMSG
	DumpARPPacket(arph);
#endif

	return 0;
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


// CKJUNG ~

__global__ void make_pkt(int* g_mem, int size)
{
	printf("[%s][%d]----------------------------------------START---make_pkt------------DEVICE.\n", __FUNCTION__, __LINE__);

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

// Just for check the value of variables
#if 0	
	uint8_t *t,*s;
	t = (uint8_t *)&src_ip;	
	s = (uint8_t *)&dst_haddr;	
	printf("[%s][%d]____CKJUNG___src_ip: %u.%u.%u.%u.\n", __FUNCTION__, __LINE__, t[0],t[1],t[2],t[3]);
	printf("[%s][%d]____CKJUNG___dst_haddr: %u.%u.%u.%u.\n", __FUNCTION__, __LINE__, s[0],s[1],s[2],s[3]);
#endif
	ARPOutput(pktBuf, arp_op_request, src_ip, dst_ip, dst_haddr);
	
	DumpPacket(pktBuf, 60);
	
#if 1
	for(int i=0; i< size/sizeof(int); i++) {
		g_mem[i] = 0;
	}

	printf("[%s][%d]____CKJUNG__ HERE\n", __FUNCTION__, __LINE__);

	for(int i=0; i< 512; i++) { // making 100 arpreq packets
		for(int j=0; j < 15; j++) { 
			//g_mem[4096*i+j] = pktBuf[j];
			memcpy(g_mem+4096*i+j, pktBuf + 4*j, 4);
		}
	}
	// For check
#if 0
	int count = 0;
	for(int j = 0; j < 4096*512; j++) {
		if(*((uint16_t*)&g_mem[j]) == 0x0608 || *((uint16_t*)&g_mem[j]) == 0x0806 ){
			count++;
			printf("[%s][%d] %d We found ethernet type 0x%02x%02x on %dth memory.\n", 
					__FUNCTION__ , __LINE__, count,g_mem[j], g_mem[j+1], j);
		}
	}
#endif
#else
#endif
	printf("[%s][%d]------------------------------------------END---make_pkt------------DEVICE.\n", __FUNCTION__, __LINE__);

}

// ~CKJUNG


int curr_num;
__device__ void d_check_data(int size, int* d_pkt_buffer, volatile int* flag)
{
  uint32_t offset_for_rx = 512 * 4096;
  volatile unsigned char * d_mem = (unsigned char*)d_pkt_buffer;
  d_mem += offset_for_rx;

  int pkt_cnt = 0;
  //const int DUMP_SIZE = 30;
  //__threadfence_system();
  //printf("[%s][%d] before waiting %d\n", __FUNCTION__ , __LINE__, *flag);
  //WAIT_ON_MEM_NE(d_mem[2093068], 0);
  WAIT_ON_MEM(*flag, 1);
  //printf("[%s][%d] after waiting %d\n", __FUNCTION__ , __LINE__, *flag);

#if 1
  while(pkt_cnt < 30000) {
    //printf("[%s][%d] BEFORE WAIT_ON_MEM %d\n", __FUNCTION__ , __LINE__, threadIdx.x);
    int curr_index = 12 + 0x1000*threadIdx.x; // + 0x1000*(THREADS_PER_TB * pkt_cnt);
    //WAIT_ON_MEM_NE(d_mem[curr_index], 0);
    pkt_cnt++;
    if(*((uint16_t*)&d_mem[curr_index]) == 0x0608 || *((uint16_t*)&d_mem[curr_index]) == 0x0806 ) {
      printf("[%s][%d] Ethernet type 0x%02x%02x on %dth memory. (threadIdx.x:%d %dpkts)\n", __FUNCTION__ , __LINE__, d_mem[curr_index], d_mem[curr_index+1], curr_index, threadIdx.x, pkt_cnt);
      *((uint16_t*)&d_mem[curr_index]) = 0;     
    }
  }
#endif

}

__global__ void pkt_consumer(int * pkt_queue, int pkt_queue_size, volatile int * server_done) 
{
  unsigned char * d_mem = (unsigned char*)pkt_queue;
  uint32_t offset_for_rx = 512 * 4096 ;
  d_mem += offset_for_rx;

  int pkt_cnt = 0;

  //__threadfence_system();
  int curr_index = 12 + 0x1000*threadIdx.x; // + 0x1000*(THREADS_PER_TB * pkt_cnt);
  while(!(*server_done)) { 
    if(*((uint16_t*)&d_mem[curr_index]) == 0x0608 || *((uint16_t*)&d_mem[curr_index]) == 0x0806) {
      pkt_cnt++;
      printf("[%s][%d] Ethernet type 0x%02x%02x on %dth memory. (threadIdx.x:%d %dpkts)\n", __FUNCTION__ , __LINE__, d_mem[curr_index], d_mem[curr_index+1],curr_index, threadIdx.x, pkt_cnt);
      // for now, found and initialize.
      *((uint16_t*)&d_mem[curr_index]) = 0;
      curr_index += 0x1000*THREADS_PER_TB;
    }
  }
}

__global__ void pkt_pumper(int* d_pkt_buffer, int size, int * pkt_queue, int pkt_queue_size, volatile int * server_done)
{
  // first block for check
  // TODO: use server_complete as in GPUnet
  int num_to_loop = 3000; 
  unsigned char * d_mem = (unsigned char*)d_pkt_buffer;
  unsigned char * d_mem2 = (unsigned char*)pkt_queue;
  uint32_t offset_for_rx = 512 * 4096;
  d_mem += offset_for_rx;

  int pkt_cnt = 0;

  //__threadfence_system();
  int my_index = 12 + 0x1000*blockIdx.x;
  //int my_index = 12 + 0x1000*threadIdx.x;
  //printf("server_done: %d\n", *server_done);
  printf("server_done: %d\n", *server_done);
  
  //while(!(*server_done)) { 
  while(num_to_loop--) { 
    printf("[%s][%d] blockIdx.x:%d %dpkts, index:%d\n", __FUNCTION__ , __LINE__, blockIdx.x, pkt_cnt, my_index);
    if(*((uint16_t*)&d_mem[my_index]) != 0) { 
      printf("[%s][%d] %dth memory != 0. (threadIdx.x:%d %dpkts)\n", __FUNCTION__ , __LINE__, my_index, threadIdx.x, pkt_cnt);
      memcpy((void*)(d_mem2 + my_index + 0x1000 * pkt_cnt), d_mem + my_index, 0x1000);
      pkt_cnt++;
      *((uint16_t*)&d_mem[my_index]) = 0;
    }
  }
  printf("server_done: %d\n", *server_done);
}

__device__ volatile int finished;

#if 0
__device__ void wait_for_something(volatile int * something_finished)
{
  BEGIN_SINGLE_THREAD_PART {
    while(!*something_finished) {
    }
  }
}
#endif

__device__ volatile int server_done;
#define NUM_TB 2 

__global__ void rx_handler(volatile int * tb_alloc_tbl)
{
  //printf("Entering rx_handler. (Block ID:%d)\n", blockIdx.x);
  //printf("server_done1:%d\n", server_done);
  int num = 0;
  if(blockIdx.x == 0) {
    BEGIN_SINGLE_THREAD_PART {
      for(int i=1; i<=NUM_TB * 50 * 10000; i++)
        if(i % (50*10000) == 0 ) {
          int block_num = i / (50*10000) ;
          printf("[%d] sets %d to %d(i:%d)\n", blockIdx.x, block_num, 20*block_num, i);
          tb_alloc_tbl[1] = 20*block_num;
        }
      //server_done = 1;
    } END_SINGLE_THREAD_PART;
  } else {
    do {
      while(!tb_alloc_tbl[blockIdx.x]) { } 
      printf("[%2d,%2d] %dth %d\n", blockIdx.x, threadIdx.x, num++, tb_alloc_tbl[blockIdx.x]);
      //tb_alloc_tbl[blockIdx.x] = 0;
      //if(threadIdx.x < tb_alloc_tbl[blockIdx.x]) {
      //  printf("[%2d,%2d]\n", blockIdx.x, threadIdx.x);
      //} else {
      //}
      if(tb_alloc_tbl[blockIdx.x] == 40)
        break;
      tb_alloc_tbl[blockIdx.x] = 0;
    } while(!tb_alloc_tbl[blockIdx.x]);
  }
  //printf("[%d] server_done2:%d\n", blockIdx.x, server_done);
}

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


#define COMPILER_BARRIER() asm volatile("" ::: "memory")
#define cpu_to_le32(x) ((__le32)(__swab32)(x))


__global__ void doorbell_test(void * io_addr, void * desc, uint32_t curr, int* g_mem, int size, int* flag)
{
  *flag = 0;
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

      //ARPOutput(pktBuf, arp_op_request, src_ip, dst_ip, dst_haddr);

      //DumpPacket(pktBuf, 60);


      for(int i=0; i< size/sizeof(int); i++) {
        g_mem[i] = 0;
      }

      for(int i=0; i< 512; i++) {
        memcpy(g_mem+4096*i/4, pktBuf, 60);
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
      unsigned long tail_val = (unsigned long)((curr + num_packets) % 512);
      *(volatile unsigned long*)db[0] = tail_val;

      COMPILER_BARRIER();

      //__threadfence_system();
      printf("[%s][%d] after flag=1.\n", __FUNCTION__, __LINE__);
      *flag = 1;
    } END_SINGLE_THREAD_PART;
    
  } else {
    // Second Block
    printf("[%s][%d] in doorbell_test Second Block.\n", __FUNCTION__, __LINE__);
    d_check_data(size, g_mem, flag);
  }
}

// YHOON~ for test
void yhoon_xmit_arp(int *g_mem, int size)
{
  printf("[%s][%d]START---yhoon_xmit_arp------------HOST.\n", __FUNCTION__, __LINE__);
  printf("[%s][%d] sizeof tx_desc:%lu \n", __FUNCTION__, __LINE__, sizeof(union ixgbe_adv_tx_desc));
  const char *myinode = "/dev/ixgbe";
  int fd = open(myinode, O_RDWR);
  //uint64_t ptr = 1234;
  //ioctl(fd, 0, &ptr);
  ioctl(fd, 1);

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
  cudaMalloc(&tx_desc, IXGBE_BAR0_SIZE * 4);
  if(cudaSuccess != cudaHostGetDevicePointer((void**)&tx_desc, (void*)desc, 0)) {
    cudaCheckErrors("cudaHostGetDevicePointer fails");
  }

  uint32_t curr_tx_index_q_zero = *(volatile unsigned int *)db[0];
  printf("curr_tx_index_q_zero: %u\n", curr_tx_index_q_zero);
  int *flag;
  cudaMalloc(&flag, sizeof(int));

	cudaStream_t cuda_stream;
  ASSERT_CUDA(cudaStreamCreate(&cuda_stream));

  doorbell_test<<< 1, 1, 0, cuda_stream >>>(dBAR, tx_desc, curr_tx_index_q_zero, g_mem, size, flag);

  //if(cudaSuccess != cudaDeviceSynchronize())
	//  cudaCheckErrors("doorbell_sync_error!");

  curr_num = curr_tx_index_q_zero;
  cudaHostUnregister(desc);
  cudaHostUnregister(ixgbe_bar0_host_addr);
  munmap(ixgbe_bar0_host_addr, IXGBE_BAR0_SIZE*5);

  // ~YHOON
  printf("[%s][%d]END-----yhoon_xmit_arp------------HOST.\n", __FUNCTION__, __LINE__);
}


int main(int argc, char *argv[])
{
  printf("[%s][%d] main\n", __FUNCTION__, __LINE__);
  int dev_id = 0;
  size_t _pkt_buffer_size = 2*512*4096; // 4MB, for rx,tx ring
  size_t pkt_queue_size = 50*1024*1024; // 50MB, for packet queue

  // CKJUNG, meaning of this?
  size_t pkt_buffer_size = (_pkt_buffer_size + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;
  printf("[%s][%d]____CKJUNG__pkt_buffer_size: %lu\n", __FUNCTION__, __LINE__, pkt_buffer_size);

  int n_devices = 0;

  ASSERTRT(cudaGetDeviceCount(&n_devices));

  cudaDeviceProp prop;
  for (int n=0; n<n_devices; ++n) { cudaGetDeviceProperties(&prop,n); OUT << "GPU id:" << n << " name:" << prop.name 
      << " PCI domain: " << prop.pciDomainID 
      << " bus: " << prop.pciBusID 
      << " device: " << prop.pciDeviceID << endl;
  }
  OUT << "selecting device " << dev_id << endl;
  OUT << "_pkt_buffer_size: " << _pkt_buffer_size << "  pkt_buffer_size: " << pkt_buffer_size << endl;

  ASSERTRT(cudaSetDevice(dev_id));
  //ASSERTRT(cudaSetDeviceFlags(cudaDeviceMapHost));

  OUT << "Before dummy malloc" << endl;
  // Test
  void* dummy;
  ASSERTRT(cudaMalloc(&dummy, 0));

  OUT << "Before d_pkt_buffer malloc" << endl;
  int* d_pkt_buffer;
  ASSERTRT(cudaMalloc((void**)&d_pkt_buffer, pkt_buffer_size));
  
  unsigned int flag = 1;
  ASSERTDRV(cuPointerSetAttribute(&flag, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr) d_pkt_buffer));


  my_t g = my_open();

  ASSERT_NEQ(g, (void*)0);

  my_mh_t mh;
  if (my_pin_buffer(g, (CUdeviceptr)d_pkt_buffer, pkt_buffer_size, 0, 0, &mh)  != 0)
    OUT << "NOT_EQ" << endl;

  OUT << "Before xmit" << endl;
  // call ixgbe_xmit_yhoon in ixgbe_main.c
  yhoon_xmit_arp(d_pkt_buffer, pkt_buffer_size);

  if(cudaSuccess != cudaDeviceSynchronize())
	  cudaCheckErrors("make_pkt_error"); 

  OUT << "END" << endl;
  cudaFree(d_pkt_buffer);
  return 0;
}
