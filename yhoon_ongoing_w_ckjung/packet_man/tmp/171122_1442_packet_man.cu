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


#if 0
__global__ void init_data(int size, int* d_A)
#else
void init_data(int size, unsigned char* h_mem, int* d_A)
#endif
{
	for(int i=0; i<size/2; i++)
		h_mem[i] = 0;
//	cudaMemcpy(d_A, h_mem, size, cudaMemcpyHostToDevice);

	char * arp_req = (char*) malloc(100*sizeof(char));

	//uint64_t seed = 0;
	//build_packet(arp_req, 1000, &seed);  

	uint8_t* buf;
	buf = (uint8_t *) malloc(60);
	uint8_t src_tmp[] = {0x0a, 0x00, 0x00, 0x02};
	uint8_t dst_tmp[] = {0x0a, 0x00, 0x00, 0x01};
	uint32_t src_ip;
	memcpy(&src_ip, src_tmp, 4);
	uint32_t dst_ip;
	memcpy(&dst_ip, dst_tmp, 4);

	unsigned char dst_haddr[ETH_ALEN];
	memset(dst_haddr, 0xFF, ETH_ALEN);

	h_ARPOutput(buf, arp_op_request, src_ip, dst_ip, dst_haddr);

	//DumpPacket(buf, 60);

	for(int i=0; i< 512; i++) { // making 100 arpreq packets
		for(int j=0; j < 60; j++) { 
			 h_mem[4096*i+j] = buf[j];
			//d_A[4096*i+j] = buf[j];
		}
	}

	// for check
	for(int j = 0; j < 4096*512; j++) {
		if(*((uint16_t*)&h_mem[j]) == 0x0608 || *((uint16_t*)&h_mem[j]) == 0x0806 ){
			printf("[%s][%d] We found ethernet type 0x%02x%02x on %dth memory.\n", 
					__FUNCTION__ , __LINE__, h_mem[j], h_mem[j+1], j);
		}
	}

	//cudaMemcpy(d_A, h_mem, size, cudaMemcpyHostToDevice);

}

int curr_num;
#if 0
__global__ void check_data(int size, unsigned char* h_mem, int* d_A)
#else
void check_data(int size, unsigned char* h_mem, int* d_A)
#endif
{
  printf("[%s][%d]----------------------------------------START---check_data------------HOST.\n", __FUNCTION__, __LINE__);
  cudaMemcpy(h_mem, d_A, size, cudaMemcpyDeviceToHost);
  uint32_t offset_for_rx = 511 * 4096 * 12;
  h_mem += offset_for_rx;

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
  int pkt_cnt = 0;
  //const int DUMP_SIZE = 30;
  for(int i = 0; i < size-offset_for_rx; i++) {
    if(*((uint16_t*)&h_mem[i]) == 0x0608 || *((uint16_t*)&h_mem[i]) == 0x0806 ) {//(h_mem[i] == 0x08 && h_mem[i+1] == 0x00) ) {
      pkt_cnt++;
      //printf("\n%s][%d] PACKET BEGINS-------------------------------------\n", __FUNCTION__, __LINE__);
      //printf("\n\n");
      printf("[%s][%d] We found ethernet type 0x%02x%02x on %dth memory. (%d pkts, curr:%d)\n", __FUNCTION__ , __LINE__, h_mem[i], h_mem[i+1],i, pkt_cnt, curr_num);
      //printf("[%s][%d] We found ethernet type 0x%04x on %dth memory.\n", __FUNCTION__ , __LINE__, *((uint16_t*)&h_mem[i]), i);
      
     // h_DumpPacket((uint8_t*)&h_mem[i-12], 60);
    } else if (h_mem[i] == 0xAB || h_mem[i] == 0xBA) {
      for(int packet_iter = i; packet_iter < (i+20); packet_iter++) {
        if((packet_iter-i) % 4 == 0)
          printf("\n");
        printf("%3d:0x%02x\t", packet_iter-i, h_mem[packet_iter]);
      }
	}
  }
  for(int i = 0; i < size-offset_for_rx; i++) 
    if(h_mem[i] != 0) 
      dirty_cnt++;
#endif
  //printf("[%s][%d] dirty_cnt:[%d]\n", __FUNCTION__ , __LINE__, dirty_cnt);
  printf("[%s][%d]----------------------------------------END---check_data------------HOST.\n", __FUNCTION__, __LINE__);
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

#ifndef __USE_GPU__
void doorbell_test(void * io_addr)
#else
__global__ void doorbell_test(void * io_addr, void * desc, uint32_t curr)
#endif
{
  //printf("[%s][%d] curr:%d\n", __FUNCTION__, __LINE__, curr);
  printf("[%s][%d] curr:%d---------------------------START---doorbell_test------------DEVICE.\n", __FUNCTION__, __LINE__,curr);

  unsigned char *db[12];
  for(int i=0; i<12; i++)
    db[i] = ((unsigned char *)io_addr) + IXGBE_TDT(i);

  COMPILER_BARRIER();
#if 0
  for(int i=0; i<12;i++)
    printf("[%s][%d] %d\n", __FUNCTION__, __LINE__, *(volatile unsigned int *)db[i] );
#endif
  volatile union ixgbe_adv_tx_desc* tx_desc;
  tx_desc = (union ixgbe_adv_tx_desc*) desc;

  int num_packets = 5;
  int index = curr;
  for(int i=0; i<curr; i++)
    tx_desc++;
  for(int i=0; i<num_packets; i++) {
    tx_desc->read.cmd_type_len |= 60;
    tx_desc->read.olinfo_status = 0xf0000;
    tx_desc++;
    index++;
    if(index == 512)
      tx_desc = (union ixgbe_adv_tx_desc*) desc;
  }
  unsigned long tail_val = (unsigned long)((curr + num_packets) % 512);
  printf("[%s][%d] tail_val:%x %x\n", __FUNCTION__, __LINE__, tail_val, tail_val >> 8);

  //*(volatile unsigned long*)db[0] = (unsigned long)((curr + num_packets) % 512);
  *(volatile unsigned long*)db[0] = tail_val;
  //*(volatile unsigned long*)(db[0]+1) = tail_val >> 8;
  printf("[%s][%d] curr:%d---------------------------END---doorbell_test------------DEVICE.\n", __FUNCTION__, __LINE__,curr);
}

#if 1
// YHOON~ for test
void yhoon_xmit_arp()
{
  printf("[%s][%d]---------------------------START---yhoon_xmit_arp------------HOST.\n", __FUNCTION__, __LINE__);
  printf("[%s][%d] sizeof tx_desc:%lu \n", __FUNCTION__, __LINE__, sizeof(union ixgbe_adv_tx_desc));
  const char *myinode = "/dev/ixgbe";
  int fd = open(myinode, O_RDWR);
  //uint64_t ptr = 1234;
  //ioctl(fd, 0, &ptr);
  ioctl(fd, 1);

  printf("cpu_to_le32 test:%x\n", htonl(60));
#ifndef __USE_GPU__
  void* dummy2;
  ASSERTRT(cudaMalloc(&dummy2, 4096*8));


#error "use_gpu"

  doorbell_test(dummy2);

#else
  void* dBAR;
  const size_t IXGBE_BAR0_SIZE = 4096*8; // A rough calculation
  void* ixgbe_bar0_host_addr = mmap(0, IXGBE_BAR0_SIZE*5 , PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  cudaHostRegister(ixgbe_bar0_host_addr, IXGBE_BAR0_SIZE, cudaHostRegisterIoMemory);
  cudaHostGetDevicePointer((void**)&dBAR, (void*)ixgbe_bar0_host_addr, 0);

  unsigned char *db[12];
  for(int i=0; i<1; i++) {
    db[i] = ((unsigned char *)ixgbe_bar0_host_addr) + IXGBE_TDT(i);
#if 1
    printf("db[%d]: %d\n", i, *(volatile unsigned int *)db[i]);
#endif
  }

  ixgbe_adv_tx_desc* desc = (ixgbe_adv_tx_desc*)((unsigned char*)ixgbe_bar0_host_addr + IXGBE_BAR0_SIZE);
  cudaHostRegister(desc, IXGBE_BAR0_SIZE * 4, cudaHostRegisterIoMemory);
  //cudaHostRegister(desc, sizeof(ixgbe_adv_tx_desc), cudaHostRegisterIoMemory);
  void* tx_desc;
  cudaHostGetDevicePointer((void**)&tx_desc, (void*)desc, 0);

  uint32_t curr_tx_index_q_zero = *(volatile unsigned int *)db[0];
  //printf("curr_tx_index_q_zero: %u\n", curr_tx_index_q_zero);
  doorbell_test<<< 1,1 >>>(dBAR, tx_desc, curr_tx_index_q_zero);
  //if(cudaSuccess != cudaDeviceSynchronize())
  //	cudaCheckErrors("doorbell_sync_error!");
  curr_num = curr_tx_index_q_zero;
#endif
  // ~YHOON
  printf("[%s][%d]---------------------------END---yhoon_xmit_arp------------HOST.\n", __FUNCTION__, __LINE__);
}
#else
// YHOON~ for test
void yhoon_xmit_arp()
{
  const char *myinode = "/dev/ixgbe";
  int fd = open(myinode, O_RDWR);
  uint64_t ptr = 1234;
  ioctl(fd, 0, &ptr);
  // ~YHOON
}
#endif

int main(int argc, char *argv[])
{
  printf("[%s][%d] main\n", __FUNCTION__, __LINE__);
  int dev_id = 0;
  size_t _size = 50*1024*1024; //50*1024*1024;

  // CKJUNG, meaning of this?
  size_t size = (_size + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;
  //printf("[%s][%d]____CKJUNG__size: %lu\n", __FUNCTION__, __LINE__, size);

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

  //init_data(size, h_mem, d_A);
  make_pkt<<<1,1>>>(d_A, size);


  // call ixgbe_xmit_yhoon in ixgbe_main.c
  yhoon_xmit_arp();

  if(cudaSuccess != cudaDeviceSynchronize())
	 cudaCheckErrors("make_pkt_error"); 

  int count = 0;
  while(count < 1) {
    check_data(size, h_mem, d_A);
    usleep(1*1000*1000);
    count++;
  }
  OUT << "END" << endl;
  cudaFree(d_A);

  return 0;
}
