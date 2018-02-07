#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "icmp.h"

#define IP_NEXT_PTR(iph) ((uint8_t *)iph + (iph->ihl << 2))

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif



/*----------------------------------------------------------------------------*/
__device__ void 
DumpICMPPacket(struct icmphdr *icmph, uint32_t saddr, uint32_t daddr)
{
	uint8_t *t;
	
	printf("ICMP header: \n");
	printf("Type: %d, "
		"Code: %d, ID: %d, Sequence: %d\n", 
		icmph->icmp_type, icmph->icmp_code,
		NTOHS(ICMP_ECHO_GET_ID(icmph)), NTOHS(ICMP_ECHO_GET_SEQ(icmph)));
	
	t = (uint8_t *)&saddr;
	printf("Sender IP: %u.%u.%u.%u\n",
		t[0], t[1], t[2], t[3]);
	
	t = (uint8_t *)&daddr;
	printf("Target IP: %u.%u.%u.%u\n",
		t[0], t[1], t[2], t[3]);
}
/*----------------------------------------------------------------------------*/

__device__ int 
ProcessICMPPacket(struct iphdr *iph, int len)
{
  printf("[%s][%d]\n",__FUNCTION__, __LINE__);
#if 1
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
	
	switch (icmph->icmp_type) {
        case ICMP_ECHO:
          printf("[%s][%d] [INFO] ICMP_ECHO received\n", __FUNCTION__, __LINE__);
          //ProcessICMPECHORequest(iph, len);
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
#endif
  return TRUE;
}


#undef IP_NEXT_PTR
