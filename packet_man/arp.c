#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <sys/queue.h> // HONESTCHOI : TAILQ, etc..
#include <string.h> // HONESTCHOI : memset
#include <stdlib.h> // HONESTCHOI : free

// HONESTCHOI :  Begins - Copy from tcp source in mTCP
#define TCP_SEQ_LT(a,b)                 ((int32_t)((a)-(b)) < 0)
#define TCP_SEQ_LEQ(a,b)                ((int32_t)((a)-(b)) <= 0)
#define TCP_SEQ_GT(a,b)                 ((int32_t)((a)-(b)) > 0)
#define TCP_SEQ_GEQ(a,b)                ((int32_t)((a)-(b)) >= 0)
#define TCP_SEQ_BETWEEN(a,b,c)  (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))
/* convert timeval to timestamp (precision: 1 ms) */
#define HZ                                              1000
#define TIME_TICK                               (1000000/HZ)            // in us
#define TIMEVAL_TO_TS(t)                (uint32_t)((t)->tv_sec * HZ + \
                                                                ((t)->tv_usec / TIME_TICK))

#define TS_TO_USEC(t)                   ((t) * TIME_TICK)
#define TS_TO_MSEC(t)                   (TS_TO_USEC(t) / 1000)

#define USEC_TO_TS(t)                   ((t) / TIME_TICK)
#define MSEC_TO_TS(t)                   (USEC_TO_TS((t) * 1000))
#define SEC_TO_TS(t)                    (t * HZ)

#define SEC_TO_USEC(t)                  ((t) * 1000000)
#define SEC_TO_MSEC(t)                  ((t) * 1000)
#define MSEC_TO_USEC(t)                 ((t) * 1000)
#define USEC_TO_SEC(t)                  ((t) / 1000000)
//#define TCP_TIMEWAIT                  (MSEC_TO_USEC(5000) / TIME_TICK)        // 5s
#define TCP_TIMEWAIT                    0
#define TCP_INITIAL_RTO                 (MSEC_TO_USEC(500) / TIME_TICK)         // 500ms
#define TCP_FIN_RTO                             (MSEC_TO_USEC(500) / TIME_TICK)         // 500ms
#define TCP_TIMEOUT                             (MSEC_TO_USEC(30000) / TIME_TICK)       // 30s

#define TCP_MAX_RTX                             16
#define TCP_MAX_SYN_RETRY               7
#define TCP_MAX_BACKOFF                 7
// HONESTCHOI :  Ends   - Copy from tcp source in mTCP

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE 
#define FALSE 0
#endif
// #include "mtcp.h"
#include "arp.h"
// #include "eth_out.h"
// #include "debug.h"

#define ARP_PAD_LEN 18			/* arp pad length to fit 64B packet size */
#define ARP_TIMEOUT_SEC 1		/* 1 second arp timeout */

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
/*----------------------------------------------------------------------------*/
struct arphdr
{
	uint16_t ar_hrd;			/* hardware address format */
	uint16_t ar_pro;			/* protocol address format */
	uint8_t ar_hln;				/* hardware address length */
	uint8_t ar_pln;				/* protocol address length */
	uint16_t ar_op;				/* arp opcode */
	
	uint8_t ar_sha[ETH_ALEN];	/* sender hardware address */
	uint32_t ar_sip;			/* sender ip address */
	uint8_t ar_tha[ETH_ALEN];	/* targe hardware address */
	uint32_t ar_tip;			/* target ip address */

	uint8_t pad[ARP_PAD_LEN];
} __attribute__ ((packed));
/*----------------------------------------------------------------------------*/
struct arp_queue_entry
{
	uint32_t ip;		/* target ip address */
	int nif_out;		/* output interface number */
	uint32_t ts_out;	/* last sent timestamp */

	TAILQ_ENTRY(arp_queue_entry) arp_link;
};
/*----------------------------------------------------------------------------*/
struct arp_manager
{
	TAILQ_HEAD (, arp_queue_entry) list;
	pthread_mutex_t lock;
};
/*----------------------------------------------------------------------------*/
struct arp_manager g_arpm;
/*----------------------------------------------------------------------------*/
void 
DumpARPPacket(struct arphdr *arph);
/*----------------------------------------------------------------------------*/
int 
InitARPTable()
{
#if 0 // HONESTCHOI : Unnecessary ?
	CONFIG.arp.entries = 0;

	CONFIG.arp.entry = (struct arp_entry *)
				calloc(MAX_ARPENTRY, sizeof(struct arp_entry));
	if (CONFIG.arp.entry == NULL) {
		perror("calloc");
		return -1;
	}
#endif 
	TAILQ_INIT(&g_arpm.list);
	pthread_mutex_init(&g_arpm.lock, NULL);

	return 0;
}
/*----------------------------------------------------------------------------*/
unsigned char *
GetHWaddr(uint32_t ip)
{
	int i;
	unsigned char *haddr = NULL;
#if 0 // HONESTCHOI : TODO
	for (i = 0; i < CONFIG.eths_num; i++) {
		if (ip == CONFIG.eths[i].ip_addr) {
			haddr = CONFIG.eths[i].haddr;
			break;
		}	
	}
#endif

	return haddr;
}
/*----------------------------------------------------------------------------*/
unsigned char *
GetDestinationHWaddr(uint32_t dip)
{
	unsigned char *d_haddr = NULL;
	int prefix = 0;
	int i;

#if 0 // HONESTCHOI : TODO
	/* Longest prefix matching */
	for (i = 0; i < CONFIG.arp.entries; i++) {
		if (CONFIG.arp.entry[i].prefix == 1) {
			if (CONFIG.arp.entry[i].ip == dip) {
				d_haddr = CONFIG.arp.entry[i].haddr;
				break;
			}	
		} else {
			if ((dip & CONFIG.arp.entry[i].ip_mask) ==
					CONFIG.arp.entry[i].ip_masked) {
				
				if (CONFIG.arp.entry[i].prefix > prefix) {
					d_haddr = CONFIG.arp.entry[i].haddr;
					prefix = CONFIG.arp.entry[i].prefix;
				}
			}
		}
	}
#endif
	return d_haddr;
}
/*----------------------------------------------------------------------------*/
static int 
ARPOutput(int nif, int opcode,
		uint32_t dst_ip, unsigned char *dst_haddr, unsigned char *target_haddr)
{
	if (!dst_haddr)
		return -1;

	/* Allocate a buffer */
#if 0
	struct arphdr *arph = (struct arphdr *)EthernetOutput(mtcp, 
			ETH_P_ARP, nif, dst_haddr, sizeof(struct arphdr));
	if (!arph) {
		return -1;
	}
#else 
	struct arphdr *arph = NULL;
#endif
	/* Fill arp header */
	arph->ar_hrd = htons(arp_hrd_ethernet);
	arph->ar_pro = htons(ETH_P_IP);
	arph->ar_hln = ETH_ALEN;
	arph->ar_pln = 4;
	arph->ar_op = htons(opcode);

	/* Fill arp body */
#if 0 // HONESTCHOI : TODO
	arph->ar_sip = CONFIG.eths[nif].ip_addr;
#endif 
	arph->ar_tip = dst_ip;

#if 0 // HONESTCHOI : TODO
	memcpy(arph->ar_sha, CONFIG.eths[nif].haddr, arph->ar_hln);
#endif
	if (target_haddr) {
		memcpy(arph->ar_tha, target_haddr, arph->ar_hln);
	} else {
		memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
	}
	memset(arph->pad, 0, ARP_PAD_LEN);

#if DBGMSG
	DumpARPPacket(arph);
#endif

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
RegisterARPEntry(uint32_t ip, const unsigned char *haddr)
{
#if 0 // HONESTCHOI : Unnecessary 
	int idx = CONFIG.arp.entries;
	
	CONFIG.arp.entry[idx].prefix = 32;
	CONFIG.arp.entry[idx].ip = ip;
	memcpy(CONFIG.arp.entry[idx].haddr, haddr, ETH_ALEN);
	CONFIG.arp.entry[idx].ip_mask = -1;
	CONFIG.arp.entry[idx].ip_masked = ip;

	CONFIG.arp.entries = idx + 1;

	TRACE_CONFIG("Learned new arp entry.\n");
	PrintARPTable();
#endif
	return 0;
}
/*----------------------------------------------------------------------------*/
void 
RequestARP(uint32_t ip, int nif, uint32_t cur_ts)
{
	struct arp_queue_entry *ent;
	unsigned char haddr[ETH_ALEN];
	unsigned char taddr[ETH_ALEN];

	pthread_mutex_lock(&g_arpm.lock);
	/* if the arp request is in progress, return */
	TAILQ_FOREACH(ent, &g_arpm.list, arp_link) {
		if (ent->ip == ip) {
			pthread_mutex_unlock(&g_arpm.lock);
			return;
		}
	}

	ent = (struct arp_queue_entry *)calloc(1, sizeof(struct arp_queue_entry));
	ent->ip = ip;
	ent->nif_out = nif;
	ent->ts_out = cur_ts;
	TAILQ_INSERT_TAIL(&g_arpm.list, ent, arp_link);
	pthread_mutex_unlock(&g_arpm.lock);

	/* else, broadcast arp request */
	memset(haddr, 0xFF, ETH_ALEN);
	memset(taddr, 0x00, ETH_ALEN);
	ARPOutput(nif, arp_op_request, ip, haddr, taddr);
}
/*----------------------------------------------------------------------------*/
static int 
ProcessARPRequest(struct arphdr *arph, int nif, uint32_t cur_ts)
{
	unsigned char *temp;

	/* register the arp entry if not exist */
	temp = GetDestinationHWaddr(arph->ar_sip);
	if (!temp) {
		RegisterARPEntry(arph->ar_sip, arph->ar_sha);
	}

	/* send arp reply */
	ARPOutput(nif, arp_op_reply, arph->ar_sip, arph->ar_sha, NULL);

	return 0;
}
/*----------------------------------------------------------------------------*/
static int 
ProcessARPReply(struct arphdr *arph, uint32_t cur_ts)
{
	unsigned char *temp;
	struct arp_queue_entry *ent;

	/* register the arp entry if not exist */
	temp = GetDestinationHWaddr(arph->ar_sip);
	if (!temp) {
		RegisterARPEntry(arph->ar_sip, arph->ar_sha);
	}

	/* remove from the arp request queue */
	pthread_mutex_lock(&g_arpm.lock);
	TAILQ_FOREACH(ent, &g_arpm.list, arp_link) {
		if (ent->ip == arph->ar_sip) {
			TAILQ_REMOVE(&g_arpm.list, ent, arp_link);
			free(ent);
			break;
		}
	}
	pthread_mutex_unlock(&g_arpm.lock);

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
ProcessARPPacket(uint32_t cur_ts,
		                  const int ifidx, unsigned char *pkt_data, int len)
{
	struct arphdr *arph = (struct arphdr *)(pkt_data + sizeof(struct ethhdr));
	int i;
	int to_me = FALSE;
	
	/* process the arp messages destined to me */
#if 0 // HONESTCHOI : TO DO
	for (i = 0; i < CONFIG.eths_num; i++) {
		if (arph->ar_tip == CONFIG.eths[i].ip_addr) {
			to_me = TRUE;
		}
	}
#endif 
	if (!to_me)
		return TRUE;
	
#if DBGMSG
	DumpARPPacket(arph);
#endif

	switch (ntohs(arph->ar_op)) {
		case arp_op_request:
			ProcessARPRequest(arph, ifidx, cur_ts);
			break;

		case arp_op_reply:
			ProcessARPReply(arph, cur_ts);
			break;

		default:
			break;
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/
/* ARPTimer: wakes up every milisecond and check the ARP timeout              */
/*           timeout is set to 1 second                                       */
/*----------------------------------------------------------------------------*/
void 
ARPTimer(uint32_t cur_ts)
{
	struct arp_queue_entry *ent;

	/* if the arp requet is timed out, retransmit */
	pthread_mutex_lock(&g_arpm.lock);
	TAILQ_FOREACH(ent, &g_arpm.list, arp_link) {
		if (TCP_SEQ_GT(cur_ts, ent->ts_out + SEC_TO_TS(ARP_TIMEOUT_SEC))) {
			TAILQ_REMOVE(&g_arpm.list, ent, arp_link);
			free(ent);
		}
	}
	pthread_mutex_unlock(&g_arpm.lock);
}
/*----------------------------------------------------------------------------*/
void
PrintARPTable()
{
#if 0 // HONESTCHOI :  Necessary ?
	int i;
		
	/* print out process start information */
	fprintf(stderr,"ARP Table:\n");
	for (i = 0; i < CONFIG.arp.entries; i++) {
			
		uint8_t *da = (uint8_t *)&CONFIG.arp.entry[i].ip;

		fprintf(stderr,"IP addr: %u.%u.%u.%u, "
				"dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				da[0], da[1], da[2], da[3],
				CONFIG.arp.entry[i].haddr[0],
				CONFIG.arp.entry[i].haddr[1],
				CONFIG.arp.entry[i].haddr[2],
				CONFIG.arp.entry[i].haddr[3],
				CONFIG.arp.entry[i].haddr[4],
				CONFIG.arp.entry[i].haddr[5]);
	}
	if (CONFIG.arp.entries == 0)
		fprintf(stderr,("(blank)\n");

#endif 
	fprintf(stderr,"----------------------------------------------------------"
			"-----------------------\n");
}
/*----------------------------------------------------------------------------*/
void 
DumpARPPacket(struct arphdr *arph)
{
	uint8_t *t;

	fprintf(stderr, "ARP header: \n");
	fprintf(stderr, "Hardware type: %d (len: %d), "
			"protocol type: %d (len: %d), opcode: %d\n", 
			ntohs(arph->ar_hrd), arph->ar_hln, 
			ntohs(arph->ar_pro), arph->ar_pln, ntohs(arph->ar_op));
	t = (uint8_t *)&arph->ar_sip;
	fprintf(stderr, "Sender IP: %u.%u.%u.%u, "
			"haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
			t[0], t[1], t[2], t[3], 
			arph->ar_sha[0], arph->ar_sha[1], arph->ar_sha[2], 
			arph->ar_sha[3], arph->ar_sha[4], arph->ar_sha[5]);
	t = (uint8_t *)&arph->ar_tip;
	fprintf(stderr, "Target IP: %u.%u.%u.%u, "
			"haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
			t[0], t[1], t[2], t[3], 
			arph->ar_tha[0], arph->ar_tha[1], arph->ar_tha[2], 
			arph->ar_tha[3], arph->ar_tha[4], arph->ar_tha[5]);
}
/*----------------------------------------------------------------------------*/
