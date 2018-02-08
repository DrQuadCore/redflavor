#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "icmp.cu.h"

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

/*----------------------------------------------------------------------------*/

#undef IP_NEXT_PTR
