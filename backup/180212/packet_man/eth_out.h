#ifndef __ETH_OUT_H_
#define __ETH_OUT_H_

#include <stdint.h>

#define MAX_SEND_PCK_CHUNK 64

uint8_t *
EthernetOutput(uint16_t h_proto, int nif, unsigned char* dst_haddr, uint16_t iplen);

#endif /* __ETH_OUT_H_ */
