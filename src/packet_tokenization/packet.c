/** @file packet.c
 *  @brief Initializes the packet portion of the compacket 
 *
 *  This file contains the function definition that will create
 *  and initialize the packet portion of the compacket
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 */

#include "../include/packet_tokenization/packet.h"

void packet_create(struct sedContext *sedCtx, struct packet_t *packet)
{	
	packet->sessionTPer = 0;
	packet->sessionHost = 0;
	packet->seqNumber = 0;
	packet->reserved = 0;
	packet->ackType = 0;
	packet->acknowledgement = 0;
	packet->length = 0;
}
