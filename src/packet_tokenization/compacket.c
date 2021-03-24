/** @file compacket.c
 *  @brief Initializes the overall Compacket to be transmitted 
 *
 *  This file contains the function defintion to create and initialize
 *  the overall compacket.
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 */
#include "../include/packet_tokenization/compacket.h"

void compacket_create(struct comPacket_t *comPacket, struct sedContext *sedCtx)
{
	comPacket->reserved = 0;
	comPacket->extendedComId = switchEndian(sedCtx->baseComId,2);
	comPacket->outstandingData = 0;
	comPacket->minTransfer = 0;
	comPacket->length = 0;
}
