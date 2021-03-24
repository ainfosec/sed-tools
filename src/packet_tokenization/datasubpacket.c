/** @file datasubpacket.c
 *  @brief Initializes the datasubpacket portion of the compacket 
 *
 *  This file contains the function definition that will create 
 *  and initialize the datasubpacket within the compacket
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 */

#include "../include/packet_tokenization/datasubpacket.h"

void datasubpacket_create(struct dataSubpacket_t *dataSubpacket)
{
	dataSubpacket->reserved = 0ll;
	dataSubpacket->kind = 0;
	dataSubpacket->length = 0;
}
