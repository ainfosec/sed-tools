/** @file packet.h
 *  @brief Prototypes that initializes the packet portion of the compacket 
 *
 *  This file contains a structure that identifies all of the members
 *  that are needed to create the packet portion of the compacket. It also
 *  contains a prototype that initialize the packet
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 *  @bug No Bugs
 */

#ifndef __SED_PACKET_H__
#define __SED_PACKET_H__

#include <inttypes.h>
#include "../sed/sed.h"

#define SIZEOF_PACKET_HDR sizeof(struct packet_t)

struct packet_t
{
	uint32_t sessionTPer;
	uint32_t sessionHost;
	uint32_t seqNumber;
	uint16_t reserved;
	uint16_t ackType;
	uint32_t acknowledgement;
	uint32_t length;
}__attribute__((packed));


/**
*    @brief Initialize the packet for SED communication
*
*    Creates the packet which is contained within the compacket
*    This function creates that packet and places it in the correct
*    location within the compacket
*
*    @param pointer to the location where the packet is to be stored.
*    @return Void
*/
void packet_create(struct sedContext *sedCtx, struct packet_t *packet);

#endif /* __SED_PACKET_H__ */
