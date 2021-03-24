/** @file compacket.h
 *  @brief Prototypes that initializes the overall Compacket to be transmitted 
 *
 *  This file contains a structure that identifies all of the members
 *  that are needed to create the compacket. It also contains a prototype
 *  that initialize the entire
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 *  @bug No Bugs
 */

#ifndef __SED_COMPACKET_H__
#define __SED_COMPACKET_H__

#include <inttypes.h>
#include "../sed/sed.h"

#define SIZEOF_COMPACKET_HDR sizeof(struct comPacket_t)

struct comPacket_t
{
	uint32_t reserved;
	uint32_t extendedComId;
	uint32_t outstandingData;
	uint32_t minTransfer;
	uint32_t length;
}__attribute__((packed));


/**
*    @brief Initialize compacket for SED communication
*
*    Creates the overall compacket, which is the primary unit of
*    communication transmitted as the payload. This function creates that
*    compacket and initialize everything within it
*
*    @param comPacket   Location where the compacket should be stored
*    @param sedCtx      Pointer to the Sed context struct
*    @return Void
*/
void compacket_create(struct comPacket_t *comPacket, struct sedContext *sedCtx);

#endif /* __SED_COMPACKET_H__ */
