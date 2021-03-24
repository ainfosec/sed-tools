/** @file datasubpacket.h
 *  @brief Prototype that initializes the datasubpacket portion of the compacket 
 *
 *  This file contains a structure that identifies all of the members
 *  that are needed to create the datasubpacket portion of the compacket. It also
 *  contains a prototype that initialize the datasubpacket
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 *  @bug No Bugs
 */

#ifndef __SED_DATASUBPACKET_H__
#define __SED_DATASUBPACKET_H__

#include <inttypes.h>

#define SIZEOF_DATASUBPACKET_HDR sizeof(struct dataSubpacket_t)

struct dataSubpacket_t
{
	uint64_t reserved:48;
	uint64_t kind:16;
	uint32_t length;
}__attribute__((packed));


/**
*    @brief Initialize the Data SubPacket for SED communication
*
*    Creates the data subpacket which is contained within the packet which
*    in itself is contained within the compacket. This function creates that
*    subpacket and places it in the correct location within the compacket
*
*    @param pointer to the location where the subpacket is to be stored. (Right after the packet)
*    @return Void
*/
void datasubpacket_create(struct dataSubpacket_t *dataSubPacket);

#endif /* __SED_DATASUBPACKET_H__ */
