#ifndef __SED_TOOLS_PACKETS_H__
#define __SED_TOOLS_PACKETS_H__

#include <stdint.h>
#include "compacket.h"
#include "dataPayload.h"
#include "datasubpacket.h"
#include "packet.h"

#define SIZEOF_PACKET_HEADERS SIZEOF_DATASUBPACKET_HDR+SIZEOF_PACKET_HDR+SIZEOF_COMPACKET_HDR

/**
    @brief Initialize the ComPacket, Data Packet and Data Subpacket for SED communication

    This function will zero out the ComPacket, Data Packet and Data Subpacket of a packet for SED Communication.  If a SpSessionId has been specified it will fill that field in the data packet field.  The Host Session Number is ALWAYS initialized to 1.

    @param start of the entire packet (index 0). This is where the compacket struct starts

    @param SpSessionId - The Security Peripheral Session Id (if not yet initialized, 0)

    @return the size of the packet headers.  This is the index into the SED packet to the data payload. 

    \code
    index = packets_initialize(entirePacketStart, gSpSessionId);
    \endcode

    @note   The HostSessionId is always initialized to 1.  If more than 1 session gets opened to the SED, this will cause an error.  Should make this dynamic
*/
int32_t packets_initialize(struct sedContext *sedCtx);


/**
    @brief Updates the size field in each packet header to include the size of the data payload

    The packets_initialize function zero's out all the size fields in each packet header.  When the data payload is populated, the size field needs to be updated to include the size of the data payload.

    @param entirePacketStart - start of the entire packet to be sent for SED communication.

    @param dataPayloadIndex - index into the dataPayload to the end of the data payload

    @return the raw size of the entire packet (com packet header start to end of datapayload). This size is rounded to the nearest 4 bytes.  When outputting, it must be to the nearest 512. This was done for debugging (minimize printed bytes)

    \code
    totalSize = packets_updateLengths(entirePacketStart, finalIndexValue);
    \endcode

    @note   The return represents the size of the packet mod 4.  To output this value must be changed to mod 512
*/
uint32_t packets_updateLengths(struct sedContext *sedCtx, uint32_t dataPayloadIndex);

/**
    @brief Checks to make sure all packet headers are consistent with regards to lengths, com ids and session ids

    When getting a packet back from tper, the packet headers should be inspected for errors.  Errors may give bad results back to host app

    @param sedCtx - struct maintaining all data about the tper - host relationship

    @return on success, index to the data payload in the packet, otherwise SED_ERROR

    \code
    retSize = packets_check(sedCtx);
    \endcode

    @note   I'm not sure how necessary this is
*/
int32_t packets_check(struct sedContext *sedCtx);

#endif /*__SED_TOOLS_PACKETS_H__*/
