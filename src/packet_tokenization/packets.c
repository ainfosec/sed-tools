#include "../include/packet_tokenization/packets.h"
#include <stdint.h>
#include "../include/sed/sed.h"

int32_t packets_initialize(struct sedContext *sedCtx)
{
    struct comPacket_t *comPacket;
    struct packet_t *packet;
    struct dataSubpacket_t *dataSubpacket;

    // Starts setting up the entire packet by creating the compack, which is
    // at the begining of the entire packet
    comPacket = (struct comPacket_t*)sedCtx->packet;

    // Sets up the appropriate values in the compacket struct. This should
    // also store those values into the buffer.
    compacket_create(comPacket, sedCtx);

    // Sets up the next region of the entirePacket, which is packet. Since
    // comPacket is already setup within the entirePacket, we want to setup
    // packet along side comPacket which is compacket + 1.  
    packet = (struct packet_t*)(comPacket + 1);  

    // Sets up the appropriate values in the compacket struct. This finishes
    // aligning the packet and setting its values in the correct spot
    // within the buffer
    packet_create(sedCtx, packet);
    
    packet->sessionHost = switchEndian(sedCtx->hostSessionNumber,4);  
    packet->sessionTPer = switchEndian(sedCtx->tperSessionNumber, 4);
    packet->seqNumber = switchEndian(sedCtx->setHostSequenceNumbers + 1, sizeof(int32_t));

    // Datasubpacket is the third packet that should be inside the entirePacket
    // Therefore it is located at packet + 1
    dataSubpacket = (struct dataSubpacket_t*)(packet + 1);

    // Sets up all of the values in the dataSubpacket struct and dumps it 
    // into the entire buffer at the correct location.
    datasubpacket_create(dataSubpacket);

    return (int32_t)((uint8_t*)dataSubpacket - (uint8_t*)comPacket + SIZEOF_DATASUBPACKET_HDR);
}

uint32_t packets_updateLengths(struct sedContext *sedCtx, uint32_t dataPayloadIndex)
{
    uint32_t finalSizeMod4;
    struct comPacket_t *comPacket = (struct comPacket_t*)sedCtx->packet;
    struct packet_t *packet = (struct packet_t*)(sedCtx->packet
            + SIZEOF_COMPACKET_HDR);
    struct dataSubpacket_t *dataSubpacket =
            (struct dataSubpacket_t*)(sedCtx->packet + SIZEOF_COMPACKET_HDR
                    + SIZEOF_PACKET_HDR);

    // Determine packet size (modular 4 byte)
    if (dataPayloadIndex % 4)
        finalSizeMod4 = dataPayloadIndex - (dataPayloadIndex % 4) + 4;
    else
        finalSizeMod4 = dataPayloadIndex;
    // This technically rounds up 4 bytes too many (if mod 4 == 0)

    // Update length fields, don't include padding
    dataSubpacket->length = switchEndian(dataPayloadIndex, 4);

    // Include padding
    packet->length = switchEndian(finalSizeMod4 + SIZEOF_DATASUBPACKET_HDR, 4);

    comPacket->length = switchEndian(
            finalSizeMod4 + SIZEOF_DATASUBPACKET_HDR + SIZEOF_PACKET_HDR, 4);
    
    return switchEndian(comPacket->length,4)+SIZEOF_COMPACKET_HDR;
}

int32_t packets_check(struct sedContext *sedCtx)
{
    uint32_t i = 0, lenTotal, lenComPacket, lenPacket, lenSubpacket, lenPadding, remainder;
    struct comPacket_t *comPacket = (struct comPacket_t*)sedCtx->packet;
    struct packet_t *packet = (struct packet_t*)(comPacket+1);
    struct dataSubpacket_t *dataSubpacket = (struct dataSubpacket_t*)(packet+1);

    return SIZEOF_COMPACKET_HDR+SIZEOF_DATASUBPACKET_HDR+SIZEOF_PACKET_HDR;
    // the rules apparently don't apply to the TPer

    // Extended ComId must be baseComId
    if(comPacket->extendedComId != switchEndian(sedCtx->baseComId,2))
    {
        // error
        printf("Error in return packet: Bad Extended ComId!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(packet->sessionHost != switchEndian(sedCtx->hostSessionNumber,4))
    {
        // error
        printf("Error in return packet: Bad Host Session NUmber!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(packet->sessionTPer != sedCtx->tperSessionNumber)
    {
        // error
        printf("Error in return packet: Bad TPer Session Number!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }

    // Make sure the length fields make sense
    // There are rules behind the lengths, make sure they adhere
    lenSubpacket = switchEndian(dataSubpacket->length, sizeof(dataSubpacket->length));
    lenPacket = switchEndian(packet->length, sizeof(packet->length));
    lenComPacket = switchEndian(comPacket->length, sizeof(comPacket->length));
    lenTotal = lenComPacket + SIZEOF_COMPACKET_HDR;
    // The ComPacket and Packet length must be modulus 4
    if(lenPacket % 4 || lenComPacket % 4)
    {
        if(lenComPacket % 4)
            printf("Error in return packet: ComPacket length must be modulus 4!\n");
        if(lenPacket % 4)
            printf("Error in return packet: Packet length must be modulus 4!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    // The packets should all point to the same point (with padding accounted for)
    // Compare subpacket to packet
    remainder = (lenSubpacket + SIZEOF_DATASUBPACKET_HDR) / 4;
    if (remainder != (lenPacket/4))
    {
        printf("Error in return packet: Inconsistency in length fields!\n");
    }
    // Compare packet to compacket
    remainder = (lenPacket + SIZEOF_PACKET_HDR) / 4;
    if (remainder != (lenComPacket/4))
    {
        printf("Error in return packet: Inconsistency in length fields!\n");
    }

    // The Method Status List must be within the last 8 bytes
    // So find it
    lenPadding = (4 - (lenSubpacket%4))%4;
    i = lenTotal - lenPadding - 1; // should point at end of method status list
    if(sedCtx->packet[i] != EndListToken)
    {
        printf("Error in return packet: No Method Status List Found!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    i -= 4;
    if(sedCtx->packet[i] != StartListToken)
    {
        printf("Error in return packet: No Method Status List Found!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    return (int32_t)((uint8_t*)dataSubpacket - (uint8_t*)comPacket + SIZEOF_DATASUBPACKET_HDR);
}
