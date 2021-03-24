#include "../include/sed/sed.h"

#include <stdio.h>
#include <string.h>


// Helper function to add a Name Property to the packet
int32_t addProperty(char *strName, uint32_t value, uint8_t *dataStart);
int32_t parseProperty(char *strProperty, uint32_t *valProperty,
        uint8_t *dataStart);

// Response functions can be made private
int32_t propertiesResponse(struct sedContext *sedCtx);
int32_t checkSyncSession(struct sedContext *sedCtx);

int32_t sessionManager_closeSession(struct sedContext *sedCtx)
{
    uint8_t *dataPayload;
    uint32_t index = 0, totalPacketLen;

    sedCtx->setHostSequenceNumbers = *(int32_t *)(sedCtx->packet + SIZEOF_COMPACKET_HDR + 8);

    // zero out entire packet
    memset(sedCtx->packet, 0, sedCtx->packetSize);
    dataPayload = (uint8_t*)(sedCtx->packet + packets_initialize(sedCtx));

    dataPayload[index++] = EndOfSessionToken;

    // Determine packet size (modular 4 byte)
    totalPacketLen = packets_updateLengths(sedCtx, index);

    //printf("\nClose Session Packet to send: \n");
    sed_OutputPacket(sedCtx->packet, totalPacketLen);

    ata_trustedSend(sedCtx);
    // Don't bother checking the return packet...
    return SED_NO_ERROR;

}

int32_t sessionManager_startSession(struct sedContext *sedCtx, uint8_t write, uint32_t passwordSize, uint8_t *password)
{
    uint8_t * dataPayload;
    uint32_t index = 0, retSize, totalPacketLen;
    uint64_t uidInvoker, uidMethod;
    struct TinyAtom_t tokenProperty;
    struct ShortAtom_t tokenHeader;
    uint8_t tokenPassword[sizeof(struct LongAtom_t)], tokenHsid[sizeof(struct LongAtom_t)];
    uint32_t hsid;
    uint64_t spid, uidSid;

    /* Zero out session numbers */
    sedCtx->hostSessionNumber = 0;
    sedCtx->tperSessionNumber = 0;
    
    /* Zero out entire packet */
    memset(sedCtx->packet, 0, sedCtx->packetSize);
    
    /* Get the Address of the dataPayload */
    dataPayload = (uint8_t*)(sedCtx->packet + packets_initialize(sedCtx));

    /* At this point all layers of the entirePacket should be aligned in
       their correct spots within the buffer. The buffer should look like
       the following      
       [ Compacket | Packet | DataSubPacket | Data Payload ]

       set up short atom token for any 8 byte sequence
       Short atoms have an id of 2. This let us know that we are dealing with
       short atoms. This works for any 8 byte sequence this will work 
       for the methodID and the Invoker ID */
    tokenHeader.id = ShortAtomId;

    // This field specifies the length of the data. Since the data we are
    // passing in is a 8 byte sequence, we pass in 8. The length field 
    // here corresponds to the number of bytes.
    tokenHeader.length = sizeof(uint64_t);  // 8

    // There are two options when it comes to short atoms. The data can be 
    // processed as an integer or it can be processed as a byte sequence.
    tokenHeader.byte = BYTE_BYTESEQ;

    // Again the data we are using is not signed.
    tokenHeader.sign = SIGN_NOSIGN;

    // Set up invoker and method UIDs
    uidInvoker = UID_SESSIONMANAGER;
    uidMethod = UID_SMLAYER_STARTSESSION;

    // This creates the Method Header. The method header consist of the 
    // InvokingID along with the Method ID. This can be looked as passing
    // in the method UID along with its type, then the invoker UID along with
    // its type. Done with error checking
    retSize = dataPayload_CreateHeader((uint8_t*)&tokenHeader, (uint8_t*)&uidInvoker, (uint8_t*)&tokenHeader, (uint8_t*)&uidMethod, (uint8_t*)(dataPayload + index));
    if (retSize & SED_ERROR)
    {
        // error occurred
        //printf("SMUID.StartSession ERROR: Could not create header!\n");
        return SED_ERROR_INVALID_HEADER;
    }
    // Update the index for the buffer
    index += retSize;

    // Add first mandatory argument Host Session ID (tiny token)
    sedCtx->hostSessionNumber = 1;
    
    dataPayload_createTokenForInteger(sedCtx->hostSessionNumber, tokenHsid);
    
    retSize = dataPayload_StartArgumentListWithArgument(tokenHsid, (uint8_t*)&hsid, (uint8_t*)(dataPayload + index));
    if (retSize & SED_ERROR)
    {
        // error occurred
        //printf("SMUID.StartSession ERROR: Argument 'HostSessionId' failed\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    // Update the index for the buffer
    index += retSize;

    // Add second mandatory argument SPID (8 byte sequence)
    
    if (sedCtx->account != PsidSP)
    {
        // Determine the user for Security Peripheral Id and Authority
        uidSid = sed_makeAuthorityUid(sedCtx->account,sedCtx->id);
        if(uidSid == 0ll)
            return SED_ERROR_INVALID_ARGUMENT;
    }

    if (sedCtx->account == AdminSP)
        spid = UID_SP_ADMIN;  

    else if (sedCtx->account == PsidSP)
    {
        
        uidSid = UID_AUTHORITY_PSID;
        spid = UID_SP_ADMIN;
    }

    else
    {
        spid = UID_SP_LOCKING;
    }
    
    retSize = dataPayload_AddArgument((uint8_t*)&tokenHeader, (uint8_t*)&spid, (uint8_t*)(dataPayload + index));
    if (retSize & SED_ERROR)
    {
        // error
        //printf("SMUID.StartSession ERROR: Argument 'SPID' failed\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += retSize;

    // Add third mandatory argument write value (tiny token)
    // Since it is a tiny token, there is no need to pass the second param
    tokenProperty.id = TinyAtomId;
    tokenProperty.sign = SIGN_NOSIGN;
    tokenProperty.data = (write ? 1 : 0);
    
    retSize = dataPayload_AddArgument((uint8_t*)&tokenProperty, NULL, (uint8_t*)(dataPayload + index));
    if (retSize & SED_ERROR)
    {
        // error
        //printf("SMUID.StartSession ERROR: Argument 'SPID' failed\n");

        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += retSize;

    // Check to add name arguments
    if (password != NULL && passwordSize != 0)
    {
        dataPayload_createTokenByLength(passwordSize, tokenPassword);
        tokenProperty.data = NAME_HOSTCHALLENGE;
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL, tokenPassword, password, (uint8_t*)(dataPayload + index));
        if (retSize & SED_ERROR)
        {
            fprintf(stderr, "SMUID.StartSession ERROR: Optional Argument 'PASSWORD' failed\n");
            return SED_ERROR_INVALID_ARGUMENT;
        }
        index += retSize;

        // Add authority
        tokenProperty.data = NAME_HOSTSIGNINGAUTHORITY;

        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL, (uint8_t*)&tokenHeader, (uint8_t*)&uidSid, (uint8_t*)(dataPayload + index));
        if (retSize & SED_ERROR)
        {
            fprintf(stderr, "SMUID.StartSession ERROR: Optional Argument 'SID_UID' failed\n");
            return SED_ERROR_INVALID_ARGUMENT;
        }

        index += retSize;
    }

    // Close the parameter listint32_t sessionManager_checkSyncSession(uint8_t *entirePacket);
    dataPayload[index++] = EndListToken;

    // Close the packet
    index += dataPayload_EndPacket(dataPayload + index);

    // Determine packet size (modular 4 byte)
    totalPacketLen = packets_updateLengths((struct sedContext*)sedCtx, index);

    ata_trustedSend(sedCtx);

    sed_OutputPacket(sedCtx->packet,totalPacketLen);

    return checkSyncSession(sedCtx);
}

int32_t checkSyncSession(struct sedContext* sedCtx)
{
    uint8_t *dataPayload;
    uint8_t flags;
    uint32_t size, argument;
    int32_t retSize, index = 0;
    struct ShortAtom_t tokenShort;
    uint64_t uidInvoker, uidMethod;

    //TODO(scott/maurice): verify packet contents, don't just skip
    dataPayload = sedCtx->packet + SIZEOF_PACKET_HEADERS;

    // We should be at the start of the dataPayload
    if (dataPayload[index++] != CallToken)
    {
        fprintf(stderr, "Error in CallToken of SyncSession!\r\n");
    }

    // Check invoking uid
    // Set up token for header
    tokenShort.id = ShortAtomId;
    tokenShort.byte = BYTE_BYTESEQ;
    tokenShort.sign = SIGN_NOSIGN;
    tokenShort.length = sizeof(uint64_t);
    
    // Set up uids
    uidInvoker = UID_SESSIONMANAGER;
    uidMethod = UID_SMLAYER_SYNCSESSION;
    if (memcmp(dataPayload+index,&tokenShort,sizeof(tokenShort)))
    {
        fprintf(stderr, "Error in invoking UID token of SyncSession\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += sizeof(tokenShort);

    if (memcmp(dataPayload+index, &uidInvoker, sizeof(uidInvoker)))
    {
        fprintf(stderr, "[-] Error in invoking UID of SyncSession!\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += sizeof(uidInvoker);
    
    // Check method uid
    if (memcmp(dataPayload+index,&tokenShort,sizeof(tokenShort)))
    {
        fprintf(stderr, "Error in method UID token of SyncSession\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += sizeof(tokenShort);
    
    if (memcmp(dataPayload+index, &uidMethod, sizeof(uidMethod)))
    {
        fprintf(stderr, "[-] Error in method UID of SyncSession!\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += sizeof(uidMethod);
    
    // Check parameters
    if (dataPayload[index++] != StartListToken)
    {
        fprintf(stderr, "Error in StartListToken of SyncSession!\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    // Check HostSessionId Parameter
    argument = 0;
    retSize = dataPayload_GetDataFromArgument(dataPayload + index, (uint8_t*)&argument, &size, &flags);
    if(retSize & SED_ERROR)
    {
        //fprintf(stderr, "Error in Host Session ID argument of SyncSession!\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += retSize;
    
    if(switchEndian(argument,4) != sedCtx->hostSessionNumber)
    {
        //printf("Warning: SyncSession returned a different Host Session Number!\n");
        //printf("         0x%x sent but returned 0x%x\n",sedCtx->hostSessionNumber,argument);
        sedCtx->hostSessionNumber = argument;
    }
    
    // check SpSessionId parameter
    argument = 0;
    retSize = dataPayload_GetDataFromArgument(dataPayload + index, (uint8_t*)&argument, &size, &flags);
    if(retSize & SED_ERROR)
    {
        fprintf(stderr, "Error in SP Session ID argument of SyncSession!\r\n");
        return SED_ERROR_INVALID_RESPONSE;
    }

    sedCtx->tperSessionNumber = switchEndian(argument, size);

    index += retSize;
    if(dataPayload[index+3] != 0)
        return OPAL_ERROR+dataPayload[index+3];
    
    return SED_NO_ERROR;
}

int32_t sessionManager_properties(struct sedContext *sedCtx)
{
    uint8_t * dataPayload;
    uint64_t uidInvoker, uidMethod;
    uint32_t index = 0, retSize, totalPacketLen, propertValues[21] = {0}, i;
    struct ShortAtom_t tokenHeader;
    struct TinyAtom_t tokenProperty;
    char *sessionProperties[MAX_STRING_SIZE] = {"MaxComPacketSize","MaxResponseComPacketSize", "MaxPacketSize","MaxIndTokenSize", "MaxPackets",
         "MaxSubpackets", "MaxMethods", "MaxAggTokenSize", "ContinuedTokens", "SequenceNumbers", "AckNak", "Asynchronous", "MaxSessions", "MaxReadSessions",
         "MaxAuthentications", "MaxTransactionLimit", "DefSessionTimeout", "MaxSessionTimeout", "MinSessionTimeout", "DefTransTimeout", "MaxComIDTime", "MaxTransTimeout", "MinTransTimeout"};

    memset(sedCtx->packet, 0, sedCtx->packetSize);

    /* Allows easy iteration when adding arguments to packet */
    propertValues[MAX_COMPACKET_SIZE] = sedCtx->hostMaxComPacketSize;
    propertValues[MAX_RESPONSE_COMPACKET_SIZE] = sedCtx->hostMaxResponseComPacketSize;
    propertValues[MAX_PACKET_SIZE] = sedCtx->hostMaxPacketSize;
    propertValues[MAX_IND_TOKEN_SIZE] = sedCtx->hostMaxIndTokenSize;
    propertValues[MAX_PACKETS] = sedCtx->hostMaxPackets;
    propertValues[MAX_SUBPACKETS] = sedCtx->hostMaxSubpackets;
    propertValues[MAX_METHODS] = sedCtx->hostMaxMethods;
    
    /* Create memory space for the dataPayload */
    dataPayload = (uint8_t*)(sedCtx->packet + packets_initialize(sedCtx));

    /* Setup the token that will be used for both the invokerUID and the MethodUID. We will make the length of the token 8bytes, which is enough to hold the UID */
    tokenHeader.id = ShortAtomId;
    tokenHeader.length = sizeof(uidInvoker);
    tokenHeader.byte = BYTE_BYTESEQ;
    tokenHeader.sign = SIGN_NOSIGN;

    uidInvoker = UID_SESSIONMANAGER;
    uidMethod = UID_SMLAYER_PROPERTIES;
  
    retSize = dataPayload_CreateHeader((uint8_t*)&tokenHeader, (uint8_t*)&uidInvoker, (uint8_t*)&tokenHeader, (uint8_t*)&uidMethod, (uint8_t*)(dataPayload + index));
    if (retSize & SED_ERROR)
    {
        fprintf(stderr, "Error: Can not create header\n");
        return SED_ERROR_INVALID_HEADER;
    }

    index += retSize;

    dataPayload[index++] = StartListToken;

    /* Start a name argument list */
    tokenProperty.id = TinyAtomId;
    tokenProperty.sign = SIGN_NOSIGN;
    tokenProperty.data = NAME_HOSTPROPERTIES;
    index += dataPayload_StartNameArgumentList(&tokenProperty, dataPayload + index);

    /* Add all of the properties as arguments */
    for (i = 0; i < 21; i++)
    {
        if (propertValues[i])
        {
            retSize = addProperty(sessionProperties[i], propertValues[i], dataPayload + index);
            if (retSize & SED_ERROR)
            {
                fprintf(stderr, "Error adding the host max compacket size\n");
                return SED_ERROR_INVALID_ARGUMENT;
            }
            index += retSize;    
        }  
    }

    /* Close Name Argument and end the packet */
    index += dataPayload_CloseNameArgumentList(dataPayload + index);
    dataPayload[index++] = EndListToken;
    index += dataPayload_EndPacket(dataPayload + index);


    totalPacketLen = packets_updateLengths((struct sedContext*)sedCtx, index);

    sed_OutputPacket(sedCtx->packet, sedCtx->packetSize);
    ata_trustedSend(sedCtx);
    sed_OutputPacket(sedCtx->packet, totalPacketLen*2);

    return propertiesResponse(sedCtx);
}

int32_t addProperty(char *strName, uint32_t value, uint8_t *dataStart)
{
    uint8_t stringToken[sizeof(struct LongAtom_t)], valueToken[sizeof(struct LongAtom_t)];
    uint32_t valueSize, argument;

    dataPayload_createTokenForString(strName, stringToken);

    valueSize = dataPayload_createTokenForInteger(value, valueToken);

    argument = switchEndian(value, valueSize);

    return dataPayload_AddNameArgument(stringToken, (uint8_t*)strName, valueToken, (uint8_t*)&argument, dataStart);
}

int32_t propertiesResponse(struct sedContext *sedCtx)
{
    uint8_t * dataPayload;
    uint32_t index = 0;
    int32_t retSize;
    char strMaxMethods[] = "MaxMethods",
            strMaxSubpackets[] = "MaxSubpackets",
            strMaxPacketSize[] = "MaxPacketSize",
            strMaxPackets[] = "MaxPackets",
            strMaxComPacketSize[] = "MaxComPacketSize",
            strMaxResponseComPacketSize[] = "MaxResponseComPacketSize",
            strMaxSessions[] = "MaxSessions",
            strMaxReadSessions[] = "MaxReadSessions",
            strMaxIndTokenSize[] = "MaxIndTokenSize",
            strMaxAggTokenSize[] = "MaxAggTokenSize",
            strMaxAuthentications[] =
                    "MaxAuthentications",
                    strMaxTransactionLimit[] =
                    "MaxTransactionLimit",
                    strDefSessionTimeout[] =
                    "DefSessionTimeout", strMaxSessionTimeout[] =
                    "MaxSessionTimeout", strMinSessionTimeout[] =
                    "MinSessionTimeout", strDefTransTimeout[] =
                    "DefTransTimeout", strMaxTransTimeout[] = "MaxTransTimeout",
            strMinTransTimeout[] = "MinTransTimeout", strMaxComIDTime[] =
                    "MaxComIDTime", strContinuedTokens[] = "ContinuedTokens",
            strSequenceNumbers[] = "SequenceNumbers", strAckNak[] = "AckNak",
            strAsynchronous[] = "Asynchronous";
    char strProperty[50];
    uint32_t valProperty = 0;
    uint8_t hostProperty = 0;

// Skip the headers
    dataPayload = sedCtx->packet + SIZEOF_COMPACKET_HDR + SIZEOF_PACKET_HDR
            + SIZEOF_DATASUBPACKET_HDR + 1;

//TODO(scott) Probably shouldn't but skip the invoker and method UIDs
    index += (2 * sizeof(uint64_t)) + 2;  // 2 8-byte buffers + 2 1-byte tokens

    if (dataPayload[index] != StartListToken
            || dataPayload[index + 1] != StartListToken)
    {
        printf("Invalid Property List!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    do
    {
        memset(strProperty, 0, 50);
        retSize = parseProperty(strProperty, &valProperty, dataPayload + index);
        if (retSize & SED_ERROR)
        {
            return retSize;
        }
        index += retSize;

        // Put variable in right property
        if (strcmp(strMaxMethods, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxMethods = valProperty;
            }
            else
            {
                sedCtx->tperMaxMethods = valProperty;
            }
        }
        else if (strcmp(strMaxSubpackets, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxSubpackets = valProperty;
            }
            else
            {
                sedCtx->tperMaxSubpackets = valProperty;
            }
        }
        else if (strcmp(strMaxPacketSize, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxPacketSize = valProperty;
            }
            else
            {
                sedCtx->tperMaxPacketSize = valProperty;
            }
        }
        else if (strcmp(strMaxPackets, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxPackets = valProperty;
            }
            else
            {
                sedCtx->tperMaxPackets = valProperty;
            }
        }
        else if (strcmp(strMaxComPacketSize, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxComPacketSize = valProperty;
            }
            else
            {
                sedCtx->tperMaxComPacketSize = valProperty;
            }
        }
        else if (strcmp(strMaxResponseComPacketSize, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxResponseComPacketSize = valProperty;
            }
            else
            {
                sedCtx->tperMaxResponseComPacketSize = valProperty;
            }
        }
        else if (strcmp(strMaxIndTokenSize, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxIndTokenSize = valProperty;
            }
            else
            {
                sedCtx->tperMaxIndTokenSize = valProperty;
            }
        }
        else if (strcmp(strMaxAggTokenSize, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostMaxAggTokenSize = valProperty;
            }
            else
            {
                sedCtx->tperMaxAggTokenSize = valProperty;
            }
        }
        else if (strcmp(strContinuedTokens, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostContinuedTokens = valProperty;
            }
            else
            {
                sedCtx->tperContinuedTokens = valProperty;
            }
        }
        else if (strcmp(strSequenceNumbers, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostSequenceNumbers = valProperty;
            }
            else
            {
                sedCtx->tperSequenceNumbers = valProperty;
            }
        }
        else if (strcmp(strAckNak, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostAckNak = valProperty;
            }
            else
            {
                sedCtx->tperAckNak = valProperty;
            }
        }
        else if (strcmp(strAsynchronous, strProperty) == 0)
        {
            if (hostProperty)
            {
                sedCtx->hostAsynchronous = valProperty;
            }
            else
            {
                sedCtx->tperAsynchronous = valProperty;
            }
        }
        else if (strcmp(strMaxSessions, strProperty) == 0)
        {
            sedCtx->tperMaxSessions = valProperty;
        }
        else if (strcmp(strMaxReadSessions, strProperty) == 0)
        {
            sedCtx->tperMaxReadSessions = valProperty;
        }
        else if (strcmp(strMaxAuthentications, strProperty) == 0)
        {
            sedCtx->tperMaxAuthentications = valProperty;
        }
        else if (strcmp(strMaxTransactionLimit, strProperty) == 0)
        {
            sedCtx->tperMaxTransactionLimit = valProperty;
        }
        else if (strcmp(strMaxSessionTimeout, strProperty) == 0)
        {
            sedCtx->tperMaxSessionTimeout = valProperty;
        }
        else if (strcmp(strMaxTransTimeout, strProperty) == 0)
        {
            sedCtx->tperMaxTransTimeout = valProperty;
        }
        else if (strcmp(strMaxComIDTime, strProperty) == 0)
        {
            sedCtx->tperMaxComIDTime = valProperty;
        }
        else if (strcmp(strDefSessionTimeout, strProperty) == 0)
        {
            sedCtx->tperDefSessionTimeout = valProperty;
        }
        else if (strcmp(strMinSessionTimeout, strProperty) == 0)
        {
            sedCtx->tperMinSessionTimeout = valProperty;
        }
        else if (strcmp(strDefTransTimeout, strProperty) == 0)
        {
            sedCtx->tperDefTransTimeout = valProperty;
        }
        else if (strcmp(strMinTransTimeout, strProperty) == 0)
        {
            sedCtx->tperMinTransTimeout = valProperty;
        }
        else
        {
            printf("Unknown Property: %s\n", strProperty);
            return SED_ERROR_INVALID_ARGUMENT;
        }

        if (dataPayload[index] == EndListToken
                && dataPayload[index + 1] == StartNameToken
                && dataPayload[index + 2] == NAME_HOSTPROPERTIES
                && dataPayload[index + 3] == StartListToken)
        {
            hostProperty = 1;
            index += 4;
        }
    } while (dataPayload[index] != EndListToken
            && dataPayload[index + 1] != EndNameToken
            && dataPayload[index + 2] != EndListToken);
    index += 3;
    
    if (dataPayload[index] != EndOfDataToken
            || dataPayload[index + 1] != StartListToken)
    {
        printf("Malformed End of Packet!1\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;
    
    if (dataPayload[index] != 0)
    {
        printf("Error in Method Status List: 0x%x", dataPayload[index]);
        return OPAL_ERROR+dataPayload[index];
    }
    ++index;
    
    if (dataPayload[index] != 0 || dataPayload[index + 1] != 0
            || dataPayload[index + 2] != EndListToken)
    {
        printf("Malformed End of Packet!2\n");
        return SED_ERROR_INVALID_RESPONSE;
    }

    return SED_NO_ERROR;
}


int32_t parseProperty(char *strProperty, uint32_t *valProperty,
        uint8_t *dataStart)
{
    int32_t index = 0, retSize;
    uint32_t tempArgSize;
    uint8_t tempArg[10], tempArgFlags, i;

// Check Start Name token
    if (dataStart[index++] != StartNameToken)
    {
        //printf("Malformed Property field!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }

// Get String Property name
    retSize = dataPayload_GetDataFromArgument(dataStart + index,
            (uint8_t*)strProperty, &tempArgSize, &tempArgFlags);
    if (retSize & SED_ERROR)
    {
        //printf("Malformed property field!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += retSize;
// Check to see if valid
// TODO(scott) don't use random numbers, struct this
    if (tempArgFlags & 1 || !(tempArgFlags & 2))
    {
        //printf("Invalid Token Parameter for a property string!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
// Get Argument field for string property name
    retSize = dataPayload_GetDataFromArgument(dataStart + index, tempArg,
            &tempArgSize, &tempArgFlags);
    if (retSize & SED_ERROR)
    {
        //printf("Malformed property field!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += retSize;
// Check to see if valid
// TODO(scott) don't use random numbers, struct this
    if (tempArgFlags & 1 || tempArgFlags & 2)
    {
        //printf("Invalid Token Parameter for a property value!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
// check if bigger than a uint32_t
    if (tempArgSize > 4)
    {
        //printf(
         //       "Warning: Property argument larger than 4-byte integer, truncating...\n");
        tempArgSize = 4;
    }
// Copy it over
    valProperty[0] = 0;
    for (i = 0; i < tempArgSize; ++i)
    {
        valProperty[0] |= ((uint32_t)tempArg[i]) << (i * 8);
    }
    valProperty[0] = switchEndian(valProperty[0], tempArgSize);

// Check close name token
    if (dataStart[index++] != EndNameToken)
    {
        //printf("Malformed Property field!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    return index;
}
