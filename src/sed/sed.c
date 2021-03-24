#include "../include/sed/sed.h"
#include "../include/password/sedAuth.h"
#include "../include/menu/adminMenu.h"

uint8_t gVerbose = 0;
uint32_t sedError = 0;

char *accountStrings[] =
{   
    "NoUser",
    "Manufacturer",
    "AdminSP",
    "Admin",
    "User",
    "Default",
    "PsidSP",
    "Distress"
};

int32_t sed_initialize(struct sedContext *sedCtx, char* sedPath, SedAccounts user, uint8_t id)
{
    memset(sedCtx, 0, sizeof(struct sedContext));
    
    /* Get the descriptor for the SED drive */
    if ((sedCtx->sedFileDescriptor = open(sedPath, O_RDWR)) == -1)
        return (sedError = EBADDRIVE);

    /* Setup the minimun requirements as specified in the specification */
    sedCtx->hostMaxComPacketSize = SED_MIN_COMPACKET_SIZE;
    sedCtx->hostMaxResponseComPacketSize = SED_MIN_COMPACKET_SIZE;
    sedCtx->hostMaxPacketSize = SED_MIN_PACKET_SIZE;
    sedCtx->hostMaxIndTokenSize = SED_MIN_INDTOKEN_SIZE;
    sedCtx->hostMaxPackets = SED_MIN_PACKETS;
    sedCtx->hostMaxSubpackets = SED_MIN_SUBPACKETS;
    sedCtx->hostMaxMethods = SED_MIN_METHODS;
    sedCtx->account = user;
    sedCtx->id = id;
    sedCtx->packetSize = SED_MIN_COMPACKET_SIZE;
    sedCtx->packet = (uint8_t*)malloc(sedCtx->packetSize);
    sedCtx->setHostSequenceNumbers = 0;
    sedCtx->totalLockingRanges = 1;

    if (!sedCtx->packet) 
        return (sedError = EMALLOC);

    /* Get drive information through levelZeroDiscovery */
    if (levelZeroDiscovery(sedCtx))
    {
        free(sedCtx->packet);
        return (sedError = ELZERO);
    }
        
    /* Determines if the drive is Opal Compliant */ 
    if (sedCtx->opalSscFeature)
    {
        if (sessionManager_properties(sedCtx))
        {   
            free(sedCtx->packet);
            return (sedError = EPROP);
        }

        /* Resize the max packetsize to equal that of the Tper */
        free(sedCtx->packet);

        /* Create packet */
       // sedCtx->packetSize = MAX_TRANSFER_SIZE;
        if (sedCtx->tperMaxComPacketSize != 0)
            sedCtx->packetSize = sedCtx->tperMaxComPacketSize;

        else if (sedCtx->hostMaxComPacketSize != 0)
            sedCtx->packetSize = sedCtx->hostMaxComPacketSize;
        
        else
            sedCtx->packetSize = SED_MIN_COMPACKET_SIZE;

        sedCtx->packet = (uint8_t *)malloc(sedCtx->packetSize);
        if (!sedCtx->packet) return (sedError = EMALLOC);
    }
    
    else
        return (sedError = EOPAL);        
   
    /* Obtain the drive identity and put information in packet */
    if (ata_getDriveIdentity(sedCtx))
    {
        free(sedCtx->packet);
        return (sedError = EIDENT);
    }

    return sedError;
}

void sed_cleanup(struct sedContext *sedCtx)
{
    /* Make sure session is closed */
    sessionManager_closeSession(sedCtx);

    /* Clean Everything */
    if (sedCtx->sedFileDescriptor)
        close(sedCtx->sedFileDescriptor);

    if (sedCtx->packet)
        free(sedCtx->packet);

	free(sedCtx);
}

void sed_enableVerbose()
{
    gVerbose = 1;
}

uint64_t sed_makeAuthorityUid(SedAccounts who, uint8_t id)
{
    uint64_t uid = 0ll;
    if(who == AdminSP)
        return UID_AUTHORITY_SID;
    // not allowed? - if(who == Manufacturer)
        //return UID_AUTHORITY_MSID;
    if(who == NoUser)
        return UID_AUTHORITY_ANYBODY;
    // this is an admin or user (hopefully)
    uid = (uint64_t)(((uint64_t)id)<<56);
    if(who == User)
        uid += UID_AUTHORITY_USER;
    else if(who == Admin)
        uid += UID_AUTHORITY_ADMIN;
    else
        return 0ll;
    return uid;
}

int32_t sed_OutputPacket(uint8_t *packet, int16_t length)
{
    if (gVerbose)
    {
        int32_t i;

        for (i = 0; i < length; ++i)
        {
            if (i % 16 == 0)
            {
                printf("%.4x", i);
            }

            if (i % 4 == 0)
            {
                printf(" ");
            }

            printf("%.2x", packet[i]);

            if ((i + 1) % 16 == 0)
            {
                printf("\n");
            }
        }

        printf("\n");
    }
    return 0;
}

void sed_printDriveIdentity(struct sedContext *sedCtx)
{
    printf("--------------------------------\n");
    printf("         DRIVE IDENTITY\n");
    printf("Serial No.:   %s\n", sedCtx->serialNumber);
    printf("Max LBAs:     0x%llx (%lld)\n",(long long unsigned int)sedCtx->maxLbas, (long long int)sedCtx->maxLbas);
    printf("--------------------------------\n");
}

void sed_printLevelZeroDiscovery(struct sedContext *sedCtx)
{
    //printf("\t -------------------------------\n");
    printf("\n\t      LEVEL ZERO DISCOVERY      \n");
    printf("\t      ____________________\n");
    printf("\n\nTPer Features ");
    if (sedCtx->tperFeature)
    {
        printf("Supported:\n");
        printf("------------------------\n");
        printf("Sync:              %s\n",
                sedCtx->syncSupported ?       "\tSupported" : "\tUnsupported");
        printf("Async:             %s\n",
                sedCtx->asyncSupported ?      "\tSupported" : "\tUnsupported");
        printf("ACK/NAK:           %s\n",
                sedCtx->acknakSupported ?     "\tSupported" : "\tUnsupported");
        printf("Buffer Management: %s\n",
                sedCtx->bufferMgmtSupported ? "\tSupported" : "\tUnsupported");
        printf("Streaming:         %s\n",
                sedCtx->streamingSupported ?  "\tSupported" : "\tUnsupported");
        printf("ComID Management:  %s\n",
                sedCtx->comIdMgmtSupported ?  "\tSupported" : "\tUnsupported");
    }
    else
    {
        printf("Unsupported\n");
    }

    printf("\nLocking Features ");
    if (sedCtx->lockingFeature)
    {
        printf("Supported:\n");
        printf("---------------------------\n");
        printf("Locking Supported: %s\n",
                sedCtx->lockingSupported ?     "\tEnabled" : "\tDisabled");
        printf("Locking Enabled:   %s\n",
                sedCtx->lockingEnabled ?       "\tEnabled" : "\tDisabled");
        printf("Locked:            %s\n",
                sedCtx->locked ?               "\tEnabled" : "\tDisabled");
        printf("Media Encryption:  %s\n",
                sedCtx->mediaEncryption ?      "\tEnabled" : "\tDisabled");
        printf("MBR Enabled:       %s\n",
                sedCtx->mbrEnabled ?           "\tEnabled" : "\tDisabled");
        printf("MBR Done:          %s\n",
                sedCtx->mbrDone ?              "\tEnabled" : "\tDisabled");
    }
    else
    {
        printf("Unsupported\n");
    }

    printf("\nOPAL SSC Features ");
    if (sedCtx->opalSscFeature)
    {
        printf("Supported:\n");
        printf("--------------------------\n");
        if (sedCtx->opalVersion == 2)
        {
            printf("Version 2.0               \t\n");
            printf("Number of LockingSP Admins \t%d\n", sedCtx->numberOfLockingSPAdmins);
            printf("Number of LockingSP Users \t%d\n", sedCtx->numberOfLockingSPUsers);
            printf("Initial CPIN Indicator     \t%d\n", sedCtx->initialCPinSidIndicator);
            printf("CPIN behavior on Revert    \t%d\n", sedCtx->behaviorCPinSidOnRevert);
            if (sedCtx->rangeCrossingBehavior)
            {
                printf("Range Crossing behavior Supported \t\n");
            }
        }
        else if(sedCtx->opalVersion == ENTERPRISE_FEATURE)
        {
            printf("Enterprise SSC version\n");
        }

        else
        {
            printf("Version 1.0        \t\n");
        }
        
        printf("Base ComID:       \t0x%x\n", sedCtx->baseComId);
        printf("Number of ComIDs:  \t%d\n", sedCtx->numberOfComIds);
    }
    else
    {
        printf("Unsupported\n");
    }

    printf("\nGeometry Reporting Features ");
    if (sedCtx->geometryFeature)
    {
        printf("Supported: \n");
        printf("--------------------------\n");
        printf("Logical Block Size       \t%d\n", sedCtx->logicalBlockSize);
        //printf("Alignment Granularity      \t0x%llx\n", sedCtx->alignmentGranularity);
        //printf("Lowest Aligned LBA         \t0x%llx\n", sedCtx->lowestAlignedLba);
    }
    else
    {
        printf("Unsupported\n");
    }

    printf("\nOpal Single User Features ");
    if (sedCtx->singleUserFeature)
    {
        printf("Supported: \n");
        printf("--------------------------\n");
        printf("Number of Locking Objects      \t%d\n", sedCtx->numberOfLockingObjects);
        if (sedCtx->any)
        {
            printf("Any Locking objects are in Single User Mode\n");    
        }
        if (sedCtx->all)
        {
            printf("All Locking objects are in Single User Mode\n");
        }
        if (sedCtx->policy)
        {
            printf("Admins Authority maintains ownership of RangeStart and RangeLength of Locking Objects in this mode\n");
        }
        else
        {
            printf("User authorities of Locking objects in this mode have ownership of their associated rangeStart and RangeLength\n");         
        }     
    }
    else
    {
        printf("Unsupported\n");
    }

    printf("\nOpal DataStore Table Features ");
    if (sedCtx->datastoreTableFeature)
    {
        printf("Supported: \n");
        printf("--------------------------\n");
        printf("Maximum number of DataStore Tables   \t%d\n",sedCtx->maxNumberOfDataStoreTables);
        printf("Maximum size of DataStore Tables     \t0x%x\n", sedCtx->maxSizeOfDataStoreTables);
        printf("DataStore table size Alignment        \t0x%x \n",sedCtx->sizeAlignmentDataStoreTable);
    }
    else
    {
        printf("Unsupported\n");
    }

    printf("\n");
}

void sed_printProperties(struct sedContext *sedCtx)
{
    //printf("\t----------------------------------\n");
    printf("\t            PROPERTIES\n");
    printf("\nTrusted Peripheral (TPer):\n");
    printf("--------------------------\n");
    printf("    Max Methods:                 %d\n", sedCtx->tperMaxMethods);
    printf("    Max Subpackets:              %d\n", sedCtx->tperMaxSubpackets);
    printf("    Max Packet Size:             %d\n", sedCtx->tperMaxPacketSize);
    printf("    Max Packets:                 %d\n", sedCtx->tperMaxPackets);
    printf("    Max ComPacket Size:          %d\n",
            sedCtx->tperMaxComPacketSize);
    printf("    Max Response ComPacket Size: %d\n",
            sedCtx->tperMaxResponseComPacketSize);
    printf("    Max Sessions:                %d\n", sedCtx->tperMaxSessions);
    printf("    Max Read Sessions:           %d\n",
            sedCtx->tperMaxReadSessions);
    printf("    Max Ind Token Size:          %d\n",
            sedCtx->tperMaxIndTokenSize);
    printf("    Max Agg Token Size:          %d\n",
            sedCtx->tperMaxAggTokenSize);
    printf("    Max Authentications:         %d\n",
            sedCtx->tperMaxAuthentications);
    printf("    Max Transaction Limit:       %d\n",
            sedCtx->tperMaxTransactionLimit);
    printf("    Max Session Timeout:         %d\n",
            sedCtx->tperMaxSessionTimeout);
    printf("    Max Transaction Timeout:     %d\n",
            sedCtx->tperMaxTransTimeout);
    printf("    Max ComID Time:              %d\n", sedCtx->tperMaxComIDTime);
    printf("    Min Session Timeout:         %d\n",
            sedCtx->tperMinSessionTimeout);
    printf("    Min Transaction Timeout:     %d\n",
            sedCtx->tperMinTransTimeout);
    printf("    Def Session Timeout:         %d\n",
            sedCtx->tperDefSessionTimeout);
    printf("    Def Transaction Timeout:     %d\n",
            sedCtx->tperDefTransTimeout);
    printf("    Continued Tokens:            %d\n",
            sedCtx->tperContinuedTokens);
    printf("    Sequence Numbers:            %d\n",
            sedCtx->tperSequenceNumbers);
    printf("    ACK/NAK:                     %d\n", sedCtx->tperAckNak);
    printf("    Asynchronous:                %d\n", sedCtx->tperAsynchronous);
    printf("\nHost:\n");
    printf("-----\n");
    printf("    Max Methods:                 %d\n", sedCtx->hostMaxMethods);
    printf("    Max Subpackets:              %d\n", sedCtx->hostMaxSubpackets);
    printf("    Max Packet Size:             %d\n", sedCtx->hostMaxPacketSize);
    printf("    Max Packets:                 %d\n", sedCtx->hostMaxPackets);
    printf("    Max ComPacket Size:          %d\n",
            sedCtx->hostMaxComPacketSize);
    printf("    Max Response ComPacket Size: %d\n",
            sedCtx->hostMaxResponseComPacketSize);
    printf("    Max Ind Token Size:          %d\n",
            sedCtx->hostMaxIndTokenSize);
    printf("    Max Agg Token Size:          %d\n",
            sedCtx->hostMaxAggTokenSize);
    printf("    Continued Tokens:            %d\n",
            sedCtx->hostContinuedTokens);
    printf("    Sequence Numbers:            %d\n",
            sedCtx->hostSequenceNumbers);
    printf("    ACK/NAK:                     %d\n", sedCtx->hostAckNak);
    printf("    Asynchronous:                %d\n", sedCtx->hostAsynchronous);
    //printf("\t----------------------------------\n");
}

int32_t sed_genericSet(struct sedContext *sedCtx, uint64_t uidInvoker, uint32_t where, uint32_t szValues, uint8_t *values)
{
    uint8_t * dataPayload;
    uint32_t index = 0, totalPacketSize, retSize;
    uint64_t uidMethod;
    struct TinyAtom_t tokenValues;
    struct ShortAtom_t tokenHeader;

    memset(sedCtx->packet, 0, sedCtx->packetSize);
    dataPayload = sedCtx->packet + packets_initialize(sedCtx);

    // Set up the header
    uidMethod = UID_METHOD_SET;
    tokenHeader.id = ShortAtomId;
    tokenHeader.sign = SIGN_NOSIGN;
    tokenHeader.byte = BYTE_BYTESEQ;
    tokenHeader.length = sizeof(uidInvoker);
    retSize = dataPayload_CreateHeader((uint8_t*)&tokenHeader,
            (uint8_t*)&uidInvoker, (uint8_t*)&tokenHeader, (uint8_t*)&uidMethod,
            dataPayload + index);
    if (retSize & SED_ERROR)
    {
        return SED_ERROR_INVALID_HEADER;
    }
    index += retSize;

    // Start the parameters
    dataPayload[index++] = StartListToken;

    // Add the where variable, if applicable
    if (where != -1)
    {
        struct TinyAtom_t tokenWhere;
        uint32_t argWhere = 0;
        uint8_t szWhere, tokenArg[sizeof(struct LongAtom_t)];
        tokenWhere.id = TinyAtomId;
        tokenWhere.sign = SIGN_NOSIGN;
        tokenWhere.data = COLUMN_WHERE;
        szWhere = dataPayload_createTokenForInteger(where, tokenArg);
        argWhere = switchEndian(where, szWhere);
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenWhere, NULL,
                tokenArg, (uint8_t*)&argWhere, dataPayload + index);
        if (retSize & SED_ERROR)
        {
            return SED_ERROR_INVALID_ARGUMENT;
        }
        index += retSize;
    }

    // Start the VALUES field
    tokenValues.id = TinyAtomId;
    tokenValues.sign = SIGN_NOSIGN;
    tokenValues.data = COLUMN_VALUES;
    dataPayload[index++] = StartNameToken;
    memcpy(dataPayload + index, &tokenValues, sizeof(tokenValues));
    index += sizeof(tokenValues);

    // Add the values
    // TODO: bounds checking?
    memcpy(dataPayload + index, values, szValues);
    index += szValues;

    // Close the VALUES name argument
    dataPayload[index++] = EndNameToken;

    // Close the parameter list
    dataPayload[index++] = EndListToken;

    // Close the packet
    index += dataPayload_EndPacket(dataPayload + index);

    // Update the packet header length fields
    totalPacketSize = packets_updateLengths(sedCtx, index);

    // Verbose output packet
    sed_OutputPacket(sedCtx->packet, totalPacketSize);

    // Trusted Send
    ata_trustedSend(sedCtx);

    // Verbose output packet
    sed_OutputPacket(sedCtx->packet, totalPacketSize);

    // Check the results
    return sed_checkSetResults(sedCtx);
}

int32_t sed_checkSetResults(struct sedContext *sedCtx)
{
    uint8_t *dataPayload;
    uint32_t index = 0, retSize;
    int32_t error = SED_NO_ERROR;

    retSize = packets_check(sedCtx);
    
    if (retSize & SED_ERROR)
        return retSize;
    
    dataPayload = sedCtx->packet + retSize;

    if (dataPayload[index++] != StartListToken)
        error = SED_ERROR_INVALID_RESPONSE;

    if (dataPayload[index++] != EndListToken)
        error = SED_ERROR_INVALID_RESPONSE;
    
    if (dataPayload[index++] != EndOfDataToken)
        error = SED_ERROR_INVALID_RESPONSE;

    if (dataPayload[index++] != StartListToken)
        error = SED_ERROR_INVALID_RESPONSE;
    
    if (dataPayload[index++] != 0)
        error = SED_ERROR_INVALID_RESPONSE;
    
    index += 2;
    
    if (dataPayload[index++] != EndListToken)
        error = SED_ERROR_INVALID_RESPONSE;

    return error;
}

int32_t sed_genericGet(struct sedContext *sedCtx, uint64_t uidInvoker, uint8_t isRow, uint32_t start, uint32_t end, uint8_t **retBuf)
{
    uint8_t * dataPayload;
    uint32_t index = 0, totalPacketSize, retSize;
    uint64_t uidMethod;
    struct TinyAtom_t tokenValId;
    struct ShortAtom_t tokenHeader;
    uint8_t tokenVal[sizeof(struct LongAtom_t)];
    uint32_t argVal, szVal;

    // Set up packet
    memset(sedCtx->packet, 0, sedCtx->packetSize);
    dataPayload = sedCtx->packet + packets_initialize(sedCtx);

    // Set up header
    uidMethod = UID_METHOD_GET;
    tokenHeader.id = ShortAtomId;
    tokenHeader.sign = SIGN_NOSIGN;
    tokenHeader.byte = BYTE_BYTESEQ;
    tokenHeader.length = sizeof(uidInvoker);
    retSize = dataPayload_CreateHeader((uint8_t*)&tokenHeader,
            (uint8_t*)&uidInvoker, (uint8_t*)&tokenHeader, (uint8_t*)&uidMethod,
            dataPayload + index);
    if (retSize & SED_ERROR)
    {
        return SED_ERROR_INVALID_HEADER;
    }
    index += retSize;

    // Start the parameter list
    dataPayload[index++] = StartListToken;
    // Start the "Cellblock"
    dataPayload[index++] = StartListToken;

    // Add the StartColumn
    tokenValId.id = TinyAtomId;
    tokenValId.sign = SIGN_NOSIGN;
    if (isRow)
        tokenValId.data = ROW_STARTROW;
    else
        tokenValId.data = COLUMN_STARTCOL;
    szVal = dataPayload_createTokenForInteger(start, tokenVal);
    argVal = switchEndian(start, szVal);
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenValId, NULL, tokenVal,
            (uint8_t*)&argVal, dataPayload + index);
    if (retSize & SED_ERROR)
    {
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += retSize;

    // Add the End Column
    if (isRow)
        tokenValId.data = ROW_ENDROW;
    else
        tokenValId.data = COLUMN_ENDCOL;
    szVal = dataPayload_createTokenForInteger(end, tokenVal);
    argVal = switchEndian(end, szVal);
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenValId, NULL, tokenVal,
            (uint8_t*)&argVal, dataPayload + index);
    if (retSize & SED_ERROR)
    {
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += retSize;

    // End "Cellblock"
    dataPayload[index++] = EndListToken;
    // End the parameter list
    dataPayload[index++] = EndListToken;
    // End the packet
    index += dataPayload_EndPacket(dataPayload + index);

    // Update packet header lengths
    totalPacketSize = packets_updateLengths(sedCtx, index);

    // Verbose output packet
    sed_OutputPacket(sedCtx->packet, totalPacketSize);

    // Trusted send
    ata_trustedSend(sedCtx);

    // Verbose output packet
    sed_OutputPacket(sedCtx->packet, totalPacketSize);

    // Check and return the get results
    return sed_checkGetResults(sedCtx, retBuf);
}

int32_t sed_checkGetResults(struct sedContext *sedCtx, uint8_t **retBuf)
{
    uint32_t retSize = packets_check(sedCtx);
    if (retSize & SED_ERROR)
    {
        printf("Error in getting results!\n");
        return retSize;
    }
    retBuf[0] = sedCtx->packet + retSize;
    return SED_NO_ERROR;
}

int32_t sed_genericSendEmptyPayload(struct sedContext *sedCtx,
        uint64_t uidInvoker, uint64_t uidMethod)
{
    uint8_t * dataPayload;
    uint32_t index = 0, retSize, totalPacketSize;
    struct ShortAtom_t tokenHeader;

    // Initialize packet
    memset(sedCtx->packet, 0, sedCtx->packetSize);
    dataPayload = sedCtx->packet + packets_initialize(sedCtx);

    // Set up header
    tokenHeader.id = ShortAtomId;
    tokenHeader.byte = BYTE_BYTESEQ;
    tokenHeader.sign = SIGN_NOSIGN;
    tokenHeader.length = sizeof(uidInvoker);
    // Create Header
    retSize = dataPayload_CreateHeader((uint8_t*)&tokenHeader,
            (uint8_t*)&uidInvoker, (uint8_t*)&tokenHeader, (uint8_t*)&uidMethod,
            dataPayload + index);
    if (retSize & SED_ERROR)
    {
        printf("Error: Could not create header!\n");
        return SED_ERROR_INVALID_HEADER;
    }
    index += retSize;
    dataPayload[index++] = StartListToken;
    dataPayload[index++] = EndListToken;
    index += dataPayload_EndPacket(dataPayload + index);

    // Update packet header lengths
    totalPacketSize = packets_updateLengths(sedCtx, index);

    // Verbose output packet
    sed_OutputPacket(sedCtx->packet, totalPacketSize);

    // Trusted send 
    ata_trustedSend(sedCtx);

    // Verbose output packet
    sed_OutputPacket(sedCtx->packet, totalPacketSize);

    // Check the results (should be same as SET command)
    return sed_checkSetResults(sedCtx);
}

int32_t levelZeroDiscovery(struct sedContext *sedCtx)
{
    struct sg_io_hdr sgio = {0};
    struct cdb cdb = {0};
    uint8_t commandDescriptorBlock[CDB_MAX_LENGTH] = {0};
    uint8_t sense[MAX_SIZE_OF_SENSE_BUFF] = {0};
    uint8_t buffer[4 + MIN_SIZE_OF_BUFFER] = {0};
 
    /* Setup the ATA passthrough for SCSI */
    ata_initScsiStruct(buffer, MIN_SIZE_OF_BUFFER, commandDescriptorBlock, sense, SG_DXFER_FROM_DEV, &sgio);

    if (ata_createCDBBuffer(&cdb, commandDescriptorBlock, PIO_DATA_IN, SECURITY_PROTOCOL_ONE, 1, LEVEL_ZERO_COMID, TRUSTED_RECEIVE))
    {
        fprintf(stderr, "Error: Can not create CDB buffer\n");
        return 1;
    }

    /* Issue the actual ATA command via IOCTL */
    if (!ioctl(sedCtx->sedFileDescriptor, SG_IO, &sgio))
    {
        if ( sense[11] != 0x00 || (sense[21] != 0x50 && sense[21] != 0x40) )
        {
            
           fprintf(stderr, "Error: [ErrorByte: %02x, and should be 0x00] [StatusByte:%02x, and should be 0x50]\n", sense[11], sense[21]);
           return ((SED_ERROR_TRUSTED_RECEIVE) | sense[11]<<8 | sense[21]<<16);
        }

        else
            return parseLevelZeroBuffer(sedCtx, buffer); 
    }

    fprintf(stderr, "Error: Could not issue IOCTL call. Are you root?\n");
    return 1;      
}

int32_t parseLevelZeroBuffer(struct sedContext *sedCtx, uint8_t *buffer)
{
    struct featureHeader
    {
        uint16_t featureCode;
        uint8_t  version;
        uint8_t  length;
    }__attribute__((packed));

    struct featureHeader *feature = (struct featureHeader *)(buffer + 48);
      
    while (feature->version != 0)
    {
        feature->featureCode = switchEndian(feature->featureCode,2);
                
        uint8_t *featureData = (uint8_t*)feature + sizeof(*feature);
        
        if (feature->featureCode == TPER_FEATURE)
        {
            sedCtx->tperFeature = SED_ENABLED;

            if (*featureData & TPER_FEATURE_SYNC_SUPPORT)
                sedCtx->syncSupported = SED_ENABLED;

            if (*featureData & TPER_FEATURE_ASYNC_SUPPORT)
                sedCtx->asyncSupported = SED_ENABLED;

            if (*featureData & TPER_FEATURE_ACKNAK_SUPPORT)
                sedCtx->acknakSupported = SED_ENABLED;

            if (*featureData & TPER_FEATURE_BUFFERMGMT_SUPPORT)
               sedCtx->bufferMgmtSupported = SED_ENABLED;

            if (*featureData & TPER_FEATURE_STREAMING_SUPPORT)
                sedCtx->streamingSupported = SED_ENABLED;

            if (*featureData & TPER_FEATURE_COMIDMGMT_SUPPORT)
                sedCtx->comIdMgmtSupported = SED_ENABLED;
        }

        else if (feature->featureCode == LOCKING_FEATURE)
        {
            sedCtx->lockingFeature = SED_ENABLED;

            if (*featureData & LOCKING_FEATURE_LOCKING_SUPPORT)
                    sedCtx->lockingSupported = SED_ENABLED;

            if (*featureData & LOCKING_FEATURE_LOCKING_ENABLED)
                sedCtx->lockingEnabled = SED_ENABLED;

            if (*featureData & LOCKING_FEATURE_LOCKED)
                sedCtx->locked = SED_ENABLED;

            if (*featureData & LOCKING_FEATURE_MEDIA_ENCRYPTION)
                sedCtx->mediaEncryption = SED_ENABLED;

            if (*featureData & LOCKING_FEATURE_MBR_ENABLED)
                sedCtx->mbrEnabled = SED_ENABLED;

            if (*featureData & LOCKING_FEATURE_MBRDONE)
                sedCtx->mbrDone = SED_ENABLED;
        }

        else if(feature->featureCode == GEOMETRY_REPORTING_FEATURE)
        {
            sedCtx->geometryFeature = SED_ENABLED;
            struct geometryReportingFeatures *grFeatures = (struct geometryReportingFeatures*)featureData;
            switchBytesEndian((uint8_t*)&(grFeatures->logicalBlockSize),4);
            switchBytesEndian((uint8_t*)&(grFeatures->alignmentGranularity),8);
            switchBytesEndian((uint8_t*)&(grFeatures->lowestAlignedLba),8);
            sedCtx->logicalBlockSize = grFeatures->logicalBlockSize;
            sedCtx->alignmentGranularity = grFeatures->alignmentGranularity;
            sedCtx->lowestAlignedLba = grFeatures->lowestAlignedLba;          
        }

        else if (feature->featureCode == ENTERPRISE_FEATURE || feature->featureCode == OPAL_SSC_1 || feature->featureCode == OPAL_SSC_2)
        {
            struct opalSscFeatures *opalFeatures = (struct opalSscFeatures*)featureData;
                    
            //sedCtx->opalVersion = feature->featureCode;   
            sedCtx->opalSscFeature = SED_ENABLED;
            sedCtx->baseComId = switchEndian(opalFeatures->baseComId,2);
            sedCtx->numberOfComIds = switchEndian(opalFeatures->numberOfComIds,2);

            if(feature->featureCode == OPAL_SSC_2)
            {
                sedCtx->opalVersion = 2;
                sedCtx->rangeCrossingBehavior = opalFeatures->rangeCrossingBehavior;
                sedCtx->numberOfLockingSPAdmins = switchEndian(opalFeatures->numberOfLockingSPAdmins,2);
                sedCtx->numberOfLockingSPUsers = switchEndian(opalFeatures->numberOfLockingSPUsers,2);
                sedCtx->initialCPinSidIndicator = opalFeatures->initialCPinSidIndicator;
                sedCtx->behaviorCPinSidOnRevert = opalFeatures->behaviorCPinSidOnRevert;
            }
            else
                sedCtx->opalVersion = 1;
        }

        else if (feature->featureCode == OPAL_SINGLE_USER_FEATURE)
        {
            sedCtx->singleUserFeature = SED_ENABLED;
            struct singleUserFeatures *suFeatures = (struct singleUserFeatures*)featureData;
            sedCtx->numberOfLockingObjects = switchEndian(suFeatures->numberOfLockingObjects,4);
            sedCtx->any = suFeatures->any;
            sedCtx->all = suFeatures->all;
            sedCtx->policy = suFeatures->policy;
        }

        else if(feature->featureCode == OPAL_DATASTORE_TABLES_FEATURE)
        {
            sedCtx->datastoreTableFeature = SED_ENABLED;
            struct dataStoreFeatures *dsFeatures = (struct dataStoreFeatures*)featureData;
            sedCtx->maxNumberOfDataStoreTables = switchEndian(dsFeatures->maxNumberOfDataStoreTables,2);
            sedCtx->maxSizeOfDataStoreTables = switchEndian(dsFeatures->maxSizeOfDataStoreTables,4);
            sedCtx->sizeAlignmentDataStoreTable = switchEndian(dsFeatures->sizeAlignmentDataStoreTable,4);
        }

        else {}

        feature = (struct featureHeader*)(featureData + feature->length);
    }

    return SED_NO_ERROR;
}

int32_t sed_listSupportedProtocols(int8_t fileDescriptor)
{
    // Makes an instance of the scsi struct
    struct sg_io_hdr sgio;

    // Command struct
    struct cdb cdb;

    // The command data block
    uint8_t commandDescriptorBlock[16] = {0};

    // Sense array used for error checking
    uint8_t sense[32] = {0};

    // Return databuffer, this is where the security protocols will be returned
    uint8_t dataBuffer[512];

    // Used to hold the length of the response data
    uint8_t protocolLength = 0;

    // Counter
    uint8_t i;

    /* Initialize all data structures */

    //Initializes the SCSI struct to zeroes
    memset(&sgio, 0, sizeof(sgio));

    // Initializes the Command Descriptor block to all zeroes
    memset(&commandDescriptorBlock, 0, sizeof(commandDescriptorBlock));

    // Initializes the sense array to all zeroes
    memset(&sense, 0, sizeof(sense));

    /* Setup scsi struct */

    // Sets up the scsi struct that will be used for processing the IOCTL.
    // It points to the databuffer as well as the commanddescriptorBlock
    // amongst other things needed to process the IOCTL
    ata_initScsiStruct(dataBuffer, MIN_SIZE_OF_BUFFER, commandDescriptorBlock, sense, 1, &sgio);

    /* Setup command block for receiving */
	if(ata_createCDBBuffer(&cdb, commandDescriptorBlock, 4, 0, 1, 0, 0x5C))
	{
		fprintf(stderr, "Error creating CDB Buffer\n");
		return 1;
	}

    /* Issue ATA command via IOCTL */

    // If the Ioctl was successfully called
    if (!ioctl(fileDescriptor, SG_IO, &sgio))
    {
        // If sense[11] is not 0x00 or sense[21] is not 0x50 then an error
        // occured
        if (sense[11] != 0x00 || sense[21] != 0x50)
        {
            return ((SED_ERROR_TRUSTED_SEND)  | sense[11]<<8 | sense[21]<<16);
        }

        // Data was successfully transfered during the IOCTL call
        else
        {
            // Reads and store the length of the return supported protocols
            protocolLength = dataBuffer[7];

            // If the legnth is zero, then it supports no protocols
            if (protocolLength == 0)
            {
                // Alert user no Security protocols are supported
                printf("This drive supports no Security Protocols\n");

                // Good return
                return SED_NO_ERROR;
            }

            // Since the length is not zero it supports protocols
            else
            {
                printf("\n");
                printf("Security Protocols supported by this device:\n");
                printf("--------------------------------------------\n");

                // Loops through the length to print out each protocol
                for (i = 0; i < protocolLength; ++i)
                {
                    // Print out the supported protocols
                    printf("0x%.2x\n", dataBuffer[8 + i]);
                }

                printf("\n");
            }
        }
    }

    // IOCTL Failed
    // TODO: Implement errno, so we can have meaningful errors
    else
    {
        // Print error
      //  printf("ERROR: Could not process IOCTL Call Successfully\n");

        // Return Error
        return SED_ERROR_IOCTL_FAILED;
    }

    // Success
    return SED_NO_ERROR;
}

// TODO: Add doxygen comments for sed_tperReset
// TODO: Function is not tested
int32_t sed_tperReset(int8_t file_descriptor)
{
    // Makes an instance of the scsi struct
    struct sg_io_hdr sgio;

    // The structure that defines the ATA command to be issued
    struct cdb cdb;

    // The command data block
    uint8_t commandDescriptorBlock[CDB_MAX_LENGTH];

    // Sense array used for error checking
    uint8_t sense[MAX_SIZE_OF_SENSE_BUFF];

    /* Initialize Data Structures */

    // Initializes the SCSI struct to zeroes
    memset(&sgio, 0, sizeof(sgio));

    // Initializes the Command Descriptor block to all zeroes
    memset(&commandDescriptorBlock, 0, sizeof(commandDescriptorBlock));

    // Initializes the sense array to all zeroes
    memset(&sense, 0, sizeof(sense));

    /* Manually Set up SCSI Strcuture */

    // Dont know why, but its always suppose to be 'S'
    sgio.interface_id = 'S';

    // Points to the command data block  
    sgio.cmdp = commandDescriptorBlock;

    // The lenght of the command struct        
    sgio.cmd_len = CDB_MAX_LENGTH;

    // The amount of bytes to be transfered. Has to be a multiple of 512
    sgio.dxfer_len = 0;

    // The direction in which the data is being transferred is host->device
    sgio.dxfer_direction = SG_DXFER_NONE;

    // Points to the sense buffer, which is responsible for error messages
    sgio.sbp = sense;

    // The length of the sense variable
    sgio.mx_sb_len = MAX_SIZE_OF_SENSE_BUFF;

    // 5 seconds for the time out period.
    sgio.timeout = 5000;

    /* Prepare command descriptor block */
	if(ata_createCDBBuffer(&cdb, commandDescriptorBlock, PIO_DATA_OUT, 0x0200, 1, 0x0140, TRUSTED_SEND))
	{
	    fprintf(stderr, "Error creating cdb buffer\n");
		return 1;
	}

    // If the Ioctl was successfully called
    if (!ioctl(file_descriptor, SG_IO, &sgio))
    {
        // If sense[11] is not 0x00 or sense[21] is not 0x50 then an error
        // occured
        if (sense[11] != 0x00 || sense[21] != 0x50)
        {
            return ((SED_ERROR_TRUSTED_SEND)  | sense[11]<<8 | sense[21]<<16);
        }

        // Everything was process correctly
        else
        {
            // Print happy statement
            //printf("TperRest Successful...\n");
        }
    }

    // IOCTL Failed
    // TODO: Implement errno, so we can have meaningful errors
    else
    {
        // Print error
       // printf("ERROR: Could not process IOCTL Call Successfully\n");

        // Return Error
        return SED_ERROR_IOCTL_FAILED;
    }

    // Success
    return SED_NO_ERROR;
}

void sed_printHex(uint8_t *string, int stringLength)
{
    int i;

    for (i = 0; i < stringLength; i++)
    {
        printf("%02x",string[i]);
    }

    printf("\n");
}



int sed_generateRandomString(unsigned char *buffer, unsigned int numBytes)
{    
    memset(buffer, 0, numBytes);

    /* Generates numBytes of random data */
    if (!RAND_bytes(buffer, numBytes))
        return (sedError = ESALT);
    
    return 0;
}



int32_t sed_iterateTable(struct sedContext *sedCtx, uint64_t tableUID, uint32_t row)
{
    struct ShortAtom_t tokUid, tokMethod;
    uint32_t retVal, index = 0, totalPacketLen;
    uint8_t *dataPayload;
    uint64_t uidMethod; 

    
    // zero out entire packet
    memset(sedCtx->packet, 0, sedCtx->packetSize);

    // Setup the actual datapayload
    dataPayload = (uint8_t*)(sedCtx->packet + packets_initialize(sedCtx));

    /**************************************** Create Header ********************************************/

    // Setup everything for the invoker. In this case the invoker will be thisSP
    tokUid.id = ShortAtomId;
    tokUid.sign = SIGN_NOSIGN;
    tokUid.byte = BYTE_BYTESEQ;
    tokUid.length = sizeof(tableUID); // 8

    
    // Setup everything for the method to be called, in this case we are calling Nexr
    tokMethod.id = ShortAtomId;
    tokMethod.sign = SIGN_NOSIGN;
    tokMethod.byte = BYTE_BYTESEQ;
    tokMethod.length = 8; // 8
    uidMethod = UID_METHOD_NEXT; 
    

    // This will create the actual header for the function  
    retVal = dataPayload_CreateHeader((uint8_t*)&tokUid, (uint8_t*)&tableUID,(uint8_t*)&tokMethod, (uint8_t*)&uidMethod, dataPayload+index);
    if(retVal & SED_ERROR)
    {
        //PRINT SOMETHING
        fprintf(stderr, "Error[thisSP.createTable]: Could not create the header in the dataPayload\n");
        return -1;
    }
    index += retVal;

    // Start the arguments
    dataPayload[index++] = StartListToken;

    // Endlist for the end of parameters
    dataPayload[index++] = EndListToken;

    // Close the packet
    index += dataPayload_EndPacket(dataPayload + index);

    totalPacketLen = packets_updateLengths((struct sedContext*)sedCtx, index);

    sed_OutputPacket(sedCtx->packet, totalPacketLen);

    ata_trustedSend(sedCtx);

    printf("Packet Received: \n");
    sed_OutputPacket(sedCtx->packet, totalPacketLen*3);

    filterUIDS(sedCtx->packet, totalPacketLen*3);


    return 0;
}

void filterUIDS(uint8_t *packet, int size)
{
    uint8_t uidBuffer[8] = {0};
    int i = 0;
    uint8_t flags;
    uint32_t argSize;


    printf("------------------UIDs --------------------------\n");
    // Populate the Array
    for (i = 0; i < size; i++)
    {
        if (packet[i] == 0xA8)
        {
            dataPayload_GetDataFromArgument(packet + i, uidBuffer, &argSize, &flags);
            sed_OutputPacket(uidBuffer, 8); 
            memset(uidBuffer, 0, 8);
        }
    }
    printf("-------------------------------------------------\n");    
    return;
}

uint8_t *getCpinUIDS(struct sedContext *sedCtx, uint8_t *uidList)
{
    uint8_t uid[UID_SIZE], id;
    int32_t i = 0;

    // Clear out entire list
    memset(uidList, 0, UID_LIST_SIZE);
    
    // Get all of the Admin UIDs
    for (id = 1; id <= MAX_ADMINS; ++id)
    {
        memset(uid, 0, UID_SIZE);
        
        // Get the UID for this Admin+ID combination
        cpin_getUID(sedCtx, (SedAccounts)Admin, id, uid);
        
        // If nothing was returned from the packet then we are done
        if (uid == NULL)
            break;
        
        // Fill up the list with the UIDs
        memcpy(uidList + i, uid, 8);
        i+=8;
    }

    for (id = 1; id <= MAX_USERS; ++id)
    {
        memset(uid, 0, 8);
        
        // Get UID for this User+IF combination
        cpin_getUID(sedCtx, (SedAccounts)User, id, uid);
        
        // If the packet returned is NULL then we are done
        if (uid == NULL)
            break;

        // Fill up the list with the UIDs
        memcpy(uidList + i, uid, 8);
        i+=8;
    }

    return uidList;
}



char getMenuChoice()
{
    char choice = 0;

    // Make it so as soon as the user selects the option it executes, rather than having to press enter
    system("stty raw");
    
    choice = getchar();

    system("stty cooked");
    return choice;
}

int32_t sed_testLogin(struct sedContext *sedCtx, SedAccounts newUser, uint8_t newId, uint8_t *passwordHash)
{
    int32_t retVal;
    SedAccounts savedAccount = newUser;
    uint8_t savedID = newId;

    // Make sure Context is set correctly 
    sedCtx->account = newUser;
    sedCtx->id = newId;
    
    // In case session is already started
    sessionManager_closeSession(sedCtx);

    // If we can start a session with the new password, user, and id, then the account was successfulluy created.
    retVal = sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, passwordHash);
    if (retVal & SED_ERROR)
    {
        fprintf(stderr, "Error: Something went wrong with the creation of the account\n");
        sedCtx->account = savedAccount;
        sedCtx->id = savedID;
        return retVal;
    }

    printf("User Successfully created!\n");

    sessionManager_closeSession(sedCtx);

    // Restore Values
    sedCtx->account = savedAccount;
    sedCtx->id = savedID;

    return 0;
}

int32_t mountDevice(char *device, char *mountPoint)
{
    char fileTypes[][MAX_STRING_SIZE] = {"auto", "ext2", "ext3", "ext4", "btrfs", "ntfs", "vfat", "msdos" "END"};
    int32_t i = 0;


    /* We dont know in advance the filesystem of the device, so we iterate through each type to figure it out */
    while (strncmp(fileTypes[i], "END", 3))
    {
       if (!mount(device, mountPoint, fileTypes[i], 0, NULL))
       {
            i++;
            break;
       }

       /* Invalid filesystem type */
       if (errno == EINVAL)
       {
           i++;
           continue;
       }
           
       /* Devive is busy/ already mounted */
       else if (errno == EBUSY)
       {
           /* Attempt to unmount it and mount again */
           if (unmountDevice(mountPoint))
           {
               fprintf(stderr, "Device is already mounted and busy. Failed to unmount it\n");
               return 1;
           }
           i = 0;
       }

       /* Something else other than wrong filesystem */
       else
       {
           printf("%d\n", errno);
           fprintf(stderr, "Error: Cannot mount\n");
           return 1;
       }
    }
    
    return 0;
}

int32_t mountUSB(char *device)
{
    //char fileTypes[][MAX_STRING_SIZE] = {"ext4", "auto", "ext2", "ext3", "btrfs", "ntfs", "vfat", "msdos", "END"};
    char command[MAX_STRING_SIZE] = {0};
    //int32_t i = 0;

    sprintf(command, "umount %s > /dev/null 2>&1", device); 

    system(command);

    memset(command, 0, MAX_STRING_SIZE);
    sprintf(command, "mount -t auto %s %s > /dev/null 2>&1", device, USB_MOUNT_POINT); 
    
    if (!system(command))
    {
        CLEAR_SCREEN
        return 0;
    }

    perror("Error");
    printf("Command failed\n");

    // /* Attempt to unmount it incase its mounted */
    // if (umount2(USB_MOUNT_POINT, MNT_FORCE))
    //     perror("Warning");

    // /* We dont know in advance the filesystem of the device, so we iterate through each type to figure it out */
    // while (strncmp(fileTypes[i], "END", 3))
    // {
    //    CLEAR_SCREEN

    //    memset(command, 0, MAX_STRING_SIZE);
    //    sprintf(command, "mount -t %s %s %s > /dev/null 2>&1", "auto", device, USB_MOUNT_POINT);
       
    //    if (!system(command))
    //    {
    //     printf("pass\n");
    //        CLEAR_SCREEN
    //        return 0;
    //    }
       
    //    else
    //        i++;     
    // }

    // fprintf(stderr, "Error: Could not mount the device\n");
    return 1;
}

int32_t unmountDevice(char *device)
{
    int32_t count = 0;

    while(umount2(device, MNT_FORCE) && count < 2)
    {
        printf("Device: %s\n",device);
        /* Attempt to wait until its finished being busy */
        if (errno == EBUSY)
        {
            sleep(2);
            count++;
            continue;
        }

        else
        {
            perror("Unmount");
            return 1;
        }
    }

    if (count == 2)
        return 1;
    else
        return 0;
}

int32_t bufferToFile(char *file, uint8_t *buffer, uint32_t bufferSize)
{
    int32_t fd;

    /* Create the file if it does not exist */
    if ((fd = open(file, O_WRONLY | O_CREAT)) == -1)
    {
        perror("Error Opening file");
        return 1;
    }

    /* Write up to bufferSize bytes to the file */
    if (write(fd, buffer, bufferSize) == -1)
    {
        perror("Error writing buffer to file");
        
        if (close(fd) == -1)
            perror("Error closing file");
        
        return 1;
    }  
    
    /* Done with the file, close it up */
    if (close(fd) == -1)
        perror("Error closing file");

    return 0;
}

uint8_t *fileToBuffer(char *file, uint8_t *buffer, uint32_t bufferSize)
{
    int32_t fd;

    /* Attempt to open the file that contains the information we need */
    if ((fd = open(file, O_RDONLY)) == -1)
    {
        perror("Error Opening file ");
        return NULL;
    }

    /* Attempt to read bufferSize bytes into the buffer */
    if (read(fd, buffer, bufferSize) == -1)
    {
        perror("Error reading file");
        
        if (close(fd) == -1)
            perror("Error closing file");
        return NULL;
    }

    /* Cleanup */
    if (close(fd) == -1)
        perror("Error closing file");
    return buffer;
}

int32_t generateRsaKeys(char *keyPassword)
{
    char command[MAX_STRING_SIZE] = {0};
        
    /* Generate the public private key pair */
    sprintf(command, "openssl genrsa -des3 -out private.pem -passout pass:%s 2048", keyPassword);
    
    /* Attempt to execute the command, checking for errors */
    if (system(command))
    {
        fprintf(stderr, "Error: Could not generate key pairs!\n");
        sleep(2);
        return 1;
    }

    /* Extract the public key */
    memset(command, 0, MAX_STRING_SIZE);
    
    sprintf(command, "openssl rsa -passin pass:%s -in private.pem -outform PEM -pubout -out public.pem", keyPassword);
    
    /* Attempt to execute the command, checking for errors */
    if (system(command))
    {
        fprintf(stderr, "Error: Could not extract public key!\n");
        sleep(2);
        return 1;
    }

    return 0;
}

int32_t generateEcdsaKeys()
{
    ECDSA_SIG *signature;

    /* Generate a new signature */
    signature = ECDSA_SIG_new();  

    /* Free up that signature */
    ECDSA_SIG_free(signature);

    return 0;
}


uint8_t *encryptWithPublicKey(uint8_t *plaintext, uint8_t *encryptedBuffer, char *keyLocation, char *keyPassword)
{
    char command[MAX_STRING_SIZE];

    memset(command, 0, MAX_STRING_SIZE);
    memset(encryptedBuffer, 0, MAX_ENCRYPT_SIZE);

    /* Copy the plaintext to a file*/
    if (bufferToFile("plaintext.txt", plaintext, MAX_PASSWORD_LEN))
        return NULL;
    
    /* Encrypt the plaintext */
    sprintf(command, "openssl rsautl -in plaintext.txt -encrypt -passin pass:%s -pubin -inkey %s -out output.txt", keyPassword, keyLocation);
    
    if (system(command))
    {
        fprintf(stderr, "Error: Could not encrypt the string\n");
        return NULL;
    }

    /* Retrieve Encrypted blob */
    if (fileToBuffer("output.txt", encryptedBuffer, MAX_ENCRYPT_SIZE) == NULL)
        return NULL;

    /* Remove the file that we created */
    if (unlink("plaintext.txt") == -1)
        fprintf(stderr, "Warning: Could not remove a temporary file\n");

    if (unlink("output.txt") == -1)
        fprintf(stderr, "Warning: Could not remove a temporary file\n");

    return encryptedBuffer;
}

uint8_t *decryptWithPrivateKey(uint8_t *blob, uint8_t *decryptBuffer, char *keyLocation, char *keyPassword)
{
    char command[MAX_STRING_SIZE];

    memset(command, 0, MAX_STRING_SIZE);
    memset(decryptBuffer, 0, MAX_PASSWORD_LEN);

    /* Copy the blob to a file*/
    if (bufferToFile("blob.txt", blob, MAX_ENCRYPT_SIZE))
        return NULL;

    /* Decrypt the blob */
    sprintf(command, "openssl rsautl -in blob.txt -passin pass:%s -decrypt -inkey %s -out output.txt", keyPassword, keyLocation);

    if (system(command))
    {
        fprintf(stderr, "Error: Could not decrypt the blob\n");
        return NULL;
    }

    /* Retrieve plaintext */
    if (fileToBuffer("output.txt", decryptBuffer, MAX_ENCRYPT_SIZE))
        return NULL;

    /* Remove the file that we created */
    if (unlink("blob.txt") == -1)
        fprintf(stderr, "Warning: Could not remove a temporary file\n");

    if (unlink("output.txt") == -1)
        fprintf(stderr, "Warning: Could not remove a temporary file\n");
    
    printf("decrypted\n");
    return decryptBuffer;
}

uint32_t loginWithDefaultAccount(struct sedContext *sedCtx, SedAccounts account)
{       
    uint8_t id = 1, salt[MAX_SALT_LENGTH] = {0}, hashedPassword[MAX_PASSWORD_LEN] = {0};
    char defaultPassword[MAX_PASSWORD_LEN] = {0};


    /* If the account is AdminSP, then we dont need a salt */
    if (account == AdminSP)
    {
        if (strlen(DEFAULT_ADMINSP_PASSWORD) > MAX_PASSWORD_LEN)
            return EPASSLEN;
            
        strncpy(defaultPassword, DEFAULT_ADMINSP_PASSWORD, sizeof(defaultPassword)); 

        if (loginAsAdminSP(sedCtx, defaultPassword))
            return sedError;
        
        return 0;
    }

    /* Start session as anybody to get salt */ 
    if (sed_startSessionAsAnybody(sedCtx, Admin))
        return sedError;

    if (getSalt(sedCtx, account, 1, salt) == NULL)
        return sedError;

    sessionManager_closeSession(sedCtx);
    
    if (strlen(DEFAULT_ADMIN_PASSWORD) > MAX_PASSWORD_LEN)
        return EPASSLEN;

    /* Hash that password with the salt */
    strncpy(defaultPassword, DEFAULT_ADMIN_PASSWORD, sizeof(defaultPassword));

    if (hashWithSalt(defaultPassword, salt, hashedPassword) == NULL)
        return sedError;
            
    /* Login with the account */
    sedCtx->account = account;
    sedCtx->id = id;
        
    if (sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, hashedPassword) & SED_ERROR)
        return sedError = ESSESSION;

    return 0;
}

char *sed_getMSIDPassword(struct sedContext *sedCtx, char *pass)
{
    uint32_t  id;
    SedAccounts account;

    memset(pass, 0, MAX_PASSWORD_LEN);

    /* Backup context information */
    account = sedCtx->account;
    id = sedCtx->id;

    /* Start session as the anybody */   
    if (sed_startSessionAsAnybody(sedCtx, AdminSP))
    {
        sedError = ESSESSION;
        return NULL;
    }

    /* Get the MSID PIN */
    if (cpin_getPassword(sedCtx, Manufacturer, 0, NULL, (uint8_t *)pass) & SED_ERROR)
    {
        sedError = ECPINR;
        return NULL;
    }

    sessionManager_closeSession(sedCtx);

    /* Restore information */
    sedCtx->account = account;
    sedCtx->id = id;

    return pass;
}

uint32_t sed_takeOwnership(struct sedContext *sedCtx, char *hardDrive, char *newPassword)
{
    uint8_t id = 0;
    char msidPassword[MAX_PASSWORD_LENGTH] = {0}, newSIDPassword[MAX_PASSWORD_LENGTH] = {0};
    SedAccounts user = AdminSP;

    if ((sedError = sed_initialize(sedCtx, hardDrive, user, id)) != 0)
        return sedError;
    
    printf("[+] SED context initialized\n");

    /* In order to login, we must first get the MSID password, then login with the MSID password */
    if (sed_getMSIDPassword(sedCtx, msidPassword) == NULL)
        return sedError;

    /* Print MSID */
    printf("[+] MSID: ");
    sed_printHex((uint8_t *)msidPassword, 32);

    /* Now we can change the password to a known password */
    if (sessionManager_startSession(sedCtx, 1, strlen(msidPassword), (uint8_t *)msidPassword) & SED_ERROR)
        return (sedError = EOWNED);

    if (strlen(newPassword) > MAX_PASSWORD_LENGTH)
        return sedError = EPASSLEN;

    strncpy(newSIDPassword, newPassword, sizeof(newSIDPassword));

    if (cpin_setPassword(sedCtx, AdminSP, id, MAX_PASSWORD_LENGTH, (uint8_t *)newSIDPassword) & SED_ERROR)
        return (sedError = ECPINW);

    printf("[+] Default distress password: %s\n", newSIDPassword);

    /* Change the lifeCycle State from manufacture-inactive to manufactured */
    if (sed_activateTper(sedCtx))
        return sedError;


    sessionManager_closeSession(sedCtx);

    return 0;
}

uint32_t sed_isOwned(struct sedContext *sedCtx, char *hardDrive)
{
    char msidPassword[MAX_PASSWORD_LENGTH] = {0};
    SedAccounts user = AdminSP;
    uint8_t id = 0;

    if ((sedError = sed_initialize(sedCtx, hardDrive, user, id)) != 0)
        return sedError;

    /* In order to login, we must first get the MSID password, then login with the MSID password */
    if (sed_getMSIDPassword(sedCtx, msidPassword) == NULL)
        return sedError;

    /* If I failed to login with the msid password, then the drive is owned */
    if (sessionManager_startSession(sedCtx, 1, strlen(msidPassword), (uint8_t *)msidPassword) & SED_ERROR)
        return 1;

    sessionManager_closeSession(sedCtx);

    return 0;
}

uint32_t sed_activateTper(struct sedContext *sedCtx)
{
    uint8_t lifeCycleState;

    /* Check the current life cycle state */
    if (lockingSP_getLifeCycleState(sedCtx, &lifeCycleState) & SED_ERROR)
        return (sedError = ELIFEC);

    /* Activate the Tper */
    if (lockingSP_activate(sedCtx) & SED_ERROR)
        return (sedError = EACTIVATE);

    /* Make Sure the drive was succefully Activated */
    if (lockingSP_getLifeCycleState(sedCtx, &lifeCycleState) & SED_ERROR)
        return (sedError = ELIFEC);

    return 0;
}

uint32_t sed_unlockDrive(struct sedContext *sedCtx)
{
    lockingRange range = {0};
            
    range.rangeNumber = -1;
    range.readLocked = 0;
    range.writeLocked = 0;
    range.readLockingEnabled = -1;
    range.writeLockingEnabled = -1;
    range.configure = -1;

    if (lockingRange_set(sedCtx, range))
        return (sedError = EUNLOCK);
    
    return 0;
}

uint32_t sed_lockDrive(struct sedContext *sedCtx)
{
    lockingRange range;
    
    /* Setup struct so it knows that we are locking the drive */
    range.rangeNumber = -1;
    range.readLocked = 1;
    range.writeLocked = 1;
    range.readLockingEnabled = -1;
    range.writeLockingEnabled = -1;
    range.rangeLength = -1;
    range.configure = -1;
 
    /* Lock the range */ 
    if (lockingRange_set(sedCtx, range))
        return (sedError = ELOCKCONF);

    return 0;
}

uint32_t sed_configureRange(struct sedContext *sedCtx, int32_t rangeNumber)
{
    lockingRange range;

    range.rangeNumber = rangeNumber;
    range.readLocked = -1;
    range.writeLocked = -1;
    range.readLockingEnabled = 1;
    range.writeLockingEnabled = 1;
    range.configure = 1;
    range.rangeLength = sedCtx->maxLbas;
    
    /* Setup this locking range. Leaving it unlocked */ 
    if (lockingRange_set(sedCtx, range))
    {
        /* Some SEDs must be have their locking range set to 1 minus the max */
        range.rangeLength = sedCtx->maxLbas - 1;

        if (lockingRange_set(sedCtx, range))
            return (sedError = ELOCKCONF);
    }
    
    /* Erase the locking range to generate a MEK */
    if (lockingRange_erase(sedCtx, 1) & SED_ERROR)
        return (sedError = EERANGE);

    /*  Unlock the range */
    if (sed_unlockDrive(sedCtx))
        return sedError;

    return 0;
}

uint32_t sed_unshadowDrive(struct sedContext *sedCtx)
{
    char username[MAX_NAME_LENGTH] = {0};

    /* Authenticate to drive prior to locking */
    if (promptUsername(sedCtx, username, 0))
        return sedError;

    if (authenticate(sedCtx, username))
        return sedError;

    /* Unshadow the MBR */
    if (mbrControl_set(sedCtx, MBR_DISABLED, MBR_DONE_SET) & SED_ERROR)
        return (sedError = ESMBR);

    return 0;
}

uint32_t sed_startSessionAsAnybody(struct sedContext *sedCtx, SedAccounts account)
{
    /* Start a Session as anybody authority to the AdminSP security provider */
    if (account == AdminSP)
    {
        sedCtx->account = AdminSP;
        sedCtx->id = 0; 
    }

    /* Start a stssion as anybody to the AdminSP security Provider */
    else
    {
        sedCtx->account = Admin;
        sedCtx->id = 1; 
    }
    
    /* Make sure no other session is started */
    sessionManager_closeSession(sedCtx);

    /* Start the session with error checking */
    if ((sessionManager_startSession(sedCtx, 1, 0, NULL)) & SED_ERROR) 
       return (sedError = ESSESSION);
    
    return 0;
}

int32_t switchByte(uint8_t *buffer)
{    
/******* Variables *******/
    
    // Holds both low and high bytes respectively
    uint8_t low, high;

    // Iterator
    uint32_t i;

    /****************  Swapping *********************/

    // Loops through the entire arry swapping byte i with byte i+1
    for (i = 0; i < 510; i+=2)
    {
        // Sets the low byte to the current count value
        low = buffer[i];

        // Sets the high byte to the current count + 1
        high = buffer[i + 1];

        // Switch this value buffer[x] with buffer[x+1]
        buffer[i] = high;

        // Switch this value buffer[x] with buffer[x-1]
        buffer[i + 1] = low;
    }
    return 0;
}

int32_t switchWord(uint8_t *buffer)
{    
    /******* Variables *******/
    
    // Holds both low and high bytes respectively
    uint8_t first, second, third, fourth;

    // Iterator
    uint32_t i;

    /****************  Swapping *********************/

    // Loops through the entire arry swapping byte i with byte i+1
    for (i = 0; i < 508; i+=4)
    {
        // Sets the low byte to the current count value
        first = buffer[i];

        // Sets the high byte to the current count + 1
        second = buffer[i + 1];

        third = buffer[i + 2];

        fourth = buffer[i + 3];

        // Switch this value buffer[x] with buffer[x+1]
        buffer[i] = fourth;

        // Switch this value buffer[x] with buffer[x-1]
        buffer[i + 1] = third;

        buffer[i + 2] = second;

        buffer[i + 3] = first;

    }
    return 0;
}

uint32_t switchEndian(uint32_t value, uint8_t size)
{
    uint32_t retVal=0;
    if(size == 2)
    {
        // switch value at byte 0 with value at byte 1
        retVal = (uint32_t)((value&0xFF)<<8);
        retVal |= (uint32_t)((value>>8)&0xFF);
    }
    else if(size == 3)
    {
        // swtich value at byte 2 with value at byte 0
        retVal = (uint32_t)((value&0xFF)<<16);
        retVal |= (uint32_t)(value&0xFF00);
        retVal |= (uint32_t)((value>>16)&0xFF);
    }
    else if(size == 4) // catch any > 4 error
    {
        // switch byte 0 with byte 3
        // switch byte 1 with byte 2
        retVal = ((value>>24)&0xFF);
        retVal |= ((value>>8)&0xFF00);
        retVal |= ((value<<8)&0xFF0000);
        retVal |= ((value<<24)&0xFF000000);
    }
    else
    {
        retVal = value & 0xFF;
    }
    return retVal;
}

void switchBytesEndian(uint8_t *buf, uint32_t size)
{
    uint8_t temp;
    uint32_t i;
    for(i = 0; i < (size/2+(size%2)); ++i)
    {
        temp = buf[i];
        buf[i] = buf[size-i-1];
        buf[size-i-1] = temp;
    }
}

uint32_t loginAsAdminSP(struct sedContext *sedCtx, char *password)
{
    char msidPassword[MAX_PASSWORD_LEN] = {0};

    if (passwordLogin(sedCtx, password))
    {
        /* If the password isnt the same as the new AdminSP password, try the MSID password as the password */    
        if (sed_getMSIDPassword(sedCtx, msidPassword) == NULL)
            return sedError;

        if (passwordLogin(sedCtx, msidPassword))
            return (sedError = ESSESSION);
    }
    
    return 0;
}

void updateProgress(uint64_t bytesWritten, uint64_t totalBytes)
{
    uint8_t percentage, i;
    
    percentage = (100 * bytesWritten) / totalBytes;
    
    printf("\r[");
    fflush(stdout);
    
    // For every 5% throw in another =
    for(i = 1; i <= 20; ++i)
    {
        if(percentage >= (i * 5))
            printf("=");
        else
            printf(" ");
    }
    
    printf("] %d%%", percentage);

    if (bytesWritten >= totalBytes)
        printf("\n");
}

uint32_t configureMBR(struct sedContext *sedCtx, char *filePath)
{     
    /* Give users MBR access */
    if (giveUsersPermission(sedCtx))
        return sedError;

    /* Set the MBR table */
    if (filePath)
    { 
        if (mbr_set(sedCtx, filePath, updateProgress) & SED_ERROR)  
            return (sedError = ESMBR);
    }
    
    /* Enable MBR Shadowing */
    if (mbrControl_set(sedCtx, 1, 1) & SED_ERROR)
        return (sedError = ESMBR);

    return 0;
}

uint32_t sed_revertDrive(struct sedContext *sedCtx, char *password)
{
    sessionManager_closeSession(sedCtx);

    /* Must be logged in as AdminSP. Close session of whoever is logged in */    
    sedCtx->account = AdminSP;
    sedCtx->id = 0;

    if (loginAsAdminSP(sedCtx, password))
        return sedError;
        
    /* AdminSP is successfully authenticated, Now we can revert */    
    if (adminSP_revert(sedCtx) & SED_ERROR)
        return (sedError = EREVERT);
    
    return 0; 
}

uint32_t sed_psidRevert(struct sedContext *sedCtx, char *psid)
{   
    printf("%s\n%s\n\n", INITIATE_REVERT, REVERT_WARNING);

    /* We want to connect to the PSID SP since that is the SP that allows the emergency reverting */
    sedCtx->account = PsidSP;

    /* Start a session to the AdminSP as the PSID authorithy */
    if (sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LENGTH, (uint8_t *)psid) & SED_ERROR)
        return (sedError = ESSESSION);

    /*revert */    
    if (adminSP_revert(sedCtx) & SED_ERROR)
        return (sedError = EREVERT);
     
    return 0; 
}

uint32_t setupTools(struct sedContext *sedCtx, char *device, char *pba)
{
    struct password_complexity complexity;
    char defaultPassword[MAX_PASSWORD_LENGTH] = {0};
    
    system("clear");

    /* Set default AdminSP password to dpassword */
    if (strlen(DEFAULT_ADMINSP_PASSWORD) > MAX_PASSWORD_LENGTH)
        return sedError = EPASSLEN;

    strncpy(defaultPassword, DEFAULT_ADMINSP_PASSWORD, sizeof(defaultPassword));
     
    /* Start by taking ownership of the drive. Changes default password of AdminSp */ 
    if ((sedError = sed_takeOwnership(sedCtx, device, defaultPassword)))
        return sedError;

    printf("[+] Drive Successfully Activated.\n");
    printf("[+] Drive Successfully Owned\n");

    /* Sets the Default login to admin:password */
    if ((sedError = setupAdminDefaultCredentials(sedCtx)))
        return sedError;

    printf("[+] Administrator account information Successfully stored in database\n");
    printf("[+] Default login information: admin:password\n");

    /* Enable the Anybody Authority to read the datastore */
    if (datastore_enableAccess(sedCtx, 0, NoUser, 0) & SED_ERROR)
        return (sedError = EACCES);

    /* Sets the default complexit to 8 min chars, 32 max, 1 numerical, 1 special, 1 uppercase and 3 sequence */
    if ((sedError = setPasswordComplexityToDefault(sedCtx, &complexity)))
        return sedError;

    printf("[+] Default Password Complexity set\n");
    printf("[+] Configuring MBR (this step may take several minutes)\n");
    
    /* Get MBR setup for shadowing, and install PBA if there is any */
    if ((sedError = configureMBR(sedCtx, pba)))
        return  sedError;

    printf("[+] MBR Successfully configured\n");
    printf("[+] Configuring Locking Range\n");
   
    /* Setup only a single locking range. Multiple locking ranges are not supported */
    if (sed_configureRange(sedCtx, 1))
        return  sedError;

    printf("[+] Locking Range Successfully configured\n");
    printf("[+] Successfully Installed Sed-tools on Opal Drive\n");

    
    return 0;
}

uint32_t formatDataStore(struct sedContext *sedCtx)
{
    uint8_t clear[ACCOUNT_SIZE] = {0};
    int32_t offset = 0, id;

    /* Format Admin section */
    for (id = 1; id <= MAX_ADMINS; id++)
    {
        if ((offset = getAccountOffset(Admin, id)) == -1)
            return 1;
        
        CHECK_SED_ERROR(datastore_set(sedCtx, offset, ACCOUNT_SIZE, clear), ERROR_DATASTORE_WRITE, 1);
    }

    /* Format User section */
    for (id = 1; id < MAX_USERS; id++)
    {
        if ((offset = getAccountOffset(User, id)) == -1)
            return 1;

        CHECK_SED_ERROR(datastore_set(sedCtx, offset, ACCOUNT_SIZE, clear), ERROR_DATASTORE_WRITE, 1);
    }
    
    return 0;
}

uint32_t secureErase(struct sedContext *sedCtx)
{
    char choice; 

    printf("%s\n", INITIATE_ERASE);
    printf("%s\n", ERASE_WARNING);
    printf("\n%s\n", CONTINUE_CHOICE);

    /* Make sure the user really wants to erase the drive */
    choice = getMenuChoice();

    /* If the user does not want to erase the drive, then go back to admin menu */
    if (choice == 'n' || choice == 'N')
        return 1;

    
    else if (choice == 'y' || choice == 'Y')
    {
        /* Need admin Privilege */
        if (promptAdminLogin(sedCtx))
            return sedError;

        /* Continue with erasing the drive */
        if (lockingRange_erase(sedCtx, LOCKING_RANGE_1) & SED_ERROR)
            return (sedError = EERASE);
    }
            
    
    else
        return sedError = EINVAL;
    
    printf("\n%s\n", ERASE_SUCCESS);

    return 0;   
}

uint32_t userNameScreen(struct sedContext *sedCtx, char *username)
{
    displayTitle(UNLOCK_DRIVE, 1);

    /* Get the username for the user attempting to log in */
    printf("%s", ENTER_USER);

    /* Grab the username from the user */
    if (readInput(username, MAX_NAME_LENGTH) == NULL)
        return sedError;

    /* Check to see if the userName is in the System*/
    if (!searchForUser(sedCtx, username))
        return sedError = ENACCOUNT;

    return 0;
}

/*TODO: Make this more dynamic. Allow user to place what string they want to be displayed */
void displayTitle(char *title, int32_t clearScreen)
{
    if (clearScreen)
        system("clear");

    printf("%s\n", title);
    PRINT_CHAR_LOOP("_", strlen(title));
    PRINT_CHAR_LOOP("\n", 3);
}

uint32_t authenticationScreen(struct sedContext *sedCtx, char *username)
{
    system("clear");

    /* TODO: Maybe insert Title or something here */

    /* Auto detect authentication type and login based on that */
    if (authenticate(sedCtx, username))
        return sedError;

    return 0;
}

void adminLogin(struct sedContext *sedCtx)
{
    char choice;

    system("clear");

    printf("Press B to boot the drive. Press A to enter the Administrator Menu\n");

    choice = getMenuChoice();

    /* Carry out the correct operation based on the operation that the admin chooses */
    if (choice == 'B' || choice == 'b')
        bootDrive(sedCtx);
    
    else if (choice == 'A' || choice == 'a')
        displayAdminMenu(sedCtx);
    
    else
        adminLogin(sedCtx);
}

uint32_t bootDrive(struct sedContext *sedCtx)
{
    /* First Unlock the drive */
    if (sed_unlockDrive(sedCtx))
        return sedError;

    /* Unshadow the MBR */
    if (mbrControl_set(sedCtx, MBR_DISABLED, MBR_DONE_SET) & SED_ERROR)
        return (sedError = EUNLOCK);
    
    /* Reboots with an unlocked system */
    system("clear");  
    printf("%s\n", UNLOCK_SUCCESS);

    system("reboot -f 2>/dev/null");

    return 0;
}

SedAccounts getSedAccountFromString(char *account)
{
    int i;

    for (i = 0; i < 8; i++)
    {
        if (!strcmp(accountStrings[i], account))
            return i;
    }

    /* Account Does not Exist */
    return -1;
}

uint32_t interactiveCreateUser(struct sedContext *sedCtx)
{
    struct userInfo user;

    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;

    /* Get the username from the user */
    if (promptNewUsername(sedCtx, &user))
        return sedError;

    /* Get the new account type from the user */
    if (promptNewAccountType(sedCtx, &user))
        return sedError;
    
    /* Get next available id */
    user.id = getNextAvailableID(sedCtx, user.accountType);
    if (sedError)
        return sedError;

    /* Get the new authentication type from the user */
    if (promptNewAuthType(sedCtx, &user))
        return sedError;

    /* Create user with gathered credentials */
    if (createUser(sedCtx, user))
        return sedError;

    printf("Successfully Created %s\n", user.userName);

    return 0;
}

uint32_t interactiveChangeUsername(struct sedContext *sedCtx)
{
    char oldName[MAX_NAME_LENGTH] = {0};
    char newName[MAX_NAME_LENGTH] = {0};

    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;

    /* Choose which user account name to change */
    if (selectUserFromList(sedCtx, oldName, sizeof(oldName)) == NULL)
    {
        if (sedError)
            return sedError;  
        else
            return 0;
    }
    
    /* Get the new userName */  
    printf("%s", PROMPT_USERNAME);
    
    if (readInput(newName, MAX_NAME_LENGTH) == NULL)
        return sedError;

    /* Update the userName with the new name */
    if (changeUserName(sedCtx, oldName, newName))
        return sedError;

    printf("Successfully Changed Username\n");

    return 0;
}

uint32_t interactiveChangePassword(struct sedContext *sedCtx)
{
    char choice;
    struct userInfo user;

    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;

    printf("Select the Account Type: \n\n1) User Accounts\n2) Distress Account\n");
    choice = getMenuChoice();

    if (choice == '2')
    {
        if (setDistressPassword(sedCtx))
        return sedError;
    }

    /* Choose which user account to change the password for and gather its information */
    if (selectUserFromList(sedCtx, *(&user.userName), sizeof(user.userName)) == NULL)
    {
        if (sedError)
            return sedError;  
        else
            return 0;
    }


    if (getUserInformationFromUserName(sedCtx, &user))
        return sedError;

    /* Allow the user to select the new authentication type */
    printf("%s\n\n", AUTH_CHOICE);
    printf("1) Password\n2) SmartCard\n3) SmartCard + Password\n4) USB\n5) Two Passwords\n"); 
    
    choice = getMenuChoice();
    user.authenticationType = choice;

    if (setupNewAuth(sedCtx, user))
        return sedError;

    printf("%s\n",CHANGE_PASSWORD_SUCCESS);

    return 0;
}

uint32_t interactiveDeleteUser(struct sedContext *sedCtx)
{
    char user[MAX_NAME_LENGTH] = {0};

    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;

    /* Choose which user account to change the password for and gather its information */
    if (selectUserFromList(sedCtx, user, sizeof(user)) == NULL)
    {
        if (sedError)
            return sedError;  
        else
            return 0;
    }

    if (deleteUser(sedCtx, user))
        return sedError;

    printf("\n%s\n", DELETE_USER_SUCCESS);

    return 0;
}

uint32_t stringToLower(char *str)
{
    size_t length = strlen(str);
    int32_t i;
 
    /* Check for a bad pointer */
    if (!str)
        return sedError = EBPOINTER;

    /* If the length of the string is larger than the String size limit, dont procress it */
    if (length > MAX_STRING_SIZE)
        return (sedError = ESTRINGMAX);
  
    /* Convert Each character to a lower case one by one */
    for (i = 0; i < length; i++)
        str[i] = tolower(str[i]); 

    /*
        while (*str != 0)
        {
            *str++ = tolower(*str++);
        }

        *str = '\0';
    */
        
    return 0;
}

char *selectUsbDevice(char *usbDevice, uint32_t size, int32_t onLogin)
{
    DIR *dirp;
    struct dirent *devices;
    int32_t i = 0, fd, count = 0;
    char deviceName[MAXNAMLEN] = {0}, isRemovable[2] = {0}, usbDevices[10][12], choice;
    char blockDevice[] = "/sys/block/";

refresh:

    system("clear");   
    
    for (i = 0; i < 10; i++)
        memset(usbDevices[i], 0, 12);

    memset(usbDevice, 0, MAX_NAME_LENGTH);
    count = 0;

    /* All of the block devices are located in /sys/block */
    if ((dirp = opendir(blockDevice)) == NULL)
    {
        perror("Error(opendir) ");
        exit(EXIT_FAILURE);
    }

    /* Get all of the block devices that are in that directory */
    for (i = 0; i < 20; i++)
    {
        memset(deviceName, 0, MAXNAMLEN);
        memset(isRemovable, 0, 2);

        if ((devices = readdir(dirp)) == NULL)
            break;

        /* Dont want to check out files ., .., or sr* */
        if ((!strncmp(devices->d_name, ".", 1) || (!strncmp(devices->d_name, "..", 2) || (!strncmp(devices->d_name, "sr", 2)))))
            continue;
    
        /* /sys/block/DEVICE_NAME/removable will be set if it is removable storage */
        if (strlen(blockDevice) > sizeof(deviceName))
            return NULL;

        strncpy(deviceName, blockDevice, sizeof(deviceName));
        strcat(deviceName, devices->d_name); 
        strcat(deviceName, "/removable");

        /* Read the file removable to see if the byte is set */
        if ((fd = open(deviceName, O_RDONLY)) < 1)
            usbCleanup(dirp, fd, 1);

        if ((read(fd, isRemovable, 1)) != 1)
            usbCleanup(dirp, fd, 1);

        close(fd);
        
        if ((!strncmp(isRemovable, "1", 1)))
        {
            strcat(usbDevices[count], "/dev/");
            strcat(usbDevices[count++], devices->d_name);
        } 
    }

    /* Close Main path with error checking */
    usbCleanup(dirp, 0, 0);

    printf("Select USB Storage Device\n");
    printf("-------------------------\n");
    for (i = 0; i < count; i++)
            printf("%d) %s\n", i + 1, usbDevices[i]);

    printf("\n");

    if (!onLogin)
        printf("%d) Go Back\n", i+1);
    
    printf("\nPress R to refresh the list...\n");
    
    choice = getMenuChoice();

    /* The user wants to "Go Back" */
    if (!onLogin)
    {
        if ((choice - 0x30) == (i + 1))
            return NULL;
    }

    /* Refresh the USB list */
    if (choice ==  'r' || choice == 'R')
        goto refresh;

    if ((choice - 0x30) > count || (choice - 0x30) < 1)
        goto refresh;

    else
    {
        if (strlen(usbDevices[(choice - 0x30) - 1]) > MAX_PATH_LENGTH)
            return NULL;


        strncpy(usbDevice, usbDevices[(choice - 0x30) - 1], size);
        strcat(usbDevice, "1");   
    }
    
    return usbDevice;
}

uint32_t usbCleanup(DIR *dirp, int32_t fd, int32_t onError)
{
    if (onError)
        perror("Error ");

    /* Close file if provided */
    if (fd)
        close(fd);

    /* Close main directory */
    if (closedir(dirp))
    {
        perror("Error: ");
        exit(EXIT_FAILURE);
    }

    if (onError)
        exit(EXIT_FAILURE);
    else
        return 0;    
}
