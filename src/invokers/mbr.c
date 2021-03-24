#include "../include/sed/sed.h"

#include <stdio.h>
#include <inttypes.h>

// max datapayload overhead, I think it actually is 40 but being careful
#define MAXIMUM_DATAPAYLOAD_OVERHEAD 50

int32_t mbr_set(struct sedContext *sedCtx, char *filePath, void (*cbUpdateProgress)(uint64_t,uint64_t))
{
    uint64_t uidInvoker;
    uint32_t pbaSize, where;
    int32_t retVal, maxTransferSize;
    FILE *pbaFile;
    uint8_t *pbaBuffer, *transferData;

    // set up uid
    uidInvoker = UID_MBR;

    // read in the file and save it to a buffer
    pbaFile = fopen(filePath, "rb");
    if (!pbaFile)
    {
        //printf("Unable to open file %s", filePath);
        return SED_ERROR_INVALID_ARGUMENT;
    }

    /* Get the file length */
    fseek(pbaFile, 0, SEEK_END);
    pbaSize = ftell(pbaFile);
    fseek(pbaFile, 0, SEEK_SET);

    if (pbaSize > 0x8000000 && (sedCtx->opalVersion == 1))  // if fileLength>128MB its too big
    {
        printf("PBA ERROR: must be less than 128MB");
        fclose(pbaFile);
        return SED_ERROR_INVALID_ARGUMENT;
    }

    pbaBuffer = (uint8_t *)malloc(pbaSize);
    if (!pbaBuffer)
    {
        //printf("Memory error!");
        fclose(pbaFile);
        return SED_ERROR;
    }
    // zero out ourPba
    memset(pbaBuffer, 0, pbaSize);

    // Read In the contents of our binary file into the buffer
    if (fread(pbaBuffer, 1, pbaSize, pbaFile) != pbaSize)
    {
        //printf("Error: cannot read PBA file!\n");
        fclose(pbaFile);
        free(pbaBuffer);
        return SED_ERROR_INVALID_ARGUMENT;
    }
    // close the file, no longer needed
    fclose(pbaFile);

    // Figure out our max transfer size
    // Start with the assumption that the limiting value is max compacket size
    maxTransferSize = sedCtx->tperMaxComPacketSize - SIZEOF_COMPACKET_HDR;

    // the max packet size could be more limiting than the max compacket size
    if (maxTransferSize > sedCtx->tperMaxPacketSize)
        maxTransferSize = sedCtx->tperMaxPacketSize;
    // make room for packet and datasubpacket header
    // make room for invoking, method uid, where, etc.
    maxTransferSize = maxTransferSize - SIZEOF_PACKET_HDR
            - SIZEOF_DATASUBPACKET_HDR - MAXIMUM_DATAPAYLOAD_OVERHEAD;
    // the maximum token size could be a limiting factor
    if (maxTransferSize > sedCtx->tperMaxIndTokenSize)
        maxTransferSize = sedCtx->tperMaxIndTokenSize;

    // set up a buffer to send
    transferData = (uint8_t*)malloc(maxTransferSize+sizeof(struct LongAtom_t));
    // it is time to loop through performing set operations
    //maxTransferSize = 2047;

    for(where = 0; where < pbaSize; where += maxTransferSize)
    {
        uint32_t actualTransferSize = maxTransferSize;
        uint8_t transferToken[sizeof(struct LongAtom_t)];

        if (cbUpdateProgress)
            cbUpdateProgress(where, pbaSize);

        if (where + maxTransferSize > pbaSize)
            actualTransferSize = pbaSize - where;

        memset(transferData,0,maxTransferSize+sizeof(struct LongAtom_t));
        dataPayload_createTokenByLength(actualTransferSize,transferToken);

        // FIXME: Should not be hard coded, figure out the best way to get this size in sed initialize
        //dataPayload_createTokenByLength(512,transferToken);

        retVal = dataPayload_AddArgument(transferToken,pbaBuffer+where,transferData);
        if(retVal & SED_ERROR)
        {
            printf("Error: Could not set shadow MBR at 0x%x\n",where);
            free(pbaBuffer);
            return SED_ERROR_INVALID_ARGUMENT;
        }

        retVal = sed_genericSet(sedCtx, uidInvoker, where, retVal, transferData);
        if(retVal & SED_ERROR)
        {
            sed_errors_print(retVal);
            printf("Error: Could not set MBR in range 0x%x - 0x%x\n!",where,where+actualTransferSize);
            free(pbaBuffer);
            return retVal;
        }
    }
    
    if(cbUpdateProgress)
        cbUpdateProgress(where, pbaSize);

    free(pbaBuffer);
    return SED_NO_ERROR;
}
