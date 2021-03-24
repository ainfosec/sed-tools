#include "../include/sed/sed.h"

#include <stdio.h>

int32_t datastore_set(struct sedContext *sedCtx, uint32_t where, uint32_t size, uint8_t *values)
{
    uint8_t *valsWithToken;
    uint32_t retVal, szValsWithToken = size;
    uint8_t szToken = 0;
    if(size <= ShortAtom_MaximumLength)
        szToken = 1;
    else if(size <= MediumAtom_MaximumLength)
        szToken = 2;
    else
        return SED_ERROR_INVALID_ARGUMENT;

    szValsWithToken += szToken;

    valsWithToken = (uint8_t*)malloc(szValsWithToken);
    if(!valsWithToken)
        return SED_ERROR_MALLOC;
    dataPayload_createTokenByLength(size,valsWithToken);
    memcpy(valsWithToken+szToken,values,size);

    retVal = sed_genericSet(sedCtx, UID_DATASTORE, where, szValsWithToken, valsWithToken);
    free(valsWithToken);
    return retVal;
}

int32_t datastore_get(struct sedContext *sedCtx, uint32_t where, uint32_t size, uint8_t *retBuf)
{
    uint8_t *dataPayload, flags;
    uint32_t index = 0, retSize;
    dataPayload = NULL;
    int32_t retVal = sed_genericGet(sedCtx, UID_DATASTORE, 1, where, where+size-1, &dataPayload);
    if(retVal & SED_ERROR)
    {
        //printf("Error: Couldn't read the datastore!\n");
        return retVal;
    }
    if(!dataPayload)
    {
        printf("Error: Return buffer from datastore not found\n");
    }
    // datapayload is pointing to return buffer, strip out SED bits
    if(dataPayload[index++] != StartListToken)
    {
        //printf("Error: Bad output from datastore read!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(dataPayload[index] == EndListToken)
    {
        if(size == 0)
            return SED_NO_ERROR;
        return SED_ERROR_INVALID_RESPONSE;
    }

    retVal = dataPayload_GetDataFromArgument(dataPayload+index, retBuf, &retSize, &flags);
    if(retVal & SED_ERROR)
    {
        //printf("Error: Couldn't parse output from datastore!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(retSize != size)
    {
        //printf("Warning: Read back %d bytes of requested %d bytes!\n",retSize,size);
    }
    return SED_NO_ERROR;
}

int32_t datastore_enableAccess(struct sedContext *sedCtx, uint8_t write, SedAccounts who, uint8_t id)
{
    uint64_t uidInvoker;
    uint8_t *values;
    uint32_t szValues, retVal;

    // Set up the UID
    if (write)
        uidInvoker = UID_ACE_DATASTORE_SET_ALL;
    else
        uidInvoker = UID_ACE_DATASTORE_GET_ALL;

    // Set up the values buffer first
    values = (uint8_t*)malloc(sedCtx->tperMaxPacketSize);  // overkill but big enough
    memset(values, 0, sedCtx->tperMaxPacketSize);
    // Populate the buffer, only user1 access is implemented
    szValues = ace_giveAccess(who, id, values);
    if (szValues & SED_ERROR)
    {
        free(values);
        return szValues;
    }

    // Call the generic set
    retVal = sed_genericSet(sedCtx, uidInvoker, -1, szValues, values);
    free(values);
    return retVal;
}
