#include "../include/sed/sed.h"

#include <stdio.h>

//TODO: Determine if this should be 'public'
int32_t getMediaEncryptionKeyUid(struct sedContext *sedCtx, uint8_t lockingRange, uint64_t *uidMEK);

int32_t lockingRange_set(struct sedContext *sedCtx, lockingRange range)
{
    uint8_t *buffer, rangeToken[sizeof(struct LongAtom_t)];
    uint32_t size = 0, retSize = 0, argument, argumentSize;
    uint64_t invokerUID, rangeLength;
    int64_t rangeStart;
    struct TinyAtom_t tokenTiny, tokenTinyArg;

    /* Dynamically obtain the InvokerUID, which is the SPINFO_UID with the range number appended */ 
    invokerUID = switchEndian(1, sizeof(int));
    invokerUID = (uint64_t)((uint64_t)invokerUID << 32);
    invokerUID += UID_SPINFO_LOCKINGRANGE;

    buffer = (uint8_t*)malloc(sedCtx->tperMaxPacketSize);

    buffer[size++] = StartListToken;


    
    tokenTiny.id = TinyAtomId;
    tokenTiny.sign = SIGN_NOSIGN;
    tokenTinyArg.id = TinyAtomId;
    tokenTinyArg.sign = SIGN_NOSIGN;

    /* Only need to hit this during the initial configuration of the locking ranges */
    if (range.configure == 1)
    {
        tokenTiny.data = NAME_RANGESTART;
    
        /* Assume Only one range */
        rangeStart = 0;

        argumentSize = dataPayload_createTokenForInteger(rangeStart, rangeToken);
        argument = switchEndian(rangeStart, argumentSize);

        /* RangeStart = X */
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenTiny, NULL, rangeToken, (uint8_t*)&argument, (uint8_t*)(buffer + size));

        RANGE_ERROR_CHECK(retSize, ERROR_LOCKING_RANGE_ARGUMENT, buffer)

        size += retSize;
        
        
 
        /* RangeLength = x */
    
        tokenTiny.data = NAME_RANGELENGTH;
        
        rangeLength = range.rangeLength;

        argumentSize = dataPayload_createTokenForInteger(rangeLength, rangeToken);

        argument = switchEndian(rangeLength, argumentSize);
    
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenTiny, NULL, rangeToken, (uint8_t*)&argument, (uint8_t*)(buffer + size));

        RANGE_ERROR_CHECK(retSize, ERROR_LOCKING_RANGE_ARGUMENT, buffer)

        size += retSize;
    }
    
    /* ReadLockEnabled */
    
    if (range.readLockingEnabled != -1)
    {
        tokenTiny.data = NAME_READLOCKENABLED;
        tokenTinyArg.data = range.readLockingEnabled;
        
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenTiny, NULL, (uint8_t*)&tokenTinyArg, NULL, (uint8_t*)(buffer + size));

        RANGE_ERROR_CHECK(retSize, ERROR_LOCKING_RANGE_ARGUMENT, buffer)

        size += retSize;
    }


    /* WriteLockEnabled */

    if (range.writeLockingEnabled != -1)
    {
        tokenTiny.data = NAME_WRITELOCKENABLED;
        tokenTinyArg.data = range.writeLockingEnabled;
        
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenTiny, NULL, (uint8_t*)&tokenTinyArg, NULL, (uint8_t*)(buffer + size));
        
        RANGE_ERROR_CHECK(retSize, ERROR_LOCKING_RANGE_ARGUMENT, buffer)
        
        size += retSize;
    }

    /* ReadLocked */

    if (range.readLocked != -1)
    {
        tokenTiny.data = NAME_READLOCKED;
        tokenTinyArg.data = range.readLocked;
        
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenTiny, NULL, (uint8_t*)&tokenTinyArg, NULL, (uint8_t*)(buffer + size));

        RANGE_ERROR_CHECK(retSize, ERROR_LOCKING_RANGE_ARGUMENT, buffer)
        
        size += retSize;
    }

    /* WriteLocked */
    if (range.writeLocked != -1)
    {
        tokenTiny.data = NAME_WRITELOCKED;
        tokenTinyArg.data = range.writeLocked;
        
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenTiny, NULL, (uint8_t*)&tokenTinyArg, NULL, (uint8_t*)(buffer + size));

        RANGE_ERROR_CHECK(retSize, ERROR_LOCKING_RANGE_ARGUMENT, buffer)
        
        size += retSize;
    }

    buffer[size++] = EndListToken;

    retSize = sed_genericSet(sedCtx, invokerUID, -1, size, buffer);

    free(buffer);
    
    return retSize;
}

int32_t getMediaEncryptionKeyUid(struct sedContext *sedCtx, uint8_t rangeNumber, uint64_t *uidMEK)
{
    uint64_t uidInvoker;
    uint32_t retVal, index = 0, szMek;
    uint8_t *dataPayload, flags;

    //printf("GET MEK!\n");

    // Set up invoking uid
    uidInvoker = switchEndian(rangeNumber,4);
    uidInvoker = (uint64_t)((uint64_t)uidInvoker << 32);
    uidInvoker += UID_SPINFO_LOCKINGRANGE;

    dataPayload = NULL;
    retVal = sed_genericGet(sedCtx, uidInvoker, 0, COLUMN_ACTIVEKEY, COLUMN_ACTIVEKEY, &dataPayload);
    if(retVal & SED_ERROR)
    {
        return retVal;
    }
    if(!dataPayload)
        return SED_ERROR;

    if(dataPayload[index] != StartListToken || dataPayload[index+1] != StartListToken)
    {
        //printf("Error: Get MEK results, List does not start properly\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;

    if(dataPayload[index] != StartNameToken && dataPayload[index+1] != COLUMN_ACTIVEKEY)
    {
        //printf("Error: Get MEK results, Name argument incorrect\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;

    retVal = dataPayload_GetDataFromArgument(dataPayload+index, (uint8_t*)uidMEK, &szMek, &flags);
    if(retVal & SED_ERROR)
    {
        //printf("Error: Can't parse MEK!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += retVal;
    if(szMek != sizeof(uint64_t))
    {
        //printf("Warning: MEK UID is %d bytes!\n",szMek);
    }

    if(dataPayload[index++] != EndNameToken)
    {
        //printf("Error: In closing name argument!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }

    if(dataPayload[index] != EndListToken || dataPayload[index+1] != EndListToken)
    {
        //printf("Error: Get MEK results, closing lists\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    return dataPayload_checkEndOfPacket(dataPayload+index);
}

int32_t lockingRange_erase(struct sedContext *sedCtx, uint32_t rangeNumber)
{
    uint64_t uidInvoker, uidMethod = UID_METHOD_GENKEY;
    uint32_t retVal = getMediaEncryptionKeyUid(sedCtx, rangeNumber, &uidInvoker);
    if(retVal & SED_ERROR)
    {
        //printf("LockingRange%d.Erase ERROR: Could not determine encryption type!\n",rangeNumber);
        return retVal;
    }
    return sed_genericSendEmptyPayload(sedCtx, uidInvoker, uidMethod);
}

int32_t lockingRange_enableAccess(struct sedContext *sedCtx, uint32_t rangeNumber, uint8_t write, SedAccounts who, uint8_t id)
{
    uint64_t uidInvoker;
    uint8_t *values;
    uint32_t szValues, retVal;

    // Set up the UID
    uidInvoker = switchEndian(rangeNumber,4);
    uidInvoker = (uint64_t)((uint64_t)uidInvoker << 32);
    if (write)
        uidInvoker += UID_ACE_LOCKINGRANGE_WRITE;
    else
        uidInvoker += UID_ACE_LOCKINGRANGE_READ;

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

int32_t lockingRange_enableAccessForAll(struct sedContext *sedCtx, uint32_t rangeNumber, uint8_t write)
{
    uint64_t uidInvoker;
    uint8_t *values;
    uint32_t szValues, retVal;

    // Set up the UID
    uidInvoker = switchEndian(rangeNumber,4);
    uidInvoker = (uint64_t)((uint64_t)uidInvoker << 32);
    
    // Check if permission is read or write
    if (write)
        uidInvoker += UID_ACE_LOCKINGRANGE_WRITE;
    else
        uidInvoker += UID_ACE_LOCKINGRANGE_READ;

    // Set up the values buffer first
    values = (uint8_t*)malloc(sedCtx->tperMaxPacketSize);
    memset(values, 0, sedCtx->tperMaxPacketSize);
    
    // Give all users access to the locking ranges
    szValues = ace_giveAccessToAll(values);
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

void lockingRange_handleError(struct sedContext *sedCtx, int32_t error, char *buffer)
{
    if (error & SED_ERROR)
    {
        if (buffer != NULL)
            free(buffer);

        sed_errors_print(error);
        sed_cleanup(sedCtx);
    }
}
