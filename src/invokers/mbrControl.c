#include "../include/sed/sed.h"

#include <stdio.h>

int32_t addBoolProperty(uint8_t nameProperty, uint8_t valProperty, uint8_t *buffer);

int32_t mbrControl_enableAccessToDone(struct sedContext *sedCtx, SedAccounts who, uint8_t id)
{
    uint8_t *values;
    uint32_t retVal, szValues;
    uint64_t uidInvoker = UID_ACE_MBRCONTROL_DONE;

    // Set up values buffer
    values = (uint8_t*)malloc(sedCtx->tperMaxPacketSize);  // overkill but big enough
    memset(values, 0, sedCtx->tperMaxPacketSize);  // zero out
    // Populate buffer
    retVal = ace_giveAccess(who, id, values);
    
    if (retVal & SED_ERROR)
    {
        free(values);
        return retVal;
    }
    szValues = retVal;

    retVal = sed_genericSet(sedCtx, uidInvoker, -1, szValues, values);
    free(values);
    return retVal;
}

int32_t mbrControl_enableAccessToDoneForAll(struct sedContext *sedCtx)
{
    uint8_t *values;
    uint32_t retVal, szValues;
    uint64_t uidInvoker = UID_ACE_MBRCONTROL_DONE;

    // Set up values buffer
    values = (uint8_t*)malloc(sedCtx->tperMaxPacketSize);  // overkill but big enough
    memset(values, 0, sedCtx->tperMaxPacketSize);  // zero out
    
    // Populate buffer
    retVal = ace_giveAccessToAll(values);   
    if (retVal & SED_ERROR)
    {
        free(values);
        return retVal;
    }
    szValues = retVal;
    
    retVal = sed_genericSet(sedCtx, uidInvoker, -1, szValues, values);
    free(values);
    return retVal;
}

int32_t mbrControl_set(struct sedContext *sedCtx, int8_t enable, int8_t done)
{
    uint64_t uidInvoker;
    uint32_t retSize, size = 0;
    uint8_t *values;

    if (enable == -1 && done == -1)
    {
        // I have no idea why this would be called with no parameters
        return SED_NO_ERROR;
    }

    // Set up invoking uid
    uidInvoker = UID_MBRCONTROL;

    // Set up values buffer
    values = (uint8_t*)malloc(sedCtx->tperMaxPacketSize);  // overkill
    memset(values, 0, sedCtx->tperMaxPacketSize);
    // Start populating buffer
    values[size++] = StartListToken;
    // Add enable property if needed
    if (enable != -1)
    {
        retSize = addBoolProperty(NAME_ENABLE, enable, values + size);
        if(retSize & SED_ERROR)
        {
            //printf("Error: Could not %s MBR!\n",(enable?"enable":"disable"));
            free(values);
            return SED_ERROR_INVALID_ARGUMENT;
        }
        size += retSize;
    }
    // Add done property if needed
    if (done != -1)
    {
        retSize = addBoolProperty(NAME_DONE, done, values + size);
        if(retSize & SED_ERROR)
        {
            //printf("Error: Could not %s MBR Done flag!\n",(done?"enable":"disable"));
            free(values);
            return SED_ERROR_INVALID_ARGUMENT;
        }
        size += retSize;
    }
    // Close the list
    values[size++] = EndListToken;

    // Call the set function
    retSize = sed_genericSet(sedCtx, uidInvoker, -1, size, values);
    free(values);
    return retSize;
}

int32_t addBoolProperty(uint8_t nameProperty, uint8_t valProperty, uint8_t *buffer)
{
    struct TinyAtom_t tokenProperty, tokenPropertyVal;
    tokenProperty.id = TinyAtomId;
    tokenProperty.sign = SIGN_NOSIGN;
    tokenProperty.data = nameProperty;
    tokenPropertyVal.id = TinyAtomId;
    tokenPropertyVal.sign = SIGN_NOSIGN;
    tokenPropertyVal.data = (valProperty ? 1 : 0);
    return dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL,
            (uint8_t*)&tokenPropertyVal, NULL, buffer);

}
