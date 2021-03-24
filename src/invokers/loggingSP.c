#include "../include/sed/sed.h"

#include <stdio.h>

int32_t loggingSP_getLifeCycleState(struct sedContext *sedCtx, uint8_t *lifeCycleState)
{
    uint8_t *dataPayload;
    uint64_t uidInvoker;
    uint32_t retVal, index = 0;

    // Set up UID
    uidInvoker = (uint64_t)UID_LOGLIST;

    // Call get
    dataPayload = NULL;
    retVal = sed_genericGet(sedCtx, uidInvoker, 0, COLUMN_LIFECYCLE, COLUMN_LIFECYCLE, &dataPayload);
    if(retVal & SED_ERROR)
    {
        return retVal;
    }
    if(! dataPayload)
        return SED_ERROR;

    // Check packet
    if(dataPayload[index] != StartListToken && dataPayload[index+1] != StartListToken)
    {
        //printf("Error: Get results, List does not start properly!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    if(dataPayload[index] != StartNameToken && dataPayload[index+1] != COLUMN_LIFECYCLE)
    {
        //printf("Error: Get results, Wrong parameter returned (not LifeCycle)!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    // Put the life cycle state in the output argument
    lifeCycleState[0] = dataPayload[index++];
    if(dataPayload[index++] != EndNameToken)
    {
        //printf("Error: Get results, Parameter did not close properly!\n");
        return SED_ERROR_INVALID_STATUS;
    }
    if(dataPayload[index] != EndListToken && dataPayload[index+1] != EndListToken)
    {
        //printf("Error: Get results, List does not end properly!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    // check the rest of the packet
    return dataPayload_checkEndOfPacket(dataPayload+index);
}

int32_t loggingSP_genericGetLCS(struct sedContext *sedCtx, uint64_t uid, uint8_t *lifeCycleState)
{
    uint8_t *dataPayload;
    uint32_t retVal, index = 0;

    // Call get
    dataPayload = NULL;
    retVal = sed_genericGet(sedCtx, uid, 0, COLUMN_LIFECYCLE, COLUMN_LIFECYCLE, &dataPayload);
    if(retVal & SED_ERROR)
    {
        return retVal;
    }
    if(! dataPayload)
        return SED_ERROR;

    // Check packet
    if(dataPayload[index] != StartListToken && dataPayload[index+1] != StartListToken)
    {
        //printf("Error: Get results, List does not start properly!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    if(dataPayload[index] != StartNameToken && dataPayload[index+1] != COLUMN_LIFECYCLE)
    {
        //printf("Error: Get results, Wrong parameter returned (not LifeCycle)!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    // Put the life cycle state in the output argument
    lifeCycleState[0] = dataPayload[index++];
    if(dataPayload[index++] != EndNameToken)
    {
        //printf("Error: Get results, Parameter did not close properly!\n");
        return SED_ERROR_INVALID_STATUS;
    }
    if(dataPayload[index] != EndListToken && dataPayload[index+1] != EndListToken)
    {
        //printf("Error: Get results, List does not end properly!\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    index += 2;
    // check the rest of the packet
    return dataPayload_checkEndOfPacket(dataPayload+index);
}
