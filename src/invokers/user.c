#include "../include/sed/sed.h"

#include <stdio.h>

int32_t user_set(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint8_t enable)
{
    uint8_t *values;
    uint32_t size = 0, retSize;
    uint64_t uidInvoker;
    struct TinyAtom_t tokenEnabled, tokenValue;

    // set up invoker uid
    uidInvoker = sed_makeAuthorityUid(who,id);
    if(uidInvoker == 0ll)
    return SED_ERROR_INVALID_ARGUMENT;

    // Set up the values field (enable parameter)
    values = (uint8_t*)malloc(6); // StartList,StartName,TinyToken,TinyToken,EndName,EndList

    // Set up the tokens
    tokenEnabled.id = TinyAtomId;
    tokenEnabled.sign = SIGN_NOSIGN;
    tokenEnabled.data = COLUMN_ENABLED;
    tokenValue.id = TinyAtomId;
    tokenValue.sign = SIGN_NOSIGN;
    tokenValue.data = (enable?1:0);

    // Create the values field
    values[size++] = StartListToken;
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenEnabled,NULL,(uint8_t*)&tokenValue,NULL,values+size);
    if(retSize & SED_ERROR)
    {
        free(values);
        return SED_ERROR_INVALID_ARGUMENT;
    }
    size += retSize;
    values[size++] = EndListToken;

    retSize = sed_genericSet(sedCtx, uidInvoker, -1, size, values);
    free(values);
    return retSize;
}
