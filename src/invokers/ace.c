#include "../include/sed/sed.h"

#include <stdio.h>

int32_t ace_giveAccess(SedAccounts who, uint8_t id, uint8_t *values)
{
    struct TinyAtom_t tokenBooleanExpr;
    struct ShortAtom_t tokenAuthority, tokenWho;
    uint32_t size = 0, retSize;
    uint32_t authHalfUid;
    uint64_t uidWho = sed_makeAuthorityUid(who,id);
    if (uidWho == 0ll)
        return SED_ERROR_INVALID_ARGUMENT;

    // Start the list
    values[size++] = StartListToken;

    // Add the booleanexpr name list
    tokenBooleanExpr.id = TinyAtomId;
    tokenBooleanExpr.sign = SIGN_NOSIGN;
    tokenBooleanExpr.data = NAME_BOOLEANEXPR;
    size += dataPayload_StartNameArgumentList(&tokenBooleanExpr, values + size);

    // Add the name argument for User1 UID
    // Half UID for authority object ref
    tokenAuthority.id = ShortAtomId;
    tokenAuthority.sign = SIGN_NOSIGN;
    tokenAuthority.byte = BYTE_BYTESEQ;
    tokenAuthority.length = sizeof(authHalfUid);
    authHalfUid = HALF_UID_AUTHORITY_OBJECT;
    
    // User1 UID argument
    tokenWho.id = ShortAtomId;
    tokenWho.sign = SIGN_NOSIGN;
    tokenWho.byte = BYTE_BYTESEQ;
    tokenWho.length = sizeof(uidWho);
    
    // Add it
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenAuthority, (uint8_t*)&authHalfUid, (uint8_t*)&tokenWho, (uint8_t*)&uidWho, values + size);
    if (retSize & SED_ERROR)
    {
        //printf("Error: Could not add User1 UID to authority list\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    size += retSize;
    
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenAuthority, (uint8_t*)&authHalfUid, (uint8_t*)&tokenWho, (uint8_t*)&uidWho, values + size);
    if (retSize & SED_ERROR)
    {
        //printf("Error: Could not add User1 UID to authority list\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    size += retSize;
    
    // Add boolean expr OR
    authHalfUid = HALF_UID_BOOLEAN_ACE;
    tokenBooleanExpr.data = 1; 
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenAuthority, (uint8_t*)&authHalfUid, (uint8_t*)&tokenBooleanExpr, NULL, values + size);
    if (retSize & SED_ERROR)
    {
        //printf("Error: Could not add User1 UID to authority list\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    size += retSize;

    // Close BooleanExpr name argument list
    size += dataPayload_CloseNameArgumentList(values + size);

    // Close argument list
    values[size++] = EndListToken;

    return size;
}

int32_t ace_giveAccessToAll(uint8_t *values)
{
    struct TinyAtom_t tokenBooleanExpr;
    struct ShortAtom_t tokenAuthority, tokenWho;
    SedAccounts who;
    int32_t id;
    uint32_t size = 0, retSize;
    uint32_t authHalfUid;
    uint64_t uidWho;

    // Start the list
    values[size++] = StartListToken;

    // Add the booleanexpr name list
    tokenBooleanExpr.id = TinyAtomId;
    tokenBooleanExpr.sign = SIGN_NOSIGN;
    tokenBooleanExpr.data = NAME_BOOLEANEXPR;
    size += dataPayload_StartNameArgumentList(&tokenBooleanExpr, values + size);

    // Add the name argument for User1 UID
    // Half UID for authority object ref
    tokenAuthority.id = ShortAtomId;
    tokenAuthority.sign = SIGN_NOSIGN;
    tokenAuthority.byte = BYTE_BYTESEQ;
    tokenAuthority.length = sizeof(authHalfUid);
    authHalfUid = HALF_UID_AUTHORITY_OBJECT;

    who = User;

    // Loop through all users to give them access
    for (id = 1; id <= 2; ++id)
    {
        uidWho = sed_makeAuthorityUid(who,id);
        
        if (uidWho == 0ll)
            return SED_ERROR_INVALID_ARGUMENT;

        // Create Token for that user
        tokenWho.id = ShortAtomId;
        tokenWho.sign = SIGN_NOSIGN;
        tokenWho.byte = BYTE_BYTESEQ;
        tokenWho.length = sizeof(uidWho);
    
        // Add it
        retSize = dataPayload_AddNameArgument((uint8_t*)&tokenAuthority, (uint8_t*)&authHalfUid, (uint8_t*)&tokenWho, (uint8_t*)&uidWho, values + size);
        if (retSize & SED_ERROR)
        {
            //printf("Error: Could not add User1 UID to authority list\n");
            return SED_ERROR_INVALID_ARGUMENT;
        }
        size += retSize;
    }
 
    // Add boolean expr OR
    authHalfUid = HALF_UID_BOOLEAN_ACE;
    tokenBooleanExpr.data = 1; 
    retSize = dataPayload_AddNameArgument((uint8_t*)&tokenAuthority, (uint8_t*)&authHalfUid, (uint8_t*)&tokenBooleanExpr, NULL, values + size);
    if (retSize & SED_ERROR)
    {
        //printf("Error: Could not add User1 UID to authority list\n");
        return SED_ERROR_INVALID_ARGUMENT;
    }
    size += retSize;

    // Close BooleanExpr name argument list
    size += dataPayload_CloseNameArgumentList(values + size);

    // Close argument list
    values[size++] = EndListToken;

    return size;
}
