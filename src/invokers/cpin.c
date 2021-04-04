#include "../include/sed/sed.h"

#include <stdio.h>

int32_t cpin_setPassword(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint32_t szPassword, uint8_t *password)
{
    uint8_t *values;
    uint32_t size = 0, retVal;
    uint64_t uidInvoker;
    struct TinyAtom_t tokenPin;
    uint8_t tokenPassword[sizeof(struct LongAtom_t)];

    // Set up the Invoking UID (depends on user)
    if(who == AdminSP)
        uidInvoker = UID_CPIN_SID;
    else if(who == Manufacturer)
        uidInvoker = UID_CPIN_MSID;
    else
    {
        uidInvoker = (uint64_t)(((uint64_t)id)<<56);
        if(who == Admin)
            uidInvoker += UID_CPIN_ADMIN;
        else if(who == User)
            uidInvoker += UID_CPIN_USER;
        else
            return SED_ERROR_INVALID_ARGUMENT;
    }

    if(szPassword == 0)
        return SED_ERROR_INVALID_ARGUMENT;

    // Allocate the maximum size of values
    // StartListToken + StartNameToken + "PIN" + max password token size + password + EndNameToken + EndListToken
    values = (uint8_t*)malloc(2 + sizeof(tokenPin) + sizeof(struct LongAtom_t) + szPassword + 2);

    // Start the list
    values[size++] = StartListToken;
    // Create the password argument
    // Tiny Atom representing "PIN"
    tokenPin.id = TinyAtomId;
    tokenPin.sign = SIGN_NOSIGN;
    tokenPin.data = COLUMN_PIN;
    // Create token for password
    dataPayload_createTokenByLength(szPassword, tokenPassword);
    // Place argument in values
    
    retVal = dataPayload_AddNameArgument((uint8_t*)&tokenPin, NULL, tokenPassword, password, values+size);
    if(retVal & SED_ERROR)
    {
        printf("ERROR: Could not create password argument!\n");
        free(values);
        return SED_ERROR_INVALID_ARGUMENT;
    }
    size += retVal;
    values[size++] = EndListToken;

    retVal = sed_genericSet(sedCtx, uidInvoker, -1, size, values);
    free(values);
    return retVal;
}

int32_t cpin_getPassword(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint32_t *szPassword, uint8_t *password)
{
    uint8_t *dataPayload;
    uint64_t uidInvoker;
    int32_t retVal;
    uint32_t index=0;
    uint8_t flags;

    // Set up invoking UID (only MSID is acceptable)
    if(who == AdminSP)
        uidInvoker = UID_CPIN_SID;
    else if(who == Manufacturer)
        uidInvoker = UID_CPIN_MSID;
    else
    {
        uidInvoker = (uint64_t)(((uint64_t)id)<<56);
        if(who == Admin)
            uidInvoker += UID_CPIN_ADMIN;
        else if(who == User)
            uidInvoker += UID_CPIN_USER;
        else
            return SED_ERROR_INVALID_ARGUMENT;
    }

    // Call generic set, return type is error
    // ptrPayload will point within packet to password argument
    dataPayload = NULL;

    retVal = sed_genericGet(sedCtx, uidInvoker, 0, COLUMN_PIN, COLUMN_PIN, &dataPayload);
    if(retVal & SED_ERROR)
    {
        return retVal;
    }
    
    if(!dataPayload)
    {
        return SED_ERROR;
    }

    
    // Returned fine, get password and password size
    if(dataPayload[index] != StartListToken || dataPayload[index+1] != StartListToken)
    {
        printf("Error: Get results, list not started right![%02x, %02x]\n", dataPayload[index], dataPayload[index + 1]);
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;
    if(dataPayload[index] != StartNameToken || dataPayload[index+1] != COLUMN_PIN)
    {
        printf("Error: Get results, wrong parameter returned (not \"PIN\")\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;
    // dataPayload + index now points at password token and password
    retVal = dataPayload_GetDataFromArgument(dataPayload + index, password, szPassword, &flags);
    if(retVal & SED_ERROR)
    {
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += retVal;
    // the password and size are not set for return
    // check the rest of the packet
    if(dataPayload[index++] != EndNameToken)
    {
        printf("Error: Get results, password argument did not close properly\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(dataPayload[index] != EndListToken || dataPayload[index+1] != EndListToken)
    {
        printf("Error: Get results, list did not close right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    // Check EndOfData token and Method Status List
    return dataPayload_checkEndOfPacket(dataPayload+index);
}

int32_t cpin_auditLogins(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint32_t *attempts, uint32_t *maxAttempts, uint8_t *persistence)
{
    uint8_t *dataPayload;
    uint64_t uidInvoker;
    int32_t retVal;
    uint32_t index=0,retSize;
    uint8_t flags;
    uint8_t col,i;

    // Set up invoking UID (only MSID is acceptable)
    if(who == AdminSP)
        uidInvoker = UID_CPIN_SID;
    else if(who == Manufacturer)
        uidInvoker = UID_CPIN_MSID;
    else
    {
        uidInvoker = (uint64_t)(((uint64_t)id)<<56);
        if(who == Admin)
            uidInvoker += UID_CPIN_ADMIN;
        else if(who == User)
            uidInvoker += UID_CPIN_USER;
        else
            return SED_ERROR_INVALID_ARGUMENT;
    }

    // Call generic set, return type is error
    // ptrPayload will point within packet to password argument
    dataPayload = NULL;
    retVal = sed_genericGet(sedCtx, uidInvoker, 0, COLUMN_TRYLIMIT, COLUMN_PERSISTENCE, &dataPayload);
    if(retVal & SED_ERROR)
    {
        return retVal;
    }
    if(!dataPayload)
    {
        return SED_ERROR;
    }

    // Returned fine, get password and password size
    if(dataPayload[index] != StartListToken || dataPayload[index+1] != StartListToken)
    {
        //printf("Error: Get results, list not started right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;
    for(i = 0; i < 3; ++i)
    {
        uint8_t *outData;
        if(dataPayload[index++] != StartNameToken)
        {
            //printf("Error: Get results, wrong parameter returned (not \"PIN\")\n");
            return SED_ERROR_INVALID_RESPONSE;
        }
        col = dataPayload[index++];
        if(col == COLUMN_TRYLIMIT)
        {
            outData = (uint8_t*)maxAttempts;
        }
        else if(col == COLUMN_TRIES)
        {
            outData = (uint8_t*)attempts;
        }
        else if(col == COLUMN_PERSISTENCE)
        {
            outData = (uint8_t*)persistence;
        }
        else
        {
            return SED_ERROR_INVALID_RESPONSE;
        }
        // dataPayload + index now points at value
        retVal = dataPayload_GetDataFromArgument(dataPayload + index, outData, &retSize, &flags);
        if(retVal & SED_ERROR)
        {
            return SED_ERROR_INVALID_RESPONSE;
        }
        index += retVal;
        // the password and size are not set for return
        // check the rest of the packet
        if(dataPayload[index++] != EndNameToken)
        {
            //printf("Error: Get results, password argument did not close properly\n");
            return SED_ERROR_INVALID_RESPONSE;
        }
    }
    if(dataPayload[index] != EndListToken || dataPayload[index+1] != EndListToken)
    {
        //printf("Error: Get results, list did not close right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;
    // Check EndOfData token and Method Status List
    return dataPayload_checkEndOfPacket(dataPayload+index);
}

int32_t cpin_setLoginProperties(struct sedContext *sedCtx, SedAccounts who, uint8_t id, int32_t attempts, int32_t attemptLimit, int8_t persistence)
{
    uint8_t *values;
    uint32_t size=0, retVal;
    struct TinyAtom_t tokenProperty;
    uint8_t tokenValue[sizeof(struct LongAtom_t)];
    uint64_t uidInvoker;
    uint8_t p;


    if(who == AdminSP)
        uidInvoker = UID_CPIN_SID;
    else if(who == Manufacturer)
        uidInvoker = UID_CPIN_MSID;
    else
    {
        uidInvoker = (uint64_t)(((uint64_t)id)<<56);
        if(who == Admin)
            uidInvoker += UID_CPIN_ADMIN;
        else if(who == User)
            uidInvoker += UID_CPIN_USER;
        else
            return SED_ERROR_INVALID_ARGUMENT;
    }

    values = (uint8_t*)malloc(30); // startlist(1) attempts(7) trylimit(7) persist(4) endlist(1) = 20
    if(!values)
        return SED_ERROR_MALLOC;

    tokenProperty.id = TinyAtomId;
    tokenProperty.sign = SIGN_NOSIGN;

    values[size++] = StartListToken;
    if(attemptLimit != -1)
    {
        tokenProperty.data = COLUMN_TRYLIMIT;
        dataPayload_createTokenForInteger(attemptLimit, tokenValue);
        retVal = dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL, tokenValue, (uint8_t*)&attemptLimit, values+size);
        if(retVal & SED_ERROR)
        {
            free(values);
            return SED_ERROR_INVALID_ARGUMENT;
        }
        size += retVal;
    }
    if(attempts != -1)
    {
        tokenProperty.data = COLUMN_TRIES;
        //memset(tokenValue,0,sizeof(struct LongAtom_t));
        dataPayload_createTokenForInteger(attempts, tokenValue);
        retVal = dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL, tokenValue, (uint8_t*)&attempts, values+size);
        if(retVal & SED_ERROR)
        {
            free(values);
            return SED_ERROR_INVALID_ARGUMENT;
        }
        size += retVal;
    }
    
    if(persistence != -1)
    {

        // // Add the booleanexpr name list
        // tokenBooleanExpr.id = TinyAtomId;
        // tokenBooleanExpr.sign = SIGN_NOSIGN;
        // tokenBooleanExpr.data = NAME_BOOLEANEXPR;
        // size += dataPayload_StartNameArgumentList(&tokenBooleanExpr, values + size);

        if(persistence)
            p = 1;
        
        tokenProperty.data = COLUMN_PERSISTENCE;
        //memset(tokenValue,0,sizeof(struct LongAtom_t));
        dataPayload_createTokenForInteger(p, tokenValue);
        retVal = dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL, tokenValue, &p, values+size);
        if(retVal & SED_ERROR)
        {
            free(values);
            return SED_ERROR_INVALID_ARGUMENT;
        }
        size += retVal;


        // // Add the name argument for User1 UID
        // // Half UID for authority object ref
        // tokenAuthority.id = ShortAtomId;
        // tokenAuthority.sign = SIGN_NOSIGN;
        // tokenAuthority.byte = BYTE_BYTESEQ;
        // tokenAuthority.length = sizeof(authHalfUid);
        // authHalfUid = HALF_UID_BOOLEAN_ACE;


        // // Add boolean expr OR
        // authHalfUid = HALF_UID_BOOLEAN_ACE;
        // tokenBooleanExpr.data = 1; 
        // retVal = dataPayload_AddNameArgument((uint8_t*)&tokenAuthority, (uint8_t*)&authHalfUid, (uint8_t*)&tokenBooleanExpr, NULL, values + size);
        // if (retVal & SED_ERROR)
        // {
        //     //printf("Error: Could not add User1 UID to authority list\n");
        //     return SED_ERROR_INVALID_ARGUMENT;
        // }
        // size += retVal;

    }
    

    if(size == 1) // nothing was to be set
    {
        free(values);
        return SED_ERROR_INVALID_ARGUMENT;
    }
    values[size++] = EndListToken;
    retVal = sed_genericSet(sedCtx, uidInvoker, -1, size, values);
    free(values);
    return retVal;
}

int32_t cpin_setAccountNames(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, char *username)
{
    struct TinyAtom_t tokenProperty;
    uint64_t uidInvoker;
    uint8_t values[sedCtx->hostMaxPacketSize];
    uint8_t tokenValue[sizeof(struct LongAtom_t)];
    uint32_t size=0;
    int32_t retVal = SED_NO_ERROR;

    
    // Checks the type of account that is to be created and generate a new UID for that user
    // If the accountype is is an AdminSP then we already have a UID for that type
    if (accountType == AdminSP)
    {
        uidInvoker = UID_CPIN_SID;
    }

    // If the accountype is a manufacturer then we already have an UID for that type
    else if (accountType == Manufacturer)
    {
        uidInvoker = UID_CPIN_MSID;
    }

    // If the accounType is not an AdminSP nor Manufacturer, then we must generate a UID from scratch
    else
    {
        // Use the id that was passed in for the created of the id. This works because there is a base UID for a user and an Admin.
        // In oder to differentiate between the different users, we can check the MSB of the UID for the user. If the base UID is
        // that of a user, then we check the MSB and if the MSB is 3, then we know it is user3. This is the same for admin.
        uidInvoker = (uint64_t)(((uint64_t)id) << 56);
        
        // Generate UID for an Admin
        if(accountType == Admin)
        {
            uidInvoker += UID_CPIN_ADMIN;
        }

        // Generate a UID for a user
        else if(accountType == User)
        {
            uidInvoker += UID_CPIN_USER;
        }

        else
        {
            printf("bad account!? %d %d\n",accountType, id);
            return SED_ERROR_INVALID_ARGUMENT;
        }
    }

    // Sets up the start list token
    tokenProperty.id = TinyAtomId;
    tokenProperty.sign = SIGN_NOSIGN;    
    values[size++] = StartListToken;
        
    // Creates a token for the password type thats associated with the user and adds the argument
    if (username != NULL)
    {
        tokenProperty.data = COLUMN_COMMONNAME;
        dataPayload_createTokenForString(username,tokenValue);
        retVal = dataPayload_AddNameArgument((uint8_t*)&tokenProperty, NULL, tokenValue, (uint8_t*)username, values + size);
        if(retVal & SED_ERROR)
        {
            return retVal;
        }
        size += retVal;
    }
    
    // End the argument list and set the values.
    values[size++] = EndListToken;
    return sed_genericSet(sedCtx, uidInvoker, -1, size, values);
}

int32_t cpin_getAccountNames(struct sedContext *sedCtx, SedAccounts who, uint8_t id, char *userName)
{
    uint8_t *dataPayload;
    uint64_t uidInvoker;
    int32_t retVal;
    uint32_t index=0;
    uint8_t flags;
    uint32_t size;

    // Set up invoking UID (only MSID is acceptable)
    if(who == AdminSP)
        uidInvoker = UID_CPIN_SID;
    else if(who == Manufacturer)
        uidInvoker = UID_CPIN_MSID;
    else
    {
        uidInvoker = (uint64_t)(((uint64_t)id)<<56);
        if(who == Admin)
            uidInvoker += UID_CPIN_ADMIN;
        else if(who == User)
            uidInvoker += UID_CPIN_USER;
        else
            return SED_ERROR_INVALID_ARGUMENT;
    }

    // Call generic set, return type is error
    // ptrPayload will point within packet to password argument
    dataPayload = NULL;
    retVal = sed_genericGet(sedCtx, uidInvoker, 0, COLUMN_COMMONNAME, COLUMN_COMMONNAME, &dataPayload);
    if(retVal & SED_ERROR)
    {
        return retVal;
    }
    if(!dataPayload)
    {
        return SED_ERROR;
    }
    
    // Returned fine, get password and password size
    if (dataPayload[index] != StartListToken || dataPayload[index+1] != StartListToken)
    {
        //printf("Error: Get results, list not started right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    //
    // Get Username
    //
    if (dataPayload[index] != StartNameToken || dataPayload[index+1] != COLUMN_COMMONNAME)
    {
        //printf("Error: Get results, wrong parameter returned (not \"PIN\")\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    // dataPayload + index now points at password token and password
    retVal = dataPayload_GetDataFromArgument(dataPayload + index, (uint8_t*)userName, &size, &flags);
    if(retVal & SED_ERROR)
    {
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += retVal;

    // the password and size are not set for return
    // check the rest of the packet
    if(dataPayload[index++] != EndNameToken)
    {
        //printf("Error: Get results, password argument did not close properly\n");
        return SED_ERROR_INVALID_RESPONSE;
    }

    // End of packet (hopefully)
    if(dataPayload[index] != EndListToken || dataPayload[index+1] != EndListToken)
    {
        //printf("Error: Get results, list did not close right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    // Check EndOfData token and Method Status List
    return dataPayload_checkEndOfPacket(dataPayload+index);
}

int32_t cpin_getUID(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint8_t *uid)
{
    uint8_t *dataPayload;
    uint64_t uidInvoker;
    int32_t retVal;
    uint32_t index=0;
    uint8_t flags;
    uint32_t size;

    // Set up invoking UID (only MSID is acceptable)
    if (who == AdminSP)
        uidInvoker = UID_CPIN_SID;
    
    else if (who == Manufacturer)
        uidInvoker = UID_CPIN_MSID;
    
    else
    {
        uidInvoker = (uint64_t)(((uint64_t)id)<<56);
        
        if (who == Admin)
            uidInvoker += UID_CPIN_ADMIN;
        
        else if (who == User)
            uidInvoker += UID_CPIN_USER;
        
        else
            return SED_ERROR_INVALID_ARGUMENT;
    }

    dataPayload = NULL;
    retVal = sed_genericGet(sedCtx, uidInvoker, 0, 0x00, 0x00, &dataPayload);
    if (retVal & SED_ERROR)
    {
        return retVal;
    }
    
    if (!dataPayload)
    {
        return SED_ERROR;
    }

    // The first two bytes of the return packet should be the start list token
    if (dataPayload[index] != StartListToken || dataPayload[index+1] != StartListToken)
    {
        //printf("Error: Get results, list not started right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

 
    // the third byte should be a start name token, and the fourth byte should be the column number, in our case 0x00
    if (dataPayload[index] != StartNameToken || dataPayload[index+1] != 0x00)
    {
        //printf("Error: Get results, wrong parameter returned (not \"PIN\")\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    // We should now be pointing the the UID. However the first byte we are pointing to is the token for that UID
    retVal = dataPayload_GetDataFromArgument(dataPayload + index, (uint8_t*)uid, &size, &flags);
    if (retVal & SED_ERROR)
    {
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += retVal;


    // retval should be the size of the data we just extracted. So adding it to the current index should put us at the next byte in the packet after the data which
    // should be a end name token
    if (dataPayload[index++] != EndNameToken)
    {
        //printf("Error: Get results, password argument did not close properly\n");
        return SED_ERROR_INVALID_RESPONSE;
    }

    // The next two byte should be end list tokens
    if (dataPayload[index] != EndListToken || dataPayload[index+1] != EndListToken)
    {
        //printf("Error: Get results, list did not close right!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    index += 2;

    // Check EndOfData token and Method Status List
    return dataPayload_checkEndOfPacket(dataPayload+index);
  
    return 0;
}

int8_t cpin_getAuthenticationType(struct sedContext *sedCtx, SedAccounts user, uint8_t id)
{
    int32_t retVal;
    char userName[MAX_NAME_LENGTH];

    /* Empty out buffer */
    memset(userName, 0, MAX_NAME_LENGTH); 
  
    /* Do a lookup on the Cpin table for ther specified user and gets the associated username */
    retVal = cpin_getAccountNames(sedCtx, user, id, userName);
    if (retVal & SED_ERROR)
    {
        fprintf(stderr, "Error: Could not obtain the authentication type for this particular user.\n");
        sleep(1);
        return 0;
    }
    
    /* Set the authenticationType To Password */
    if (userName[(strlen((char *)userName)) - 1] == 'P')
        return 'P';
        
    // TODO: Re-add once smartcard support is updated
    /* Set authenticationType to SmartCard */
    // else if (userName[(strlen((char *)userName)) - 1] == 'S')
    //    return 'S';
             
    /* Set the authenticationType to USB */
    else if (userName[(strlen((char *)userName)) - 1] == 'U')
        return 'U';

    /* Set the authenticationType to SC with password */
    else if (userName[(strlen((char *)userName)) - 1] == 'T')
        return 'T';

    /* Set the authenticationType to double password */
    else if (userName[(strlen((char *)userName)) - 1] == 'D')
        return 'D';

    else
    {
        fprintf(stderr, "Unknown authenticationType detected! %c\n",userName[(strlen((char *)userName)) - 1]);
        sleep(1);
        return 0;
    }
}
