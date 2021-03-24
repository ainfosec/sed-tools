#ifndef __SED_DATAPAYLOAD_H__
#define __SED_DATAPAYLOAD_H__

#include "../sed/sed.h"

/**
 @brief Initialize the Data Payload header

 This function will populate the Method UID (table) and the function UID (row) to be performed by the SED

 @param methodToken - determines the size, sign and value type of the method UID (should be length=8,sign=unsigned,b=byte sequence)
 @param methodUid - the UID of the method (table) to be called. Should be an 8 byte unique value
 @param functionToken - determines the size, sign and value type of the function UID (len=8,sign=unsigned,b=byte seq)
 @param functionUid - the UID of the function (row) to be called.  Should be an 8 byte unique value
 @param dataPacket - pointer to where these UIDs should be inserted

 @return total bytes inserted into the packet, -1 on error

 \code
 // Example from Session Manager - Start Session
 if ((retSize = dataPayload_CreateHeader((uint8_t*)&tokenLen8,
 (uint8_t*)&SMUID_invoke, (uint8_t*)&tokenLen8,
 (uint8_t*)&SMUID_methodStartSessionUID,
 (uint8_t*)(dataPayload + index))) == -1)
 {
 // error occurred
 printf("SMUID.StartSession ERROR: Could not create header!\n");
 return -1;
 }
 index += retSize;
 \endcode

 @note   The header is always an 8 byte method UID followed by an 8 byte function UID.  The token should always be a short token with value 0xA8 (short token, len 8, sign unsigned, byte byte sequence)
 */
int32_t dataPayload_CreateHeader(uint8_t *methodToken, uint8_t *methodUid,
        uint8_t *functionToken, uint8_t *functionUid, uint8_t *dataPacket);

// This is stupid, remove this function
int32_t dataPayload_StartArgumentListWithArgument(uint8_t *firstArgToken,
        uint8_t *firstArg, uint8_t *dataPacket);

/**
 @brief Add an argument into the data payload.  Argument consists of a token and a value

 This function will insert the token and the value of the argument into the data payload

 @param argumentToken - determines the size, sign and value type of the argument
 @param argument - pointer to the argument that should be inserted in the data payload
 @param dataPacket - pointer to where the argument should be inserted

 @return total bytes inserted into the packet, -1 on error

 \code
 // Example from Session Manager - Start Session
 if ((retSize = dataPayload_AddArgument((uint8_t*)&tokenLen8,
 (uint8_t*)&SPID, (uint8_t*)(dataPayload + index))) == -1)
 {
 // error
 printf("SMUID.StartSession ERROR: Argument 'SPID' failed\n");
 return -1;
 }
 index += retSize;
 \endcode

 @note   Find something in the spec about this?
 */
int32_t dataPayload_AddArgument(uint8_t *argumentToken, uint8_t *argument,
        uint8_t *dataPacket);

/**
 @brief Add a name argument into the data payload.

 This function will insert a name argument (optional argument) into the data payload.  Name arguments consist of a parameter description and the parameter value.  The desciption and value both consist of a token and value.

 @param tokenParam - determines the size, sign and value type of the parameter description
 @param optionalParamDesc - pointer to the parameter description, tells the SED what parameter value will be passed in the next argument.  If previous token was a tiny token, this value should be NULL.
 @param optionalArgumentToken - determines the size, sign and value type of the parameter value
 @param optionalArgument - pointer to the parameter value, associates the value with the previous parameter description.  If previous token was a tiny token, this value should be NULL
 @param dataPacket - pointer to where the argument should be inserted

 @return total bytes inserted into the packet, -1 on error

 \code
 // Example from Session Manager - Start Session
 if ((retSize = dataPayload_AddNameArgument(
 (uint8_t*)&tokenHostChallenge, NULL, passToken, msid_password,
 (uint8_t*)(dataPayload + index))) == -1)
 {
 printf(
 "SMUID.StartSession ERROR: Optional Argument 'MSID_PASSWORD' failed\n");
 return -1;
 }
 index += retSize;
 \endcode

 @note   Find something in the spec about this?
 */
int32_t dataPayload_AddNameArgument(uint8_t *tokenParam,
        uint8_t *optionalParamDesc, uint8_t *optionalArgumentToken,
        uint8_t *optionalArgument, uint8_t *dataPacket);

/**
 @brief Add a name argument list

 This function will insert a Tiny Atom token describing a name argument then the StartList token

 @param tokenParam - determines the named argument list
 @param dataPacket - pointer to where the argument should be inserted

 @return total bytes inserted into the packet, -1 on error

 \code
 // Example from Session Manager - Properties
 if ((retSize = dataPayload_AddNameArgumentList(
 &tokenProperty,(uint8_t*)(dataPayload + index))) == -1)
 {
 printf(
 "SMUID.Properties ERROR: Optional Argument List 'Host Properties' failed\n");
 return -1;
 }
 index += retSize;
 \endcode

 @note   Find something in the spec about this?
 */
int32_t dataPayload_StartNameArgumentList(struct TinyAtom_t *tokenParam,
        uint8_t *dataPacket);

/**
 @brief Closes a name argument list

 This function will insert an EndList token then a EndName token

 @param tokenParam - determines the named argument list
 @param dataPacket - pointer to where the argument should be inserted

 @return total bytes inserted into the packet

 \code
 // Example from Session Manager - Properties
index += dataPayload_CloseNameArgumentList((uint8_t*)(dataPayload+index))

 @note   Find something in the spec about this?
 */
int32_t dataPayload_CloseNameArgumentList(uint8_t *dataPacket);

/**
 @brief Close the data payload

 This function will close the data payload with EndOfDataToken and zero'd Method Status List

 @param dataPacket - pointer to where the argument should be inserted

 @return total bytes inserted into the packet (always 6), no errors reported (could just crash if buffer overflow)

 \code
 // Close the packet
 index += dataPayload_EndPacket(dataPayload + index);
 \endcode

 @note   Find something in the spec about this?
 */
int32_t dataPayload_EndPacket(uint8_t *dataPacket);

/**
 @brief Parse the argument out of the data payload starting at the token

 This function will determine the value stored at the pointer, the type of value, and other associated flags.  Helper to determine value of something returned by the SED

 @param argStart - where the argument to be parsed starts at
 @param argVal - output, byte array to store the argument at argStart
 @param argValSize - output, uint32_t* to the size of the array of the argument
 @param argValFlags - output, uint8_t* to the byte and sign flags of the argument bit0 = sign, bit1 = byte

 @return total size of the argument (includes token and argument), offset to next byte in data payload

 \code
 // From Session Manager - checkSyncSession
 // Gets the SpSessionId from the TPer (SED)
 if((retSize=dataPayload_GetDataFromArgument(entirePacket+index,argument,&size,&flags))==-1)
 {
 printf("Error in SP Session ID argument of SyncSession!\r\n");
 }
 \endcode

 @note   Find something in the spec about this?
 */
int32_t dataPayload_GetDataFromArgument(uint8_t *argStart, uint8_t *argVal,
        uint32_t *argValSize, uint8_t *argValFlags);

/**
 @brief Identify the type of token at a specified pointer, helps parse out a packet from the SED

 This function will parse out what type of token is at the packet.  When checking TRUSTED_RECEIVE, it may be necessary to parse an argument out of the data payload.  This identifies the token so the argument length can be determined

 @param pointer into a data payload where a token should be

 @return TokenType - the type of token at the pointer (enum: TinyAtom, ShortAtom, MediumAtom or LongAtom), -1 on error

 \code
 // From Session Manager - getPropertiesResponse
 tokenType = dataPayload_IdentifyToken(tokenPtr);
 switch(tokenType)
 \endcode

 @note   Find something in the spec about this?
 */
TokenType dataPayload_IdentifyToken(uint8_t *token);

/**
 @brief This function will create the correct token based on the length of the string

 @param str, string for which the token is being created
 @param token, byte array, at least the length of a long atom, that will output the token

 @return none

 \code
 // From Session Manager - properties
 dataPayload_createTokenForString(strMaxPackets, tokenString);
 \endcode

 @note   Find something in the spec about this?
 */
void dataPayload_createTokenForString(char* str, uint8_t *token);

/**
 @brief This function will create the smallest token possible for an integer

 @param val, integer for which the token is being created
 @param token, byte array, at least the length of a long atom, that will output the token

 @return length of argument for token, TinyAtom will return 0, Short Atom will return 1-4

 \code
 // From Session Manager - properties
 dataPayload_createTokenForInteger(sedCtx->hostMaxPackets, tokenValue);
 \endcode

 @note   Find something in the spec about this?
 */
uint8_t dataPayload_createTokenForInteger(uint32_t val, uint8_t *token);

/**
 @brief This function will create the smallest token possible based on the length field

 @param length, length of byte sequence
 @param token, byte array, at least the length of a long atom, that will output the token

 @return none

 \code
 // From Session Manager - properties
 size = dataPayload_createTokenByLength(passwordSize, tokenPassword);
 \endcode

 @note   Find something in the spec about this?
 */
void dataPayload_createTokenByLength(uint32_t length, uint8_t *token);


int32_t dataPayload_checkEndOfPacket(uint8_t *dataPayload);

#endif /* __SED_DATAPAYLOAD_H__ */
