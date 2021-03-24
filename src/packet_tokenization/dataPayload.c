#include "../include/sed/sed.h"
#include "../include/packet_tokenization/dataPayload.h"

int32_t dataPayload_CreateHeader(uint8_t *invokerToken, uint8_t *invokingUid, uint8_t *methodToken, uint8_t *methodUid, uint8_t *dataPacket)
{
    int32_t size = 0, retSize;
    
    /* First add the call Token (F8) to the dataPayload */
    dataPacket[size++] = (uint8_t)CallToken;

    /* Add the invoker UID to the dataPayload next */
    if ((retSize = dataPayload_AddArgument(invokerToken, invokingUid, (uint8_t*)(dataPacket + size))) == -1)
    {
        fprintf(stderr, "Error: Can not add the invokerUID to the dataPayload\n");
        return SED_ERROR_INVALID_HEADER;
    }

    /* Update the total size used so far */
    size += retSize;

    /* Add the method UID to the dataPayload next */
    if ((retSize = dataPayload_AddArgument(methodToken, methodUid, dataPacket + size)) == -1)
    {
        fprintf(stderr, "Error: Can not add the methodUID to the dataPayload\n");
        return SED_ERROR_INVALID_HEADER;
    }

    /* Return the size of the dataPayload */   
    return size + retSize;
}

int32_t dataPayload_StartArgumentListWithArgument(uint8_t *firstArgToken, uint8_t *firstArg, uint8_t *dataPacket)

{
    int32_t size = 0, retSize;

    // Prepend that parameter list with the start list token
    dataPacket[size++] = StartListToken;

    if ((retSize = dataPayload_AddArgument(firstArgToken, firstArg,
            dataPacket + size)) == -1)
    {
        return SED_ERROR_INVALID_ARGUMENT;
    }

    return size + retSize;
}

int32_t dataPayload_AddArgument(uint8_t *argumentToken, uint8_t *argument,
        uint8_t *dataPacket)
{
    uint32_t packetIndex = 0, tokenIndex = 0, argumentIndex = 0, tokenSize,
            argumentSize;
    TokenType tokenIdentifier;

    tokenIdentifier = dataPayload_IdentifyToken(argumentToken);

    switch (tokenIdentifier)
    {
        // TODO(scott/maurice) we don't take into account the b or s bits
        // currently because I think what they mean by extend into another
        // atom is moreso on the parsing side
        case TinyAtom:
        {
            // this is a tiny atom, 1 byte, no argument
            // the arg is self contained in the token
            dataPacket[0] = argumentToken[0];

            // only 1 byte was written
            return 1;
        }

            // Sets up the datapacket correctly if it is a short atom
        case ShortAtom:
        {
            // Pass the token to a shortAtom struct
            struct ShortAtom_t *token = (struct ShortAtom_t*)argumentToken;

            // Gets the size of the struct
            tokenSize = sizeof(struct ShortAtom_t);

            // Gets the length of the token and pass it in argumentsize
            argumentSize = token->length;

            // breaks
            break;
        }

            // Sets up the datapacket correctly if it is a medium atom
        case MediumAtom:
        {
            // Case the argument toke to a medium atom struct 
            struct MediumAtom_t *token = (struct MediumAtom_t*)argumentToken;

            // Gets the size of the medium struct
            tokenSize = sizeof(struct MediumAtom_t);

            // Gets the size of the argument
            argumentSize = MediumAtom_MakeLength(token->mostSignificantLength,
                    token->leastSignificantLength);

            // break
            break;
        }

            // Sets up the datapacket correctly if it is a long atom
        case LongAtom:
        {
            // Cast the argument token as a long atom
            struct LongAtom_t *token = (struct LongAtom_t*)argumentToken;

            // Gets the size of the long struct
            tokenSize = sizeof(struct LongAtom_t);

            // Gets the actual size of the atom
            argumentSize = switchEndian(token->length,3);
            break;
        }

            // Error Checking
        default:
        {
            printf("Invalid Token Type Specified: 0x%.2x\n", argumentToken[0]);

            // this is an error
            return SED_ERROR_INVALID_ARGUMENT;
        }
    }

    // copy the token in the buffer
    for (tokenIndex = 0; tokenIndex < tokenSize; tokenIndex++)
    {
        dataPacket[packetIndex++] = argumentToken[tokenIndex];
    }

    // copy the argument in the buffer
    for (argumentIndex = 0; argumentIndex < argumentSize; argumentIndex++)
    {
        dataPacket[packetIndex++] = argument[argumentIndex];
    }

    // return the new index into the packet
    return packetIndex;
}

int32_t dataPayload_AddNameArgument(uint8_t *tokenParam,
        uint8_t *optionalParamDesc, uint8_t *optionalArgumentToken,
        uint8_t *optionalArgument, uint8_t *dataPacket)
{
    int32_t size = 0, retSize;
    dataPacket[size++] = (uint8_t)StartNameToken;
    // Add the name parameter argument descriptor
    if ((retSize = dataPayload_AddArgument(tokenParam,
            optionalParamDesc, dataPacket + size)) == -1)
    {
        return retSize;  // -1
    }
    size += retSize;

    // Add the optional argument value
    if ((retSize = dataPayload_AddArgument(optionalArgumentToken,
            optionalArgument, dataPacket + size)) == -1)
    {
        return SED_ERROR_INVALID_ARGUMENT;  // -1
    }
    size += retSize;
    dataPacket[size++] = (uint8_t)EndNameToken;
    return size;
}

int32_t dataPayload_StartNameArgumentList(struct TinyAtom_t *tokenParam,
        uint8_t *dataPacket)
{
    int32_t size = 0;
    dataPacket[size++] = (uint8_t)StartNameToken;
    memcpy(dataPacket+size,tokenParam,sizeof(struct TinyAtom_t));
    size += sizeof(struct TinyAtom_t);
    dataPacket[size++] = (uint8_t)StartListToken;
    return size;
}

int32_t dataPayload_CloseNameArgumentList(uint8_t *dataPacket)
{
    dataPacket[0] = EndListToken;
    dataPacket[1] = EndNameToken;
    return 2;
}

int32_t dataPayload_EndPacket(uint8_t *dataPacket)
{
    // TODO(scott/maurice) do this without hard coding
    dataPacket[0] = EndOfDataToken;

    // Method Status List
    dataPacket[1] = StartListToken;
    dataPacket[2] = 0;  // this tells the TP to not abort
    dataPacket[3] = 0;  // reserved
    dataPacket[4] = 0;  // reserved
    dataPacket[5] = EndListToken;
    return 6;
}

int32_t dataPayload_GetDataFromArgument(uint8_t *argStart, uint8_t *argVal,
        uint32_t *argValSize, uint8_t *argValFlags)
{
    int32_t argumentSize = 0,tokenSize = 0;
    TokenType tokenIdentifier;

    tokenIdentifier = dataPayload_IdentifyToken(argStart);
    switch (tokenIdentifier)
    {
        case TinyAtom:
        {
            struct TinyAtom_t *token = (struct TinyAtom_t*)argStart;
            argVal[0] = token->data;
            
            if (argValSize)
                argValSize[0] = 1;
            argValFlags[0] = token->sign;
            return 1;
        }
        case ShortAtom:
        {
            struct ShortAtom_t *token = (struct ShortAtom_t*)argStart;
            tokenSize = sizeof(struct ShortAtom_t);
            argumentSize = token->length;
            argValFlags[0] = token->sign | ((token->byte)<<1);
            break;
        }
        case MediumAtom:
        {
            struct MediumAtom_t *token = (struct MediumAtom_t*)argStart;
            tokenSize = sizeof(struct MediumAtom_t);
            argumentSize = MediumAtom_MakeLength(token->mostSignificantLength,
                    token->leastSignificantLength);
            argValFlags[0] = token->sign | ((token->byte)<<1);
            break;
        }
        case LongAtom:
        {
            // Cast the argument token as a long atom
            struct LongAtom_t *token = (struct LongAtom_t*)argStart;
            tokenSize = sizeof(struct LongAtom_t);
            argumentSize = switchEndian(token->length,3);
            argValFlags[0] = token->sign | ((token->byte)<<1);
            break;
        }
        default:
        {
            return SED_ERROR_INVALID_RESPONSE;
        }
    }


    memcpy(argVal,argStart+tokenSize,argumentSize);
    
    if (argValSize)
        argValSize[0] = argumentSize;

    return argumentSize+tokenSize;
}

TokenType dataPayload_IdentifyToken(uint8_t *token)
{
    //check the id
    uint8_t idByte = token[0];

    // Shifts the byte 7 bits to the right to see if it is a tiny atom
    if ((idByte >> TinyAtomIdShift) == TinyAtomId)
    {
        return TinyAtom;
    }

    // Shifts the byte 6 bits to the right to see if it is a short atom
    else if ((idByte >> ShortAtomIdShift) == ShortAtomId)
    {
        return ShortAtom;
    }

    // Shifts the byte 5 bits to the right to see if it is a medium atom
    else if ((idByte >> MediumAtomIdShift) == MediumAtomId)
    {
        return MediumAtom;
    }

    // Shifts the byte 4 bits to the right to see if it is a long atom.
    else if ((idByte >> LongAtomIdShift) == LongAtomId)
    {
        return LongAtom;
    }

    // this should be impossible!!!!
    return SED_ERROR_INVALID_ARGUMENT;

}

//TODO: Clean code, add comments
void dataPayload_createTokenForString(char* str, uint8_t *token)
{
    uint32_t len = strlen(str);
    if (len < 16)
    {
        // Short Atom
        struct ShortAtom_t *tok = (struct ShortAtom_t*)token;
        tok->id = ShortAtomId;
        tok->byte = BYTE_BYTESEQ;
        tok->sign = SIGN_NOSIGN;
        tok->length = len;
    }
    else if (len < 2048)
    {
        // Medium Atom
        struct MediumAtom_t *tok = (struct MediumAtom_t*)token;
        tok->id = MediumAtomId;
        tok->byte = BYTE_BYTESEQ;
        tok->sign = SIGN_NOSIGN;
        tok->leastSignificantLength = MediumAtom_GetLeastSignificantLength(
                len);
        tok->mostSignificantLength = MediumAtom_GetMostSignificantLength(len);
    }
    else
    {
        // Assume a long string
        struct LongAtom_t *tok = (struct LongAtom_t*)token;
        tok->id = LongAtomId;
        tok->byte = BYTE_BYTESEQ;
        tok->sign = SIGN_NOSIGN;
        tok->length = switchEndian(len,3);
        tok->reserved = 0;
    }
}

uint8_t dataPayload_createTokenForInteger(uint32_t val, uint8_t *token)
{
    struct ShortAtom_t *tokenShort;
    if(val <= MAX_TINYATOM_VALUE)
    {
        struct TinyAtom_t *tokenTiny = (struct TinyAtom_t*)token;
        tokenTiny->id = TinyAtomId;
        tokenTiny->sign = SIGN_NOSIGN;
        tokenTiny->data = val;
        return 0;
    }
    // a short atom can represent a 15 byte integer (a uint32_t is only 4 bytes)
    tokenShort = (struct ShortAtom_t*)token;
    tokenShort->id = ShortAtomId;
    tokenShort->sign = SIGN_NOSIGN;
    tokenShort->byte = BYTE_INTEGER;
    tokenShort->length = 0;
    // figure out how many bytes
    while(val)
    {
        tokenShort->length+=1;
        // dividing by 256 consecutively will determine number of bytes
        val /= 256;
    }
    return tokenShort->length;
}

void dataPayload_createTokenByLength(uint32_t length, uint8_t *ptrToken)
{
    if(length <= ShortAtom_MaximumLength)
    {
        struct ShortAtom_t *token = (struct ShortAtom_t *)ptrToken;
        token->id = ShortAtomId;
        token->byte = BYTE_BYTESEQ;
        token->sign = SIGN_NOSIGN;
        token->length = length;
    }
    else if(length <= MediumAtom_MaximumLength)
    {
        struct MediumAtom_t *token = (struct MediumAtom_t *)ptrToken;
        token->id = MediumAtomId;
        token->byte = BYTE_BYTESEQ;
        token->sign = SIGN_NOSIGN;
        token->mostSignificantLength = MediumAtom_GetMostSignificantLength(length);
        token->leastSignificantLength = MediumAtom_GetLeastSignificantLength(length);
    }
    else
    {
        struct LongAtom_t *token = (struct LongAtom_t *)ptrToken;
        token->id = LongAtomId;
        token->byte = BYTE_BYTESEQ;
        token->sign = SIGN_NOSIGN;
        token->length = switchEndian(length,3);
        token->reserved = 0;
    }
}

int32_t dataPayload_checkEndOfPacket(uint8_t *dataPayload)
{
    uint32_t index = 0;
    if(dataPayload[index++] != EndOfDataToken)
    {
        printf("Error: Get results, EndOfData Token Missing!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(dataPayload[index++] != StartListToken)
    {
        printf("Error: Get results, Method Status List did not start properly!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    if(dataPayload[index] != 0)
    {
        printf("Error, Get results, Error in Method Status List: 0x%x\n",dataPayload[index]);
        return OPAL_ERROR | dataPayload[index];
    }
    // skip the rest of method status list
    index += 3;
    if(dataPayload[index++] != EndListToken)
    {
        printf("Error: Get results, Method Status List did not close properly!\n");
        return SED_ERROR_INVALID_RESPONSE;
    }
    return SED_NO_ERROR;
}
