#include "../include/sed/sed.h"

#include <stdio.h>

int32_t thisSP_revert(struct sedContext *sedCtx)
{
    return sed_genericSendEmptyPayload(sedCtx, UID_THISSP, UID_METHOD_REVERTSP);
}

int32_t thisSP_issueSP(struct sedContext *sedCtx, char *name, uint32_t size, uint8_t enableBase, uint8_t enableAdmin, uint8_t enableClock, uint8_t enableCrypto, uint8_t enableLog, uint8_t enableLocking, uint32_t key_size, uint8_t enable)
{
	uint8_t token[sizeof(struct LongAtom_t)];
	struct ShortAtom_t tokUid, tokMethod, tokTemplate;
	struct TinyAtom_t tokenProperty;
	uint32_t retVal, index = 0, actualSize, totalPacketLen;
	uint8_t *dataPayload;
	uint64_t uidTable, uidMethod, uidTemplate;

	
	dataPayload = (uint8_t*)(sedCtx->packet
            + packets_initialize(sedCtx));

	// Create tokens for table uid and method uid
	tokUid.id = ShortAtomId;
	tokUid.sign = SIGN_NOSIGN;
	tokUid.byte = BYTE_BYTESEQ;
	tokUid.length = 8; 
	uidTable = UID_THISSP;
	
	tokMethod.id = ShortAtomId;
	tokMethod.sign = SIGN_NOSIGN;
	tokMethod.byte = BYTE_BYTESEQ;
	tokMethod.length = 8; // 8
	uidMethod = UID_METHOD_ISSUESP;	

	// Add it
	retVal = dataPayload_CreateHeader((uint8_t*)&tokUid, (uint8_t*)&uidTable,(uint8_t*)&tokMethod, (uint8_t*)&uidMethod,dataPayload+index);
	if(retVal & SED_ERROR)
	{
		//PRINT SOMETHING
		return -1;
	}
	index += retVal;

	// Start the arguments
    	dataPayload[index++] = StartListToken;

	// Add argument 1: SPName
	dataPayload_createTokenForString(name, token);
	
	retVal = dataPayload_AddArgument(token, (uint8_t*)name, dataPayload+index);
	if(retVal & SED_ERROR) return SED_ERROR_INVALID_ARGUMENT;
	
	index += retVal;

	// Add argument 2: size
    retVal = dataPayload_createTokenForInteger(1, token);
        
    // Do we need to switch endian here?       
    //actualSize = switchEndian(spSize, retVal);
    actualSize = 1;
    retVal = dataPayload_AddArgument(token, (uint8_t*)&actualSize, (uint8_t*)(dataPayload + index));
    if (retVal & SED_ERROR) return SED_ERROR_INVALID_ARGUMENT;
    index += retVal;

	// Add argument 3: templates
	dataPayload[index++] = StartListToken;
	tokTemplate.id = ShortAtomId;
	tokTemplate.sign = SIGN_NOSIGN;
	tokTemplate.byte = BYTE_BYTESEQ;
	tokTemplate.length = 8;
	
	if(enableBase)
	{
		uidTemplate = UID_SPTEMPLATES_BASE;
		retVal = dataPayload_AddArgument((uint8_t*)&tokTemplate,(uint8_t*)&uidTemplate,(uint8_t*)(dataPayload+index));
		if(retVal & SED_ERROR) return SED_ERROR;
		index+=retVal;
	}
	if(enableAdmin)
	{
		uidTemplate = UID_SPTEMPLATES_ADMIN;
		retVal = dataPayload_AddArgument((uint8_t*)&tokTemplate,(uint8_t*)&uidTemplate,(uint8_t*)(dataPayload+index));
		if(retVal & SED_ERROR) return SED_ERROR;
		index+=retVal;
	}
	if(enableClock)
	{
		uidTemplate = UID_SPTEMPLATES_CLOCK;
		retVal = dataPayload_AddArgument((uint8_t*)&tokTemplate,(uint8_t*)&uidTemplate,(uint8_t*)(dataPayload+index));
		if(retVal & SED_ERROR) return SED_ERROR;
		index+=retVal;
	}
	if(enableCrypto)
	{
		uidTemplate = UID_SPTEMPLATES_CRYPTO;
		retVal = dataPayload_AddArgument((uint8_t*)&tokTemplate,(uint8_t*)&uidTemplate,(uint8_t*)(dataPayload+index));
		if(retVal & SED_ERROR) return SED_ERROR;
		index+=retVal;
	}
	if(enableLog)
	{
		uidTemplate = UID_SPTEMPLATES_LOG;
		retVal = dataPayload_AddArgument((uint8_t*)&tokTemplate,(uint8_t*)&uidTemplate,(uint8_t*)(dataPayload+index));
		if(retVal & SED_ERROR) return SED_ERROR;
		index+=retVal;
	}
	if(enableLocking)
	{
		uidTemplate = UID_SPTEMPLATES_LOCKING;
		retVal = dataPayload_AddArgument((uint8_t*)&tokTemplate,(uint8_t*)&uidTemplate,(uint8_t*)(dataPayload+index));
		if(retVal & SED_ERROR) return SED_ERROR;
		index+=retVal;
	}
	dataPayload[index++] = EndListToken;

	
	// Add fourth argument: AdminExch
    dataPayload_createTokenForInteger(256, token);
        
    // Do we need to switch endian here?       
    actualSize = switchEndian(256, 2);;
 
    retVal = dataPayload_AddArgument((uint8_t*)&token, (uint8_t*)&actualSize, (uint8_t*)(dataPayload + index));
    if (retVal & SED_ERROR) return SED_ERROR_INVALID_ARGUMENT;
    index += retVal;  
     

    // Add fifth argument: Enabled
    tokenProperty.id = TinyAtomId;
    tokenProperty.sign = SIGN_NOSIGN;
    tokenProperty.data = (enable ? 1 : 0);
    retVal = dataPayload_AddArgument((uint8_t*)&tokenProperty, NULL, (uint8_t*)(dataPayload + index));
    if (retVal & SED_ERROR) return SED_ERROR_INVALID_ARGUMENT;
    index += retVal; 

    // Endlist for the end of parameters
    dataPayload[index++] = EndListToken;

    // Close the packet
    index += dataPayload_EndPacket(dataPayload + index);

    totalPacketLen = packets_updateLengths((struct sedContext*)sedCtx, index);

    sed_OutputPacket(sedCtx->packet, totalPacketLen);

    printf("Sending and receiving the test packet\n");

    ata_trustedSend(sedCtx);

    sed_OutputPacket(sedCtx->packet,totalPacketLen);

    return 0;
}

