/** @file ata.c
 *  @brief Handles all of the ata/scsi functionality
 *
 *  ATA functionality include SCSI's ata passthrough. All interaction to the drive
 *  through ata commands are found here.
 *
 *  @author Maurice Gale
 *  @bug No Bugs
 */

#include "../include/ata/ata.h"


void ata_initScsiStruct(uint8_t *dataBuffer, uint32_t len, uint8_t *cdb, uint8_t *sense, uint32_t direction, struct sg_io_hdr *sgio)
{
    sgio->interface_id = 'S'; 
    sgio->cmdp = cdb;   
    sgio->cmd_len = CDB_MAX_LENGTH;
    sgio->dxferp = dataBuffer;
    sgio->dxfer_len = len;
    sgio->dxfer_direction = direction;
    sgio->sbp = sense;
    sgio->mx_sb_len = MAX_SIZE_OF_SENSE_BUFF;
    sgio->timeout = 5000;
}

int32_t ata_createCDBBuffer(struct cdb *cdb, uint8_t *buffer, uint32_t protocol, uint32_t securityProtocol, uint16_t sectorCount, uint16_t comid, uint32_t command)
{
    /* Static Information */
    cdb->operationCode = ATA_PASSTHROUGH16;
    cdb->checkCond = RETURN_ATA_INFORMATION;
    cdb->byteBlock = LENGTH_AS_BLOCKS;
    cdb->tLength = LENGTH_IN_SECTOR_COUNT;
    cdb->features = securityProtocol;
    cdb->lbaMid = comid << BYTE;
    cdb->lbaHigh = comid & 0xFF00;    
    cdb->command = command;
    cdb->protocol = protocol;
    cdb->sectorCount = sectorCount << 8;

    /* Determine the transfer direction from the protocol. We only support PIO_DATA_IN/OUT */   
    if (protocol == PIO_DATA_IN)
        cdb->tDir = DEVICE_TO_HOST;
    
    else if (protocol == PIO_DATA_OUT)
        cdb->tDir = HOST_TO_DEVICE;
    
    else
    {
        fprintf(stderr, "Error: Protocol not supported\n");
        return 1;
    }

    if (command == IDENTIFY_DEVICE)
        cdb->lbaLow = 0x0100;

    /* Put the struct in a nice buffer */
    if (memcpy(buffer, (uint8_t *)cdb, CDB_MAX_LENGTH) == NULL)
    {
        fprintf(stderr, "Error copying CDB to the buffer\n");
        return 1;
    }

    return 0;
}

int32_t ata_trustedSend(struct sedContext *sedCtx)
{
    struct sg_io_hdr sgio = {0};
    struct cdb cdb = {0};
    uint8_t commandDescriptorBlock[CDB_MAX_LENGTH] = {0}, sense[SENSE_BUFFER_SIZE] = {0};
    uint32_t sectorCount = (sedCtx->packetSize / SIZE_OF_SECTOR);

    /* The packetSize MUST be a multiple of 512 */
    if (sedCtx->packetSize % SIZE_OF_SECTOR)
    {
        fprintf(stderr, "Invalid packet size. Size must be a multople of 512\n");
        return SED_ERROR_INVALID_BUFFER_SIZE;
    }

    /* Setup ATA Passthrough for SCSI */
    ata_initScsiStruct(sedCtx->packet, sedCtx->packetSize, commandDescriptorBlock, sense, SG_DXFER_TO_DEV, &sgio);

    if (ata_createCDBBuffer(&cdb, commandDescriptorBlock, PIO_DATA_OUT, SECURITY_PROTOCOL_ONE, sectorCount, sedCtx->baseComId, TRUSTED_SEND))
    {
        fprintf(stderr, "Error: Can not create cdb Buffer\n");
        return 1;
    }

    sed_OutputPacket(sedCtx->packet, 128);

    /* Issue the actual ATA command via IOCTL */
    if (!ioctl(sedCtx->sedFileDescriptor, SG_IO, &sgio))
    {
        if (sense[11] != 0x00 || sense[21] != 0x50)
        {
            fprintf(stderr, "Error[ata_trustedSend]: ");
            printf("Status: %02x \nError: %02x\n",sense[21], sense[11]);
            return ((SED_ERROR_TRUSTED_SEND)  | sense[11]<<8 | sense[21]<<16);
        }

        else
            ata_trustedReceive(sedCtx);
    }

    else
    {
        perror("[TrustedSend] Error in IOCTL ");
        return SED_ERROR_IOCTL_FAILED;
    }

    return SED_NO_ERROR;
}

int32_t ata_trustedReceive(struct sedContext *sedCtx)
{
    struct sg_io_hdr sgio = {0};
    struct cdb cdb = {0};
    uint8_t commandDescriptorBlock[16] = {0};
    uint8_t sense[32] = {0};
    uint32_t sectorCount = (sedCtx->packetSize / SIZE_OF_SECTOR);

    /* Packetsize MUST be a multiple of 512 */
    if (sedCtx->packetSize % SIZE_OF_SECTOR)
    {
        fprintf(stderr, "Invalid packet size. Size must be a multople of 512\n");
        return SED_ERROR_INVALID_BUFFER_SIZE;
    }

    /* Setup ATA Passthrough for SCSI */
    ata_initScsiStruct(sedCtx->packet, sedCtx->packetSize, commandDescriptorBlock, sense, SG_DXFER_FROM_DEV, &sgio);

    if (ata_createCDBBuffer(&cdb, commandDescriptorBlock, PIO_DATA_IN, SECURITY_PROTOCOL_ONE, sectorCount, sedCtx->baseComId, TRUSTED_RECEIVE))
    {
        fprintf(stderr, "Error: Can not create cdb Buffer\n");
        return 1;
    }

    /* Issue ATA command via IOCTL call */
    if (!ioctl(sedCtx->sedFileDescriptor, SG_IO, &sgio))
    {

        /* If sense[11] is not 0x00 or sense[21] is not 0x50 then an error occured */
        if (sense[11] != 0x00 || sense[21] != 0x50)
        {
            printf("Error: Can not issue trustes receive\n");
            return ((SED_ERROR_TRUSTED_RECEIVE)  | sense[11]<<8 | sense[21]<<16);
        }

        else
        {
            /* If its more data, get it */
            if (sedCtx->packet[11] != 0x00)
                ata_trustedReceive(sedCtx);
        }
    }

    else
    {
        perror("[TrustedReceive] Error in IOCTL ");
        return SED_ERROR_IOCTL_FAILED;
    }

    return SED_NO_ERROR;
}

int32_t ata_getDriveIdentity(struct sedContext *sedCtx)
{
    struct sg_io_hdr sgio = {0};
    struct cdb cdb = {0};
    uint8_t commandDescriptorBlock[CDB_MAX_LENGTH] = {0};
    uint8_t sense[SENSE_BUFFER_SIZE] = {0};
    uint8_t buffer[4 + 512] = {0};
    uint8_t i, r;

    /* Set up the SCSI Struct */
    ata_initScsiStruct(buffer, MIN_SIZE_OF_BUFFER, commandDescriptorBlock, sense, SG_DXFER_FROM_DEV, &sgio);

    if (ata_createCDBBuffer(&cdb, commandDescriptorBlock, PIO_DATA_IN, 0x00, 1, 0, IDENTIFY_DEVICE))
    {
        fprintf(stderr, "Error: Can not create cdb buffer\n");
        return 1;
    }

    /* Issue the actual ATA command via IOCTL */
    if (!ioctl(sedCtx->sedFileDescriptor, SG_IO, &sgio))
    {
        switchByte(buffer);

        /* If sense[11] is not 0x00 or sense[21] is not 0x50 then an error occured */
        if (sense[11] != 0x00 || sense[21] != 0x50)
            return ((SED_ERROR_TRUSTED_SEND)  | sense[11]<<8 | sense[21]<<16);
        
        // Extracts the serail number from the output
        for (i = 25, r = 0; i < 44; ++i, ++r)
        {
            // Sets up serial number array
            sedCtx->serialNumber[r] = buffer[i];
        }

        // Get the max user addressable sectors for 28 bit addressing
        memcpy(&sedCtx->maxSectors28, (buffer + 120), 4);
        switchBytesEndian(((uint8_t*)&sedCtx->maxSectors28)+2, 2);
        switchBytesEndian((uint8_t*)&sedCtx->maxSectors28, 2);

        // Get the max user addressable sectors for 48 bit addressing
        memcpy(&sedCtx->maxSectors48, (buffer + 200), 8);
        switchBytesEndian(((uint8_t*)&sedCtx->maxSectors48)+2, 2);
        switchBytesEndian(((uint8_t*)&sedCtx->maxSectors48)+4, 2);
        switchBytesEndian(((uint8_t*)&sedCtx->maxSectors48)+6, 2);
        switchBytesEndian(((uint8_t*)&sedCtx->maxSectors48), 2);

        if(sedCtx->maxSectors28 == MAX_SECTORS_28)
            sedCtx->maxLbas = sedCtx->maxSectors48;
        else
            sedCtx->maxLbas = sedCtx->maxSectors28;
    }

    else
    {
        perror("[IDENTIFY_DEVICE] Error in IOCTL");
        return SED_ERROR_IOCTL_FAILED;
    }

    return SED_NO_ERROR;
}
