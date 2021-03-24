/** @file ata.h
 *  @brief Prototypes for all ATA and SCSI functionality
 *
 *  This file contains all of prototypes for ATA commands as well
 *  as all of the SCSI ATA passthrough stuff
 *
 *  @author Maurice Gale
 *  @bug No Bugs
 */

#ifndef __ATA_H_
#define __ATA_H_

#include "../sed/sed.h"

/**
*    @brief  SCSI Command Descriptor Block
*/
struct cdb
{
    uint32_t operationCode:8;
    uint32_t extend:1; 
    uint32_t protocol:4;  
    uint32_t multipleCount:3;   
    uint32_t tLength:2;
    uint32_t byteBlock:1;
    uint32_t tDir:1;
    uint32_t reserved:1; 
    uint32_t checkCond:1;
    uint32_t offLine:2;
    uint32_t features:16;
    uint32_t sectorCount:16;       
    uint32_t lbaLow:16;        
    uint32_t lbaMid:16;               
    uint32_t lbaHigh:16;            
    uint32_t device:8;           
    uint32_t command:8;          
    uint32_t control:8;
}__attribute__((packed));

/**
*    @brief Initializes a scsi struct needed for ata passthrough
*
*    Initializes all of the values for the scsci structure needed for ata
*    passthrough such. Default values are automatically set, and the parameters
*    set the remaining values
*
*    @param databuffer An address that the transfer buffer should point to
*    @param len        The length of the packet to be transmitted
*    @param cdb        An address of a command descriptor block that is to be used
*    @param sense      A sense buffer, used for error checking'
*    @param direction  The direction of data transfer. host->drive, or drive->host
*    @param sgio       The address of the scsi struct to be populated
*    @return void
*/
void ata_initScsiStruct(uint8_t *dataBuffer, uint32_t len, uint8_t *cdb, uint8_t *sense, uint32_t direction, struct sg_io_hdr *sgio);

/**
*    @brief Helper function needed for any ATA command. Creates the CDB buffer
*
*    Helper function that creates the command descriptor block for ATA commands.
*
*    @param cdb Address of the cdb struct that is to be populated
*    @param buffer The output buffer to copy the created cdb struct into
*    @param protocol    The ATA protocol used in this command
*    @param securityProcotol The Security Protocol to be used. Specified in the ATA spec
*    @param sectorCount     The size of the command buffer in respect to sector blocks
*    @param comid         OPAL specific comid that is assigned to the drive
*    @param command       The actual command to execute
*    @return 0 on success, 1 on error 
*/
int32_t ata_createCDBBuffer(struct cdb *cdb, uint8_t *buffer, uint32_t protocol, uint32_t securityProtocol, uint16_t sectorCount, uint16_t comid, uint32_t command);

/**
*    @brief Send a packet using ATA's SecureSend
*
*    Sends the packet that is located at sedCtx->packet and sends it to the
*    drive using ATA's secure Send command.
*
*    @param sedCtx pointer to the sedContext that holds the packet that must be sent
*    @return SED_NO_ERROR on success, SED_ERROR_* otherwise
*/
int32_t ata_trustedSend(struct sedContext *sedCtx);

/**
*    @brief Receive a packet using ATA secure Receive
*
*    Receive the packet into the buffer at sedCtx->packet using ATA's secure receive command.
*
*    @param sedCtx pointer to the sedContext to store the incoming packet
*    @return SED_NO_ERROR on success, SED_ERROR_* otherwise
*/
int32_t ata_trustedReceive(struct sedContext *sedCtx);

/**
*    @brief ATA's get drive identity function
*
*    Issues the ATA getIdentity function
*
*    @param sedCtx pointer to the sedContext to store the incoming packet
*    @return SED_NO_ERROR on success, SED_ERROR_* otherwise
*/
int32_t ata_getDriveIdentity(struct sedContext *sedCtx);

#endif /*__ATA_H_ */
