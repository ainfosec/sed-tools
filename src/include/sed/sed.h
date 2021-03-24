#ifndef __SED_H_
#define __SED_H_

#include <inttypes.h>

#define MAX_PASSWORD_LENGTH 32
#define MIN_PASSWORD_LENGTH 1
#define MAX_PROMPT_SIZE 256
#define MAX_ENCRYPT_SIZE 256
#define MAX_STRING_SIZE 256
#define MAX_ARGS 32
#define MAX_PASSWORD_LEN 32
#define MAX_SALT_LENGTH 32
#define MAX_PATH_LENGTH 256
#define TRUE 1
#define FALSE 0
#define PIPE_READ 0
#define PIPE_WRITE 1
#define ALLOWED_PASSWORD_ATTEMPTS 3

 /* User and Admin configurations */
#define CPIN_TABLE 0x000000000B000000ll
#define UID_SIZE 8
#define UID_LIST_SIZE ((MAX_USERS + MAX_ADMINS) * UID_SIZE)


/* Password Complexity */
#define PASSWORD_COMPLEXITY_OFFSET     (USER8_DATASTORE_OFFSET + ACCOUNT_SIZE)
#define COMPLEXITY_MIN_CHARS           (PASSWORD_COMPLEXITY_OFFSET + 0)
#define COMPLEXITY_MAX_CHARS           (COMPLEXITY_MIN_CHARS + 4)
#define COMPLEXITY_MIN_CAPS            (COMPLEXITY_MAX_CHARS + 4)
#define COMPLEXITY_MIN_SPECIAL         (COMPLEXITY_MIN_CAPS + 4)
#define COMPLEXITY_MIN_NUMBERS         (COMPLEXITY_MIN_SPECIAL + 4)
#define COMPLEXITY_MAX_SEQUENCE        (COMPLEXITY_MIN_NUMBERS + 4)

#define RANDOMSTRING_DATASTORE_OFFSET 0x41


#pragma pack(push)
#pragma pack(1)

// Simple token types
typedef enum
{
    TinyAtom,
    ShortAtom,
    MediumAtom,
    LongAtom
} TokenType;

typedef enum 
{
    NoUser,
    Manufacturer,
    AdminSP,
    Admin,
    User,
    Default,
    PsidSP,
    Distress
} SedAccounts;


enum
{
    MAX_COMPACKET_SIZE = 0,
    MAX_RESPONSE_COMPACKET_SIZE,
    MAX_PACKET_SIZE,
    MAX_IND_TOKEN_SIZE,
    MAX_PACKETS,
    MAX_SUBPACKETS,
    MAX_METHODS,
    MAX_AGG_TOKEN_SIZE,
    CONTINUED_TOKENS,
    SEQUENCE_NUMBERS,
    ACK_NAK,
    ASYNCHRONOUS,
    MAX_SESSIONS,
    MAX_READ_SESSIONS,
    MAX_AUTHENTICATIONS,
    MAX_TRANSACTION_LIMIT,
    DEF_SESSION_TIMEOUT,
    MAX_SESSION_TIMEOUT,
    MIN_SESSION_TIMEOUT,
    DEF_TRANS_TIMEOUT,
    MAX_COMID_TIME,
    MAX_TRANS_TIMEOUT,
    MIN_TRANS_TIMEOUT
};


#define SERIAL_NUMBER_LENGTH 20 // it is always 20
#define SED_ENABLED 1
#define SED_DISABLED 0
#define MAX_SECTORS_28  0xFFFFFFF

struct geometryReportingFeatures
{
    uint64_t reserved:56;
    uint32_t logicalBlockSize;
    uint64_t alignmentGranularity;
    uint64_t lowestAlignedLba;
};

struct opalSscFeatures
{
    uint16_t baseComId;
    uint16_t numberOfComIds;
    uint8_t rangeCrossingBehavior;
    uint16_t numberOfLockingSPAdmins;
    uint16_t numberOfLockingSPUsers;
    uint8_t initialCPinSidIndicator;
    uint8_t behaviorCPinSidOnRevert;
};

struct singleUserFeatures
{
    uint32_t numberOfLockingObjects;
    uint8_t any:1;
    uint8_t all:1;
    uint8_t policy:1;
};

struct dataStoreFeatures
{
    uint16_t reserved;
    uint16_t maxNumberOfDataStoreTables;
    uint32_t maxSizeOfDataStoreTables;
    uint32_t sizeAlignmentDataStoreTable;
};

struct sedContext
{
    /* Level Zero Discovery TPER features */
    
    uint8_t tperFeature:1;
    uint8_t syncSupported:1;
    uint8_t asyncSupported:1;
    uint8_t acknakSupported:1;
    uint8_t bufferMgmtSupported:1;
    uint8_t streamingSupported:1;
    uint8_t comIdMgmtSupported:1;
    
    /* Level Zero Discovery locking features */
    
    uint8_t lockingFeature:1;
    uint8_t lockingSupported:1;
    uint8_t lockingEnabled:1;
    uint8_t locked:1;
    uint8_t mediaEncryption:1;
    uint8_t mbrEnabled:1;
    uint8_t mbrDone:1;
    
    /* Level Zero Discovery geometry reporting */
    
    uint8_t geometryFeature:1;
    uint32_t logicalBlockSize;
    uint64_t alignmentGranularity;
    uint64_t lowestAlignedLba;
    
    /* Level Zero Disvoery Opal Single User features */
    
    uint8_t singleUserFeature:1;
    uint32_t numberOfLockingObjects;
    uint8_t any:1;
    uint8_t all:1;
    uint8_t policy:1;
    
    /* Opal Datastore Table features */
    
    uint8_t datastoreTableFeature:1;
    uint16_t maxNumberOfDataStoreTables;
    uint32_t maxSizeOfDataStoreTables;
    uint32_t sizeAlignmentDataStoreTable;
    
    /* Opal Features */
    
    uint16_t opalVersion;
    uint8_t opalSscFeature:1;
    uint16_t baseComId;
    uint16_t numberOfComIds;
    uint8_t rangeCrossingBehavior;
    uint16_t numberOfLockingSPAdmins;
    uint16_t numberOfLockingSPUsers;
    uint8_t initialCPinSidIndicator;
    uint8_t behaviorCPinSidOnRevert;
    
    /* Enterprise Features */
    
    uint8_t enterpriseSscFeature:1;
    uint32_t extendedComId;

    /* Drive Identity */
    
    uint8_t serialNumber[SERIAL_NUMBER_LENGTH];
    uint32_t maxSectors28;
    uint64_t maxSectors48;
    uint64_t maxLbas;

    /* Properties */
    uint32_t tperMaxMethods;
    uint32_t tperMaxSubpackets;
    uint32_t tperMaxPacketSize;
    uint32_t tperMaxPackets;
    uint32_t tperMaxComPacketSize;
    uint32_t tperMaxResponseComPacketSize;
    uint32_t tperMaxSessions;
    uint32_t tperMaxReadSessions;
    uint32_t tperMaxIndTokenSize;
    uint32_t tperMaxAggTokenSize;
    uint32_t tperMaxAuthentications;
    uint32_t tperMaxTransactionLimit;
    uint32_t tperMaxSessionTimeout;
    uint32_t tperMaxTransTimeout;
    uint32_t tperMaxComIDTime;
    uint32_t tperMinSessionTimeout;
    uint32_t tperMinTransTimeout;
    uint32_t tperDefSessionTimeout;
    uint32_t tperDefTransTimeout;
    uint32_t tperContinuedTokens;
    uint32_t tperSequenceNumbers;
    uint32_t tperAckNak;
    uint32_t tperAsynchronous;
    uint32_t hostMaxMethods;
    uint32_t hostMaxSubpackets;
    uint32_t hostMaxPacketSize;
    uint32_t hostMaxPackets;
    uint32_t hostMaxComPacketSize;
    uint32_t hostMaxResponseComPacketSize;
    uint32_t hostMaxIndTokenSize;
    uint32_t hostMaxAggTokenSize;
    uint8_t  setHostContinuedTokens;
    uint32_t hostContinuedTokens;
    int8_t  setHostSequenceNumbers;
    uint32_t hostSequenceNumbers;
    uint8_t  setHostAckNak;
    uint32_t hostAckNak;
    uint8_t  setHostAsynchronous;
    uint32_t hostAsynchronous;
    uint32_t totalLockingRanges;

    /* Account Information */
    
    SedAccounts account;
    uint8_t id;
    int8_t sedFileDescriptor;
    uint32_t hostSessionNumber;
    uint32_t tperSessionNumber;
    uint32_t packetSize;
    uint8_t *packet;
};

typedef struct lockingRange
{
    int32_t rangeNumber;
    int64_t rangeStart;
    int64_t rangeLength;
    int8_t readLockingEnabled;
    int8_t writeLockingEnabled;
    int8_t readLocked;
    int8_t writeLocked;
    int8_t configure;
}lockingRange;


// simple tokens
#define TinyAtomId 0
#define TinyAtomIdShift 7
struct TinyAtom_t
{
    uint8_t data:6;
    uint8_t sign:1;
    uint8_t id:1;
};
#define MAX_TINYATOM_VALUE 63 //2^6 - 1

#define ShortAtomId 0x2
#define ShortAtomIdShift 6
struct ShortAtom_t
{
    uint8_t length:4;
    uint8_t sign:1;
    uint8_t byte:1;
    uint8_t id:2;
};
#define ShortAtom_MaximumLength 15

#define MediumAtomId 0x6
#define MediumAtomIdShift 5
struct MediumAtom_t
{
    uint16_t mostSignificantLength:3;
    uint16_t sign:1;
    uint16_t byte:1;
    uint16_t id:3;
    uint16_t leastSignificantLength:8;
};
#define MediumAtom_MakeLength(a,b) (((a&0x7)<<8)|(b&0xFF))
#define MediumAtom_GetMostSignificantLength(a) ((a>>8)&0x7)
#define MediumAtom_GetLeastSignificantLength(a) (a&0xFF)
#define MediumAtom_MaximumLength 2047

#define LongAtomId 0xE
#define LongAtomIdShift 4
struct LongAtom_t
{
    uint32_t sign:1;
    uint32_t byte:1;
    uint32_t reserved:2;
    uint32_t id:4;
    uint32_t length:24;
};

// simple token bit definitions
#define SIGN_NOSIGN  0
#define SIGN_SIGNED  1
#define BYTE_INTEGER 0
#define BYTE_BYTESEQ 1

#define TPER_FEATURE_SYNC_SUPPORT 1
#define TPER_FEATURE_ASYNC_SUPPORT 2
#define TPER_FEATURE_ACKNAK_SUPPORT 4
#define TPER_FEATURE_BUFFERMGMT_SUPPORT 8
#define TPER_FEATURE_STREAMING_SUPPORT 16
#define TPER_FEATURE_COMIDMGMT_SUPPORT 64 
#define LOCKING_FEATURE_LOCKING_SUPPORT 1
#define LOCKING_FEATURE_LOCKING_ENABLED 2
#define LOCKING_FEATURE_LOCKED 4
#define LOCKING_FEATURE_MEDIA_ENCRYPTION 8
#define LOCKING_FEATURE_MBR_ENABLED 16
#define LOCKING_FEATURE_MBRDONE 32  
#define MAX_NAME_LENGTH 32
#define MAX_USERS 2
#define MAX_ADMINS 4


// generic stuff
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <scsi/sg.h>
#include "../ata/ata.h"

#include "../packet_tokenization/packets.h"
#include "../packet_tokenization/packet.h"
#include "../packet_tokenization/compacket.h"
#include "../packet_tokenization/datasubpacket.h"
#include "../packet_tokenization/dataPayload.h"
#include "../invokers/ace.h"
#include "../invokers/adminSP.h"
#include "../invokers/cpin.h"
#include "../invokers/datastore.h"
#include "../invokers/lockingRange.h"
#include "../invokers/lockingSP.h"
#include "../invokers/mbr.h"
#include "../invokers/mbrControl.h"
#include "../invokers/sessionManager.h"
#include "../invokers/thisSP.h"
#include "../invokers/user.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include "error.h"
#include "sed_uids.h"
#include "sed_columns.h"





#define UID_ADMINSP             0x0100000005020000ll
#define UID_ADMIN1              0x0100010009000000ll
#define UID_LOCKINGSP           0x0200000005020000ll
#define UID_AUTHORITY_PSID      0x01FF010009000000ll
#define PSID_SP                 0xE000010008000000ll

#define ADMINSP_UID             0x0100000005020000ll
#define ADMIN1_UID              0x0100010009000000ll
#define LOCKINGSP_UID           0x0200000005020000ll


#define MAX_DATA_PAYLOAD_SIZE 512

// control tokens
#define StartListToken          0xF0
#define EndListToken            0xF1
#define StartNameToken          0xF2
#define EndNameToken            0xF3
#define CallToken               0xF8
#define EndOfDataToken          0xF9
#define EndOfSessionToken       0xFA
#define StartOfTransaction      0xFB
#define EndOfTransaction        0xFC

// hard drive / trusted_send/rcv type stuff?
#define TRUSTED_RECEIVE         0x5C
#define TRUSTED_SEND            0x5E
#define ATA_PASSTHROUGH12       0xA1
#define ATA_PASSTHROUGH16       0x85
#define PIO_DATA_IN             0x04
#define PIO_DATA_OUT            0x05
#define HOST_TO_DEVICE          0x00
#define DEVICE_TO_HOST          0x01
#define LENGTH_AS_BYTES         0x00
#define LENGTH_AS_BLOCKS        0x01
#define NO_DATA_IS_TRANSFERRED  0x00
#define LENGTH_IN_FEATURE_FIELD 0x01
#define LENGTH_IN_SECTOR_COUNT  0x02
#define LENGTH_IN_STPSIU        0x03
#define IDENTIFY_DEVICE         0xEC
#define GETS_IGNORED            0x00
#define CDB_MAX_LENGTH          0x10
#define MIN_SIZE_OF_BUFFER      0x200
#define SENSE_BUFFER_SIZE       0x20
#define SECURITY_PROTOCOL_ZERO  0x0000
#define SECURITY_PROTOCOL_ONE   0x0100
#define SECURITY_PROTOCOL_TWO   0x0200
#define MAX_NUMBER_PROPERTIES   0x17
#define MAX_PROPERTY_LENGTH     0x19
#define SIZE_OF_SECTOR          0x200
#define LEVEL_ZERO_COMID        0x0001
#define RETURN_ATA_INFORMATION  1
#define MAX_SIZE_OF_SENSE_BUFF  0x20
#define MAX_ATA_PACKET_SIZE     0x1E000
#define BYTE                    8
#define ENABLE                  1     
#define INTERACTIVE             1 

// ERRORS
#define IOCTL_FAILED            -1       
#define INCORRECT_BUFFER_SIZE   -1

// SED Configuration Values
#define SED_MIN_COMPACKET_SIZE   1024
#define SED_MIN_PACKET_SIZE      1004
#define SED_MIN_INDTOKEN_SIZE    968
#define SED_MIN_PACKETS          1
#define SED_MIN_SUBPACKETS       1
#define SED_MIN_METHODS          1
#define MAX_TRANSFER_SIZE        1024


/* User-Interface Strings */

#define UNLOCK_DRIVE                       "Unlock Drive!"
#define ENTER_USER                         "Username: "
#define ADMIN_MENU_TITLE                   "Administrator Menu"
#define MANAGE_ACCOUNT                     "Account Management"
#define SECURE_ERASE                       "Secure Erase"
#define REVERT_DRIVE                       "Revert Drive"
#define BOOT_DRIVE                         "Boot Drive"
#define USER_MENU_TITLE                    "User Options"
#define CREATE_USER                        "Create User"
#define CHANGE_USERNAME                    "Change Username"
#define CHANGE_PASSWORD                    "Change Password"
#define DELETE_USER                        "Delete User"
#define LIST_USERS                         "List All Users"
#define CONFIGURE_COMPLEXITY               "Configure Password Complexity"
#define INITIATE_ERASE                     "Initiating Secure Erase..."
#define ERASE_WARNING                      "WARNING: THIS WILL WIPE ANY OPERATING SYSTEM OR DATA THAT IS STORED ON THE DEVICE"
#define CONTINUE_CHOICE                    "Do you want to continue[y/n]?"
#define ERASE_SUCCESS                      "Successfully Erased Drive!"
#define INITIATE_REVERT                    "Reverting the TPer..."
#define REVERT_WARNING                     "WARNING: REVERTING THE TPER WILL PUT THE DRIVE IN ITS ORIGINAL MANUFACTURED STATE!"
#define REVERT_SUCCESS                     "Successfully Reverted Drive!"
#define UNLOCK_SUCCESS                     "Drive Unlocked. Rebooting..."
#define PROMPT_USERNAME                     "Enter new Username: "
#define CHANGE_NAME_SUCCESS                "Successfully changed Username"
#define CHANGE_PASSWORD_SUCCESS            "Successfully changed password"
#define AUTH_CHOICE                        "Choose an authentication type: "
#define PASSWORD_CHANGE_SUCCESS            "Successfully Changed the password"
#define DELETE_USER_SUCCESS                "Successfully deleted Account "
#define CURRENT_USER_ACCOUNTS              "Current User Accounts"
#define NUMBER_OF_AVAIL_SLOTS_USER         "Number of available slots to create an User: "
#define CURRENT_ADMINS                     "Current Administrator Accounts"
#define NUMBER_OF_AVAIL_SLOTS_ADMIN        "Number of available slots to create an Administrator: "
#define PRESS_ANY_KEY                      "Press any key to Continue..."
#define ENTER_PASSWORD                     "Enter password: "
#define SET_PRIVATE_KEY_PASSWORD           "Please set a password for your private key: "
#define PROCESSING                         "Processing..."
#define SELECT_ACCOUNT                     "Select Account "
#define ENTER_ADMIN_INFO                   "Enter Administrator Credentials below to Continue"
#define ENTER_KEY_PASS                     "Please set a password for your private key: "


/* RSA KEY Information */
#define USB_MOUNT_POINT "/mnt"
#define PRIVATE_KEY     "private.pem"
#define PUBLIC_KEY      "public.pem"
#define PRIVATE_KEY_LOCATION "/mnt/private.pem"
#define PUBLIC_KEY_LOCATION "/mnt/public.pem"
#define CUSTOM_PBA "/mnt/sed-pba.bin"
#define TPER_FEATURE 0x0001
#define LOCKING_FEATURE 0x0002
#define GEOMETRY_REPORTING_FEATURE 0x0003
#define OPAL_SSC_1 0x0200
#define OPAL_SINGLE_USER_FEATURE 0x0201
#define OPAL_DATASTORE_TABLES_FEATURE 0x0202
#define OPAL_SSC_2 0x0203
#define ENTERPRISE_FEATURE 0x0100


/* Function Macros */
#define PRINT_CHAR_LOOP(character, loopCount) \
    {int counter = 0; while (counter < loopCount) {printf("%s",character); ++counter;}}

#define CLEAR_SCREEN system("clear");

/* Locking Range Stuff */
#define WRITE 1
#define READ 0
#define LOCKING_RANGE_1 1
#define DEFAULT_RANGE_START -1
#define DEFAULT_RANGE_LENGTH 0
#define READ_LOCKING_DISABLED -1
#define WRITE_LOCKING_DISABLED -1
#define READ_UNLOCKED 0
#define WRITE_UNLOCKED 0

/* MbrControl stuff */
#define MBR_ENABLED 1
#define MBR_DISABLED -1
#define MBR_DONE_SET 1
#define MBR_DONE_UNSET 0

/* Defaults */
#define DEFAULT_PBA "/usr/bin/sed-pba.bin"
#define DELAY 2
#define MAX_ATTEMPTS 3
/* Function Declarations */
int32_t switchByte(uint8_t *buffer);
int32_t switchWord(uint8_t *buffer);
uint32_t switchEndian(uint32_t value, uint8_t size);
void switchBytesEndian(uint8_t *value, uint32_t size);
int32_t levelZeroDiscovery(struct sedContext *sedCtx);
int32_t sed_initialize(struct sedContext *sedCtx, char *sedPath, SedAccounts user, uint8_t id);
void sed_cleanup(struct sedContext *sedCtx);
uint64_t sed_makeAuthorityUid(SedAccounts who, uint8_t id);
int32_t sed_genericSet(struct sedContext *sedCtx, uint64_t uidInvoker, uint32_t where, uint32_t szValues, uint8_t *values);
int32_t sed_checkSetResults(struct sedContext *sedCtx);
int32_t sed_genericGet(struct sedContext *sedCtx, uint64_t uidInvoker, uint8_t isRow, uint32_t startCol, uint32_t endCol, uint8_t **retBuf);
int32_t sed_checkGetResults(struct sedContext *sedCtx, uint8_t **retBuf);
int32_t sed_genericSendEmptyPayload(struct sedContext *sedCtx, uint64_t uidInvoker, uint64_t uidMethod);
int32_t sed_OutputPacket(uint8_t* packet, int16_t length);
void sed_printDriveIdentity(struct sedContext *sedCtx);
void sed_printLevelZeroDiscovery(struct sedContext *sedCtx);
void sed_printProperties(struct sedContext *sedCtx);
int32_t sed_listSupportedProtocols(int8_t fileDescriptor);
int32_t sed_tperReset(int8_t file_descriptor);
void sed_enableVerbose(void);
void sed_printHex(uint8_t *string, int stringLength);
int sed_generateRandomString(unsigned char *buffer, unsigned int numBytes);
int32_t sed_iterateTable(struct sedContext *sedCtx, uint64_t tableUID, uint32_t row);
void filterUIDS(uint8_t *packet, int size);
int32_t sed_testLogin(struct sedContext *sedCtx, SedAccounts newUser, uint8_t newId, uint8_t *passwordHash);
char getMenuChoice();
int32_t mountDevice(char *device, char *mountPoint);
int32_t unmountDevice(char *device);
int32_t bufferToFile(char *file, uint8_t *buffer, uint32_t bufferSize);
uint8_t *fileToBuffer(char *file, uint8_t *buffer, uint32_t bufferSize);
int32_t mountUSB(char *device);
int32_t generateRsaKeys(char *keyPassword);
uint8_t *encryptWithPublicKey(uint8_t *plaintext, uint8_t *encryptedBuffer, char *keyLocation, char *keyPassword);
uint8_t *decryptWithPrivateKey(uint8_t *blob, uint8_t *decryptBuffer, char *keyLocation, char *keyPassword);
uint32_t loginWithDefaultAccount(struct sedContext *sedCtx, SedAccounts account);
char *sed_getMSIDPassword(struct sedContext *sedCtx, char *pass);
uint32_t sed_takeOwnership(struct sedContext *sedCtx, char *hardDrive, char *newPassword);
uint32_t sed_activateTper(struct sedContext *sedCtx);
uint32_t sed_unlockDrive(struct sedContext *sedCtx);
uint32_t sed_lockDrive(struct sedContext *sedCtx);
uint32_t sed_configureRange(struct sedContext *sedCtx, int32_t rangeNumber);
uint32_t sed_startSessionAsAnybody(struct sedContext *sedCtx, SedAccounts account);
int32_t parseLevelZeroBuffer(struct sedContext *sedCtx, uint8_t *buffer);
uint32_t loginAsAdminSP(struct sedContext *sedCtx, char *password);
void updateProgress(uint64_t bytesWritten, uint64_t totalBytes);
uint32_t configureMBR(struct sedContext *sedCtx, char *filePath);
uint32_t sed_revertDrive(struct sedContext *sedCtx, char *password);
uint32_t sed_psidRevert(struct sedContext *sedCtx, char *psid);
uint32_t getCredentials(struct sedContext *sedCtx, uint32_t getAdmin);
uint32_t setupTools(struct sedContext *sedCtx, char *device, char *pba);
uint32_t sed_unshadowDrive(struct sedContext *sedCtx);
uint32_t formatDataStore(struct sedContext *sedCtx);
uint32_t secureErase(struct sedContext *sedCtx);
uint32_t userNameScreen(struct sedContext *sedCtx, char *username);
void displayTitle(char *title, int32_t clearScreen);
uint32_t authenticationScreen(struct sedContext *sedCtx, char *username);
void adminLogin(struct sedContext *sedCtx);
uint32_t bootDrive(struct sedContext *sedCtx);
SedAccounts getSedAccountFromString(char *account); 
uint32_t interactiveCreateUser(struct sedContext *sedCtx);
uint32_t interactiveChangeUsername(struct sedContext *sedCtx);
uint32_t interactiveChangePassword(struct sedContext *sedCtx);
uint32_t interactiveDeleteUser(struct sedContext *sedCtx);
uint32_t sed_isOwned(struct sedContext *sedCtx, char *hardDrive);

#endif /* __SED_H_ */
