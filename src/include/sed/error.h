/** @file sed_errors.h
 *  @brief Error handling for the sed library
 *
 *  This file contains all of the SED error codes and any prototype
 *  to help detect and handle the error.
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 */

#ifndef __ERROR_H_
#define __ERROR_H_

#include "sed.h"

/* Normal Operational Errors */

#define	ECOMPW     1   /* Password Complexity Write Issue */
#define ECOMPR     2   /* Password Complexity Read Issue */ 
#define	ENADMIN    3   /* Account is not Administrator */
#define	EPGRANT    4   /* Permissions can not be granted */
#define	ESMBR      5   /* Setting Shadow MBR Issue */
#define	EERANGE    6   /* Erase Locking Range Issue */
#define	EINSTALL   7   /* Installation Issue */
#define	ESPLOGIN   8   /* Can not login with AdminSP account */
#define	ESSESSION  9   /* Start Session Issue */
#define	ENACCOUNT  10  /* Account is not Found */
#define	EINIT      11  /* Unable to Initialize Sed context */
#define	ECPINR     12  /* CPIN table read issue */
#define	EIACCT     13  /* Invalid Account Type */
#define	ESTORER    14  /* DataStore Read Issue */
#define	ESTOREW    15  /* DataStore Write Issue */
#define	ECPINW     16  /* CPIN table write issue */
#define	EICREDS    17  /* Invalid Credentials */
#define	EOWNED     18  /* Drive is already Owned */
#define	ELIFEC     19  /* Unable to obtain current lifecycle */
#define	EACTIVATE  20  /* Unable to activate the drive */
#define	ELRARG     21  /* Invalid Locking Range Argument */
#define	EGENSET    22  /* Set table issue */
#define	EDELUSR    23  /* Issue Deleting Account */
#define	ECLRSLT    24  /* Error Cleaing salt from Datastore */
#define	ECLRBLB    25  /* Error Clearing Encrypted Blob from Datastore */
#define	ECLRPASS   26  /* Error Clearing password from Datastore */
#define	ECLRNME    27  /* Error Clearing name from Datastore */
#define	ESETNME    28  /* Error setting name in table */
#define	ECHNGNME   29  /* Error Chaning account name */
#define	EACCTEXT   30  /* Account already exist */
#define	EGETINFO   31  /* Issue gathering account information */
#define	EUNLOCK    32  /* Error unlocking the drive */
#define	EUNMBR     33  /* Error Unshadowing the MBR */
#define	EIPASS     34  /* Invalid password */
#define	EREVERT    35  /* Reverting Drive Issue */
#define	EICHOICE   36  /* User selected an Invalid choice */
#define	EERASE     37  /* Issue performing secure erase */
#define EOFFSET    38  /* There was an error when trying to retrive the offset of an account */
#define EHASH      39  /* There was an issue while calculating a hash */
#define ESALT      40  /* There was an error generating a random salt */
#define ENOFFSET   41  /* No offset exist for the account */
#define EIAUTH     42  /* An Invalid authentication type was detected */
#define ELOCKCONF  43  /* Something occured while attempting to configure the locking range */
#define ESTRINGMAX 44  /* The string is longer than the set maximum length */
#define ESMARTCARD 45  /* Something went wrong while setting up smart card authentication */
#define ECERT      46  /* Issue obtaining a Certificate for smart cart initialization */
#define EPUBKEY	   47  /* There was an issue when trying to extract the public key from the smart cards cert */
#define EENCRYPT   48  /* Something occured while attempting to encrypt a blob with the public key */
#define EUSB	   49  /* Something occured while setting up USB authentication */
#define ESETPASS   50  /* Something occured while attempting to setup password */
#define EGENKEYS   51  /* Something occured while generating keys */
#define EENABLE    52  /* Something occured while enable account */
#define EBADDRIVE  53  /* Could not open drive at the specified location */
#define EMALLOC    54  /* Bad memory returned */
#define EOPAL      55  /* Drive is not Opal Compliant */
#define ELZERO     56  /* Something occured while trying to display the level zero discovery */
#define EPROP	   57  /* Something occured while trying to display the properties information */
#define EIDENT     58  /* Something occured while trying to display identity information */
#define EMUSER     59  /* The maximum number of users is created */
#define EMADMIN	   60  /* The maximum number of admin is created */
#define ELOGIN     61  /* The maximum number of login attempts were exceeded */
#define ENAMELEN   62  /* The name length exceeds the maximum set limit */
#define EPASSLEN   63  /* The password length exceeds the maximum set limit */
#define EBADINPUT  64  /* Something went wrong while reading in a string from the user */
#define EPBAEXIST  65  /* Something went wrong while reading the pba */
#define EUSBMOUNT  66  /* Something went wrong when trying to mount the usb device */

#define ERROR_WRITE_COMPLEXITY             "Could not set Password Complexity Values"
#define ERROR_READ_COMPLEXITY              "Could not read Password Complexity Values"
#define ERROR_NO_ADMIN                     "This account is not an Administrator Account"
#define ERROR_PERMISSION_GRANT             "Could not give accounts correct permissions"
#define ERROR_SHADOW_MBR                   "Couldn't set shadow MBR"
#define ERROR_ERASE_RANGE                  "Couldn't erase locking range #1!"
#define ERROR_INSTALLATION                 "Installation Error"
#define ERROR_ADMINSP_LOGIN                "Could not authenticate to AdminSP"
#define ERROR_START_SESSION                "Failed to start a session"
#define ERROR_NO_ACCOUNT_EXIST             "Account not Found!"
#define ERROR_INITIALIZE_FAIL              "Failed to initialize the Context"
#define ERROR_CPIN_ITERATION               "Can not enumerate Cpin table"
#define ERROR_INVALID_ACCOUNT_TYPE         "Invalid Account Type"       
#define ERROR_DATASTORE_READ               "Could not parse Datastore"    
#define ERROR_DATASTORE_WRITE              "Could not write to the Datastore"   
#define ERROR_CPIN_WRITE                   "Could not write to the Cpin Table"   
#define ERROR_INVALID_CREDENTIALS          "Invalid credentials, Rebooting"
#define ERROR_DRIVE_OWNED                  "Drive is already Owned"   
#define ERROR_LIFE_CYCLE                   "Could not obtain the current lifeCycle state"
#define ERROR_ACTIVATING                   "Could not activate the drive"
#define ERROR_LOCKING_RANGE_ARGUMENT       "while adding an argument for the lockingRange"
#define ERROR_GENERIC_SET                  "while setting a value in the table"
#define ERROR_DELETING_USER                "Could not delete User"
#define ERROR_CLEAR_SALT                   "Could not clear the salt or randomString"
#define ERROR_CLEAR_BLOB                   "Couldn't clear the encrypted blob in the datastore!"
#define ERROR_CLEAR_PASSWORD               "Could not clear the password"
#define ERROR_CLEAR_NAME                   "Could not clear original username!"
#define ERROR_SET_NAME                     "Could not clear username!"
#define ERROR_CHANGE_NAME                  "Could not change username!"
#define ERROR_ACCOUNT_EXIST                "Account Already Exist!" 
#define ERROR_GET_INFO                     "Could not get user Information"
#define ERROR_UNLOCK                       "Could not unlock the Locking range"
#define ERROR_UNSHADOW_MBR                 "Could not unshadowing MBR"
#define ERROR_INVALID_PASSWORD             "Invalid password"
#define ERROR_REVERT                       "Could notreverting the drive. Please try again"
#define ERROR_INVALID_CHOICE               "Invalid Option"
#define ERROR_ERASE                        "Could not erase the locking range"
#define ERROR_NO_OFFSET					   "Could not get the Account's offset"
#define ERROR_HASH						   "Could not calculate hash"
#define ERROR_SALT_GEN					   "Could not generate a random salt"
#define ERROR_BAD_OFFSET				   "Could not find offset for this account"
#define ERROR_BAD_AUTH					   "Invalid Authentication Type detected"
#define ERROR_LOCKING_CONFIG			   "Could not configure the locking range"
#define ERROR_STRING_MAX_LENGTH            "String exceeds the maximum length"
#define ERROR_SMART_CARD				   "Could not setup smart card"
#define ERROR_OBTAINING_CERT			   "Could not obtain a cert for encryption"
#define ERROR_PUBLIC_KEY				   "Could not extract the public key from the cert"
#define ERROR_PUB_ENCRYPT                  "Could not encrypt using the public key"
#define ERROR_USB						   "Could not setup usb"
#define ERROR_SET_PASSWORD				   "Could not setup password"
#define ERROR_GEN_KEYS                     "Could not generate public/private key pair"
#define ERROR_ENABLE_USER				   "Could not enable user account"
#define ERROR_BAD_DRIVE				   	   "Could not open Path to Drive"
#define ERROR_MALLOC					   "Malloc Returned bad memory"
#define ERROR_OPAL						   "Drive is not Opal Compliant"
#define ERROR_LEVEL_ZERO				   "Could not display Level Zero Discovery"
#define ERROR_PROPERTIES				   "Could not display Drive and Host property information"
#define ERROR_IDENTITY					   "Could not display Drive Identity information"
#define ERROR_MAX_USERS					   "Unable to create user. The Maximum number of User Accounts is already created"
#define ERROR_MAX_ADMINS				   "Unable to create user. The Maximum number of Administrators is already created"
#define ERROR_PASS_ATTEMPTS                "Maximun number of login attempts exceeded"
#define ERROR_NAME_LENGTH				   "The name that was entered exceeds the maximum limit"
#define ERROR_PASS_LENGTH				   "The password exceeds the maximum set limit."
#define ERROR_BAD_INPUT                    "Can not read input. Something occured while reading. Is the string empty?"
#define ERROR_PBA_NOT_EXIST				   "PBA File not found. Please make sure that the custom pba is labeled \"sed-pba.bin\""
#define ERROR_USB_MOUNT					   "Could not mount the USB device"
#define ERROR_UNKNOWN_ERROR                "Unknown Error"




/* Map the Error Codes with its Error Strings */
struct error{
	uint32_t errorNum;
	const char *errorString;
};

extern uint32_t sedError;

/* SED and OPAL related errors */
#define SED_NO_ERROR 0
#define SED_ERROR                       0x80000000
#define SED_ERROR_INVALID_DRIVE_PATH    SED_ERROR+1
#define SED_ERROR_MALLOC                SED_ERROR+2
#define SED_ERROR_INVALID_ARGUMENT      SED_ERROR+3
#define SED_ERROR_INVALID_HEADER        SED_ERROR+4
#define SED_ERROR_INVALID_STATUS        SED_ERROR+5
#define SED_ERROR_NOT_OPAL              SED_ERROR+6
#define SED_ERROR_ALREADY_OWNED         SED_ERROR+7
#define SED_ERROR_IOCTL_FAILED          SED_ERROR+8
#define SED_ERROR_INVALID_RESPONSE      SED_ERROR+9
#define SED_ERROR_INVALID_BUFFER_SIZE   SED_ERROR+10
#define SED_ERROR_TRUSTED_SEND          SED_ERROR+11
#define SED_ERROR_TRUSTED_RECEIVE       SED_ERROR+12
#define SED_ERROR_OTHER                 SED_ERROR+0x7FFFFFFF
#define OPAL_ERROR                      0xC0000000
#define OPAL_NOT_AUTHORIZED             OPAL_ERROR+1
#define OPAL_OBSOLETE                   OPAL_ERROR+2
#define OPAL_SP_BUSY                    OPAL_ERROR+3
#define OPAL_SP_FAILED                  OPAL_ERROR+4
#define OPAL_SP_DISABLED                OPAL_ERROR+5
#define OPAL_SP_FROZEN                  OPAL_ERROR+6
#define OPAL_NO_SESSIONS_AVAILABLE      OPAL_ERROR+7
#define OPAL_UNIQUENESS_CONFLICT        OPAL_ERROR+8
#define OPAL_INSUFFICIENT_SPACE         OPAL_ERROR+9
#define OPAL_INSUFFICIENT_ROWS          OPAL_ERROR+10
#define OPAL_INVALID_PARAMETER          OPAL_ERROR+12
#define OPAL_OBSOLETE1                  OPAL_ERROR+13
#define OPAL_OBSOLETE2                  OPAL_ERROR+14
#define OPAL_TPER_MALFUNCTION           OPAL_ERROR+15
#define OPAL_TRANSACTION_FAILURE        OPAL_ERROR+16
#define OPAL_RESPONSE_OVERFLOW          OPAL_ERROR+17
#define OPAL_AUTHORITY_LOCKED_OUT       OPAL_ERROR+18
#define OPAL_FAIL                       OPAL_ERROR+0x3F

#define ERROR_CHECK(error, msg) \
    {if (error & SED_ERROR) {sed_handleError(sedCtx, error, msg);}}

#define CHECK_SED_ERROR(func, msg, exitOnError) \
     {int ret; \
     ret = (func); \
     if (ret & SED_ERROR) {\
     	if (exitOnError) {sed_handleError(sedCtx, ret, msg);} \
     	fprintf(stderr, "%s\n", msg); \
 		return ret; }}

#define EXIT_ON_ERROR(sedCtx, msg) \
 		{ fprintf(stderr, "%s\n", msg); \
 		  if (sedCtx) {sed_cleanup(sedCtx);} \
 		  exit(EXIT_FAILURE); }

/**
*    @brief Prints out the error definition from the error code.
*
*    Finds the appropriate error strings based on the error code
*    that was passed to it. It then prints a detailed error explanation
*    to stdout.
*
*    @param errorNum  The error number.
*    @return Void
*/
void sed_errors_print(int32_t errorNum);

/**
*    @brief Helper function to ERROR_CHECK that will exit cleanly on error.
*
*    In common sed functions, it is possible for a certain sed_error to be returned. This
*    is a helper function that will cleanup all resources, and print out the sed error. This
*    function is not normally called directly, rather from the ERROR_CHECK macro.
*
*    @param sedCtx Pointer to the sed context.
*    @param error  The error code to print
*    @param msg    An error message to be printed out to stdout
*    @return Void
*/
void sed_handleError(struct sedContext *sedCtx, int32_t error, char *msg);

/**
*    @brief Get the error string associated with an error number
*
*    Returns the error string that is mapped to the error number
*
*    @param errorNum  The error number to get the associated string for
*    @return Error String
*/
const char *getStringError(uint32_t errorNum);

/**
*    @brief Print error string
*
*    Prints the error string associated wit the error.
*
*    @param errorNum  The error number to get the associated string for
*    @return Error String
*/
inline void printError(uint32_t errorNum);

#endif /*__SED_ERRORS_H_ */
