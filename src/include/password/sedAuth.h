/** @file sedAuth.h
 *  @brief Prototypes that handle authentication to the Tper
 *
 *  THis files contains all of the function prototypes that deals with
 *  any kind of authentication from password, smartcard to usb. Even 
 *  functions that deals with salt generation or gathering.
 *
 *  @author Maurice Gale
 *  @author Scott Markgraf
 *  @bug No Bugs
 */

#ifndef __SEDAUTH_H_
#define __SEDAUTH_H_

#include <stdio.h>
#include <stdint.h>
#include <dirent.h>
#include "../sed/sed.h"
#include "../password/password.h"
#include "../account/account.h"



#define ITERATIONS 4096
#define MAXLENGTH 32


/**
*    @brief Generates random bytes using OpenSSL
*
*    Creates numBytes Salt, using OpenSLL random function
*
*    @param *saltBuffer  The location to store the salt
*    @param numBytes     The number of bytes for the salt
*    @return 0 on success, 1 on failure
*/
uint32_t generateSalt(uint8_t *saltBuffer, uint8_t numBytes);

/*
    @description: Hashes a password with a salt and returns the hash

    @parameter password 			- Password to hash
    @parameter salt 				- The salt to use along with the hash
    @parameter passwordhash 	    - Location to store the password hash
    
    @return - The password hash, or NULL on error.
*/
uint8_t *hashWithSalt(char *password, uint8_t *salt, uint8_t *passwordHash);

/*
    @description: Hashes a password with a salt, then hash that hash with a random string
    			  Alternatively, the "hashWithSalt" function can be called twice

    @parameter password 			- Password to hash
    @parameter salt 				- The salt to use along with the hash
    @parameter randomString 		- The randomString to hash the first results with
    @parameter passwordhash 	    - Location to store the final password hash
    
    @return - The password hash, or NULL on error.
*/
uint8_t *hashWithSaltAndRandomString(char *password, uint8_t *salt, uint8_t *randomString, uint8_t *passwordHash);

/*
    @description: Search the database by username, to see if a user exist.

    @parameter sedCtx      	        - Sed context struct
    @parameter name 				- The name to search for.

    @return - 1 if the account was found, or 0 if the account does not exist;
*/
uint32_t searchForUser(struct sedContext *sedCtx, char *name);

/*
    @description: Retrieves the accountype and the ID that is associated with the account name

    @parameter sedCtx      	        - Sed context struct
    @parameter userName 			- The name to get data for.
    @parameter account 				- The location where the account type will be stored
    @paramter  accountID 			- The location where the ID will be stored

    @return - 1 if the information was successfully retrieved, or 0 if the account does not exist;
*/
int32_t getAccountAndIdFromName(struct sedContext *sedCtx, char *userName, SedAccounts *account, uint8_t *accountId);

/*
    @description: Displays a list of the existing accounts and allows the user to select one

    @parameter sedCtx      	        - Sed context struct
    @parameter selectedUser 		- The location to store the name of the selected user


    @return - The name of the user that was selected.
*/
char  *selectUserFromList(struct sedContext *sedCtx, char *selectedUser, int size);

/*
    @description: Gets the next available ID for a particular user account type. This is needed when creating a new user.

    @parameter sedCtx      	        - Sed context struct
    @parameter accountType 		    - The type of account to get an ID for. Either User or Admin
    @parameter size                 - The size of the selectedUser buffer

    @return - The next available ID. 0 on error.
*/
uint8_t getNextAvailableID(struct sedContext *sedCtx, SedAccounts accountType);

/*
    @description: Sets up a password for a new user

    @parameter sedCtx      	        - Sed context struct
    @parameter user 				- userInfo struct that will provide the username, id, and account Type
    @parameter passwordHash		    - Location to store the password hash


    @return - 0 on success, 1 on error
*/
uint32_t setupPasswordForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash);


/*
    @description: Sets up USB authentication for the selected user

    @parameter sedCtx               - Sed context struct
    @parameter accountType          - The type of account for this user, either User or Admin
    @parameter newID                - ID number associated with the account
    @parameter passwordHash         - Location to store the password hash


    @return - 0 on success, 1 on error
*/
uint32_t setupUsbForUser(struct sedContext *sedCtx, SedAccounts accountType, uint8_t newID, uint8_t *passwordHash);

/*
    TODO: Add this back once smartcard support has been updated
    @description: Sets up smartcard authentication with a password for the selected user

    @parameter sedCtx               - Sed context struct
    @parameter user                 - Contains the neccessary user information for the setup
    @parameter passwordHash         - Location to store the password hash

    @return - 0 on success, 1 on error
uint32_t setupSmartCardWithPasswordForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash);
*/

/*
    TODO: Add this back once smartcard support has been updated
    @description: Sets up smartcard authentication for the selected user

    @parameter sedCtx               - Sed context struct
    @parameter user                 - Contains the neccessary user information for the setup
    @parameter passwordHash         - Location to store the password hash

    @return - 0 on success, 1 on error
uint32_t setupSmartCardForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash);
*/


/*
    @description: Sets up a two password authentication scheme, where two separate password will be needed 
                  to authenticate to a system and the passwords must be entered in the correct order

    @parameter sedCtx               - Sed context struct
    @parameter user                 - Contains the neccessary user information for the setup
    @parameter passwordHash         - Location to store the password hash

    @return - 0 on success, 1 on error
*/
uint32_t setupTwoPasswordsForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash);


/*
    @description: Set the password that will be used for distress

    @parameter sedCtx   - Sed context struct

    @return - Nothing
*/
uint32_t setDistressPassword(struct sedContext *sedCtx);


/*
    @description: Attempts to login using password authentication

    @parameter sedCtx - Sed context Struct.

    @return 0 on success 
*/
int32_t passwordLogin(struct sedContext *sedCtx, char *pass);

/*
    @description: Attempt to login using USB authentication.

    @parameter sedCtx    - Sed context Struct.

    @return 0 on success 
*/
int32_t usbLogin(struct sedContext *sedCtx);

/*
    TODO: Add this back once smartcard support has been updated
    @description: Attempt to login using smartCard authentication.

    @parameter sedCtx    - Sed context Struct.

    @return 0 on success 
int32_t smartCardLogin(struct sedContext *sedCtx);
*/

/*
    TODO: Add this back once smartcard support has been updated
    @description: Attempt to login using smartCard authentication in conjuction with a password.

    @parameter sedCtx - Sed context Struct.

    @return 0 on success 
int32_t smartCardWithPasswordLogin(struct sedContext *sedCtx);
*/

/*
    @description: Attempt to login using two different passwords

    @parameter sedCtx - Sed context Struct.

    @return 0 on success 
*/
int32_t twoPasswordLogin(struct sedContext *sedCtx);

/*
    @description: Autodetects the authentication type, and carry out the authentication method

    @parameter sedCtx - Sed context Struct.

    @parameter account - The type of account, either User or Admin

    @parameter id - The id that is associated with the user

    @return 0 on success 
*/
uint32_t authenticateUserByID(struct sedContext *sedCtx, SedAccounts account, uint8_t id);

/*
    @description: Displays a list of connected USB devices and allows a user to select one

    @parameter usbDevice - Place to store the path to the selected usbDevice

    @return Path to selected USB device
*/
char *selectUsbDevice(char *usbDevice, uint32_t size);

/*
    @description: Cleanup resources that were created from gathering USB information

    @parameter dirp - DIR struct that was created

    @parameter fd - Descriptor of a file that was open (if any)

    @parameter onError - Set if this function was called due to an error

    @return Path to selected USB device
*/
int32_t usbCleanup(DIR *dirp, int32_t fd, int32_t onError);

/*
    @description: Allows the user to modify the password complexity rules

    @parameter sedCtx - Sed context Struct.

    @parameter complexity - Address of the complexity struct

    @parameter interactive - Set if the user once to be prompted to set each complexity rule individually

    @return 0 on success, 1 on error
*/
uint32_t configurePasswordRequirements(struct sedContext *sedCtx, struct password_complexity *complexity, int32_t interactive);

/*
    @description: Grabs the current password complexity set from the datastore

    @parameter sedCtx - Sed context Struct.

    @parameter complexity - Address to store the complexities

    @parameter interactive - Set if the user wants to be prompted to set each complexity rule individually

    @return 0 on success, 1 on error
*/
uint32_t getPasswordRequirements(struct sedContext *sedCtx, struct password_complexity *complexity);

/*
    @description: Prints out the current password complexity rules to stdout

    @parameter sedCtx - Sed context Struct.

    @parameter complexity - Address to store the complexities

    @return 0 on success, 1 on error
*/
void displayPasswordComplexity(struct sedContext *sedCtx, struct password_complexity *complexity);

/*
    @description: Checks to see if the password is the distress password. If it is, wipe the drive

    @parameter sedCtx - Sed context Struct.

    @parameter password - Set if the user once to be prompted to set each complexity rule individually

    @return 0 on success, 1 on error
*/
void attemptDistress(struct sedContext *sedCtx, char *password);

/*
    @description: Sets the current password compleity to default values: 8 Minimum characters, 32
    max characters, 1 special character, 1 numerical character, 1 uppercase character, and 5 max sequence.

    @parameter sedCtx - Sed context Struct.

    @parameter complexity - Address of the complexity struct

    @return 0 on success, 1 on error
*/
uint32_t setPasswordComplexityToDefault(struct sedContext *sedCtx, struct password_complexity *complexity);

/*
    @description: Prompt user to login with Administrator account

    @parameter sedCtx - Sed context Struct.

    @return 0 on success, 1 on error
*/
uint32_t promptAdminLogin(struct sedContext *sedCtx);

uint32_t getSaltAndBlob(struct sedContext *sedCtx, SedAccounts account, uint8_t id, uint8_t *salt, uint8_t *encryptedBlob);

#endif /*__SEDAUTH_H_*/
