/** @account.h
 *  @brief User account management function prototypes
 *
 *  Contains all of the functions neccessary to create and modify user accounts
 *
 *  @author Maurice Gale
 *  @bug No Bugs
 */

#ifndef __ACCOUNT_H_
#define __ACCOUNT_H_

#include <inttypes.h>
#include "../sed/sed.h"


/* Account Information */
#define MAX_NAME_LENGTH 32
#define MAX_ACCOUNTS (MAX_USERS + MAX_ADMINS + 1)
#define AUTHENTICATION_SIZE 1
#define ACCOUNT_SIZE (MAX_NAME_LENGTH + MAX_SALT_LENGTH + MAX_ENCRYPT_SIZE + AUTHENTICATION_SIZE)
#define AUTHENTICATION_TYPE_OFFSET 0x20
#define SALT_OFFSET 0x21
#define ENCRYPTED_STRING_OFFSET 0x41
#define ADMINSP_DATASTORE_OFFSET 0
#define ADMIN1_DATASTORE_OFFSET  ADMINSP_DATASTORE_OFFSET + ACCOUNT_SIZE
#define ADMIN2_DATASTORE_OFFSET  ADMIN1_DATASTORE_OFFSET + ACCOUNT_SIZE
#define ADMIN3_DATASTORE_OFFSET  ADMIN2_DATASTORE_OFFSET + ACCOUNT_SIZE
#define ADMIN4_DATASTORE_OFFSET  ADMIN3_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER1_DATASTORE_OFFSET   ADMIN4_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER2_DATASTORE_OFFSET   USER1_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER3_DATASTORE_OFFSET   USER2_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER4_DATASTORE_OFFSET   USER3_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER5_DATASTORE_OFFSET   USER4_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER6_DATASTORE_OFFSET   USER5_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER7_DATASTORE_OFFSET   USER6_DATASTORE_OFFSET + ACCOUNT_SIZE
#define USER8_DATASTORE_OFFSET   USER7_DATASTORE_OFFSET + ACCOUNT_SIZE
#define DEFAULT_ADMINSP_PASSWORD "dpassword"
#define DEFAULT_ADMIN_PASSWORD   "password"


/**
*    @brief  Main structure to hold all of a user's account information
*/
struct userInfo
{
    SedAccounts accountType;
    uint8_t id;
    char  userName[MAX_NAME_LENGTH + 1];
    uint8_t authenticationType;
    uint8_t salt[MAX_SALT_LENGTH];
    uint8_t encryptedBlob[MAX_ENCRYPT_SIZE];
}__attribute__((packed));


/**
*    @brief Creates a new user account
*
*    Creates a new user or admin account. Also sets up authentication types for this user.
*
*    @param sedCtx  Pointer to the sed context.
*	 @param user    Struct holding all of the information gathered from the user
*
*    @return 0 on success, 1 on error
*/
uint32_t createUser(struct sedContext *sedCtx, struct userInfo user);

/**
*    @brief Gives all user accounts various drive permissions
*
*    Gives all user accounts permission to the mbrControl flag as well as locking and unlocking
*	 permissions
*
*    @param sedCtx Pointer to the sed context.
*
*    @return 0 on success, 1 on error
*/
uint32_t giveUsersPermission(struct sedContext *sedCtx);

/**
*    @brief Activates an User account
*
*    Activate an user account, allowing it to be usable
*
*    @param sedCtx  Pointer to the sed context.
*	 @param user    The type of account for the user. Either Admin or User
*    @param id      The id number of the user
*
*    @return 0 on success, SED_ERROR on error
*/
uint32_t enableUser(struct sedContext *sedCtx, SedAccounts user, uint8_t id);

/**
*    @brief De-activate an User account
*
*    de-activate an user account. This account will no longer be usable
*
*    @param sedCtx  Pointer to the sed context.
*	 @param user    The type of account for the user. Either Admin or User
*    @param id      The id number of the user
*
*    @return 0 on success, SED_ERROR on error
*/
uint32_t disableUser(struct sedContext *sedCtx, SedAccounts user, uint8_t id);

/**
*    @brief Gets the account offset in the datastore
*
*    Get ths offset of the account into the datastore so that it can be easily indexed
*
*    @param accountType  The type of account to find the offset for. Either Admin or User
*    @param id      	 The id number of the user
*
*    @return offset, -1 on error
*/
uint32_t getAccountOffset(SedAccounts accountType, uint8_t id);

/**
*    @brief Gets the associated account type and id from a certain offset
*
*    Return whether the offset belongs to an admin or user and the id of that account.
*
*    @param offset        The offset to lookup
*	 @param accountType   Location to store the type of account associated with the offset
*    @param id 			  Location to store the account id that is associated with the account
*
*    @return 0 on success, 1 on error
*/
uint32_t reverseOffsetLookUp(int32_t offset, SedAccounts *accountType, uint8_t *id);

/**
*    @brief Gets the account type and account id
*
*    Gets the account type and id from the username tha is strored in the userInfo struct
*
*	 @param sedCtx        Pointer to the sed context.
*    @param user          Address of the userInfo struct so the accountType and id fields can be populated
*
*    @return 0 on success, 1 on error
*/
uint32_t getAccountTypeAndId(struct sedContext *sedCtx, struct userInfo *user);

/**
*    @brief Setup an userName for a given account
*
*    Sets a user name for a particular user account
*
*	 @param sedCtx        Pointer to the sed context.
*    @param accountType   The accountype that the name will be set for. Either Admin or User
*    @param id            The id for the account in which the name will be set
*    @param username      The new username to set the account to
*
*    @return 0 on success, 1 on error
*/
uint32_t setUserName(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, char *username);

/**
*    @brief Setup an authentication type for a given account
*
*    Creates an authentication type for a given user. There are various authentication types to choose from including
*	 password(P), two passwords(T), usb(U), SmartCard(S), CAC + Password(W).
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that the authentication type will be set for. Either Admin or User
*    @param id             The id for the account in which the authentication type will be set
*    @param authentication Authentication type to set
*
*    @return 0 on success, 1 on error
*/
uint32_t setAuthenticationType(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t authentication);

/**
*    @brief Store a salt for an account
*
*    Each user account have their own individual salt. This function will store that salt at the 
*    correct offset.
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that the salt will be set for. Either Admin or User
*    @param id             The id for the account in which the salt will be set
*    @param salt           Address to the salt to store
*
*    @return 0 on success, 1 on error
*/
uint32_t setSalt(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *salt);

/**
*    @brief Store a blob for an account
*
*    For some authentication types such as cac and usb, it will involve encryption. This function will
*    set that encrypted blob into the data store, at the offset associated with that user.
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that the blob will be set for. Either Admin or User
*    @param id             The id for the account in which the blob will be set
*    @param blob           Address to the blob to store
*
*    @return 0 on success, 1 on error
*/
uint32_t setEncryptedBlob(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *blob);

/**
*    @brief Retrieve the username from an account and id
*
*    Retrieves the username from a given accountype and id.
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that associated with the username. Either Admin or User
*    @param id             The id associated with the username
*    @param userName       A location to store the retrieved username
*
*    @return username, NULL on error
*/
char *getUserName(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, char *userName);

/**
*    @brief Retrieves the authentication type of an account
*
*    Retrieves the authentication type of an account from its account type and its id.
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that associated with the authentication type. Either Admin or User
*    @param id             The id associated with the authentication type
*
*    @return authentication type, 0 on error
*/
uint8_t getAuthenticationType(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id);

/**
*    @brief Retrieves the salt for an account
*
*    Retrieves the salt of an account from its account type and its id.
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that associated with the salt. Either Admin or User
*    @param id             The id associated with the salt
*    @param salt 		   The location to store the salt
*
*    @return salt, NULL on error
*/
uint8_t *getSalt(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *salt);

/**
*    @brief Retrieves the encrypted blob for an account
*
*    Retrieves the encrypted blob of an account from its account type and its id.
*
*	 @param sedCtx         Pointer to the sed context.
*    @param accountType    The accountype that associated with the blob. Either Admin or User
*    @param id             The id associated with the blob
*    @param blob 		   The location to store the blob
*
*    @return blob, NULL on error
*/
uint8_t *getEncryptedBlob(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *blob);


/**
*    @brief Retrieves all user information by username
*
*    Retrieves all user information(authenticationType, salt,account type, id) from a given username, and populates
*    the information inside of the userInfo struct
*
*	 @param sedCtx         Pointer to the sed context.
*    @param user           UserInfo struct to populate
*  
*    @return 0 on success, 1 on error
*/
int32_t getUserInformationFromUserName(struct sedContext *sedCtx, struct userInfo *user);

/**
*    @brief Retrieves all user information from account type and id
*
*    Retrieves all user information(authenticationType, salt, username) from a given account type and id, and populates
*    the information inside of the userInfo struct
*
*	 @param sedCtx         Pointer to the sed context.
*    @param user           UserInfo struct to populate
*  
*    @return 0 on success, 1 on error
*/
int32_t getUserInformationFromAccountAndID(struct sedContext *sedCtx, struct userInfo *user);

/**
*    @brief Wipes all user information
*
*    Wipes all of the user information from the datastore
*
*	 @param sedCtx         Pointer to the sed context.
*    @param userName       Name of the user who information should be erased
*  
*    @return 0 on success, 1 on error
*/
uint32_t clearUserInformation(struct sedContext *sedCtx, char *userName);

/**
*    @brief Searches to see if a user exist
*
*    Searched through tables to check if the user exist or not
*
*	 @param sedCtx         Pointer to the sed context.
*    @param userName       Name of the user to search for
*  
*    @return 1 if found, 0 if user does not exist
*/
uint32_t searchForUser(struct sedContext *sedCtx, char *userName);

/**
*    @brief Set the default Credenttials for Admin1
*
*    During setup, this function is used to set the default password to "password",
*	 the default admin name to "admin", and the authentication type to password.
*    
*	 @param sedCtx         Pointer to the sed context.
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t setupAdminDefaultCredentials(struct sedContext *sedCtx);

/**
*    @brief Prompts for an UserName
*
*    Prompts to enter an Username, and validates that the username exist
*    
*	 @param sedCtx         Pointer to the sed context.
*    @param userName       Buffer to store the userName
*    @param promptAdmin    If set, prompts to enter Admin account name
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t promptUsername(struct sedContext *sedCtx, char *userName, uint32_t promptAdmin);

/**
*    @brief Authenticates a user from its username
*
*    Authenticate and logs the user into the drive
*    
*	 @param sedCtx         Pointer to the sed context.
*    @param userName       UserName to authenticate
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t authenticate(struct sedContext *sedCtx, char *userName);

/**
*    @brief Check to see if a user has Administrator Privileges
*
*    Check the userName to see if the account type is Administrator
*    
*	 @param sedCtx         Pointer to the sed context.
*    @param userName       UserName to verify
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t isAdmin(struct sedContext *sedCtx, char *userName);

/**
*    @brief List all accounts
*
*    List all of the accounts that are registerd on the opal drive
*    
*	 @param sedCtx         Pointer to the sed context.
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t listAllAccounts(struct sedContext *sedCtx);

/**
*    @brief List only Admin Accounts
*
*    List all of the Administrator accounts that are registerd on the opal drive
*    
*	 @param sedCtx         Pointer to the sed context.
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t listAdminAccounts(struct sedContext *sedCtx);

/**
*    @brief List only Normal Accounts
*
*    List all of the Mormal accounts that are registerd on the opal drive
*    
*	 @param sedCtx         Pointer to the sed context.
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t listNormalAccounts(struct sedContext *sedCtx);

/**
*    @brief Prompt to enter new user name
*
*    Prompts to enter new user name and checks to make sure that the user does not exist
*    
*	 @param sedCtx         Pointer to the sed context.
*	 @param user           Pointer to the user Information struct that will hold all info for the new user
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t promptNewUsername(struct sedContext *sedCtx, struct userInfo *user);

/**
*    @brief Prompt to enter new account type
*
*    Prompts the user to choose an account type for the new user
*    
*	 @param sedCtx         Pointer to the sed context.
*	 @param user           Pointer to the user Information struct that will hold all info for the new user
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t promptNewAccountType(struct sedContext *sedCtx, struct userInfo *user);

/**
*    @brief Prompts and configure new Authentication type
*
*    Prompts the user to choose an authententication type for the new user
*    
*	 @param sedCtx         Pointer to the sed context.
*	 @param user           Pointer to the user Information struct that will hold all info for the new user
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t promptNewAuthType(struct sedContext *sedCtx, struct userInfo *user);

/**
*    @brief Deletes a user account
*
*    Deletes a user account that it on the opal drive.
*    
*	 @param sedCtx         Pointer to the sed context.
*    @param username       User to delete
*
*    @return 0 on Success, 1 otherwise
*/
uint32_t deleteUser(struct sedContext *sedCtx, char *username);

/**
*    @brief Change a current user name
*
*    Change the username of an existing user
*    
*	 @param sedCtx         Pointer to the sed context.
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t changeUserName(struct sedContext *sedCtx, char *oldName, char *newName);

/**
*    @brief Change an accounts password.
*
*    Allows the user to select a user who's password/authentication type is to be changed.
*    
*	 @param sedCtx         Pointer to the sed context.
*  
*    @return 0 on Success, 1 otherwise
*/
uint32_t changePassword(struct sedContext *sedCtx);

uint32_t setupNewAuth(struct sedContext *sedCtx, struct userInfo user);

uint8_t getAuthenticationFromString(struct sedContext *sedCtx, char *authType);
uint32_t getAdminCount(struct sedContext *sedCtx);
uint32_t getUserCount(struct sedContext *sedCtx);

#endif /*__ACCOUNT_H_ */
