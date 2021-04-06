/** @file account.c
 *  @brief User Account management function definitions
 *
 *  User account Management function definitions which are used for the creation and
 *  modification of the accounts.
 *
 *  @author Maurice Gale
 */

#include "../include/account/account.h"
#include "../include/password/sedAuth.h"


uint32_t createUser(struct sedContext *sedCtx, struct userInfo user)
{  
    /* Setup the authentication type for the new user */
    if (setupNewAuth(sedCtx, user))
        return sedError;
    
    /* Make user account active */
    if (enableUser(sedCtx, user.accountType, user.id))
        return sedError;

    /* Save off user name into the datastore */
    if (setUserName(sedCtx, user.accountType, user.id, user.userName))
        return sedError;

    return 0;      
}

uint32_t giveUsersPermission(struct sedContext *sedCtx)
{
    /* Giving mbr access */
    if (mbrControl_enableAccessToDoneForAll(sedCtx) & SED_ERROR)
        return (sedError = EACCES);
    
    /* Giving write access */
    if (lockingRange_enableAccessForAll(sedCtx, LOCKING_RANGE_1, WRITE) & SED_ERROR)
        return (sedError = EACCES);

    /* Giving read access */
    if (lockingRange_enableAccessForAll(sedCtx, LOCKING_RANGE_1, READ) & SED_ERROR)
        return (sedError = EACCES);

    return 0;       
}

uint32_t enableUser(struct sedContext *sedCtx, SedAccounts user, uint8_t id)
{
    if (user_set(sedCtx, user, id, 1) & SED_ERROR)
        return (sedError = EENABLE);
    
    return 0;
}

uint32_t disableUser(struct sedContext *sedCtx, SedAccounts user, uint8_t id)
{
    if (user_set(sedCtx, user, id, 0) & SED_ERROR)
        return (sedError = EDELUSR);

    return 0;
}

uint32_t getAccountOffset(SedAccounts accountType, uint8_t id)
{
    if (accountType == Admin)
    {
        if (id == 1)
            return ADMIN1_DATASTORE_OFFSET;
        if (id == 2)
            return ADMIN2_DATASTORE_OFFSET;
        if (id == 3)
            return ADMIN3_DATASTORE_OFFSET;
        if (id == 4)
            return ADMIN4_DATASTORE_OFFSET;

        return (sedError = ENACCOUNT);
    }

    else if (accountType == User)
    {
        if (id == 1)
            return USER1_DATASTORE_OFFSET;
        if (id == 2)
            return USER2_DATASTORE_OFFSET;
        if (id == 3)
            return USER3_DATASTORE_OFFSET;
        if (id == 4)
            return USER4_DATASTORE_OFFSET;
        if (id == 5)
            return USER5_DATASTORE_OFFSET;
        if (id == 6)
            return USER6_DATASTORE_OFFSET;
        if (id == 7)
            return USER6_DATASTORE_OFFSET;
        if (id == 7)
            return USER7_DATASTORE_OFFSET;
        if (id == 8)
            return USER8_DATASTORE_OFFSET;
        
        return (sedError = ENACCOUNT);
    }

	else if (accountType == AdminSP)
       return ADMINSP_DATASTORE_OFFSET;

    else
        return (sedError = ENACCOUNT);
}

uint32_t reverseOffsetLookUp(int32_t offset, SedAccounts *accountType, uint8_t *id)
{
    if (offset == ADMIN1_DATASTORE_OFFSET)
    {
        *accountType = Admin;
        *id = 1;
        return 0;
    }
    
    if (offset == ADMIN2_DATASTORE_OFFSET)
    {
        *accountType = Admin;
        *id = 2;
        return 0;
    }
    
    if (offset == ADMIN3_DATASTORE_OFFSET)
    {
        *accountType = Admin;
        *id = 3;
        return 0;
    }
    
    if (offset == ADMIN4_DATASTORE_OFFSET)
    {
        *accountType = Admin;
        *id = 4;
        return 0;
    }

    if (offset == USER1_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 1;
        return 0;
    }

    if (offset == USER2_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 2;
        return 0;
    }

    if (offset == USER3_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 3;
        return 0;
    }

    if (offset == USER4_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 4;
        return 0;
    }

    if (offset == USER5_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 5;
        return 0;
    }

    if (offset == USER6_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 6;
        return 0;
    }

    if (offset == USER7_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 7;
        return 0;
    }

    if (offset == USER8_DATASTORE_OFFSET)
    {
        *accountType = User;
        *id = 8;
        return 0;
    }

    return (sedError = ENOFFSET);
}

uint32_t getAccountTypeAndId(struct sedContext *sedCtx, struct userInfo *user)
{
    int32_t offset;
    char name[MAX_NAME_LENGTH] = {0};

    for (offset = ADMIN1_DATASTORE_OFFSET; offset < (ACCOUNT_SIZE * MAX_ACCOUNTS); offset += ACCOUNT_SIZE)
    {
        memset(name, 0, MAX_NAME_LENGTH);

        if (datastore_get(sedCtx, offset, MAX_NAME_LENGTH, (uint8_t *)name) & SED_ERROR)
              return (sedError = ESTORER);

        if ((strlen(user->userName) == strlen(name)) && (strncmp(user->userName, name, strlen(user->userName)) == 0))
        {
            SedAccounts accountType = user->accountType;
            uint8_t id = user->id;

            if (reverseOffsetLookUp(offset, &accountType, &id))
                return sedError;

            user->accountType = accountType;
            user->id = id;

            return 0;
        }
    }

    return 0;
}

uint32_t setUserName(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, char *username)
{
    uint8_t clear[MAX_NAME_LENGTH] = {0};
    int32_t accountOffset;

    if ((accountOffset = getAccountOffset(accountType, id)) == -1)
        return (sedError = EOFFSET);

    /* Safety precaution. Ensuring entire namespace is wiped prior */
    if (datastore_set(sedCtx, accountOffset, MAX_NAME_LENGTH, clear) & SED_ERROR)
        return (sedError = ESTOREW);

    /* Now set the name */
    if (datastore_set(sedCtx, accountOffset, strlen(username), (uint8_t *)username) & SED_ERROR)
        return (sedError = ESTOREW);

    return 0;
}

uint32_t setAuthenticationType(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t authentication)
{
    int32_t accoutOffset;

    if ((accoutOffset = getAccountOffset(accountType, id)) == -1)
        return (sedError = EOFFSET);

    accoutOffset += AUTHENTICATION_TYPE_OFFSET;

    if (datastore_set(sedCtx, accoutOffset, AUTHENTICATION_SIZE, &authentication) & SED_ERROR)
        return (sedError = ESTOREW);

    return 0;
}

uint32_t setSalt(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *salt)
{
    int32_t accountOffset;

    if ((accountOffset = getAccountOffset(accountType, id)) == -1)
        return (sedError = EOFFSET);

    accountOffset += SALT_OFFSET;

    if (datastore_set(sedCtx, accountOffset, MAX_SALT_LENGTH, salt) & SED_ERROR)
        return (sedError = ESTOREW);

    return 0;
}

uint32_t setEncryptedBlob(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *blob)
{
    int32_t accountOffset;

    if ((accountOffset = getAccountOffset(accountType, id)) == -1)
        return sedError;

    accountOffset += ENCRYPTED_STRING_OFFSET;

    if (datastore_set(sedCtx, accountOffset, MAX_ENCRYPT_SIZE, blob) & SED_ERROR)
        return (sedError = ESTOREW);

    return 0;
}

char *getUserName(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, char *userName)
{
    int32_t accountOffset;

    memset(userName, 0, MAX_NAME_LENGTH);

    if ((accountOffset = getAccountOffset(accountType, id)) == -1)
    {
        sedError = EOFFSET;
        return NULL;
    }

    if (datastore_get(sedCtx, accountOffset, MAX_NAME_LENGTH, (uint8_t *)userName) & SED_ERROR)
    {
        sedError = ESTORER;
        return NULL;
    }

    return userName;
}

uint8_t getAuthenticationType(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id)
{
    uint8_t authenticationType;
    int32_t accountOffset;

    if ((accountOffset = getAccountOffset(accountType, id)) == ENACCOUNT)
        return sedError;

    accountOffset += AUTHENTICATION_TYPE_OFFSET;

    if (datastore_get(sedCtx, accountOffset, AUTHENTICATION_SIZE, &authenticationType) & SED_ERROR)
        return (sedError = ESTORER);

    return authenticationType;
}

uint8_t *getSalt(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *salt)
{
    int32_t accountOffset;

    memset(salt, 0, MAX_SALT_LENGTH);

    if ((accountOffset = getAccountOffset(accountType, id)) == ENACCOUNT)
        return NULL;

    accountOffset += SALT_OFFSET;

    if (datastore_get(sedCtx, accountOffset, MAX_SALT_LENGTH, salt) & SED_ERROR)
    {
        sedError = ESTORER;
        return NULL;
    }

    return salt; 
}

uint8_t *getEncryptedBlob(struct sedContext *sedCtx, SedAccounts accountType, uint8_t id, uint8_t *blob)
{
    int32_t accountOffset;

    memset(blob, 0, MAX_ENCRYPT_SIZE);

    if ((accountOffset = getAccountOffset(accountType, id)) == ENACCOUNT)
        return NULL;

    accountOffset += ENCRYPTED_STRING_OFFSET;

    if (datastore_get(sedCtx, accountOffset, MAX_ENCRYPT_SIZE, blob) & SED_ERROR)
    {
        sedError = ESTORER;
        return NULL;
    }

    return blob;
}

int32_t getUserInformationFromUserName(struct sedContext *sedCtx, struct userInfo *user)
{
    if (getAccountTypeAndId(sedCtx, user))
        return sedError;

    if (!(user->authenticationType = getAuthenticationType(sedCtx, user->accountType, user->id)))
        return sedError;

    if (getSalt(sedCtx, user->accountType, user->id, user->salt) == NULL)
        return sedError;

    if (getEncryptedBlob(sedCtx, user->accountType, user->id, user->encryptedBlob) == NULL)
        return sedError;

    return 0;
}

int32_t getUserInformationFromAccountAndID(struct sedContext *sedCtx, struct userInfo *user)
{
    if (getUserName(sedCtx, user->accountType, user->id, user->userName) == NULL)
    {
        fprintf(stderr, "Failed to get userName\n");
        return 1;
    }

    if (!(user->authenticationType = getAuthenticationType(sedCtx, user->accountType, user->id)))
    {
        fprintf(stderr, "Failed to get authenticationType\n");
        return 1;
    }
    
    if (getSalt(sedCtx, user->accountType, user->id, user->salt) == NULL)
    {
        fprintf(stderr, "Failed to get salt\n");
        return 1;
    }

    if (getEncryptedBlob(sedCtx, user->accountType, user->id, user->encryptedBlob) == NULL)
    {
        fprintf(stderr, "Failed to get Encrypted Blob\n");
        return 1;
    }

    return 0;
}

uint32_t clearUserInformation(struct sedContext *sedCtx, char *userName)
{
    int32_t accountOffset;
    struct userInfo user;
    uint8_t clear[ACCOUNT_SIZE] = {0};

    if (strlen(userName) > MAX_NAME_LENGTH)
        return ENAMELEN;

    strncpy(user.userName, userName, sizeof(user.userName));

    if (getAccountTypeAndId(sedCtx, &user))
        return sedError;    

    if ((accountOffset = getAccountOffset(user.accountType, user.id)) == sedError)
        return sedError;

    /* Wipe all user information from the datastore */
    if (datastore_set(sedCtx, accountOffset, ACCOUNT_SIZE, clear) & SED_ERROR)
        return (sedError = ESTOREW);
  
    return 0;
}

uint32_t searchForUser(struct sedContext *sedCtx, char *userName)
{
    int32_t offset;
    char name[MAX_NAME_LENGTH] = {0};

    /* Iterate over all of the names and return 1 if it is found */
    for (offset = 0; offset < (ACCOUNT_SIZE * MAX_ACCOUNTS); offset += ACCOUNT_SIZE)
    {
        memset(name, 0, MAX_NAME_LENGTH);

        if (datastore_get(sedCtx, offset, MAX_NAME_LENGTH, (uint8_t *)name) & SED_ERROR)
            return (sedError = ESTORER);

        if ((strlen(userName) == strlen(name)) && (strncmp(userName, name, strlen(userName)) == 0))
            return 1;    
    }

    return 0;
}

uint32_t setupAdminDefaultCredentials(struct sedContext *sedCtx)
{
    char defaultPassword[MAX_PASSWORD_LENGTH] = {0};
    uint8_t adminSalt[MAX_SALT_LENGTH] = {0}, password[MAX_PASSWORD_LENGTH] = {0};

    /* Generate a salt for the default admin account */
    if (generateSalt(adminSalt, MAX_SALT_LENGTH))
        return sedError;
 
    printf("[+] Generated Salt for Admin Account\n");

    /* Changing Admin1's Credentials */
    sedCtx->account = Admin;
    sedCtx->id = 1;

    if (strlen(DEFAULT_ADMINSP_PASSWORD) > MAX_PASSWORD_LEN)
        return EPASSLEN;

    strncpy(defaultPassword, DEFAULT_ADMINSP_PASSWORD, sizeof(defaultPassword));
    
    /* We can call this function since the Admin password is first set to the AdminSP password */
    if (loginAsAdminSP(sedCtx, defaultPassword))
        return sedError;

    /* Change Admin1 default password to password */
    memset(defaultPassword, 0, MAX_PASSWORD_LENGTH);

    if (strlen(DEFAULT_ADMIN_PASSWORD) > MAX_PASSWORD_LEN)
        return EPASSLEN;

    strncpy(defaultPassword, DEFAULT_ADMIN_PASSWORD, sizeof(defaultPassword));

    /* Dont store password in plain text */
    if (hashWithSalt(defaultPassword, adminSalt, (uint8_t *)password) == NULL)
        return sedError;

    /* Set the password */
    if (cpin_setPassword(sedCtx, Admin, sedCtx->id, MAX_PASSWORD_LEN, (uint8_t *)password) & SED_ERROR)
        return (sedError = ECPINW);

    /* Store admin as the username in the table */
    if (setUserName(sedCtx, (SedAccounts)Admin, 1, "admin"))
        return sedError;
    
    /* Store admin salt at its correct offset in the datasotre */
    if (setSalt(sedCtx, (SedAccounts)Admin, 1, adminSalt))
        return sedError;

    /* Set the default authentication types */
    if (setAuthenticationType(sedCtx, (SedAccounts)Admin, 1, 'P'))
        return sedError;
            
    return 0;
}

uint32_t promptUsername(struct sedContext *sedCtx, char *userName, uint32_t promptAdmin)
{
    /* Need to start a session as anybody to read the datastore */
    if (sed_startSessionAsAnybody(sedCtx, Admin))
        return (sedError = ESSESSION);
        
    /* Notify the user that Admin Credentials must be entered */
    if (promptAdmin)
        printf("%s\n", ENTER_ADMIN_INFO);

    /* Get the username for the user attempting to log in */
    printf("%s", ENTER_USER);

    if (readInput(userName, MAX_NAME_LENGTH) == NULL)
        return (sedError = EGETINFO);
    
    /* Make sure that the user exist */
    if (!searchForUser(sedCtx, userName))
        return (sedError = ENACCOUNT);

    return 0;
}

uint32_t authenticate(struct sedContext *sedCtx, char *userName)
{
    struct userInfo user;

    if (strlen(userName) > MAX_NAME_LENGTH)
        return ENAMELEN;

    strncpy(user.userName, userName, sizeof(user.userName));

    /* Populate User Information from datastore */
    if (getUserInformationFromUserName(sedCtx, &user))
        return sedError;
                  
    /* Detect Authentication type and login */
    if (authenticateUserByID(sedCtx, user.accountType, user.id))
        return sedError;

    return 0;
}

uint32_t isAdmin(struct sedContext *sedCtx, char *userName)
{
    struct userInfo user;

    if (strlen(userName) > MAX_NAME_LENGTH)
        return ENAMELEN;

    strncpy(user.userName, userName, sizeof(user.userName));

    /* Populate User Information from datastore */
    if (getUserInformationFromUserName(sedCtx, &user))
        return sedError;

    /* Account type is Admin */
    if (user.accountType == Admin)
        return 1;

    return 0;
}

uint32_t listAdminAccounts(struct sedContext *sedCtx)
{
    uint32_t i;
    char username[MAX_NAME_LENGTH + 1] = {0};

    /* Iterate through all Admins */
    for (i = 1; i <= MAX_ADMINS; ++i)
    {
        memset(username, 0, MAX_NAME_LENGTH);

        if ((getUserName(sedCtx, Admin, i, username)) == NULL)
            return sedError;

        if (username[0] != '\0')
            printf("%s\t\t\tAdministrator\n", username);

    }

    return 0;
}

uint32_t listNormalAccounts(struct sedContext *sedCtx)
{
    uint32_t i;
    char username[MAX_NAME_LENGTH + 1] = {0};
    
    /* Iterate through all users */    
    for (i = 1; i <= MAX_USERS; ++i)
    {
        memset(username, 0, MAX_NAME_LENGTH);

        if ((getUserName(sedCtx, User, i, username)) == NULL)
            return sedError;

        if (username[0] != '\0')
            printf("%s\t\t\tNormal User\n", username);

    }

    return 0;
}

uint32_t listAllAccounts(struct sedContext *sedCtx)
{
    /* Print out all Admin Accounts */
    if (listAdminAccounts(sedCtx))
        return sedError;

    /* Print out all Normal Accounts */
    if (listNormalAccounts(sedCtx))
        return sedError;
    
    return 0;
}

uint32_t getAdminCount(struct sedContext *sedCtx)
{
    uint32_t i, count = 0;
    char username[MAX_NAME_LENGTH] = {0};

    /* Iterate through all Admins */
    for (i = 1; i <= MAX_ADMINS; ++i)
    {
        memset(username, 0, MAX_NAME_LENGTH);

        if ((getUserName(sedCtx, Admin, i, username)) == NULL)
            return sedError;

        if (username[0] != '\0')
            ++count;
    }

    return count;
}

uint32_t getUserCount(struct sedContext *sedCtx)
{
    uint32_t i, count = 0;
    char username[MAX_NAME_LENGTH] = {0};
    
    /* Iterate through all users */    
    for (i = 1; i <= MAX_USERS; ++i)
    {
        memset(username, 0, MAX_NAME_LENGTH);

        if ((getUserName(sedCtx, User, i, username)) == NULL)
            return sedError;

        if (username[0] != '\0')
            ++count;
    }

    return count;
}

uint32_t promptNewUsername(struct sedContext *sedCtx, struct userInfo *user)
{
    printf("%s", PROMPT_USERNAME);
    
    /* Update user struct if the name was valid */
    if (readInput(user->userName, MAX_NAME_LENGTH) == NULL)
        return sedError;
 
    /* Check to see if the userName is in the System */ 
    if (searchForUser(sedCtx, user->userName))
        return (sedError = EACCTEXT);
    
    return 0;
}

uint32_t promptNewAccountType(struct sedContext *sedCtx, struct userInfo *user)
{
    char choice;
    
    printf("\nWhat type of Account will %s have?\n\n"
           "1) Normal User\n"
           "2) Administrator\n", user->userName);
    
    /* Get User response and verify */
    choice = getMenuChoice();

    if (choice < '1' || choice > '2')
        return sedError = EICHOICE;
    
    /* Update struct with account type */
    (choice < '2') ? (user->accountType = User) : (user->accountType = Admin);

    return 0;
}

uint32_t promptNewAuthType(struct sedContext *sedCtx, struct userInfo *user)
{
    char choice;

    printf("\n\n%s\n", AUTH_CHOICE);
    printf("\n1) Password\n2) SmartCard\n3) SmartCard + Password\n"
             "4) USB\n5) Two Passwords\n"); 
    
    /* Get and check users response */
    choice = getMenuChoice();
    
    if (choice > '5' || choice < '1')
        return sedError = EICHOICE;

    /* Update the user struct with the new Authentication type */
    user->authenticationType = choice;

    return 0;
}

uint32_t setupNewAuth(struct sedContext *sedCtx, struct userInfo user)
{
    uint8_t passwordHash[MAX_PASSWORD_LENGTH] = {0};

    switch(user.authenticationType)
    {
        case '1':
            if (setupPasswordForUser(sedCtx, user, passwordHash) == 1)
                return sedError;
            break;
        
        case '2':
            /*
            if (setupSmartCardForUser(sedCtx, user, passwordHash) == 1)
               return sedError;
            */
            break;
        
        case '3':
            /*
            if (setupSmartCardWithPasswordForUser(sedCtx, user, passwordHash) == 1)
                return sedError;
            */
            break;
        
        case '4':
            if (setupUsbForUser(sedCtx, user.accountType, user.id, passwordHash) == 1)
                return sedError;
            break;
        
        case '5':
            if (setupTwoPasswordsForUser(sedCtx, user, passwordHash) == 1)
                return sedError;
            break;
        
        default:
            return sedError = EICHOICE;    
    }

    return 0;
}

uint32_t deleteUser(struct sedContext *sedCtx, char *username)
{
    uint8_t clearPassword[MAX_PASSWORD_LEN] = {0};
    struct userInfo user;

    if (strlen(username) > MAX_NAME_LENGTH)
        return ENAMELEN;

    strncpy(user.userName, username, sizeof(user.userName));
    
    /* Get All info about user */
    if (getUserInformationFromUserName(sedCtx, &user))
        return sedError;

    /* Disable User Account */
    if (disableUser(sedCtx, user.accountType, user.id))
        return sedError;
    
    /* Remove all user information from the datastore */
    if (clearUserInformation(sedCtx, user.userName))        
        return sedError;
    
    /* Set the password to an empty string, therefore the old password will no longer be in existence */
    if (cpin_setPassword(sedCtx, user.accountType, user.id, MAX_PASSWORD_LEN, clearPassword) & SED_ERROR)
        return (sedError = ECPINW);

    return 0;
}

uint32_t changeUserName(struct sedContext *sedCtx, char *oldName, char *newName)
{
    struct userInfo user;

    /* Pull Old account information */
    strcpy(user.userName, oldName);
    
    if (getUserInformationFromUserName(sedCtx, &user))
        return sedError;
    
    if (setUserName(sedCtx, user.accountType, user.id, newName))
        return sedError;
    
    return 0;
}

uint32_t changePassword(struct sedContext *sedCtx)
{
    char choice;
    uint8_t passwordHash[MAX_PASSWORD_LEN] = {0};
    uint32_t retVal = 0;
    struct userInfo user;
    
    printf("Select the Account Type: \n\n1) User Accounts\n2) Distress Account\n");
    choice = getMenuChoice();

    if (choice == '2')
    {
        /* If this function fails or succeeds, we still want to go to the account management screen 
        This function prints the error within the function */
        return setDistressPassword(sedCtx);
    }

    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;

    /* Choose which user account to change the password for and gather its information */
    if (selectUserFromList(sedCtx, *(&user.userName), sizeof(user.userName)) == NULL)
        return sedError;

    if (getUserInformationFromUserName(sedCtx, &user))
        return (sedError = EGETINFO);

    printf("%s\n\n", AUTH_CHOICE);
    printf("1) Password\n2) SmartCard\n3) SmartCard + Password\n4) USB\n5) Two Passwords\n"); 
    choice = getMenuChoice();

    switch(choice)
    {
        case '1':
            retVal = setupPasswordForUser(sedCtx, user, passwordHash);
            break;
        
        case '2':
            //retVal = setupSmartCardForUser(sedCtx, user, passwordHash);
            break;
        
        case '3':
            //retVal = setupSmartCardWithPasswordForUser(sedCtx, user, passwordHash);
            break;
        
        case '4':
            retVal = setupUsbForUser(sedCtx, user.accountType, user.id, passwordHash);
            break;
        
        case '5':
            retVal = setupTwoPasswordsForUser(sedCtx, user, passwordHash);
            break;
        
        default:
            retVal = EINVAL;
    }

    printf("%s%s\n",PASSWORD_CHANGE_SUCCESS, user.userName);

    return retVal;
}

uint8_t getAuthenticationFromString(struct sedContext *sedCtx, char *authType)
{
    if (!strcmp(authType, "password"))
        return '1';
    
    else if (!strcmp(authType, "smartcard"))
        return '2';
    
    else if (!strcmp(authType, "smartcard+password"))
        return '3';
    
    else if (!strcmp(authType, "usb"))
        return '4';
    
    else if (!strcmp(authType, "2password"))
        return '5';
    
    else
        return (sedError = EICHOICE);
}
