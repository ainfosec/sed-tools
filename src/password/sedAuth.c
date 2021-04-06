#include "../include/password/sedAuth.h"
#include <openssl/evp.h>


uint32_t generateSalt(uint8_t *saltBuffer, uint8_t numBytes)
{    
    if (!RAND_bytes(saltBuffer, numBytes))
        return (sedError = ESALT);
    
    return 0;
}

uint8_t *hashWithSalt(char *password, uint8_t *salt, uint8_t *passwordHash)
{
    memset(passwordHash, 0, MAX_PASSWORD_LEN);

    /* Hash the plaintext password using the salt that was provided and store the result inside passwordHash */
    if (PKCS5_PBKDF2_HMAC(password, MAX_PASSWORD_LEN, salt, MAX_SALT_LENGTH, ITERATIONS, EVP_sha1(), MAX_PASSWORD_LEN, passwordHash) == 0)
    {
        fprintf(stderr, "PKCS5_PBKDF2_HMAC SHA512 failed\n");
        sedError = EHASH;
        return NULL;
    }

    return passwordHash;
}

uint8_t *hashWithSaltAndRandomString(char *password, uint8_t *salt, uint8_t *randomString, uint8_t *passwordHash)
{
    uint8_t hash[MAX_PASSWORD_LEN] = {0};

    memset(passwordHash, 0, MAX_PASSWORD_LEN);
    
    /* First hash the plaintext password using the salt that was provided and store the result inside passwordHash */
    if (PKCS5_PBKDF2_HMAC(password, MAX_PASSWORD_LEN, salt, MAX_SALT_LENGTH, ITERATIONS, EVP_sha1(), MAX_PASSWORD_LEN, hash) == 0)
    {
        sedError = EHASH;
        return NULL;
    }

    /* Hash again using the randomString */
    if (PKCS5_PBKDF2_HMAC((char *)hash, MAX_PASSWORD_LEN, randomString, MAX_PASSWORD_LEN, ITERATIONS, EVP_sha1(), MAX_PASSWORD_LEN, passwordHash) == 0)
    {
        sedError = EHASH;
        return NULL;
    }

    return passwordHash;
}

char  *selectUserFromList(struct sedContext *sedCtx, char *selectedUser, int size)
{
    int8_t choice;
    int32_t id, count = 1, offset = 0;
    char userName[MAX_NAME_LENGTH], accounts[MAX_ACCOUNTS][MAX_NAME_LENGTH] = {{0}};

    memset(selectedUser, 0, MAX_NAME_LENGTH);

    offset = ADMIN1_DATASTORE_OFFSET;

    /* Enumerate Users while populating the accounts array with found accounts */
    for (id = 1; id <= MAX_ADMINS; ++id)
    {
        memset(userName, 0, MAX_NAME_LENGTH);
   
        if (datastore_get(sedCtx, offset, MAX_NAME_LENGTH, (uint8_t *)userName) & SED_ERROR)
        {
            sedError = ESTORER;
            return NULL;
        }
            
        
        if (userName[0] != '\0')
        {
            if (strlen(userName) > MAX_NAME_LENGTH)
                return NULL;

            strncpy(accounts[count - 1], userName, sizeof(accounts[0]));
            count++;
        }

        offset += ACCOUNT_SIZE;
    }  
    
    /* Enumerate Admins while populating the accounts array with found accounts */
    for (id = 1; id <= MAX_USERS; ++id)
    {
        memset(userName, 0, MAX_NAME_LENGTH);

        if (datastore_get(sedCtx, offset, MAX_NAME_LENGTH, (uint8_t *)userName) & SED_ERROR)
        {
            sedError = ESTORER;
            return NULL;
        }

        if (userName[0] != '\0')
        {
            if (strlen(userName) > MAX_NAME_LENGTH)
                return NULL;

            strncpy(accounts[count - 1], userName, sizeof(accounts[0]));
            count++;
        }

        offset += ACCOUNT_SIZE;     
    }


    /* Display the Title */
    
    printf("\n%s\n",SELECT_ACCOUNT); 
    PRINT_CHAR_LOOP("-", strlen(SELECT_ACCOUNT)); 
    printf("\n\n");

    /* List the names */
    for (id = 0; id < (count - 1); id++)
        printf("%d) %s\n", (id + 1), accounts[id]);
        
    printf("%d) Cancel\n", count);

    /* Get Users selection */    
    choice = getMenuChoice();

    /* Invalid Choice */
    if ((choice - 0x30) > (count) || (choice - 0x30) < 1)
    {
        fprintf(stderr, "\n%s\n", ERROR_INVALID_CHOICE);
        sedError = EICHOICE;
        return NULL;
    }

    /* User chose to go back */
    else if ((choice - 0x30) == (count))
        return NULL;
    
    /* Selected User */    
    else
    {
        if (strlen(accounts[(choice - 0x30)]) > MAX_NAME_LENGTH)
            return NULL;

        strncpy(selectedUser, accounts[(choice - 0x30) - 1], size);
    }
    return selectedUser;
}

uint8_t getNextAvailableID(struct sedContext *sedCtx, SedAccounts accountType)
{
    int32_t id = 0, offset;
    char name[MAX_NAME_LENGTH];

    /* Enumerate Users */
    if (accountType == User)
    {
        offset = USER1_DATASTORE_OFFSET;

        for (id = 1; id <= MAX_USERS; ++id)
        {
            memset(name, 0, MAX_NAME_LENGTH);

            if (datastore_get(sedCtx, offset, MAX_NAME_LENGTH, (uint8_t *)name) & SED_ERROR)
                return (sedError = ESTORER);

            if (strlen(name) == 0)
                return id;

            else
                printf("Name: %s\n",name);
            offset += ACCOUNT_SIZE;
        }
        
        return sedError = EMUSER;  
    }

    /* Enumerate Admins */
    else if (accountType == Admin)
    {
        offset = ADMIN1_DATASTORE_OFFSET;
        
        for (id = 1; id <= MAX_ADMINS; ++id)
        {
            memset(name, 0, MAX_NAME_LENGTH);

            if (datastore_get(sedCtx, offset, MAX_NAME_LENGTH, (uint8_t *)name) & SED_ERROR)
                return (sedError = ESTORER);

            if (strlen(name) == 0)
              return id;  
 
            offset += ACCOUNT_SIZE;
        }
        
        return sedError = EMADMIN;
    }

    /* An invalid account type (neither User nor Admin) was passed in. */
    else
    {
        fprintf(stderr, "%s\n", ERROR_INVALID_ACCOUNT_TYPE);
        sedError = EIACCT;
        return 0;
    }
    
}

uint32_t setupPasswordForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash)
{
    char password[MAX_PASSWORD_LEN], prompt[MAX_PROMPT_SIZE] = {0};
    uint8_t salt[MAX_SALT_LENGTH] = {0};
    struct password_complexity complexity;

   if (getPasswordRequirements(sedCtx, &complexity))
       return sedError;
    
    if (generateSalt(salt, MAX_SALT_LENGTH))
         return sedError;

    sprintf(prompt, "\n\nPlease set a password for %s: ", user.userName);

    /* Create password for the new user */
    if (setPassword(prompt, password, MAX_PASSWORD_LEN, &complexity, 3) != NULL)
    {    
        if (hashWithSalt(password, salt, passwordHash) == NULL)
           return sedError;

        /* Set the newly created password into the Cpin table */
        if (cpin_setPassword(sedCtx, user.accountType, user.id, MAX_PASSWORD_LEN, passwordHash) & SED_ERROR)
            return (sedError = ECPINW);
        
        memset(password, 0, MAX_PASSWORD_LEN);
        memset(passwordHash, 0, MAX_PASSWORD_LEN);
    }
    
    if (setSalt(sedCtx, user.accountType, user.id, salt))
        return sedError;

    if (setAuthenticationType(sedCtx, user.accountType, user.id, 'P'))
        return sedError;

    return 0;
}

uint32_t setupUsbForUser(struct sedContext *sedCtx, SedAccounts accountType, uint8_t newID, uint8_t *passwordHash)
{
    uint8_t randomString[MAX_PASSWORD_LEN] = {0}, encBuffer[MAX_ENCRYPT_SIZE] = {0}, salt[MAX_SALT_LENGTH] = {0};
    char usbDevice[MAX_PATH_LENGTH] = {0}, password[MAX_PASSWORD_LEN] = {0}, prompt[MAX_PROMPT_SIZE] = {0};
    struct password_complexity complexity;
    
    if (getPasswordRequirements(sedCtx, &complexity))
        return sedError;
    
    if (generateSalt(salt, MAX_SALT_LENGTH))
        return sedError;
    
    if (sed_generateRandomString(randomString, MAX_PASSWORD_LEN))
        return sedError;
      
    if (hashWithSalt((char *)randomString, salt, passwordHash) == NULL)
        return sedError;

    /* Set the newly created password into the Cpin table */
    if (cpin_setPassword(sedCtx, accountType, newID, MAX_PASSWORD_LEN, passwordHash) & SED_ERROR)
        return (sedError = ECPINW);

    memset(passwordHash, 0, MAX_PASSWORD_LEN);

    if (selectUsbDevice(usbDevice, sizeof(usbDevice)) == NULL)
        return (sedError = EUSB);
    
    if (mountUSB(usbDevice))
        return (sedError = EUSB);
    
    if (strlen(ENTER_KEY_PASS) > MAX_PROMPT_SIZE)
        return (sedError = ENAMELEN);

    strncpy(prompt, ENTER_KEY_PASS, sizeof(prompt));

    if (setPassword(prompt, password, MAX_PASSWORD_LEN, &complexity, 3) == NULL)
        return (sedError = ESETPASS);
 
    /* Generate Public/Private key pair */
    if (generateRsaKeys(password))
        return (sedError = EGENKEYS);

    /* Copy keys to device */
    if (system("cp private.pem public.pem /mnt"))
        return (sedError = EGENKEYS);
    
    /* The random string gets encrypted with the public key that was generated, and stored into the datastore */
    if (encryptWithPublicKey(randomString, encBuffer, PUBLIC_KEY_LOCATION, password) == NULL)
    {
        memset(randomString, 0, MAX_PASSWORD_LEN);
        memset(password, 0, MAX_PASSWORD_LEN);

        return (sedError = EENCRYPT);
    }
        
    memset(randomString, 0, MAX_PASSWORD_LEN);
    memset(password, 0, MAX_PASSWORD_LEN);

    if (umount("/mnt"))
        fprintf(stderr, "Warning: Could not unmount device\n");

    /* Store the users salt */
    if (setSalt(sedCtx, accountType, newID, salt))
        return sedError;

    /* Store the encrypted blob into the datastore */
    if (setEncryptedBlob(sedCtx, accountType, newID, encBuffer))
        return sedError;

    memset(encBuffer, 0, MAX_ENCRYPT_SIZE);

    if (setAuthenticationType(sedCtx, accountType, newID, 'U'))
        return sedError;

    return 0;
}

/*
TODO: Re-add once smartcard support is updated
uint32_t setupSmartCardWithPasswordForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash)
{
    uint8_t randomString[MAX_PASSWORD_LEN], encBuffer[MAX_ENCRYPT_SIZE], salt[MAX_SALT_LENGTH];
    char prompt[MAX_PROMPT_SIZE], tempPassword[MAX_PASSWORD_LEN];
    struct password_complexity complexity;

    memset(randomString, 0, MAXLENGTH);
    memset(prompt, 0, MAX_PASSWORD_LEN);

    if (getPasswordRequirements(sedCtx, &complexity))
        return sedError;

    sprintf(prompt, "Please set a password for %s: ", user.userName);

    if (generateSalt(salt, MAX_SALT_LENGTH))
        return (sedError = ESALT);
    
    if (sed_generateRandomString(randomString, MAX_PASSWORD_LEN))
        return (sedError = ESALT);

    if (setPassword(prompt, tempPassword, MAX_PASSWORD_LEN, &complexity, 3) != NULL)
    {
        // Hash the users password with the generated salt, then hash that hash with the randomstring
        if (hashWithSaltAndRandomString(tempPassword, salt, randomString, passwordHash) == NULL)
            return sedError;

        memset(tempPassword, 0, MAX_PASSWORD_LEN);
    }
    
    // Set the newly created password into the Cpin table 
    if (cpin_setPassword(sedCtx, user.accountType, user.id, MAX_PASSWORD_LEN, passwordHash) & SED_ERROR)
        return (sedError = ECPINW);

    memset(passwordHash, 0, MAX_PASSWORD_LEN);

    // Encrypt the randomString that was created 
    if (smartCardEncrypt(randomString, encBuffer) == NULL)
        return sedError;

    memset(randomString, 0, MAX_PASSWORD_LEN);

    // Store the users salt 
    if (setSalt(sedCtx, user.accountType, user.id, salt))
        return sedError;

    memset(salt, 0, MAX_SALT_LENGTH);

    // Store the encrypted blob into the datastore 
    if (setEncryptedBlob(sedCtx, user.accountType, user.id, encBuffer))
        return sedError;

    memset(encBuffer, 0, MAX_ENCRYPT_SIZE);

    if (setAuthenticationType(sedCtx, user.accountType, user.id, 'W'))
        return sedError;
    
    return 0;
}
*/

/*
TODO: Re-add once smartcard support has been updated
uint32_t setupSmartCardForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash)
{
    uint8_t randomString[MAX_PASSWORD_LEN] = {0}, encBuffer[MAX_ENCRYPT_SIZE] = {0}, salt[MAX_SALT_LENGTH] = {0};

    if (generateSalt(salt, MAX_SALT_LENGTH))
        return sedError;
    
    if (sed_generateRandomString(randomString, MAX_PASSWORD_LEN))
        return sedError;
    
    if (hashWithSalt((char *)randomString, salt, passwordHash) == NULL)
        exit(EXIT_FAILURE);
 
    // Set the newly created password into the Cpin table as the user password 
    if (cpin_setPassword(sedCtx, user.accountType, user.id, MAX_PASSWORD_LEN, passwordHash) & SED_ERROR)
        return (sedError = ECPINW);

    memset(passwordHash, 0, MAX_PASSWORD_LEN);

    // Encrypt the randomString with the private key that is on the smart card 
    if (smartCardEncrypt(randomString, encBuffer) == NULL)
        return sedError;

    // Store the users salt into the correct offset of that account 
    if (setSalt(sedCtx, user.accountType, user.id, salt))
    {
        memset(randomString, 0, MAX_PASSWORD_LEN);
        memset(salt, 0, MAX_SALT_LENGTH);
        return sedError;
    }

    memset(randomString, 0, MAX_PASSWORD_LEN);
    memset(salt, 0, MAX_SALT_LENGTH);

    // Store the encrypted blob into the datastore 
    if (setEncryptedBlob(sedCtx, user.accountType, user.id, encBuffer))
        return sedError;

    if (setAuthenticationType(sedCtx, sedCtx->account, sedCtx->id, 'S'))
        return sedError;

    
    memset(encBuffer, 0, MAX_ENCRYPT_SIZE);

    return 0;
}
*/

uint32_t setupTwoPasswordsForUser(struct sedContext *sedCtx, struct userInfo user, uint8_t *passwordHash)
{
    char firstPassword[MAX_PASSWORD_LEN] = {0}, secondPassword[MAX_PASSWORD_LEN] = {0}, prompt[MAX_PROMPT_SIZE] = {0};
    uint8_t salt[MAX_SALT_LENGTH] = {0};
    struct password_complexity complexity;

    if (getPasswordRequirements(sedCtx, &complexity))
        return sedError;
    
    if (generateSalt(salt, MAX_SALT_LENGTH))
        return sedError;

    sprintf(prompt, "Please set the first password for %s: ", user.userName);

    /* Setup password1 */
    if (setPassword(prompt, firstPassword, MAX_PASSWORD_LEN, &complexity, ALLOWED_PASSWORD_ATTEMPTS) != NULL)
    {   
        memset(prompt, 0, MAX_PASSWORD_LEN);
        sprintf(prompt, "Please set the second password for %s: ", user.userName);

        /* Setup password2 */
        if (setPassword(prompt, secondPassword, MAX_PASSWORD_LEN, &complexity, ALLOWED_PASSWORD_ATTEMPTS) != NULL)
        {
            /* Hash password1 with the salt, then hash that result with the second password */
            if (hashWithSaltAndRandomString(firstPassword, salt, (uint8_t *)secondPassword, passwordHash) == NULL)
                return (sedError = EHASH);

            /* Set the password in the datastore */
            if (cpin_setPassword(sedCtx, user.accountType, user.id, MAX_PASSWORD_LEN, passwordHash) & SED_ERROR)
                return (sedError = ECPINW);
        
            memset(firstPassword, 0, MAX_PASSWORD_LEN);
            memset(secondPassword, 0, MAX_PASSWORD_LEN);
            memset(passwordHash, 0, MAX_PASSWORD_LEN);
        }
    }

    else
        return (sedError = ESETPASS);

    /* Store the salt to the datastore at accounts offset */
    if (setSalt(sedCtx, user.accountType, user.id, salt))
        return sedError;

    if (setAuthenticationType(sedCtx, user.accountType, user.id, 'D'))
        return sedError;

    return 0;
}

uint32_t setDistressPassword(struct sedContext *sedCtx)
{
    char password[MAX_PASSWORD_LEN] = {0}, distress[MAX_PASSWORD_LEN] = {0};

    /* Need to be adminSP in order to change its password */
    sessionManager_closeSession(sedCtx);
    
    sedCtx->account = AdminSP;
    sedCtx->id = 0;

    /* The adminSP account will always have password authentication */
    if (promptPassword("Enter current Distress password: ", password, MAX_PASSWORD_LENGTH) == NULL)
        return (sedError = EINVAL);

    /* Check password */
    if (sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, (uint8_t *)password) & SED_ERROR)
        return (sedError = EINVAL);

    /* Create password for the Distress account */
    /* Note: Distress password is not Hashed nor Salted */
    if (setPassword("Please set a distress password: ", password, MAX_PASSWORD_LEN, NULL, ALLOWED_PASSWORD_ATTEMPTS) != NULL)
    {
        if (strlen(password) > MAX_PASSWORD_LEN)
            return sedError = EPASSLEN;

        /* Always want it 32 bytes so pad with zeros */
        strncpy(distress, password, sizeof(distress));

        /* Set the newly created password into the Cpin table */
        if (cpin_setPassword(sedCtx, AdminSP, 0, MAX_PASSWORD_LEN, (uint8_t *)distress) & SED_ERROR)
            return (sedError = ECPINW);

        memset(password, 0, MAX_PASSWORD_LEN);
        memset(distress, 0, MAX_PASSWORD_LEN);
    }

    printf("Successfully changed distress password\n");
    printf("System must reboot in order for changes to take effect\n");

    return 0;
}

int32_t passwordLogin(struct sedContext *sedCtx, char *pass)
{
    int32_t retries = 0, id;
    uint8_t hashedPassword[MAX_PASSWORD_LEN] = {0}, salt[MAX_SALT_LENGTH] = {0};
    char password[MAX_PASSWORD_LEN] = {0};
    SedAccounts account;

	/* If the user passes in a password, then immediately attempt to login */
    if (pass != NULL)
    {
        if (sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, (uint8_t *)pass) & SED_ERROR)   
        {
            sed_errors_print(SED_ERROR);
            fprintf(stderr, "Invalid Password\n");
            return 1;
        }

        memset(password, 0, MAX_PASSWORD_LEN);

        return 0;
    }

	/* If the user does not pass in an password, do an interactive login */
    /* Backup information, since it will be manipulated by other functions */
    account = sedCtx->account;
    id = sedCtx->id;

    /* Grab the salt associated with the account from the datastore */
    if (sed_startSessionAsAnybody(sedCtx, Admin))
        return 1;

    if (getSalt(sedCtx, account, id, salt) == NULL)
        return 1;

    sessionManager_closeSession(sedCtx); 
    
    while (retries != ATTEMPTS_ALLOWED)
    {
        /* Restore the account information */
        sedCtx->account = account;
        sedCtx->id = id;
        
        if (promptPassword("Enter password: ", password, MAX_PASSWORD_LENGTH) == NULL)
            exit(EXIT_FAILURE);

        /* Check to see if Distress password is entered */
        attemptDistress(sedCtx, password);

        /* Since the password is not distress, hash it and attempt to login */
        if (hashWithSalt(password, salt, hashedPassword) == NULL)
            exit(EXIT_FAILURE);
            
        if (sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, hashedPassword) & SED_ERROR)   
        {
            fprintf(stderr, "Invalid Password\n");
            retries++;
        }

        /* Successful Login */   
        else
        {
            memset(hashedPassword, 0, MAX_PASSWORD_LEN);
            memset(password, 0, MAX_PASSWORD_LEN);
            return 0;
        }
            
    }

    return (sedError = ELOGIN);
}

int32_t usbLogin(struct sedContext *sedCtx)
{
    int32_t retVal = 0, retries = 0, id;
    uint8_t hashedPassword[MAX_PASSWORD_LEN] = {0}, salt[MAX_SALT_LENGTH] = {0};
    uint8_t encryptedBlob[MAX_ENCRYPT_SIZE] = {0}, randomString[MAX_PASSWORD_LEN] = {0};
    char password[MAX_PASSWORD_LEN] = {0}, usbDevice[MAX_NAME_LENGTH] = {0};
    SedAccounts account;

    /* Backup information, since it will be manipulated by other functions */
    account = sedCtx->account;
    id = sedCtx->id;

    sedCtx->account = Admin;
    sedCtx->id = 1;

    memset(salt, 0, MAX_SALT_LENGTH);

    /* Start session as anybody under the Admin1 account */
    retVal = sessionManager_startSession(sedCtx, 1, 0, NULL); 
    ERROR_CHECK(retVal, ERROR_START_SESSION)

    if (getSalt(sedCtx, account, id, salt) == NULL)
        return 1;

    if (getEncryptedBlob(sedCtx, account, id, encryptedBlob) == NULL)
        return 1;

    sessionManager_closeSession(sedCtx);

    if (selectUsbDevice(usbDevice, sizeof(usbDevice)) == NULL)
        return 1;

    if (mountUSB(usbDevice))
        return 1;
    
    system("clear");

    if (promptPassword("Enter password: ", password, MAX_PASSWORD_LENGTH) == NULL)
        exit(EXIT_FAILURE);

    /* Check to see if Distress password is entered */
    attemptDistress(sedCtx, password);

    /* Grab the private key from the usb, and decrypt the blob that was pulled from the datastore */
    if (decryptWithPrivateKey(encryptedBlob, randomString, PRIVATE_KEY_LOCATION, password))
        return 1;

    if (umount(USB_MOUNT_POINT))
        fprintf(stderr, "Warning: Could not unmount device\n");

    /* Hash that password with the salt and attempt to login with the password */
    if (hashWithSalt((char *)randomString, salt, hashedPassword) == NULL)
        return 1;

    /* Restore the account information */
    sedCtx->account = account;
    sedCtx->id = id;
                    
    retVal = sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, hashedPassword);    
    if (retVal & SED_ERROR)
        retries++;
        
    /* Able to login */    
    else
    {
        memset(hashedPassword, 0, MAX_PASSWORD_LEN);
        memset(password, 0, MAX_PASSWORD_LEN);
        memset(encryptedBlob, 0, MAX_ENCRYPT_SIZE);
        memset(randomString, 0, MAX_PASSWORD_LEN);

        return 0;
    }
        
    
    return 1;
}

/*
TODO: Re-add once smartcard support has been updated
int32_t smartCardLogin(struct sedContext *sedCtx)
{
    int32_t retries = 0, id, retVal;
    uint8_t randomString[MAX_PASSWORD_LEN] = {0}, hashedPassword[MAX_PASSWORD_LEN] = {0};
    uint8_t salt[MAX_SALT_LENGTH] = {0}, encryptedBlob[MAX_ENCRYPT_SIZE] = {0};
    SedAccounts account;

    // Backup information, since it will be manipulated by other functions 
    account = sedCtx->account;
    id = sedCtx->id;

    sedCtx->account = Admin;
    sedCtx->id = 1;

    memset(salt, 0, MAX_SALT_LENGTH);

    // Start session as anybody under the Admin1 account 
    retVal = sessionManager_startSession(sedCtx, 1, 0, NULL); 
    ERROR_CHECK(retVal, ERROR_START_SESSION)

    if (getSalt(sedCtx, account, id, salt) == NULL)
        return 1;

    if (getEncryptedBlob(sedCtx, account, id, encryptedBlob) == NULL)
        return 1;

    sessionManager_closeSession(sedCtx);

    // Gives the user x amount of attempts to enter their PIN correctly 
    while (retries != ATTEMPTS_ALLOWED)
    {
        // Decrypt the encrypted the blob with the private key on the smartcard 
        if (smartCardDecrypt(encryptedBlob, randomString) == NULL)
        {
            fprintf(stderr, "Error: Failed to unlock the drive\n");
            sleep(3);
            return 1;
        }
              
        if (hashWithSalt((char *)randomString, salt, hashedPassword) == NULL)
            exit(EXIT_FAILURE);
            
        // Restore values and attempt to login 
        sedCtx->account = account;
        sedCtx->id = id;
        
        if ((sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, hashedPassword)) & SED_ERROR)
            retries++;
            
        // Successful Login 
        else
        {
            memset(encryptedBlob, 0, MAX_ENCRYPT_SIZE);
            memset(randomString, 0, MAX_PASSWORD_LEN);
            memset(hashedPassword, 0, MAX_PASSWORD_LEN);
            return 0;
        }
            
    }

    fprintf(stderr, "Too many Login attempts\n");
    return 1;
}
*/

/*
TODO: re-add once smart card support has been updated
int32_t smartCardWithPasswordLogin(struct sedContext *sedCtx)
{
    int32_t retries = 0, id, retVal;
    uint8_t randomString[MAX_PASSWORD_LEN] = {0}, hashedPassword[MAX_PASSWORD_LEN] = {0};
    uint8_t salt[MAX_SALT_LENGTH] = {0}, encryptedBlob[MAX_ENCRYPT_SIZE] = {0};
    char password[MAX_PASSWORD_LEN] = {0};
    SedAccounts account;

    // Backup information, since it will be manipulated by other functions 
    account = sedCtx->account;
    id = sedCtx->id;

    sedCtx->account = Admin;
    sedCtx->id = 1;

    memset(salt, 0, MAX_SALT_LENGTH);

    // Start session as anybody under the Admin1 account 
    retVal = sessionManager_startSession(sedCtx, 1, 0, NULL); 
    ERROR_CHECK(retVal, ERROR_START_SESSION)

    if (getSalt(sedCtx, account, id, salt) == NULL)
        return 1;

    sessionManager_closeSession(sedCtx);

    // Give them x amount of attemps to get both their PIN and password correct 
    while (retries != ATTEMPTS_ALLOWED)
    {
        retVal = sessionManager_startSession(sedCtx, 1, 0, NULL); 
        ERROR_CHECK(retVal, ERROR_START_SESSION)
        
        if (getEncryptedBlob(sedCtx, account, id, encryptedBlob) == NULL)
            return 1;

        sessionManager_closeSession(sedCtx);

        // Decrypt blob with the private key from the smartCard 
        if (smartCardDecrypt(encryptedBlob, randomString) == NULL)
        {
            fprintf(stderr, "Error: Failed to unlock the drive\n");
            sleep(3);
            return 1;
        }

        if (promptPassword("Enter password: ", password, MAX_PASSWORD_LENGTH) == NULL)
                exit(EXIT_FAILURE);

        // Check to see if Distress password is entered 
        attemptDistress(sedCtx, password);
                
        // Hashes the password that the user entered with the salt, then hash that with the random string 
        if (hashWithSaltAndRandomString(password, salt, randomString, hashedPassword) == NULL)
                exit(EXIT_FAILURE);    
            
        // Restore user credential and attempt to login 
        sedCtx->account = account;
        sedCtx->id = id;
        
        if ((sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, hashedPassword)) & SED_ERROR)
            retries++;
            
        // Successful login
        else
        {
            memset(hashedPassword, 0, MAX_PASSWORD_LEN);
            memset(encryptedBlob, 0, MAX_ENCRYPT_SIZE);
            memset(randomString, 0, MAX_PASSWORD_LEN);
            memset(password, 0, MAX_PASSWORD_LEN);

            return 0;
        }
            
    }

    fprintf(stderr, "Too many Login attempts\n");
    return 1;
}
*/

int32_t twoPasswordLogin(struct sedContext *sedCtx)
{
    char firstPassword[MAX_PASSWORD_LEN] = {0}, secondPassword[MAX_PASSWORD_LEN] = {0};
    uint8_t salt[MAX_SALT_LENGTH] = {0}, password[MAX_PASSWORD_LEN] = {0};
    int32_t retVal = 0, id, retries = 0;
    SedAccounts account;

    /* Backup information, since it will be manipulated by other functions */
    account = sedCtx->account;
    id = sedCtx->id;

    sedCtx->account = Admin;
    sedCtx->id = 1;

    memset(salt, 0, MAX_SALT_LENGTH);

    /* Start session as anybody under the Admin1 account */
    retVal = sessionManager_startSession(sedCtx, 1, 0, NULL); 
    ERROR_CHECK(retVal, ERROR_START_SESSION)

    if (getSalt(sedCtx, account, id, salt) == NULL)
        return 1;

    sessionManager_closeSession(sedCtx);

    while (retries != ATTEMPTS_ALLOWED)
    {
        /* Get the first password from the user */
        if (promptPassword("Enter the first password: ", firstPassword, MAX_PASSWORD_LENGTH) == NULL)
            exit(EXIT_FAILURE);

        /* Get the second password from the user */
        if (promptPassword("Enter the second password: ", secondPassword, MAX_PASSWORD_LENGTH) == NULL)
            exit(EXIT_FAILURE);

        /* Check to see if one of the passwords that was entered is the distress password */
        attemptDistress(sedCtx, firstPassword);

        attemptDistress(sedCtx, secondPassword);

        /* Hash the first password with the salt and hash the result with the second password */
        if (hashWithSaltAndRandomString(firstPassword, salt, (uint8_t *)secondPassword, password) == NULL)
            exit(EXIT_FAILURE);
            
        /* Restore the user credentials and attempt to login */
        sedCtx->account = account;
        sedCtx->id = id;
        
        retVal = sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, password);    
        if (retVal & SED_ERROR)
            retries++;
        
        /* Successful login */    
        else
        {
            memset(firstPassword, 0, MAX_PASSWORD_LEN);
            memset(secondPassword, 0, MAX_PASSWORD_LEN);
            memset(password, 0, MAX_PASSWORD_LEN);

            return 0;
        }
            
    }

    fprintf(stderr, "Too many Login attempts\n");
    return 1;
}

uint32_t authenticateUserByID(struct sedContext *sedCtx, SedAccounts account, uint8_t id)
{
    int8_t authenticationType;
    int32_t retVal = 0;

    /* Get the authentication type so I know which authentication to carry out */
    if ((authenticationType = getAuthenticationType(sedCtx, account, id)) & sedError)
        return sedError;

    /* Make sure the session is close before attempting to reauthenticate */
    sessionManager_closeSession(sedCtx);

    sedCtx->account = account;
    sedCtx->id = id;

    /* Carry out the correct authentication method based on the returned authentication type */
    switch(authenticationType)
    {
        case 'P':
            retVal = passwordLogin(sedCtx, NULL);
            break;
        
        /*
        case 'S':
            retVal = smartCardLogin(sedCtx);
            break;
        */
        
        /*
        case 'T':
            retVal = smartCardWithPasswordLogin(sedCtx);
            break;
        */
        
        case 'U':
            retVal = usbLogin(sedCtx);
            break;
        
        case 'D':
            retVal = twoPasswordLogin(sedCtx);
            break;
        
        default:
            return (sedError = EIAUTH);
    }

    return retVal;
}

char *selectUsbDevice(char *usbDevice, uint32_t size)
{
    DIR *dirp;
    struct dirent *devices;
    int32_t i = 0, fd, count = 0;
    char deviceName[MAXNAMLEN] = {0}, isRemovable[2] = {0}, usbDevices[10][12], choice;
    char blockDevice[] = "/sys/block/";

refresh:

    system("clear");   
    
    for (i = 0; i < 10; i++)
        memset(usbDevices[i], 0, 12);

    memset(usbDevice, 0, MAX_NAME_LENGTH);
    count = 0;

    /* All of the block devices are located in /sys/block */
    if ((dirp = opendir(blockDevice)) == NULL)
    {
        perror("Error(opendir) ");
        exit(EXIT_FAILURE);
    }

    /* Get all of the block devices that are in that directory */
    for (i = 0; i < 20; i++)
    {
        memset(deviceName, 0, MAXNAMLEN);
        memset(isRemovable, 0, 2);

        if ((devices = readdir(dirp)) == NULL)
            break;

        /* Dont want to check out files ., .., or sr* */
        if ((!strncmp(devices->d_name, ".", 1) || (!strncmp(devices->d_name, "..", 2) || (!strncmp(devices->d_name, "sr", 2)))))
            continue;
    
        /* /sys/block/DEVICE_NAME/removable will be set if it is removable storage */
        if (strlen(blockDevice) > sizeof(deviceName))
            return NULL;

        strncpy(deviceName, blockDevice, sizeof(deviceName));
        strcat(deviceName, devices->d_name); 
        strcat(deviceName, "/removable");

        /* Read the file removable to see if the byte is set */
        if ((fd = open(deviceName, O_RDONLY)) < 1)
            usbCleanup(dirp, fd, 1);

        if ((read(fd, isRemovable, 1)) != 1)
            usbCleanup(dirp, fd, 1);

        close(fd);
        
        if ((!strncmp(isRemovable, "1", 1)))
        {
            strcat(usbDevices[count], "/dev/");
            strcat(usbDevices[count++], devices->d_name);
        } 
    }

    /* Close Main path with error checking */
    usbCleanup(dirp, 0, 0);

    printf("Select USB Storage Device\n");
    printf("-------------------------\n");
    for (i = 0; i < count; i++)
            printf("%d) %s\n", i + 1, usbDevices[i]);

    printf("\n");
    printf("%d) Go Back\n", i+1);
    printf("\nPress R to refresh the list...\n");
    
    
    /* Handle Users Selection */
    choice = getMenuChoice();

    if ((choice - 0x30) == (i + 1))
        return NULL;

    if (choice ==  'r' || choice == 'R')
        goto refresh;

    if ((choice - 0x30) > count || (choice - 0x30) < 1)
    {
        printf("Choice: %d Count: %d\n",choice, count);
        printf("Invalid Option\n");
        goto refresh;
    }

    else
    {
        if (strlen(usbDevices[(choice - 0x30) - 1]) > MAX_PATH_LENGTH)
            return NULL;


        strncpy(usbDevice, usbDevices[(choice - 0x30) - 1], size);
        strcat(usbDevice, "1");   
    }
    
    return usbDevice;
}

int32_t usbCleanup(DIR *dirp, int32_t fd, int32_t onError)
{
    if (onError)
        perror("Error ");

    /* Close file if provided */
    if (fd)
        close(fd);

    /* Close main directory */
    if (closedir(dirp))
    {
        perror("Error: ");
        exit(EXIT_FAILURE);
    }

    if (onError)
        exit(EXIT_FAILURE);
    else
        return 0;    
}

uint32_t configurePasswordRequirements(struct sedContext *sedCtx, struct password_complexity *complexity, int32_t interactive)
{
    int32_t retVal = 0;

    /* Prompt the user to enter a value for each possible complexity */
    if (interactive)
    {
        if (setComplexity(complexity))
            return sedError;
    }

    /* Set the Configured Complexity into the datasotre */
    retVal  = datastore_set(sedCtx, COMPLEXITY_MIN_CHARS, sizeof(int32_t), (uint8_t *)&complexity->minNumberOfChars);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MAX_CHARS, sizeof(int32_t), (uint8_t *)&complexity->maxNumberOfChars);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MIN_CAPS, sizeof(int32_t), (uint8_t *)&complexity->numberOfCaps);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MIN_SPECIAL, sizeof(int32_t), (uint8_t *)&complexity->numberOfSpecial);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MIN_NUMBERS, sizeof(int32_t), (uint8_t *)&complexity->numberofNumbers);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MAX_SEQUENCE, sizeof(int32_t), (uint8_t *)&complexity->maxSequenceChars);

    /* An Error occured while setting a datastore value */
    if (retVal)
        return (sedError = ECOMPW);
    
    printf("Successfully modified Complexity.\n");
    return 0;
}

uint32_t setPasswordComplexityToDefault(struct sedContext *sedCtx, struct password_complexity *complexity)
{
    int32_t retVal = 0;

    /* Default values for the password complexity. This it modifiable at a later stage */
    complexity->minNumberOfChars = 8;
    complexity->maxNumberOfChars = 32;
    complexity->numberOfSpecial = 1;
    complexity->numberOfCaps = 1;
    complexity->numberofNumbers = 1;
    complexity->maxSequenceChars = 5;

    /* Store complexity configuration in the dataStore */
    retVal  = datastore_set(sedCtx, COMPLEXITY_MIN_CHARS, sizeof(int32_t), (uint8_t *)&complexity->minNumberOfChars);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MAX_CHARS, sizeof(int32_t), (uint8_t *)&complexity->maxNumberOfChars);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MIN_CAPS, sizeof(int32_t), (uint8_t *)&complexity->numberOfCaps);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MIN_SPECIAL, sizeof(int32_t), (uint8_t *)&complexity->numberOfSpecial);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MIN_NUMBERS, sizeof(int32_t), (uint8_t *)&complexity->numberofNumbers);
    retVal |= datastore_set(sedCtx, COMPLEXITY_MAX_SEQUENCE, sizeof(int32_t), (uint8_t *)&complexity->maxSequenceChars);

    /* Some error occured while attempting to set a value */
    if (retVal)
        return (sedError = ESTOREW);
    
    return 0;
}

uint32_t getPasswordRequirements(struct sedContext *sedCtx, struct password_complexity *complexity)
{
    int32_t retVal = 0;

    /* Retrieve Current Password Complexity Values */
    retVal = datastore_get(sedCtx, COMPLEXITY_MIN_CHARS, sizeof(int32_t), (uint8_t *)&complexity->minNumberOfChars);
    retVal |= datastore_get(sedCtx, COMPLEXITY_MAX_CHARS, sizeof(int32_t), (uint8_t *)&complexity->maxNumberOfChars);
    retVal |= datastore_get(sedCtx, COMPLEXITY_MIN_CAPS, sizeof(int32_t), (uint8_t *)&complexity->numberOfCaps);
    retVal |= datastore_get(sedCtx, COMPLEXITY_MIN_SPECIAL, sizeof(int32_t), (uint8_t *)&complexity->numberOfSpecial);
    retVal |= datastore_get(sedCtx, COMPLEXITY_MIN_NUMBERS, sizeof(int32_t), (uint8_t *)&complexity->numberofNumbers);
    retVal |= datastore_get(sedCtx, COMPLEXITY_MAX_SEQUENCE, sizeof(int32_t), (uint8_t *)&complexity->maxSequenceChars);
 
    /* An Error Occured while attempting to read from datastore */
    if (retVal)
        return (sedError = ESTORER);
    
    return 0;
}

void displayPasswordComplexity(struct sedContext *sedCtx, struct password_complexity *complexity)
{
    /* Display the complexity */
    printf("%s%13d\n", MIN_CHARS, complexity->minNumberOfChars);
    printf("%s%13d\n",MAX_CHARS, complexity->maxNumberOfChars);
    printf("%s%3d\n", MIN_UPPER, complexity->numberOfCaps);
    printf("%s%5d\n", MIN_NUMBERS, complexity->numberofNumbers);
    printf("%s%5d\n", MIN_SPECIAL, complexity->numberOfSpecial);
    printf("%s%4d\n\n", MAX_SEQUENCE, complexity->maxSequenceChars);
}

void attemptDistress(struct sedContext *sedCtx, char *password)
{
    int32_t retVal;
    SedAccounts backupAccount;
    uint8_t backupID;
    char distress[MAX_PASSWORD_LEN] = {0};

    sessionManager_closeSession(sedCtx);
    
    /* Backup the current context information */
    backupAccount = sedCtx->account;
    backupID = sedCtx->id;
    
    /* Setup the AdminSP account since the distress password is mapped to there */
    sedCtx->account = AdminSP;
    sedCtx->id = 0;

    if (strlen(password) > MAX_PASSWORD_LENGTH)
        return;

    strncpy(distress, password, sizeof(distress));

    /* Check to see if password is the distress password */
    retVal = sessionManager_startSession(sedCtx, 1, MAX_PASSWORD_LEN, (uint8_t *)distress);    
    if (retVal & SED_ERROR)
    {
        /* Restore original context Values */
        sedCtx->account = backupAccount;
        sedCtx->id = backupID;
        return;
    } 
            
    /* AdminSP is successfully authenticated, Now we can revert */    
    retVal = adminSP_revert(sedCtx);
    
    ERROR_CHECK(retVal, ERROR_REVERT);

    system("reboot -f 2>/dev/null");
}

uint32_t promptAdminLogin(struct sedContext *sedCtx)
{
    char username[MAX_NAME_LENGTH] = {0};

    if (promptUsername(sedCtx, username, 1))
        return sedError;

    /* Verify that the account is an Admin Account */
    if (!isAdmin(sedCtx, username))
        return (sedError = ENADMIN);
    
    /* Login with admin account */
    if (authenticate(sedCtx, username))
        return sedError;

    return 0;
}
