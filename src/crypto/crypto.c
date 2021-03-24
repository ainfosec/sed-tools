#include "../include/crypto/crypto.h"

uint8_t *smartCardEncrypt(uint8_t *bufferToEncrypt, uint8_t *encryptedBuffer)
{
    PKCS11_CTX *ctx;
    PKCS11_SLOT *slot, *slots = NULL;
    PKCS11_CERT *authcert;
    EVP_PKEY *pubkey = NULL;
    uint32_t nslots;
    uint8_t  *cryptoBuffer = NULL;
    int32_t cryptoLen;

    printf("Setting up User...\n");

    //ensure that the daemon
    if (system("/usr/sbin/pcscd &"))
	{
	    fprintf(stderr, "Error locating pcscd. Did you place it in /usr/sbin? \n");
        return NULL;
	}

    // Get a context for this session
    ctx = PKCS11_CTX_new();

    // Load the module
    if (PKCS11_CTX_load(ctx, "/usr/lib/pkcs11/libcoolkeypk11.so"))
    {
        fprintf(stderr, " Can not load the module: %s\n", ERR_reason_error_string(ERR_get_error()));
        sedError = ESMARTCARD;
        return NULL;
    }

    /* Poll for smartCard */

    printf("Scanning for SmartCard ...\n");   
    
    do
    {
        slot = getSlot(ctx, &nslots, slots); 
    } while (!slot);
    
    /* Obtain a certificate located on the given slot */
    if (!(authcert = getCert(slot)))
    {
        sedError = ECERT;
        return NULL;
    }
         
    /* Get public key from the cert */

    pubkey = X509_get_pubkey(authcert->x509);

    if (pubkey == NULL)
    {
        sedError = EPUBKEY;
        return NULL;
    }

    /* Setup the buffer that will be used for encryption */
    cryptoBuffer = malloc(RSA_size(pubkey->pkey.rsa));
    if (!cryptoBuffer)
    {
        sedError = ESMARTCARD;
        return NULL;
    }
    
    /* Encrypt */
    cryptoLen = RSA_public_encrypt(MAX_PASSWORD_LENGTH, bufferToEncrypt, cryptoBuffer, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
    if (cryptoLen < 0)
    {
        sedError = EENCRYPT;
        return NULL;
    }
        
    /* Copy to user provided buffer */
   // memset(encryptedBuffer, 0, MAX_ENCRYPT_SIZE);
    memcpy(encryptedBuffer, cryptoBuffer, MAX_ENCRYPT_SIZE);
    
    /* Cleanup */
    PKCS11_CTX_unload(ctx);
    PKCS11_CTX_free(ctx);


    EVP_PKEY_free(pubkey);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    free(cryptoBuffer);
    
    return encryptedBuffer;
}

uint8_t *smartCardDecrypt(uint8_t *encryptedBlob, uint8_t *decryptedBuffer)
{
    PKCS11_CTX *ctx;
    PKCS11_SLOT *slots = NULL, *slot;
    PKCS11_KEY *authkey;
    PKCS11_CERT *authcert;
    EVP_PKEY *pubkey = NULL;
    unsigned char *cryptoBuffer = NULL;
    unsigned int nslots;

    // Get a context for this session
    ctx = PKCS11_CTX_new();

    // Load the module
    if (PKCS11_CTX_load(ctx, "/usr/lib/pkcs11/libcoolkeypk11.so"))
    {
        fprintf(stderr, " Can not load the module: %s\n", ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

    // Scan for smartCard
    printf("Scanning for SmartCard ...\n");    
    do
    {
        slot = getSlot(ctx, &nslots, slots); 
    }while (!slot);

    // Obtain a certificate located on the given slot
    if (!(authcert = getCert(slot)))
        return NULL;

    // Get RSA Key
    pubkey = X509_get_pubkey(authcert->x509);

    if (pubkey == NULL)
    {
        fprintf(stderr, "Could not extract public key\n");
        return NULL;
    }

    // Authenticate with the card
    if (!(authenticateToSmartCard(slot)))
    {
        printf("Unable to authenticate with card\n");
        return NULL;
    }

    printf("Decrypting data ...\n");

    // Find a private key that can be used for decryption
    authkey = PKCS11_find_key(authcert);
    if (!authkey)
    {
        fprintf(stderr, "No key matching certificate available\n");
        return NULL;
    }

    // Allocate the buffer for encryption/decryption
    cryptoBuffer = malloc(RSA_size(pubkey->pkey.rsa));
    if (!cryptoBuffer)
    {
        fprintf(stderr, "Could not allocate buffer to hold cryptoBuffer data\n");
        return NULL;
    }
    

    // Perform the decryption
    if ((PKCS11_private_decrypt(MAX_ENCRYPT_SIZE, encryptedBlob, cryptoBuffer, authkey, RSA_PKCS1_PADDING)) == 0)
    {
        fprintf(stderr, "Error with decryption\n");
        return NULL;
    }

    // Assume that the user didnt empty the buffer
    //memset(decryptedBuffer, 0, MAX_PASSWORD_LENGTH);

    // Copy the decrypted buffer to the users buffer
    memcpy(decryptedBuffer, cryptoBuffer, MAX_PASSWORD_LENGTH);

    // Cleanup
    // PKCS11_release_all_slots(ctx, slots, nslots);
    PKCS11_CTX_unload(ctx);
    PKCS11_CTX_free(ctx);


    EVP_PKEY_free(pubkey);
    

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    free(cryptoBuffer);

    return decryptedBuffer;
}


PKCS11_SLOT *getSlot(PKCS11_CTX *ctx, unsigned int *numSlots, PKCS11_SLOT *slotList)
{
    PKCS11_SLOT *slot;

    // Get information from all of the slot
    if (PKCS11_enumerate_slots(ctx, &slotList, numSlots) < 0)
    {
        PKCS11_CTX_unload(ctx);
        return 0;
    }

    // Grab the first slot with a token
    slot = PKCS11_find_token(ctx, slotList, *numSlots);
    if (!slot || !slot->token)
    {
        PKCS11_release_all_slots(ctx, slotList, *numSlots);
        return 0;
    }

    return slot;
}

PKCS11_CERT *getCert(PKCS11_SLOT *slot)
{
    unsigned int ncerts;
    PKCS11_CERT *certs, *authcert;

    // Get all certs
    if (PKCS11_enumerate_certs(slot->token, &certs, &ncerts))
    {
        fprintf(stderr, "PKCS11_enumerate_certs failed\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Make sure at least one cert was located
    if (ncerts == 0)
    {
        fprintf(stderr, "no certificates found\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Use the first possible cert
    authcert= &certs[0];

    return authcert;
}

int32_t authenticateToSmartCard(PKCS11_SLOT *slot)
{
    char password[20];
    
    // Check to see if login is required
    if (!slot->token->loginRequired)
        return 1;

    // Perpare terminal
    struct termios old, new;

    // turn off echo
    if (tcgetattr(0, &old) != 0)
        return 0;

    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(0, TCSAFLUSH, &new) != 0)
        return 0;

    system("clear");

    // read the password
    printf("Enter PIN %.32s: ", slot->token->label);
    fgets(password, sizeof(password), stdin);
    printf("\n");

    //restore the terminal
    (void)tcsetattr(0, TCSAFLUSH, &old);

    // take off \n from password
    if (strlen(password) <= 0)
        return 0;
    password[strlen(password) - 1] = 0;

    // Perfom pkcs 11 login
    if ((PKCS11_login(slot, 0, password)))
    {
        // Wipe password from memory
        memset(password, 0, strlen(password));
        fprintf(stderr, "PKCS11_login failed!\n");
        return 0;
    }

    // wipe password from memory
    memset(password, 0, strlen(password));

    return 1;
}

EVP_PKEY *getPublicKey()
{   
    PKCS11_CERT *certificate = NULL;
    EVP_PKEY *pubkey = NULL;

    /* Make sure the daemone and modules are loaded and setup everything for the context */
    if (initializeCtx(&ctx))
        return NULL;

    /* Ensure that the ctx is good */
    if (!ctx)
    {
        sedError = EBPOINTER;
        return NULL;
    }

    /* Wait until a smartcard is inserted */
    if (pollForSmartCard(ctx))
        return NULL;

    /* Get the first available slot */
    if (!(slot = getSlot()))
        return NULL;

    /* Obtain a certificate located on the given slot */
    if (!(certificate = getCertificate(slot)))
    {
        sedError = ECERT;
        return NULL;
    }
         
    /* Get public key from the cert */
    pubkey = X509_get_pubkey(certificate->x509);

    if (pubkey == NULL)
    {
        sedError = EPUBKEY;
        return NULL;
    }

    return pubkey;
}

void clean()
{
    /* Cleanup */
    cardFound = 0;
    PKCS11_release_all_slots(ctx, slotList, slotCount);
    PKCS11_CTX_unload(ctx);
    PKCS11_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    
    return;
}
