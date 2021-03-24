#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <libp11.h>
#include <stdint.h>
#include "../sed/sed.h"


/*
    Gets the first available slot that contains a token
*/
PKCS11_SLOT *getSlot(PKCS11_CTX *ctx, unsigned int *numSlots, PKCS11_SLOT *slotList);

/*
    Gets an cert from the card located in the slot provided
*/
PKCS11_CERT *getCert(PKCS11_SLOT *slot);

/*
    Takes in a plaintext bufferToEncrypt, encrypt it using the public key on the smartCard,
    then store the encrypted results in encrpytedBuffer which must be 256 bytes.
*/
uint8_t *smartCardEncrypt(uint8_t *bufferToEncrypt, uint8_t *encryptedBuffer);

/*
    Takes in an encryptedBlob and attempt to decrypt it using the private key located on the 
    smart card and dump the results in the decryptedBuffer.
*/
uint8_t *smartCardDecrypt(uint8_t *encryptedBlob, uint8_t *decryptedBuffer);

/*
    Authenticates the user to the card
*/
int32_t authenticateToSmartCard(PKCS11_SLOT *slot);