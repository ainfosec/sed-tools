#ifndef __SED_TOOLS_CPIN_H__
#define __SED_TOOLS_CPIN_H__

#include "../sed/sed.h"
#include <inttypes.h>

#define COLUMN_USERNAME 1
#define COLUMN_COMMONNAME 2

/**
    @brief Get the MSID's PIN from the C_PIN table

    This function will get the MSID's PIN (The pin that comes manufactured with
    the drive) from the C_PIN table

    @return 0 on success. 

    \code
    cpin_msiduid_get(0x01, 0x00, filedescriptor, passToken, password);
    \endcode

    @note   The response from this command must be verified.. For a more
            detailed example and explanation, please refer to
            section 3.2.3.2 of the "TCG Storage Application Note: Encrypting
            Drives Compliant with Opal SSC".
*/
int32_t cpin_getPassword(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint32_t *szPassword, uint8_t *password);


/**
    @brief Set the new admin1 password

    This function sets the new admin1 password in the Admin1's C_PIN table

    @return 0 on success. 

    \code
    cpin_adminOneUID_set(0x01, 0x00, "ADMIN1_PASSWORD", "ADMIN1_PASSWORD_LENGTH, 
                         fileDescriptor")
    \endcode

    @note   For a more detailed example and explanation, please refer to
            section 3.2.5.2 of the "TCG Storage Application Note: Encrypting
            Drives Compliant with Opal SSC".
*/
int32_t cpin_setPassword(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint32_t szPassword, uint8_t *password);


// Gets the # of login attempts, maximum number of attempts and whether attempts persist through a power cycle
int32_t cpin_auditLogins(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint32_t *attempts, uint32_t *maxAttempts, uint8_t *persistence);
int32_t cpin_setLoginProperties(struct sedContext *sedCtx, SedAccounts who, uint8_t id, int32_t attempts, int32_t attemptLimit, int8_t persistence);

int32_t cpin_setAccountNames(struct sedContext *sedCtx, SedAccounts who, uint8_t id, char *username);

int32_t cpin_getAccountNames(struct sedContext *sedCtx, SedAccounts who, uint8_t id, char *userName);
int32_t cpin_getUID(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint8_t *uid);
int8_t cpin_getAuthenticationType(struct sedContext *sedCtx, SedAccounts user, uint8_t id);

#endif /* __SED_TOOLS_CPIN_H__ */
