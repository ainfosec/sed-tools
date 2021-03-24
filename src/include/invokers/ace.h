#ifndef __SED_TOOLS_ACE_H__
#define __SED_TOOLS_ACE_H__

#include <stdint.h>
#include "../sed/sed.h"

/**
    @brief Configure Locking range and enable read and write lock

    This function configures the range and enable read and write locking
    by changing the range and enabling readlocked or writedlocked

    @return 0 on success. 

    \code
    ace_locking_range_setRdWrLocked(fileDescriptor, 1000, 1, 1);
    \endcode

    @note   For a more detailed example and explanation, please refer to
            section 3.2.6.2 of the "TCG Storage Application Note: Encrypting
            Drives Compliant with Opal SSC".
*/
int32_t ace_giveAccess(SedAccounts who, uint8_t id, uint8_t *values);
int32_t ace_giveAccessToAll(uint8_t *values);


#endif /* __SED_TOOLS_ACE_H__ */
