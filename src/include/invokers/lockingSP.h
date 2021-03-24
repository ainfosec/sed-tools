#ifndef __SED_LOCKINGSP_H__
#define __SED_LOCKINGSP_H__

#include "../sed/sed.h"
#include <inttypes.h>

/**
    @brief Gets the life cycle state of the Locking SP

    This function checks the life cycle state of the Locking SP to determing
    if it is in the Manufactured state or any other state to ensure that we 
    are able to invoke the activate method

    @return 0 on success. 

    \code
    lockingSP_getLifeCycle(fileDescriptor);
    \endcode

    @note   For a more detailed example and explanation, please refer to
            section 3.2.4.2 of the "TCG Storage Application Note: Encrypting
            Drives Compliant with Opal SSC".
*/
int32_t lockingSP_getLifeCycleState(struct sedContext *sedCtx, uint8_t *lifeCycleState);

/**
    @brief Activate the locking SP

    This function activates the locking SP by using the Activate method on
    Locking SP object in the Admin SP

    @return 0 on success. 

    \code
    lockingSP_activate(fileDescriptor);
    \endcode

    @note   For a more detailed example and explanation, please refer to
            section 3.2.4.3 of the "TCG Storage Application Note: Encrypting
            Drives Compliant with Opal SSC".
*/
int32_t lockingSP_activate(struct sedContext *sedCtx);



#endif /* __SED_LOCKINGSP_H__ */
