#ifndef __SED_TOOLS_ADMINSP_H__
#define __SED_TOOLS_ADMINSP_H__

#include "../sed/sed.h"
#include <stdint.h>

/**
    @brief Revert the Tper

    This function will revert the Tper. This is similar to a format command in
    which the drive will have all factory settings restored on the drive, 
    meaning it will be unowned and no users or sessions will be associated
    with this.

    @return 0 on success. 

    \code
    adminsp_revert(fileDescriptor);
    \endcode

    @note   This will erase all the work you have done with the opal drive. 
            functions like takeOwnership and configure locking ranges will have
            to be carried out again because the drive will have no knowledge of
            it. For a more detailed example and explanation, please refer to
            section 3.2.11.2 of the "TCG Storage Application Note: Encrypting
            Drives Compliant with Opal SSC".
*/
int32_t adminSP_revert(struct sedContext *sedCtx);

#endif /* __SED_TOOLS_ADMINSP_H__ */
