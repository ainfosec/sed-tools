#include "../include/sed/sed.h"

#include <stdio.h>

int32_t adminSP_revert(struct sedContext *sedCtx)
{
    return sed_genericSendEmptyPayload(sedCtx, UID_SP_ADMIN, UID_METHOD_REVERTTPER);
}
