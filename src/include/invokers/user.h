#ifndef __SED_USER_H__
#define __SED_USER_H__

#include "../sed/sed.h"
#include <inttypes.h>

int32_t user_set(struct sedContext *sedCtx, SedAccounts who, uint8_t id, uint8_t enable);

#endif /* __SED_USER_H__ */
  
