#ifndef __SED_TOOLS_DATASTORE_H__
#define __SED_TOOLS_DATASTORE_H__

#include "../sed/sed.h"
#include <inttypes.h>

int32_t datastore_set(struct sedContext *sedCtx, uint32_t where, uint32_t size, uint8_t *values);

int32_t datastore_get(struct sedContext *sedCtx, uint32_t where, uint32_t size, uint8_t *retBuf);

int32_t datastore_enableAccess(struct sedContext *sedCtx, uint8_t write,
        SedAccounts who, uint8_t id);

#endif /* __SED_TOOLS_DATASTORE_H__ */
  
