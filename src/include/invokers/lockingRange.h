#ifndef __SED_TOOLS_LOCKING_RANGE_H__
#define __SED_TOOLS_LOCKING_RANGE_H__

#include <stdint.h>
#include "../sed/sed.h"

#define RANGE_ERROR_CHECK(error, msg, buffer) \
    { if (error & SED_ERROR) \
     { sed_errors_print(error); \
       free(buffer); \
       fprintf(stderr, "%s\n", msg); \
   	   exit(EXIT_FAILURE);}}

int32_t lockingRange_set(struct sedContext *sedCtx, lockingRange range);

int32_t lockingRange_erase(struct sedContext *sedCtx, uint32_t rangeNumber);

int32_t lockingRange_enableAccess(struct sedContext *sedCtx, uint32_t rangeNumber,
        uint8_t write, SedAccounts who, uint8_t id);
int32_t lockingRange_enableAccessForAll(struct sedContext *sedCtx, uint32_t rangeNumber, uint8_t write);

#endif /* __SED_TOOLS_LOCKING_RANGE_H__ */
