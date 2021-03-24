#ifndef __SED_TOOLS_MBRCONTROL_H__
#define __SED_TOOLS_MBRCONTROL_H__

#include "../sed/sed.h"
#include <inttypes.h>

int32_t mbrControl_enableAccessToDone(struct sedContext *sedCtx, SedAccounts who, uint8_t id);
int32_t mbrControl_enableAccessToDoneForAll(struct sedContext *sedCtx);

int32_t mbrControl_set(struct sedContext *sedCtx, int8_t enable, int8_t done);

#endif /* __SED_TOOLS_MBRCONTROL_H__ */
  
