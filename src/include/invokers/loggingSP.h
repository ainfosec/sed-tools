#ifndef __SED_LOGGINGSP_H__
#define __SED_LOGGINGSP_H__

#include "../sed/sed.h"
#include <inttypes.h>

int32_t loggingSP_get(struct sedContext *sedCtx);

int32_t loggingSP_getLifeCycleState(struct sedContext *sedCtx, uint8_t *lifeCycleState);

int32_t loggingSP_activate(struct sedContext *sedCtx);

int32_t loggingSP_genericGetLCS(struct sedContext *sedCtx, uint64_t uid, uint8_t *lifeCycleState);

#endif /* __SED_LOGGINGSP_H__ */
