/*
 * SMUID.h
 *
 *  Created on: Oct 12, 2012
 *      Author: user
 */

#ifndef SMUID_H_
#define SMUID_H_

#include "../sed/sed.h"
#include <inttypes.h>

int32_t sessionManager_startSession(struct sedContext *sedCtx, uint8_t write,
                           uint32_t passwordSize, uint8_t *password);

int32_t sessionManager_properties(struct sedContext *sedCtx);

int32_t sessionManager_closeSession(struct sedContext *sedCtx);

#endif /* SMUID_H_ */
