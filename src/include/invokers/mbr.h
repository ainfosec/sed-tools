#ifndef __SED_TOOLS_MBR_H__
#define __SED_TOOLS_MBR_H__

#include "../sed/sed.h"
#include <inttypes.h>

int32_t mbr_set(struct sedContext *sedCtx, char *filePath,void (*cbUpdateProgress)(uint64_t,uint64_t));

#endif /* __SED_TOOLS_MBR_H__ */
  
