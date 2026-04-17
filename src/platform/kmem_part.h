/*************************************************************************
 * File:        kmem_part.h
 * Created:     Tue Nov 14 17:10:39 PST 2006
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 * Description:
 *************************************************************************/
#ifndef __KMEM_PART_H__
#define __KMEM_PART_H__

#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ubyte8 userAddress;
    ubyte8 kernAddress;
    ubyte8 physAddress;
} MemHandle_t;

typedef struct {
    ubyte2      numEntries;
    ubyte2      entSize;
    ubyte2      head;
    ubyte2      tail;
    MemHandle_t data;
} CircBuffer_t;

struct memPartDescr;

MOC_EXTERN MSTATUS  KMEM_PART_alloc(struct memPartDescr *pMemPart,
                                ubyte4 numBytesToAlloc, MemHandle_t *pMemHandle);
MOC_EXTERN MSTATUS  KMEM_PART_createPartition(struct memPartDescr
                                **ppRetMemPartition, ubyte4 memPartSize);
MOC_EXTERN MSTATUS  KMEM_PART_free(struct memPartDescr *pMemPart,
                                MemHandle_t *pMemHandle);
MOC_EXTERN CircBuffer_t  *queue_create(struct memPartDescr *pMemPart, ubyte4 nentries,
                                ubyte4 entsize);
MOC_EXTERN MSTATUS  queue_delete(struct memPartDescr *pMemPart, CircBuffer_t *aQueue);
MOC_EXTERN MSTATUS  queue_get_head(CircBuffer_t *aQueue, ubyte *content, int size);
MOC_EXTERN MSTATUS  queue_put_tail(CircBuffer_t *aQueue, ubyte *content, int size);

#ifdef __cplusplus
}
#endif

#endif                                  /* __KMEM_PART_H__ */

