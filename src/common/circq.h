/*
 * circq.h
 *
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
 */
#ifndef __CIRCQ_H__
#define __CIRCQ_H__

typedef struct c_queue
{
    ubyte4 capacity;
    ubyte  **ppQueue;
    ubyte4 head;
    ubyte4 tail;
} c_queue_t;

MOC_EXTERN MSTATUS CIRCQ_init(c_queue_t **ppCq, ubyte4 capacity);
MOC_EXTERN MSTATUS CIRCQ_deInit(c_queue_t *pCq);
MOC_EXTERN MSTATUS CIRCQ_enq (c_queue_t *pCq, ubyte *pData);
MOC_EXTERN MSTATUS CIRCQ_deq (c_queue_t *pCq, ubyte **ppData);

#endif
