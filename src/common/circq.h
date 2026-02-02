/* circq.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
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
