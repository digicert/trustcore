/*
 * stack.h
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

#ifndef __STACK_HEADER__
#define __STACK_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stack {
    ubyte4     capacity;
    ubyte4     dataSize;
    void**     data;
    ubyte4     stackIndex;
} stack;

MOC_EXTERN MSTATUS stack_init(stack *S, ubyte4 dataSize, ubyte4 initCapacity);
MOC_EXTERN MSTATUS stack_uninit(stack *S, void (*freeData)(void *data) );
MOC_EXTERN MSTATUS stack_peek(stack *S, void** data);
MOC_EXTERN MSTATUS stack_peek_at(stack *S, ubyte4 index, void** data);
MOC_EXTERN MSTATUS stack_push(stack *S, void* data);
MOC_EXTERN MSTATUS stack_pop(stack *S, void** data);
MOC_EXTERN intBoolean stack_isEmpty(stack *S);
MOC_EXTERN sbyte4 stack_size(stack* S);
MOC_EXTERN void* stack_data_at(stack *S, ubyte4 index);
MOC_EXTERN stack* stack_alloc(void);
MOC_EXTERN void stack_free(stack*, void (*freeData)(void *data));

#ifdef __cplusplus
}
#endif

#endif
