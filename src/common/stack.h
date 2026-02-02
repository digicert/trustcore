/*
 * stack.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
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
