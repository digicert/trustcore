/*
 * stack.c
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


#include "../common/moptions.h"

#include "../common/mtypes.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include "../common/stack.h"


/*-------------------------------------------------------------------------*/

extern MSTATUS
stack_init(stack *S, ubyte4 dataSize, ubyte4 initCapacity)
{
    if (!S)
        return ERR_NULL_POINTER;
    S->stackIndex = 0;
    S->dataSize = dataSize;
    S->capacity = initCapacity;
    S->data = (void**) MALLOC(dataSize*initCapacity);
    if (!S->data)
        return ERR_MEM_ALLOC_FAIL;
    return OK;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
stack_uninit(stack *S, void (*freeData)(void *data) )
{
    if (!S)
        goto exit;
    while (!stack_isEmpty(S))
    {
        void *data = NULL;
        stack_pop(S, &data);
        if (freeData)
        {
            freeData(data);
        }
    }
    FREE(S->data);
exit:
    return OK;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
stack_peek(stack *S, void** data)
{
    MSTATUS status = OK;

    if (!S)
    {
        status = ERR_INVALID_ARG;
	goto exit;
    }

    status = stack_peek_at(S, S->stackIndex-1, data);

exit:
    return status;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS
stack_peek_at(stack *S, ubyte4 index, void** data)
{
    MSTATUS status = OK;

    if (!S)
    {
        status = ERR_INVALID_ARG;
	goto exit;
    }

    if (!data)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *data = NULL;  /* clear data, just in case there is another error */

    if (S->stackIndex == 0)
    {
        status = ERR_STACK_UNDERFLOW;
        goto exit;
    }

    if (index >= S->stackIndex)
    {
        status = ERR_STACK_OVERFLOW;
	goto exit;
    }

    *data = S->data[index];

exit:
    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
stack_push(stack *S, void* data)
{
    MSTATUS status = OK;

    if (S->stackIndex >= S->capacity)
    {
        /* grow stack capacity */
        void **newData;
        newData = (void**) MALLOC(S->dataSize*(S->capacity*2));
        if (NULL == newData)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        S->capacity = S->capacity*2;
        DIGI_MEMCPY(newData, S->data, S->dataSize*S->stackIndex);
        FREE(S->data);
        S->data = newData;
    }
    S->data[S->stackIndex++] = data;
exit:
    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
stack_pop(stack *S, void **data)
{
    MSTATUS status = OK;

    if (S->stackIndex == 0)
        status = ERR_STACK_UNDERFLOW;
    else
    {
        *data = S->data[S->stackIndex-1];
        S->stackIndex--;
    }

    return status;
}


/*-------------------------------------------------------------------------*/

extern intBoolean
stack_isEmpty(stack *S)
{
    if (!S)
        return TRUE;

    return 0 == S->stackIndex;
}

/*-------------------------------------------------------------------------*/

extern sbyte4
stack_size(stack* S)
{
    /* XXX: This will have a problem if stackIndex >= 2^31 */
    return (NULL != S ? (sbyte4) S->stackIndex : -1);
}

/*-------------------------------------------------------------------------*/

extern void*
stack_data_at(stack *S, ubyte4 index)
{
    void* data = NULL;
    stack_peek_at(S, index, &data);
    return data;
}

/*-------------------------------------------------------------------------*/
extern stack*
stack_alloc(void)
{
    stack *S = (stack*) MALLOC(sizeof(stack));
    if (S)
    {
        if (OK != stack_init(S, sizeof(void*), 32))
	{
	    FREE(S);
	    S = NULL;
	}
    }
    return S;
}

/*-------------------------------------------------------------------------*/
extern void
stack_free(stack* S, void (*freeData)(void *data))
{
    if (S)
    {
        stack_uninit(S, freeData);
	FREE(S);
    }
}
