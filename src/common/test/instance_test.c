/*
 * instance_test.c
 *
 * (Session/Context) Instance Factory Test
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/instance.h"


#if 0
#include <stdio.h>
#define INSTANCE_TEST_PRINT(X)      printf X
#else
#define INSTANCE_TEST_PRINT(X)
#endif

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
extern void dbg_dump(void);
#endif


/*---------------------------------------------------------------------------*/

int instance_context_test(void)
{
    instanceTableDescr* pTable = NULL;
    int                 numTestFail = 0;
    ubyte4              theCookie = 0x4567acde;
    void*               pCookie;
    void*               pExpectedCookie;
    ubyte               ascii[] = "abcdefghijklmnopqrstuvwxyz";
    ubyte4              instances[sizeof(ascii)];
    ubyte4              instance;
    ubyte4              i, j, tracker;
    void*               pContext;
    MSTATUS             status;

    pExpectedCookie = &theCookie;

    if (OK > (status = INSTANCE_createTable(&pTable, pExpectedCookie, sizeof(ascii) - 1)))
    {
        INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_createTable() failed, status = %d\n", status));
        numTestFail++;
        goto exit;
    }

    for (j = 0; j < 100; j++)
    {
        for (i = 0; i < sizeof(ascii) - 1; i++)
        {
            if (OK > (status = INSTANCE_getInstanceSetContext(pTable, &instances[i], &ascii[i])))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getInstanceSetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            INSTANCE_TEST_PRINT(("instance_context_test: add new [%d] instance [%08x]: %s\n", i, instances[i], &(ascii[i])));
        }

        /* negative test -- see one more request can be pulled off */
        if (OK <= (status = INSTANCE_getInstanceSetContext(pTable, &instance, ascii)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getInstanceSetContext() able to remove one more than possible, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        /* output some results */
        if (OK > (status = INSTANCE_traverseListInit(pTable, &tracker)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_traverseListInit() failed, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        i = 0;

        do
        {
            i++;

            if (OK > (status = INSTANCE_traverseContextListGetNext(pTable, &tracker, &instance, &pContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_traverseContextListGetNext() failed, status = %d\n", status));
                numTestFail++;
                goto exit;
            }

            if (pContext)
                INSTANCE_TEST_PRINT(("instance_context_test: traverse test [%d]: [%08x], %s\n", i, instance, pContext));
        }
        while (NULL != pContext);

        /* negative test --- purposely walk beyond end of list */
        if (OK <= (status = INSTANCE_traverseContextListGetNext(pTable, &tracker, &instance, &pContext)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_traverseContextListGetNext() failed negative test, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        for (i = ((sizeof(ascii) - 2) & 0xfffffffe); i >= 2; i -= 2)
        {
            void*   pTempContext;

            if (OK > (status = INSTANCE_getContextFromInstance(pTable, instances[i], &pTempContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getContextFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (OK > (status = INSTANCE_putInstanceGetContext(pTable, instances[i], &pContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (pTempContext != pContext)
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext(%08x) and INSTANCE_putInstanceGetContext(%08x) disagree\n", (int)pTempContext, (int)pContext));
                numTestFail++;
                goto exit;
            }

            /* negative test --- try to get instance already put */
            if (OK <= (status = INSTANCE_getContextFromInstance(pTable, instances[i], &pTempContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getContextFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }
        }

        /* do first half to slowly scramble things up... */
        for (i = ((3 + (j % 7)) | 1); i < sizeof(ascii) - 1; i += 2)
        {
            void*   pTempContext;

            if (OK > (status = INSTANCE_getContextFromInstance(pTable, instances[i], &pTempContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getContextFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (OK > (status = INSTANCE_putInstanceGetContext(pTable, instances[i], &pContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (pTempContext != pContext)
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext(%08x) and INSTANCE_putInstanceGetContext(%08x) disagree\n", (int)pTempContext, (int)pContext));
                numTestFail++;
                goto exit;
            }

            /* negative test --- try to get instance already put */
            if (OK <= (status = INSTANCE_getContextFromInstance(pTable, instances[i], &pTempContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getContextFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }
        }

        /* do first half to slowly scramble things up... */
        for (i = 3; i < ((3 + (j % 7)) | 1); i += 2)
        {
            void*   pTempContext;

            if (OK > (status = INSTANCE_getContextFromInstance(pTable, instances[i], &pTempContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getContextFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (OK > (status = INSTANCE_putInstanceGetContext(pTable, instances[i], &pContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (pTempContext != pContext)
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext(%08x) and INSTANCE_putInstanceGetContext(%08x) disagree\n", (int)pTempContext, (int)pContext));
                numTestFail++;
                goto exit;
            }

            /* negative test --- try to get instance already put */
            if (OK <= (status = INSTANCE_getContextFromInstance(pTable, instances[i], &pTempContext)))
            {
                INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_getContextFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }
        }

        /* hopefully this will scramble the list sufficiently */
        if (OK > (status = INSTANCE_putInstanceGetContext(pTable, instances[1], &pContext)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
            numTestFail++;
            goto exit;
        }

        /* hopefully this will scramble the list sufficiently */
        if (OK > (status = INSTANCE_putInstanceGetContext(pTable, instances[0], &pContext)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_putInstanceGetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
            numTestFail++;
            goto exit;
        }

        /* try to traverse empty list --- negative test */
        if (OK > (status = INSTANCE_traverseListInit(pTable, &tracker)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_traverseListInit() failed, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        if (OK > (status = INSTANCE_traverseContextListGetNext(pTable, &tracker, &instance, &pContext)))
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_traverseContextListGetNext() failed, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        if (NULL != pContext)
        {
            INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_traverseContextListGetNext() should be null, pContext = %08x\n", (int)pContext));
            numTestFail++;
            goto exit;
        }

    } /* end of for(j) loop */

    /* clean up... */
    if (OK > (status = INSTANCE_releaseTable(&pTable, &pCookie)))
    {
        INSTANCE_TEST_PRINT(("instance_context_test: INSTANCE_releaseTable() failed, status = %d\n", status));
        numTestFail++;
        goto exit;
    }

    if (pExpectedCookie != pCookie)
    {
        INSTANCE_TEST_PRINT(("instance_context_test: unexpected cookie from INSTANCE_releaseTable(), pCookie = %08x, pExpectedCookie = %08x\n", (int)pCookie, (int)pExpectedCookie));
        numTestFail++;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif

exit:
    return numTestFail;

} /* instance_context_test */


/*---------------------------------------------------------------------------*/

int instance_index_test(void)
{
    instanceTableDescr* pTable = NULL;
    int                 numTestFail = 0;
    ubyte4              theCookie = 0x4567acde;
    void*               pCookie;
    void*               pExpectedCookie;
    ubyte               ascii[] = "abcdefghijklmnopqrstuvwxyz";
    ubyte4              instances[sizeof(ascii)];
    ubyte4              instance;
    ubyte4              i, j, tracker;
    ubyte4              index;
    MSTATUS             status;

    pExpectedCookie = &theCookie;

    if (OK > (status = INSTANCE_createTable(&pTable, pExpectedCookie, sizeof(ascii) - 1)))
    {
        INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_createTable() failed, status = %d\n", status));
        numTestFail++;
        goto exit;
    }

    for (j = 0; j < 100; j++)
    {
        for (i = 0; i < sizeof(ascii) - 1; i++)
        {
            if (OK > (status = INSTANCE_getInstanceSetContext(pTable, &instances[i], &ascii[i])))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getInstanceSetContext() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            INSTANCE_TEST_PRINT(("instance_index_test: add new [%d] instance [%08x]: %s\n", i, instances[i], &(ascii[i])));
        }

        /* negative test -- see one more request can be pulled off */
        if (OK <= (status = INSTANCE_getInstanceSetContext(pTable, &instance, ascii)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getInstanceSetContext() able to remove one more than possible, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        /* output some results */
        if (OK > (status = INSTANCE_traverseListInit(pTable, &tracker)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_traverseListInit() failed, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        i = 0;

        do
        {
            i++;

            if (OK > (status = INSTANCE_traverseIndexListGetNext(pTable, &tracker, &instance, &index)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_traverseIndexListGetNext() failed, status = %d\n", status));
                numTestFail++;
                goto exit;
            }

            if (INSTANCE_BAD_VALUE != index)
                INSTANCE_TEST_PRINT(("instance_index_test: traverse test [%d]: [%08x], %s\n", i, instance, index));
        }
        while (INSTANCE_BAD_VALUE != index);

        /* negative test --- purposely walk beyond end of list */
        if (OK <= (status = INSTANCE_traverseIndexListGetNext(pTable, &tracker, &instance, &index)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_traverseIndexListGetNext() failed negative test, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        for (i = ((sizeof(ascii) - 2) & 0xfffffffe); i >= 2; i -= 2)
        {
            ubyte4  tempIndex;

            if (OK > (status = INSTANCE_getIndexFromInstance(pTable, instances[i], &tempIndex)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getIndexFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (OK > (status = INSTANCE_putInstanceGetIndex(pTable, instances[i], &index)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (tempIndex != index)
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex(%08x) and INSTANCE_putInstanceGetContext(%08x) disagree\n", (int)tempIndex, (int)index));
                numTestFail++;
                goto exit;
            }

            /* negative test --- try to get instance already put */
            if (OK <= (status = INSTANCE_getIndexFromInstance(pTable, instances[i], &tempIndex)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getIndexFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }
        }

        /* do first half to slowly scramble things up... */
        for (i = ((3 + (j % 7)) | 1); i < sizeof(ascii) - 1; i += 2)
        {
            ubyte4  tempIndex;

            if (OK > (status = INSTANCE_getIndexFromInstance(pTable, instances[i], &tempIndex)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getIndexFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (OK > (status = INSTANCE_putInstanceGetIndex(pTable, instances[i], &index)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (tempIndex != index)
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex(%08x) and INSTANCE_putInstanceGetContext(%08x) disagree\n", (int)tempIndex, (int)index));
                numTestFail++;
                goto exit;
            }

            /* negative test --- try to get instance already put */
            if (OK <= (status = INSTANCE_getIndexFromInstance(pTable, instances[i], &tempIndex)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getIndexFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }
        }

        /* do first half to slowly scramble things up... */
        for (i = 3; i < ((3 + (j % 7)) | 1); i += 2)
        {
            ubyte4  tempIndex;

            if (OK > (status = INSTANCE_getIndexFromInstance(pTable, instances[i], &tempIndex)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getIndexFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (OK > (status = INSTANCE_putInstanceGetIndex(pTable, instances[i], &index)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }

            if (tempIndex != index)
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex(%08x) and INSTANCE_putInstanceGetContext(%08x) disagree\n", (int)tempIndex, (int)index));
                numTestFail++;
                goto exit;
            }

            /* negative test --- try to get instance already put */
            if (OK <= (status = INSTANCE_getIndexFromInstance(pTable, instances[i], &index)))
            {
                INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_getIndexFromInstance() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
                numTestFail++;
                goto exit;
            }
        }

        /* hopefully this will scramble the list sufficiently */
        if (OK > (status = INSTANCE_putInstanceGetIndex(pTable, instances[1], &index)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
            numTestFail++;
            goto exit;
        }

        /* hopefully this will scramble the list sufficiently */
        if (OK > (status = INSTANCE_putInstanceGetIndex(pTable, instances[0], &index)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_putInstanceGetIndex() failed, status = %d, ascii[i] = %c\n", status, ascii[i]));
            numTestFail++;
            goto exit;
        }

        /* try to traverse empty list --- negative test */
        if (OK > (status = INSTANCE_traverseListInit(pTable, &tracker)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_traverseListInit() failed, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        if (OK > (status = INSTANCE_traverseIndexListGetNext(pTable, &tracker, &instance, &index)))
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_traverseIndexListGetNext() failed, status = %d\n", status));
            numTestFail++;
            goto exit;
        }

        if (INSTANCE_BAD_VALUE != index)
        {
            INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_traverseIndexListGetNext() should be null, index = %08x\n", (int)index));
            numTestFail++;
            goto exit;
        }

    } /* end of for(j) loop */

    /* clean up... */
    if (OK > (status = INSTANCE_releaseTable(&pTable, &pCookie)))
    {
        INSTANCE_TEST_PRINT(("instance_index_test: INSTANCE_releaseTable() failed, status = %d\n", status));
        numTestFail++;
        goto exit;
    }

    if (pExpectedCookie != pCookie)
    {
        INSTANCE_TEST_PRINT(("instance_index_test: unexpected cookie from INSTANCE_releaseTable(), pCookie = %08x, pExpectedCookie = %08x\n", (int)pCookie, (int)pExpectedCookie));
        numTestFail++;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
    dbg_dump();
#endif

exit:
    return numTestFail;

} /* instance_index_test */


/*---------------------------------------------------------------------------*/

#if 0
main()
{
    instance_context_test();
    instance_index_test();
}
#endif

