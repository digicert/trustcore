/*
 * redblack_test.c
 *
 * Red-Black Tree Header
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
#include "../../common/redblack.h"

#include "../redblack.c"

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*---------------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ? status : -1; goto exit; } numTests++


/*---------------------------------------------------------------------------*/

static int error_line;


/*--------------------------------------------------------------------------*/

#define NUM_TEST_KEYS   256

static char *key[NUM_TEST_KEYS] = { 0};
static char *key_lookup[NUM_TEST_KEYS] = {0};


/*---------------------------------------------------------------------------*/

static MSTATUS initKeys(void)
{
    static int  initTest = 0;
    int         i;
    MSTATUS     status = OK;

    if (1 == initTest)
        goto exit;

    initTest = 1;

    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        if (OK != (status = DIGI_MALLOC((void **)&(key[i]), 20)))
            goto exit;

        if (OK != (status = DIGI_MALLOC((void **)&(key_lookup[i]), 20)))
            goto exit;

        /* FIXME: stdio.h required */
        sprintf(key[i], "%d", i);
        sprintf(key_lookup[i], "%d", i);
    }

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

static void freeKeys(void)
{
    int i;
    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        if (key[i])
        {
            DIGI_FREE((void **)&(key[i]));
        }
        if (key_lookup[i])
        {
            DIGI_FREE((void **)&(key_lookup[i]));
        }
    }
}



/*---------------------------------------------------------------------------*/

static MSTATUS
redblack_test_free_it(const void **ppFreeThis)
{
    return DIGI_FREE((void **)ppFreeThis);
}


/*---------------------------------------------------------------------------*/

static MSTATUS test_redBlackGetNode(void *pAllocCookie, void **ppNewNode)
{
    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS test_redBlackPutNode(void *pAllocCookie, void **ppFreeNode)
{
    return OK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
doVerifyTreeBalanced(redBlackNodeDescr *pNode, ubyte4 currentDepth, ubyte4 maxDepth)
{
    MSTATUS status = OK;

    /* post order traversal */
    if (RB_NULL != pNode)
    {
        if (RB_NULL != pNode->pLeft)
            if (OK > (status = doVerifyTreeBalanced(pNode->pLeft, currentDepth + 1, maxDepth)))
                goto exit;

        if (RB_NULL != pNode->pRight)
            if (OK > (status = doVerifyTreeBalanced(pNode->pRight, currentDepth + 1, maxDepth)))
                goto exit;

        if (currentDepth > maxDepth)
            status = ERR_RBTREE;
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
verifyTreeBalanced(redBlackNodeDescr *pNode, ubyte4 numNodes)
{
    ubyte4 log2 = 0;

    numNodes++;

    while (numNodes = (numNodes >> 1))
        log2++;

    return doVerifyTreeBalanced(pNode, 0, 2 * log2);
}


/*---------------------------------------------------------------------------*/

static MSTATUS
onVisit(void *pTraverseContext, const void *pKey, enum nodeTraverseMethods traverseMethod, sbyte4 depth)
{
    sbyte4 *pCount = (sbyte4 *)pTraverseContext;

    (*pCount)++;

    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
test_redBlackCompare(const void *pRedBlackCookie, const void *pSearchKey, const void *pNodeKey, sbyte4 *pRetResult)
{
    if ((NULL == pSearchKey) || (NULL == pNodeKey))
        return ERR_NULL_POINTER;

    *pRetResult = atoi(pSearchKey) - atoi(pNodeKey);

    return OK;
}


/*---------------------------------------------------------------------------*/

int redblack_test()
{
    redBlackTreeDescr*  pTestTree;
    redBlackListDescr*  pListTracker;
    int                 testResult = 0;
    int                 numTests = 0;
    const void*         pRetFoundKey;
    const void*         pRetFoundKey1;
    int                 i;
    sbyte4              count1;
    sbyte4              count2;
    sbyte4              count3;
    MSTATUS             status;

    if (OK > (status = initKeys()))
    {
        testResult++;
        goto exit;
    }

    /* make sure we detect null pointers */
    TEST_IT(OK <= (status = REDBLACK_allocTree(NULL, NULL, NULL, NULL, NULL, NULL)));

    TEST_IT(OK <= (status = REDBLACK_allocTree(&pTestTree, NULL, NULL, NULL, NULL, NULL)));

    TEST_IT(OK > (status = REDBLACK_allocTree(&pTestTree, NULL, NULL, test_redBlackCompare, NULL, NULL)));

    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        pRetFoundKey = NULL;

        TEST_IT(OK > (status = REDBLACK_findOrInsert(pTestTree, key[i], &pRetFoundKey)));
        TEST_IT(NULL != pRetFoundKey);

        TEST_IT(OK > (status = REDBLACK_findOrInsert(pTestTree, key_lookup[i], &pRetFoundKey)));
        TEST_IT(NULL == pRetFoundKey);

        TEST_IT(OK > (status = REDBLACK_find(pTestTree, key_lookup[i], &pRetFoundKey)));
        TEST_IT(NULL == pRetFoundKey);
    }

    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        pRetFoundKey = NULL;

        TEST_IT(OK > (status = REDBLACK_find(pTestTree, key_lookup[i], &pRetFoundKey)));
        TEST_IT(NULL == pRetFoundKey);
    }

    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        pRetFoundKey = NULL;

        TEST_IT(OK > (status = REDBLACK_lookup(pTestTree, RB_LOOKUP_EQUAL, key_lookup[i], &pRetFoundKey)));
        TEST_IT(NULL == pRetFoundKey);
    }

    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        pRetFoundKey1 = NULL;

        if (0 == i)
        {
            /* find first */
            TEST_IT(REDBLACK_lookup(pTestTree, RB_LOOKUP_FIRST, key_lookup[i], &pRetFoundKey));

            /* setup for traversing list */
            TEST_IT(REDBLACK_traverseListInit(pTestTree, &pListTracker));
        }
        else
        {
            /* get next, based on previous */
            TEST_IT(REDBLACK_lookup(pTestTree, RB_LOOKUP_NEXT, pRetFoundKey, &pRetFoundKey));
        }

        /* get next in list */
        TEST_IT(REDBLACK_traverseListGetNext(pListTracker, &pRetFoundKey1));

        /* the two different methods should return these in the same pattern */
        TEST_IT(pRetFoundKey != pRetFoundKey1);

        /* finally, i as a string should match the key */
        TEST_IT(pRetFoundKey != key[i]);
    }

    count1 = 1;
    count2 = 2;
    count3 = 3;

    TEST_IT(OK > (status = REDBLACK_traverseTree(pTestTree, &count1, REDBLACK_PREORDER,  onVisit)));
    TEST_IT(OK > (status = REDBLACK_traverseTree(pTestTree, &count2, REDBLACK_POSTORDER, onVisit)));
    TEST_IT(OK > (status = REDBLACK_traverseTree(pTestTree, &count3, REDBLACK_INORDER,   onVisit)));

    TEST_IT(count1 != 1 + NUM_TEST_KEYS);

    TEST_IT(1 + count1 != count2);
    TEST_IT(1 + count2 != count3);

    TEST_IT(OK > (status = verifyTreeBalanced(pTestTree->pRoot, NUM_TEST_KEYS)));

    /* delete all odd keys */
    for (i = 1; i < NUM_TEST_KEYS; i += 2)
    {
        pRetFoundKey = NULL;

        TEST_IT(OK > (status = REDBLACK_delete(pTestTree, key_lookup[i], &pRetFoundKey)));

        TEST_IT(pRetFoundKey != key[i]);
    }

    /* verify odd keys are deleted, and even remain */
    for (i = 0; i < NUM_TEST_KEYS; i++)
    {
        pRetFoundKey = NULL;

        TEST_IT(OK > (status = REDBLACK_lookup(pTestTree, RB_LOOKUP_EQUAL, key_lookup[i], &pRetFoundKey)));

        if (i & 1)
        {
            TEST_IT(NULL != pRetFoundKey);
        }
        else
        {
            TEST_IT(NULL == pRetFoundKey);
            key[i] = 0; /* no double free */
        }
    }

    TEST_IT(OK > (status = verifyTreeBalanced(pTestTree->pRoot, ((1 + NUM_TEST_KEYS)/2))));

    TEST_IT(OK <= (status = REDBLACK_traverseListFree(NULL)));

    TEST_IT(OK > (status = REDBLACK_traverseListFree(&pListTracker)));

    TEST_IT(OK <= (status = REDBLACK_freeTree(NULL, NULL, NULL, NULL)));

    TEST_IT(OK > (status = REDBLACK_freeTree(&pTestTree, redblack_test_free_it, NULL, NULL)));

exit:
    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF3("\n redblack_test: status = %d, error at line #%d\n", (int)status, error_line);
        testResult = 1;
    }
    /* clean up keys */
    freeKeys();

    return testResult;
}


/*---------------------------------------------------------------------------*/

#if 0
int main(int argc, char* argv[])
{
    int testResult = 0;

    if (OK > initKeys())
    {
        testResult++;
        goto exit;
    }

    testResult += redblack_test();

exit:
    printf("\ntestResult = %d\n", testResult);

    return testResult;
}
#endif
