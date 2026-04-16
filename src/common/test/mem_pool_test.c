/*
 * mem_pool_test.c
 *
 * unit test for mem_pool.c
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

#include "../mem_pool.c"
#include "../../../unit_tests/unittest.h"

#ifdef _MSC_VER
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/

int mem_pool_test_trac341()
{
    MSTATUS           status          = OK;
    MSTATUS           negTest_status  = OK;
    void*             pMemory         = NULL;
    poolHeaderDescr*  pPool           = NULL;
    int               errcnt          = 0;
    ubyte4            testCase        = 0;
    ubyte             subTest         = 0;

    if (NULL == (pMemory = MALLOC(sizeof(poolLink) * 5)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for (subTest = 0; 1 >= subTest; subTest++)
    {
        for (testCase = 1; sizeof(void *) > testCase; testCase++)
        {
            if (0 == subTest)
            {
                negTest_status = MEM_POOL_createPool(&pPool, pMemory, sizeof(poolLink) * 5, (sizeof(poolLink) + testCase));
                errcnt += UNITTEST_TRUE(testCase, ERR_MEM_POOL_CREATE == negTest_status);
            }

            if (1 == subTest)
            {
                if (NULL == (pPool = MALLOC(sizeof(poolHeaderDescr))))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMSET((ubyte *)pPool, 0x00, sizeof(poolHeaderDescr));
                negTest_status = MEM_POOL_initPool(pPool, pMemory, sizeof(poolLink) * 5, (sizeof(poolLink) + testCase));
                errcnt += UNITTEST_TRUE(testCase, ERR_MEM_POOL_CREATE == negTest_status);
            }

            MEM_POOL_freePool(&pPool, NULL);
        }
    }

exit:
    FREE(pMemory);
    FREE(pPool);

    if (OK != status)
    {
        errcnt += UNITTEST_STATUS(0, status);
    }

    return errcnt;
}

