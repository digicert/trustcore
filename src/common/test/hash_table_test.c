/*
 * hash_table_test.c
 *
 * unit test for hash_table.c
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

/* IMPORTANT NOTE: To use this test with dpdk make sure to enable (2048kb) memory for Hugepages via the command...

echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

ALSO make sure to build and run as root or with sudo. Also any future clean will need to be run with sudo.
*/

#include "../../common/moptions.h"

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/hash_table.h"
#include "../../common/hash_value.h"

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
#include "../../common/hash_table_external.h"
#include "rte_eal.h"
#endif

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__)
#include <stdio.h>
#define PRINTF2      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF2(X,Y)
#endif

/* INIT_HASH_VALUE is a seed value to throw off attackers */
#define INIT_HASH_VALUE   (0xab341c12)

/*---------------------------------------------------------------------------*/

static MSTATUS
allocHashPtrElement(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement)
{
    MSTATUS status = OK;

    if (NULL == (*ppRetNewHashElement = MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
freeHashPtrElement(void *pHashCookie, hashTablePtrElement *pFreeHashElement)
{
    if (NULL == pFreeHashElement)
        return ERR_NULL_POINTER;

    FREE(pFreeHashElement);

    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
HASH_TABLE_TEST_insert(hashTableOfPtrs* pHashTable, void *pKey, ubyte4 keyLen, void *pAppData)
{
    MSTATUS status;

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    status = HASH_TABLE_EXT_addPtr(pHashTable, pKey, pAppData);
#else
    ubyte4 hashValue;
    
    HASH_VALUE_hashGen(pKey, keyLen, INIT_HASH_VALUE, &hashValue);

    status = HASH_TABLE_addPtr(pHashTable, hashValue, pAppData);
#endif

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
HASH_TABLE_TEST_remove(hashTableOfPtrs* pHashTable, void *pKey, ubyte4 keyLen, void **ppRetAppDataToDelete)
{
    intBoolean  foundHashValue;
    MSTATUS     status;

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    if (OK > (status = HASH_TABLE_EXT_deletePtr(pHashTable, pKey, NULL, NULL, ppRetAppDataToDelete, &foundHashValue)))
        goto exit;
#else
    ubyte4 hashValue;

    HASH_VALUE_hashGen(pKey, keyLen, INIT_HASH_VALUE, &hashValue);

    if (OK > (status = HASH_TABLE_deletePtr(pHashTable, hashValue, NULL, NULL, ppRetAppDataToDelete, &foundHashValue)))
        goto exit;
#endif
    if (FALSE == foundHashValue)
        status = (0 - __LINE__);

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
extraMatchTest(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
HASH_TABLE_TEST_search(hashTableOfPtrs* pHashTable, void *pKey, ubyte4 keyLen, void **ppRetAppData)
{
    intBoolean  foundHashValue;
    MSTATUS     status;

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    if (OK > (status = HASH_TABLE_EXT_findPtr(pHashTable, pKey, NULL, NULL, ppRetAppData, &foundHashValue)))
        goto exit;
#else
    ubyte4 hashValue;

    HASH_VALUE_hashGen(pKey, keyLen, INIT_HASH_VALUE, &hashValue);

    if (OK > (status = HASH_TABLE_findPtr(pHashTable, hashValue, NULL, NULL, ppRetAppData, &foundHashValue)))
        goto exit;
#endif

    if (FALSE == foundHashValue)
        status = (0 - __LINE__);

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) goto exit; numTests++


/*---------------------------------------------------------------------------*/

int hash_table_test_all()
{
    hashTableOfPtrs*    pHashTable = NULL;
    sbyte4              result;
    void*               value;
    void*               pHashCookie = NULL;
    void*               pRetHashCookie = NULL;
    MSTATUS             numTests = 0;
    MSTATUS             status = 0;
#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    char *pArgV[5] = {"name", "-c" , "f", "-n", "4"};
#endif

    if (NULL == (pHashCookie = MALLOC(10)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* create an initial hash table */
#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    TEST_IT(OK > (status = (MSTATUS) rte_eal_init(5, pArgV)));

    TEST_IT(OK > (status = HASH_TABLE_EXT_createPtrsTable(&pHashTable, 0x7f, pHashCookie, 4, INIT_HASH_VALUE)));
#else
    TEST_IT(OK > (status = HASH_TABLE_createPtrsTable(&pHashTable, 0x7f, pHashCookie, allocHashPtrElement, freeHashPtrElement)));
#endif
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key1", 4, "value1")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key2", 4, "value2")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key3", 4, "value3")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key4", 4, "value4")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key2", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value2", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key3", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value3", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key1", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value1", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key2", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value2", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key5", 4, "value5")));

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key5", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value5", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    /* attempt to delete key5 */
    TEST_IT(OK > (status = HASH_TABLE_TEST_remove(pHashTable, "key5", 4, &value)));

    /* verify we deleted the right one */
    TEST_IT(OK > (status = DIGI_MEMCMP("value5", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    /* check if newly removed entry still exists in table */
    status = (0 - __LINE__);
    TEST_IT(OK <= HASH_TABLE_TEST_search(pHashTable, "key5", 4, &value));

    /* re-add key5 to hash table */
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key5", 4, "value5")));

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key5", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value5", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    TEST_IT(OK > (status = HASH_TABLE_EXT_removePtrsTable(pHashTable, &pRetHashCookie)));
#else
    TEST_IT(OK > (status = HASH_TABLE_removePtrsTable(pHashTable, &pRetHashCookie)));
#endif

    pHashTable = NULL;

    status = (0 - __LINE__);
    TEST_IT(pRetHashCookie != pHashCookie);
    FREE(pRetHashCookie);

    if (NULL == (pHashCookie = MALLOC(10)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* create an initial hash table */
#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    /* dpdk has min hash table size of 8 elements, use 0x07 mask */
    TEST_IT(OK > (status = HASH_TABLE_EXT_createPtrsTable(&pHashTable, 0x07, pHashCookie, 4, INIT_HASH_VALUE)));
#else
    TEST_IT(OK > (status = HASH_TABLE_createPtrsTable(&pHashTable, 0x03, pHashCookie, allocHashPtrElement, freeHashPtrElement)));
#endif
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key1", 4, "value1")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key2", 4, "value2")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key3", 4, "value3")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key4", 4, "value4")));
    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key2", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value2", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key3", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value3", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key1", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value1", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key2", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value2", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key5", 4, "value5")));

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key5", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value5", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    /* attempt to delete key5 */
    TEST_IT(OK > (status = HASH_TABLE_TEST_remove(pHashTable, "key5", 4, &value)));

    /* verify we deleted the right one */
    TEST_IT(OK > (status = DIGI_MEMCMP("value5", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

    /* check if newly removed entry still exists in table */
    status = (0 - __LINE__);
    TEST_IT(OK <= HASH_TABLE_TEST_search(pHashTable, "key5", 4, &value));

    /* re-add key5 to hash table */
    TEST_IT(OK > (status = HASH_TABLE_TEST_insert(pHashTable, "key5", 4, "value5")));

    TEST_IT(OK > (status = HASH_TABLE_TEST_search(pHashTable, "key5", 4, &value)));
    TEST_IT(OK > (status = DIGI_MEMCMP("value5", value, 6, &result)));

    status = (0 - __LINE__);
    TEST_IT(0 != result);

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    TEST_IT(OK > (status = HASH_TABLE_EXT_removePtrsTable(pHashTable, &pRetHashCookie)));
#else
    TEST_IT(OK > (status = HASH_TABLE_removePtrsTable(pHashTable, &pRetHashCookie)));
#endif

    status = (0 - __LINE__);
    TEST_IT(pRetHashCookie != pHashCookie);
    FREE(pRetHashCookie);

    status = OK;

exit:

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__
    (void) rte_eal_cleanup();
#endif

    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF2("hash_table_test_all: status = %d\n", (int)status);
        status = 1;
    }

    return status;
}


//int main(int argc, char* argv[])
//{
//    return hash_table_test_all();
//}
