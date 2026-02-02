/*
 *  mocencode_test.c
 *
 *  unit test for mocencode.c
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
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../../unit_tests/unittest.h"

#include <stdio.h>

/* Source code under test */
#include "../../asn1/mocencode.c"

/* OID: 1.2.840.113549.1.7.1 */
static ubyte CMS_OUTER_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static ubyte4 CMS_OUTER_DATA_LEN = 11;


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_simpleInteger()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);

    /* Test sequence with a single integer entry */
    MAsn1TypeAndCount def[2] =
    {
      { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_INTEGER, 0 }
    };

    sbyte4 cmpRes;
    ubyte4 val = 4711;
    ubyte4 usedLen;

    /* Expected result */
    ubyte checkVal[] =
    { 48, 4, 2, 2, 18, 103 };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Encode into memory array */
    status = MAsn1Encode (pRoot, encoded, encodedSize, &usedLen);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Expected value size */
    retval += UNITTEST_INT (100, usedLen, sizeof(checkVal));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (checkVal, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (101, cmpRes, 0);

    /* Done */
exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_simpleIntegerAlloc()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte  *pEncoded = NULL;
    ubyte4 encodedSize;

    /* Test sequence with a single integer entry */
    MAsn1TypeAndCount def[2] =
    {
      { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_INTEGER, 0 }
    };

    sbyte4 cmpRes;
    ubyte4 val = 4711;

    /* Expected result */
    ubyte checkVal[] =
    { 48, 4, 2, 2, 18, 103 };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Encode into memory array */
    status = MAsn1EncodeAlloc (pRoot, &pEncoded, &encodedSize);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Make sure its valid */
    retval = UNITTEST_VALIDPTR (11, pEncoded);
    if (0 < retval)
        goto exit;

    /* Expected value size */
    retval += UNITTEST_INT (100, encodedSize, sizeof(checkVal));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (checkVal, pEncoded, encodedSize, &cmpRes);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (101, cmpRes, 0);

    /* Done */
exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    DIGI_FREE ((void**)&pEncoded);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateInteger()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    /* Test sequence with a single integer entry */
    MAsn1TypeAndCount def[2] =
    {
      { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_INTEGER, 0 }
    };

    sbyte4 cmpRes;
    ubyte4 val = 4711;

    /* Expected result */
    ubyte checkVal[] =
    { 48, 4, 2, 2, 18, 103 };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Encode into memory array */
    status = MAsn1EncodeUpdate (pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(20, complete);
    if (0 < retval)
        goto exit;

    /* Expected value size */
    retval += UNITTEST_INT (100, usedLen, sizeof(checkVal));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (checkVal, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (101, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}

/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateIntegerIndef()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    /* Test sequence with a single integer entry */
    MAsn1TypeAndCount def[2] =
    {
      { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_INTEGER, 0 }
    };

    sbyte4 cmpRes;
    ubyte4 val = 4711;

    /* Expected result */
    ubyte checkVal[] =
    { 48, 4, 2, 2, 18, 103 };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Encode into memory array */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(20, complete);
    if (0 < retval)
        goto exit;

    /* Expected value size */
    retval += UNITTEST_INT (100, usedLen, sizeof(checkVal));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (checkVal, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (101, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_simpleOID()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);

    /* Test sequence with a single OID entry */
    MAsn1TypeAndCount def[2] =
    {
      { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_OID, 0 }
    };

    sbyte4 cmpRes;
    ubyte4 usedLen;

    /* Expected result */
    ubyte checkVal[] =
    { 0x30, 0x0B,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the OID entry at '1' */
    status = MAsn1SetValue (pRoot + 1, CMS_OUTER_DATA + 2, CMS_OUTER_DATA_LEN - 2);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Encode into memory array */
    status = MAsn1Encode (pRoot, encoded, encodedSize, &usedLen);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Expected value size */
    retval += UNITTEST_INT (100, usedLen, sizeof(checkVal));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (checkVal, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (101, cmpRes, 0);

    /* Done */
exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateSingleEncodedIndef()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[5] =
    {
      {  MASN1_TYPE_SEQUENCE, 2},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_SEQUENCE, 2},
           /* OID */
          {  MASN1_TYPE_ENCODED, 0},
           /* DATA */
          {  MASN1_TYPE_OCTET_STRING, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* input OID data */
    ubyte OID_enc[] =
    { 0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };

    /* Input stream */
    ubyte testInput[] = { 'O', 'n', 'c', 'e', '.' };

    /* Expected output */
    ubyte expect[] = {
            0x30, 0x18,
                  0x02, 0x01, 3,
                  0x30, 0x13,
                        0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19,
                        0x04, 0x05, 'O', 'n', 'c', 'e', '.',
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 5, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the OID entry at '3' */
    status = MAsn1SetEncoded (pRoot + 3, OID_enc, sizeof(OID_enc));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add data in OCTECT entry at '4'. Allow LAST entry to set known lengths */
    status = MAsn1AddIndefiniteData (pRoot + 4, testInput, sizeof(testInput), TRUE);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Retrieve all data: Since all length are now know, the encoder switches to DEFINITE! */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(31, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test size */
    retval += UNITTEST_INT (31, usedLen, sizeof(expect));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (expect, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (32, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (32, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateSingleEncodedForcedIndef()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[5] =
    {
      {  MASN1_TYPE_SEQUENCE, 2},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_SEQUENCE, 2},
           /* OID */
          {  MASN1_TYPE_ENCODED, 0},
           /* DATA */
          {  MASN1_TYPE_OCTET_STRING, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* input OID data */
    ubyte OID_enc[] =
    { 0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };

    /* Input stream */
    ubyte testInput[] = { 'O', 'n', 'c', 'e', '.' };

    /* Expected output */
    ubyte expect[] = {
            0x30, 0x80,
                  0x02, 0x01, 3,
                  0x30, 0x80,
                        0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19,
                        0x24, 0x80,
                              0x04, 0x05, 'O', 'n', 'c', 'e', '.',
                        0x00, 0x00,
                  0x00, 0x00,
            0x00, 0x00
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 5, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the OID entry at '3' */
    status = MAsn1SetEncoded (pRoot + 3, OID_enc, sizeof(OID_enc));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add data in OCTECT entry at '4'. Do NOT allow LAST entry to set known lengths  */
    status = MAsn1AddIndefiniteData (pRoot + 4, testInput, sizeof(testInput), MASN1_BUF_FLAG_ENCODE_INDEF);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Retrieve all data in indef mode */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(31, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test size */
    retval += UNITTEST_INT (31, usedLen, sizeof(expect));
    if (0 < retval)
        goto exit;

    /* Expected data comparison */
    status = DIGI_MEMCMP (expect, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (32, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (32, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateMultipleEncodedIndef()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[5] =
    {
      {  MASN1_TYPE_SEQUENCE, 2},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_SEQUENCE, 2},
           /* OID */
          {  MASN1_TYPE_ENCODED, 0},
           /* DATA */
          {  MASN1_TYPE_OCTET_STRING, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* input OID data */
    ubyte OID_enc[] =
    { 0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'N', 'e', 'x', 't', '.' };
    ubyte test3[] = { 'L', 'a', 's', 't', '.' };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 0x80,
                  0x02, 0x01, 3,
                  0x30, 0x80,
                        0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19,
                        0x24, 0x80,
                              0x04, 0x06, 'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                              0x04, 0x05, 'N', 'e', 'x', 't', '.'
    };

    ubyte expect3[] = {
                              0x04, 0x05, 'L', 'a', 's', 't', '.',
                        0x00, 0x00,
                  0x00, 0x00,
            0x00, 0x00
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 5, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the OID entry at '3' */
    status = MAsn1SetEncoded (pRoot + 3, OID_enc, sizeof(OID_enc));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTECT entry at '4' */
    status = MAsn1AddIndefiniteData (pRoot + 4, test1, sizeof(test1), FALSE);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Retrieve first data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(21, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 1 size */
    retval += UNITTEST_INT (21, usedLen, sizeof(expect1));
    if (0 < retval)
        goto exit;

    /* Expected data 1 comparison */
    status = DIGI_MEMCMP (expect1, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (22, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (22, cmpRes, 0);

    /* Add second part of data in OCTECT entry at '4' */
    status = MAsn1AddIndefiniteData (pRoot + 4, test2, sizeof(test2), FALSE);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    /* Retrieve second data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (40, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(41, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 2 size */
    retval += UNITTEST_INT (41, usedLen, sizeof(expect2));
    if (0 < retval)
        goto exit;

    /* Expected data 2 comparison */
    status = DIGI_MEMCMP (expect2, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (42, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (42, cmpRes, 0);

    /* Add third (and last) part of data in OCTECT entry at '4' */
    status = MAsn1AddIndefiniteData (pRoot + 4, test3, sizeof(test3), TRUE);
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    /* Retrieve third data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (60, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(61, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (61, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (62, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (62, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncodedSampleTest()
{
    MSTATUS status;
    int retval = 0;
    sbyte4 cmpRes;

    MAsn1Element *pRoot = NULL;

    ubyte4 encodingLen, currentSize, updateLen;
    intBoolean isComplete;

    ubyte pOctBuf[16] = {
      1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
    };
    ubyte pUtf8Buf[19] = {
      (ubyte)'a', (ubyte)'b', (ubyte)'c', (ubyte)'d',
      (ubyte)'e', (ubyte)'f', (ubyte)'g', (ubyte)'h',
      (ubyte)'i', (ubyte)'j', (ubyte)'k', (ubyte)'l',
      (ubyte)'m', (ubyte)'n', (ubyte)'o', (ubyte)'p',
      (ubyte)'q', (ubyte)'r', (ubyte)'s'
    };

    MAsn1TypeAndCount pTemplate[5] = {
      { MASN1_TYPE_SEQUENCE, 4 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_OCTET_STRING, 0 },
        { MASN1_TYPE_UTF8_STRING, 0 },
        { MASN1_TYPE_BOOLEAN, 0 }
    };

    /* For this sample, we're going to write to an existing buffer. Generally, you
     * won't know in advance how big something will be. For this sample, though, we
     * can come up with a good estimate. There are 5 Elements, none of which are
     * EXPLICIT. Each will probably have a TL of 2 bytes (lengths longer than 127
     * will have more length octets, but this sample's lengths are short). That's
     * 10 bytes. The V of the INTEGER and BOOLEAN will be one byte each. The V of
     * the OCTET is 16, the V of the UTF8 is 19. Altogether it is 47 bytes.
     * We can make the buffer longer in case we made a mistake in estimating.
     * Or we can say that the longest TL possible with this engine is 6 bytes (one
     * T byte, 5 L bytes of 84 L3 L2 L1 L0). Then we have 30 + 1 + 1 + 16 + 19 for
     * a max length of 67. But we know we won't have lengths in the trillions (a
     * 4-octet length). So we'll just have a buffer of length 50.
     */
    ubyte pEncoding[50];

    ubyte expected[] = {
        0x30, 0x2D,
              0x02, 0x01,
                    0x01,
              0x04, 0x10,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
              0x0C, 0x13,
                    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                    0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
                    0x71, 0x72, 0x73,
              0x01, 0x01,
                    0x00
    };

    /* Let's init the contents of the pEncoding buffer to all FF bytes so we can
     * easily see with a debugger when something is written into the buffer.
     */
    status = DIGI_MEMSET ((void *)pEncoding, 0xff, sizeof (pEncoding));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    status = MAsn1CreateElementArray (
      pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Set the Elements.
     */
    status = MAsn1SetInteger (pRoot + 1, NULL, 0, 0, 1);
    retval += UNITTEST_STATUS (11, status);
    if (0 < retval)
        goto exit;

    status = MAsn1SetBoolean (pRoot + 4, FALSE);
    retval += UNITTEST_STATUS (12, status);
    if (0 < retval)
        goto exit;

    /* For this sample, we're going to break the OCTET STRING and UTF8String into
     * multiple calls. We can't set those Elements with the data because we don't
     * have it yet. However, in order to stream we must know in advance how long
     * the data will be. Generally you will be able to know how long the data will
     * be (e.g. it is from a file and you know the file size). If you just don't
     * know how long the data is, then you cannot use this engine. If the engine
     * supported indefinite length, it could handle unknown lengths, but it does
     * not currently support that feature (it can read indefinite length). If
     * indefinite length encoding is necessary, we will add it.
     *
     * To set the length without setting any value data, call MAsn1SetValueLen.
     */
    status = MAsn1SetValueLen (pRoot + 2, 16);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    status = MAsn1SetValueLen (pRoot + 3, 19);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    /* At this point, we can encode what we have, or we can add data to the OCTET
     * STRING Element.
     * Let's see what happens when we add some data.
     *
     * You must call MAsn1AddData when encoding by parts. Call this for the first
     * adding, the second, all of them, even the last. Never call SetValue.
     *
     * We have two Elements to which we're adding partial data. You should never
     * add data to the second until all the data was added to the first.
     */
    status = MAsn1AddData (pRoot + 2, pOctBuf, 8);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    /* Now Encode what we can.
     * When encoding by parts, you must call MAsn1EncodeUpdate. This function
     * requires an output buffer. There is no other function that can handle encode
     * by parts.
     * You can either call the function with an existing buffer (maybe you estimate
     * the size, see above), or you can call with NULL output and get the required
     * size, allocate a buffer and call again.
     * The last arg is the address where the function will deposit TRUE or FALSE,
     * indicating whether the function completed the full encoding or not. For this
     * call, that should be FALSE.
     */
    currentSize = sizeof (pEncoding);
    encodingLen = 0;
    status = MAsn1EncodeUpdate (
            pRoot, (ubyte *)(pEncoding + encodingLen), currentSize, &updateLen,
            &isComplete);
    retval += UNITTEST_STATUS (31, status);
    if (0 < retval)
        goto exit;

    encodingLen += updateLen;

    /* The data written out to the buffer by this call should be this:
     *   30 2D
     *      02 01
     *         01
     *      04 10
     *         01 02 03 04 05 06 07 08
     * It was able to write out the SEQUENCE and len, the INTEGER, and some of the
     * OCTET STRING.
     *
     * Now add more data to the OCTET STRING. This will be all the data we add to
     * the OCTET STRING.
     */
    status = MAsn1AddData (pRoot + 2, pOctBuf + 8, 8);
    retval += UNITTEST_STATUS (40, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate (
            pRoot, (ubyte *)(pEncoding + encodingLen), currentSize, &updateLen,
            &isComplete);
    retval += UNITTEST_STATUS (41, status);
    if (0 < retval)
        goto exit;

    encodingLen += updateLen;

    /* This latest output should be
     *   09 0A 0B 0C 0D 0E 0F 10 0C 13
     * If we combine this with the previous result, we have
     *   30 2D
     *      02 01
     *         01
     *      04 10
     *         01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
     *      0C 13
     * The encoder was able to write out the rest of the OCTET STRING. Because it
     * was completed, it could start with the next Element. That one is the
     * UTF8String. That Element had no data added yet, so all it could write out
     * was the TL. Remember, if you have all the data, you can set the value of an
     * Element up front, but if you have only some of the input, don't add any data
     * until any previous partials have been completed.
     *
     * Add one byte, then call EncodeUpdate. If the encoder has only one byte it
     * can output, that's
     */
    status = MAsn1AddData (pRoot + 3, pUtf8Buf, 1);
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate (
            pRoot, (ubyte *)(pEncoding + encodingLen), currentSize, &updateLen,
            &isComplete);
    retval += UNITTEST_STATUS (51, status);
    if (0 < retval)
        goto exit;

    encodingLen += updateLen;

    /* The Update wrote out the byte 61. Our total encoding is
     *   30 2D
     *      02 01
     *         01
     *      04 10
     *         01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
     *      0C 13
     *         61
     */

    status = MAsn1AddData (pRoot + 3, pUtf8Buf + 1, 18);
    retval += UNITTEST_STATUS (60, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate (
            pRoot, (ubyte *)(pEncoding + encodingLen), currentSize, &updateLen,
            &isComplete);
    retval += UNITTEST_STATUS (61, status);
    if (0 < retval)
        goto exit;

    encodingLen += updateLen;

    /* That call finished the UTF8String. It could then move on. So it encoded the
     * BOOLEAN as well.
     *   62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 01 01 00
     * The encoding is complete (check isComplete).
     *   30 2D
     *      02 01
     *         01
     *      04 10
     *         01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
     *      0C 13
     *         61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70
     *         71 72 73
     *      01 01
     *         00
     */
    retval = UNITTEST_TRUE (99, TRUE == isComplete);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (99, encodingLen, sizeof(expected));
    if (0 < retval)
        goto exit;

    retval = DIGI_MEMCMP (expected, pEncoding, encodingLen, &cmpRes);
    retval += UNITTEST_STATUS (99, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (99, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncoded()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[3] =
    {
      {  MASN1_TYPE_SEQUENCE, 2},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_OCTET_STRING, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'N', 'e', 'x', 't', '.' };
    ubyte test3[] = { 'L', 'a', 's', 't', '.' };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 11,
                  0x02, 0x01, 3,
                  0x04, 6, 'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                  'N', 'e', 'x', 't', '.'
    };

    ubyte expect3[] = {
                  'L', 'a', 's', 't', '.'
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 3, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    status = MAsn1SetValueLen (pRoot + 2,
                               sizeof(test1) + sizeof(test2) + sizeof(test3));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTECT entry at '2' */
    status = MAsn1AddData (pRoot + 2, test1, sizeof(test1));
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate(pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    /* Add second part of data in OCTECT entry at '2' */
    status = MAsn1AddData (pRoot + 2, test2, sizeof(test2));
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate(pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    /* Add third (and last) part of data in OCTECT entry at '2' */
    status = MAsn1AddData (pRoot + 2, test3, sizeof(test3));
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    /* Retrieve all data sections */
    status = MAsn1EncodeUpdate (pRoot, encoded,
                                encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (60, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(61, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (61, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (62, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (62, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncodedExplicit()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[3] =
    {
      {  MASN1_TYPE_SEQUENCE, 2},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'N', 'e', 'x', 't', '.' };
    ubyte test3[] = { 'L', 'a', 's', 't', '.' };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 23,
                  0x02, 0x01, 3,
                  0xA0, 0x12,
                        0x04, 0x10,
                              'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                              'N', 'e', 'x', 't', '.'
    };

    ubyte expect3[] = {
                              'L', 'a', 's', 't', '.',
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 3, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;


    status = MAsn1SetValueLen (pRoot + 2,
                               sizeof(test1) + sizeof(test2) + sizeof(test3));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTECT entry at '2' */
    status = MAsn1AddData (pRoot + 2, test1, sizeof(test1));
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate (pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(21, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 1 size */
    retval += UNITTEST_INT (21, usedLen, sizeof(expect1));
    if (0 < retval)
        goto exit;

    /* Expected data 1 comparison */
    status = DIGI_MEMCMP (expect1, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (22, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (22, cmpRes, 0);

    /* Add second part of data in OCTECT entry at '2' */
    status = MAsn1AddData (pRoot + 2, test2, sizeof(test2));
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate(pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    /* Add third (and last) part of data in OCTECT entry at '2' */
    status = MAsn1AddData (pRoot + 2, test3, sizeof(test3));
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    /* Retrieve all data sections */
    status = MAsn1EncodeUpdate (pRoot, encoded,
                                encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (60, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(61, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (61, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (62, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (62, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncodedIndefExplicit()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[3] =
    {
      {  MASN1_TYPE_SEQUENCE, 2},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'N', 'e', 'x', 't', '.' };
    ubyte test3[] = { 'L', 'a', 's', 't', '.' };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 0x80,
                  0x02, 0x01, 3,
                  0xA0, 0x80,
                        0x24, 0x80,
                              0x04, 0x06, 'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                              0x04, 0x05, 'N', 'e', 'x', 't', '.'
    };

    ubyte expect3[] = {
                              0x04, 0x05, 'L', 'a', 's', 't', '.',
                        0x00, 0x00,
                  0x00, 0x00,
            0x00, 0x00
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 3, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTECT entry at '2' */
    status = MAsn1AddIndefiniteData (pRoot + 2, test1, sizeof(test1), FALSE);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Retrieve first data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(21, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 1 size */
    retval += UNITTEST_INT (21, usedLen, sizeof(expect1));
    if (0 < retval)
        goto exit;

    /* Expected data 1 comparison */
    status = DIGI_MEMCMP (expect1, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (22, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (22, cmpRes, 0);

    /* Add second part of data in OCTECT entry at '2' */
    status = MAsn1AddIndefiniteData (pRoot + 2, test2, sizeof(test2), FALSE);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    /* Retrieve second data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (40, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(41, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 2 size */
    retval += UNITTEST_INT (41, usedLen, sizeof(expect2));
    if (0 < retval)
        goto exit;

    /* Expected data 2 comparison */
    status = DIGI_MEMCMP (expect2, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (42, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (42, cmpRes, 0);

    /* Add third (and last) part of data in OCTECT entry at '2' */
    status = MAsn1AddIndefiniteData (pRoot + 2, test3, sizeof(test3), TRUE);
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    /* Retrieve third data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (60, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(61, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (61, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (62, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (62, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncodedExplicitWithOptional()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[4] =
    {
      {  MASN1_TYPE_SEQUENCE, 3},
        /* version:          CMSVersion */
        {  MASN1_TYPE_INTEGER, 0},
        /* encapContentInfo: EncapsulatedContentInfo */
        {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT, 0},
        /* Optional */
        {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
    };

    sbyte4 cmpRes;
    ubyte4 val = 3;

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'N', 'e', 'x', 't', '.' };
    ubyte test3[] = { 'L', 'a', 's', 't', '.' };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 23,
                  0x02, 0x01, 3,
                  0xA0, 0x12,
                        0x04, 0x10,
                              'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                              'N', 'e', 'x', 't', '.'
    };

    ubyte expect3[] = {
                              'L', 'a', 's', 't', '.',
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 4, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set the value of the integer entry at '1' */
    status = MAsn1SetInteger (pRoot + 1, NULL, sizeof(val), TRUE, val);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    status = MAsn1SetValueLen (pRoot + 2,
                               sizeof(test1) + sizeof(test2) + sizeof(test3));
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set state to No Value */
    status = MAsn1SetValueLenSpecial (pRoot + 3, MASN1_NO_VALUE);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTET entry at '2' */
    status = MAsn1AddData (pRoot + 2, test1, sizeof(test1));
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate (pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(21, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 1 size */
    retval += UNITTEST_INT (21, usedLen, sizeof(expect1));
    if (0 < retval)
        goto exit;

    /* Expected data 1 comparison */
    status = DIGI_MEMCMP (expect1, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (22, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (22, cmpRes, 0);

    /* Add second part of data in OCTET entry at '2' */
    status = MAsn1AddData (pRoot + 2, test2, sizeof(test2));
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    status = MAsn1EncodeUpdate(pRoot, encoded, encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    /* Add third (and last) part of data in OCTET entry at '2' */
    status = MAsn1AddData (pRoot + 2, test3, sizeof(test3));
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    /* Retrieve all data sections */
    status = MAsn1EncodeUpdate (pRoot, encoded,
                                encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (60, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(61, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (61, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (62, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (62, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_encodedSETOFMultiple()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element *pRoot = NULL;
    MAsn1Element *pGetElement;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;

    MAsn1TypeAndCount def[2] =
    {
      {  MASN1_TYPE_SET_OF | MASN1_IMPLICIT, 1},
        {  MASN1_TYPE_ENCODED, 0},
    };

    sbyte4 cmpRes;

    ubyte test1[] = {
            0x30, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
    };

    ubyte test2[] = {
            0x30, 0x04, 0x11, 0x12, 0x13, 0x14
    };

    /* Expected result */
    ubyte checkVal[] = {
            0xA0, 14,
                  0x30, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                  0x30, 0x04, 0x11, 0x12, 0x13, 0x14
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_ENCODE, MAsn1OfFunction, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set first SET entry */
    status = MAsn1SetEncoded (pRoot + 1, test1, sizeof(test1));
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Add another SET entry */
    status = MAsn1CopyAddOfEntry (pRoot + 0, &pGetElement);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    /* Set second SET entry */
    status = MAsn1SetEncoded (pGetElement, test2, sizeof(test2));
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Encode into memory array */
    status = MAsn1Encode (pRoot, encoded, encodedSize, &usedLen);
    retval += UNITTEST_STATUS (100, status);
    if (0 < retval)
        goto exit;

     /* Expected value size */
     retval += UNITTEST_INT (101, usedLen, sizeof(checkVal));
     if (0 < retval)
         goto exit;

     /* Expected data comparison */
     status = DIGI_MEMCMP (checkVal, encoded, usedLen, &cmpRes);
     retval += UNITTEST_STATUS (102, status);
     if (0 < retval)
         goto exit;

     retval += UNITTEST_INT (102, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;
}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncodedIndefOption0()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[7] =
    {
      {  MASN1_TYPE_SEQUENCE, 4},
        {  MASN1_TYPE_SEQUENCE, 2},
          /* OID */
          {  MASN1_TYPE_ENCODED, 0},
          /* encapContentInfo: EncapsulatedContentInfo */
          {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT, 0},
        /* certificates [0] IMPLICIT: CertificateSet OPTIONAL */
        {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
        /* crls [1] IMPLICIT: RevocationInfoChoices OPTIONAL */
        {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
        /* signerInfos:       SignerInfos */
        {  MASN1_TYPE_ENCODED, 0},
    };

    sbyte4 cmpRes;

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'L', 'a', 's', 't', '.' };
    ubyte enc0[] = {
            0xA0, 0x06,
                  0x30, 0x04, 0x11, 0x12, 0x13, 0x14
    };
    ubyte enc1[] = {
            0x30, 0x04, 0x21, 0x22, 0x23, 0x24
    };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 0x80,
                  0x30, 0x80,
                        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
                        0xA0, 0x80,
                              0x24, 0x80,
                                    0x04, 0x06, 'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                                    0x04, 0x05, 'L', 'a', 's', 't', '.',
                              0x00, 0x00,
                        0x00, 0x00,
                  0x00, 0x00
    };

    ubyte expect3[] = {
                 0xA0, 0x06,
                       0x30, 0x04, 0x11, 0x12, 0x13, 0x14,
                 0x30, 0x04, 0x21, 0x22, 0x23, 0x24,
           0x00, 0x00
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 7, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set OID at entry 2 */
    status = MAsn1SetEncoded (pRoot + 2, CMS_OUTER_DATA, CMS_OUTER_DATA_LEN);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Set OPTIONAL part '0' at entry 4 as not yet set */
    status = MAsn1SetValueLenSpecial(pRoot + 4, MASN1_UNKNOWN_VALUE);
    retval += UNITTEST_STATUS (11, status);
    if (0 < retval)
        goto exit;

    /* Set OPTIONAL part '1' at entry 5 as not yet set */
    status = MAsn1SetValueLenSpecial(pRoot + 5, MASN1_UNKNOWN_VALUE);
    retval += UNITTEST_STATUS (12, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTECT entry at '3' */
    status = MAsn1AddIndefiniteData (pRoot + 3, test1, sizeof(test1), FALSE);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    /* Retrieve first data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(31, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 1 size */
    retval += UNITTEST_INT (31, usedLen, sizeof(expect1));
    if (0 < retval)
        goto exit;

    /* Expected data 1 comparison */
    status = DIGI_MEMCMP (expect1, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (32, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (32, cmpRes, 0);

    /* Add second (and last) part of data in OCTECT entry at '3' */
    status = MAsn1AddIndefiniteData (pRoot + 3, test2, sizeof(test2), TRUE);
    retval += UNITTEST_STATUS (40, status);
    if (0 < retval)
        goto exit;

    /* Retrieve second data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(51, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 2 size */
    retval += UNITTEST_INT (51, usedLen, sizeof(expect2));
    if (0 < retval)
        goto exit;

    /* Expected data 2 comparison */
    status = DIGI_MEMCMP (expect2, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (52, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (52, cmpRes, 0);

    /* Add optional '0' but not '1' */
    status = MAsn1SetValueLenSpecial(pRoot + 4, MASN1_CLEAR_UNKNOWN_VALUE);
    retval += UNITTEST_STATUS (70, status);
    if (0 < retval)
        goto exit;

    /* Set OPTIONAL part '1' at entry 5 as not yet set */
    status = MAsn1SetValueLenSpecial(pRoot + 5, MASN1_NO_VALUE);
    retval += UNITTEST_STATUS (71, status);
    if (0 < retval)
        goto exit;

    /* Fill data in Option '0' */
    status = MAsn1SetEncoded (pRoot + 4, enc0, sizeof(enc0));
    retval += UNITTEST_STATUS (72, status);
    if (0 < retval)
        goto exit;

    /* Fill data in last section */
    status = MAsn1SetEncoded (pRoot + 6, enc1, sizeof(enc1));
    retval += UNITTEST_STATUS (73, status);
    if (0 < retval)
        goto exit;

    /* Retrieve final ASN data */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (80, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(81, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (81, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (82, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (82, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;

}


/*----------------------------------------------------------------------*/

int mocencode_test_MAsn1Element_updateEncodedIndefOption1()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element* pRoot = NULL;
    ubyte encoded[1024];
    ubyte4 encodedSize = sizeof(encoded);
    ubyte4 usedLen;
    intBoolean complete = FALSE;

    MAsn1TypeAndCount def[7] =
    {
      {  MASN1_TYPE_SEQUENCE, 4},
        {  MASN1_TYPE_SEQUENCE, 2},
          /* OID */
          {  MASN1_TYPE_ENCODED, 0},
          /* encapContentInfo: EncapsulatedContentInfo */
          {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT, 0},
        /* certificates [0] IMPLICIT: CertificateSet OPTIONAL */
        {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
        /* crls [1] IMPLICIT: RevocationInfoChoices OPTIONAL */
        {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
        /* signerInfos:       SignerInfos */
        {  MASN1_TYPE_ENCODED, 0},
    };

    sbyte4 cmpRes;

    /* Input stream */
    ubyte test1[] = { 'F', 'i', 'r', 's', 't', '.' };
    ubyte test2[] = { 'L', 'a', 's', 't', '.' };
    ubyte enc0[] = {
            0xA1, 0x06,
                  0x30, 0x04, 0x11, 0x12, 0x13, 0x14
    };
    ubyte enc1[] = {
            0x30, 0x04, 0x21, 0x22, 0x23, 0x24
    };

    /* Expected output */
    ubyte expect1[] = {
            0x30, 0x80,
                  0x30, 0x80,
                        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
                        0xA0, 0x80,
                              0x24, 0x80,
                                    0x04, 0x06, 'F', 'i', 'r', 's', 't', '.'
    };

    ubyte expect2[] = {
                                    0x04, 0x05, 'L', 'a', 's', 't', '.',
                              0x00, 0x00,
                        0x00, 0x00,
                  0x00, 0x00
    };

    ubyte expect3[] = {
                 0xA1, 0x06,
                       0x30, 0x04, 0x11, 0x12, 0x13, 0x14,
                 0x30, 0x04, 0x21, 0x22, 0x23, 0x24,
           0x00, 0x00
    };

    /* Create the 'array' root */
    status = MAsn1CreateElementArray (def, 7, MASN1_FNCT_ENCODE, NULL, &pRoot);
    retval += UNITTEST_STATUS (0, status);
    if (0 < retval)
        goto exit;

    /* Set OID at entry 2 */
    status = MAsn1SetEncoded (pRoot + 2, CMS_OUTER_DATA, CMS_OUTER_DATA_LEN);
    retval += UNITTEST_STATUS (10, status);
    if (0 < retval)
        goto exit;

    /* Set OPTIONAL part '0' at entry 4 as not yet set */
    status = MAsn1SetValueLenSpecial(pRoot + 4, MASN1_UNKNOWN_VALUE);
    retval += UNITTEST_STATUS (11, status);
    if (0 < retval)
        goto exit;

    /* Set OPTIONAL part '1' at entry 5 as not yet set */
    status = MAsn1SetValueLenSpecial(pRoot + 5, MASN1_UNKNOWN_VALUE);
    retval += UNITTEST_STATUS (12, status);
    if (0 < retval)
        goto exit;

    /* Add first part of data in OCTECT entry at '3' */
    status = MAsn1AddIndefiniteData (pRoot + 3, test1, sizeof(test1), FALSE);
    retval += UNITTEST_STATUS (20, status);
    if (0 < retval)
        goto exit;

    /* Retrieve first data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (30, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(31, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 1 size */
    retval += UNITTEST_INT (31, usedLen, sizeof(expect1));
    if (0 < retval)
        goto exit;

    /* Expected data 1 comparison */
    status = DIGI_MEMCMP (expect1, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (32, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (32, cmpRes, 0);

    /* Add second (and last) part of data in OCTECT entry at '3' */
    status = MAsn1AddIndefiniteData (pRoot + 3, test2, sizeof(test2), TRUE);
    retval += UNITTEST_STATUS (40, status);
    if (0 < retval)
        goto exit;

    /* Retrieve second data section */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (50, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(51, FALSE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 2 size */
    retval += UNITTEST_INT (51, usedLen, sizeof(expect2));
    if (0 < retval)
        goto exit;

    /* Expected data 2 comparison */
    status = DIGI_MEMCMP (expect2, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (52, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (52, cmpRes, 0);

    /* Add optional '1' but not '0' */
    status = MAsn1SetValueLenSpecial(pRoot + 4, MASN1_NO_VALUE);
    retval += UNITTEST_STATUS (70, status);
    if (0 < retval)
        goto exit;

    status = MAsn1SetValueLenSpecial(pRoot + 5, MASN1_CLEAR_UNKNOWN_VALUE);
    retval += UNITTEST_STATUS (71, status);
    if (0 < retval)
        goto exit;

    /* Fill data in Option '1' */
    status = MAsn1SetEncoded (pRoot + 5, enc0, sizeof(enc0));
    retval += UNITTEST_STATUS (72, status);
    if (0 < retval)
        goto exit;

    /* Fill data in last section */
    status = MAsn1SetEncoded (pRoot + 6, enc1, sizeof(enc1));
    retval += UNITTEST_STATUS (73, status);
    if (0 < retval)
        goto exit;

    /* Retrieve final ASN data */
    status = MAsn1EncodeIndefiniteUpdate (pRoot, encoded,
                                          encodedSize, &usedLen, &complete);
    retval += UNITTEST_STATUS (80, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_TRUE(81, TRUE == complete);
    if (0 < retval)
        goto exit;

    /* Expected test 3 size */
    retval += UNITTEST_INT (81, usedLen, sizeof(expect3));
    if (0 < retval)
        goto exit;

    /* Expected data 3 comparison */
    status = DIGI_MEMCMP (expect3, encoded, usedLen, &cmpRes);
    retval += UNITTEST_STATUS (82, status);
    if (0 < retval)
        goto exit;

    retval += UNITTEST_INT (82, cmpRes, 0);

exit:
    /* Cleanup memory */
    MAsn1FreeElementArray (&pRoot);
    return retval;

}

