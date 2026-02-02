/*
 * mocdecode_asn_test.c
 *
 * Unit Test for CMS ASN Utilities
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
#include "../../common/debug_console.h"

#include "../../../unit_tests/unittest.h"

#include "../../asn1/mocasn1.h"
#include "../../asn1/oiddefs.h"
#include "../../crypto/moccms_asn.h"

/* Include code to be tested */
#include "../../crypto/moccms_asn.c"
#include "../../crypto/mocasym.h"

int moccms_asn_test_freeDataInfo()
{
    MSTATUS status;
    int retval = 0;

    MOC_CMS_DataInfo info1 = { NULL, NULL, NULL, 0, 0, 1, 0 };

    /* Release the 'empty' test data */
    status = DIGI_CMS_A_freeDataInfo(&info1);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
       goto exit;

    /* Free data memory */
    info1.pData = MALLOC(16);
    retval += UNITTEST_VALIDPTR(11, info1.pData);
    if (retval > 0)
       goto exit;

    status = DIGI_CMS_A_freeDataInfo(&info1);
    retval += UNITTEST_STATUS(11, status);
    retval += UNITTEST_TRUE(11, NULL == info1.pData);
    if (retval > 0)
       goto exit;

exit:
    return retval;
}

int moccms_asn_test_boundarySeqDataReturn()
{
    MSTATUS status;
    int retval = 0;

    MOC_CMS_DataInfo info1 = { NULL, NULL, NULL, 0, 0, 1, 0 };

    /* Test data */
    ubyte encoded[] = { 0x30, 0x05 };


    /* Perform test call with all NULL */
    status = DIGI_CMS_A_decodeSeqDataReturn(NULL,
                                           NULL,
                                           0,
                                           NULL);
    retval += UNITTEST_TRUE(1, OK != status);
    if (retval > 0)
       goto exit;

    /* Perform test call with invalid 'element' */
    status = DIGI_CMS_A_decodeSeqDataReturn(&info1,
                                           encoded,
                                           sizeof(encoded),
                                           NULL);
    retval += UNITTEST_TRUE(2, OK == status);
    if (retval > 0)
       goto exit;


    /* Perform test call with invalid 'element' and 'empty' data */
    status = DIGI_CMS_A_decodeSeqDataReturn(&info1,
                                           encoded,
                                           0,
                                           NULL);
    retval += UNITTEST_TRUE(3, OK == status);
    if (retval > 0)
       goto exit;

    /* Perform test call with invalid 'element' and 'no' data */
    status = DIGI_CMS_A_decodeSeqDataReturn(&info1,
                                           NULL,
                                           0,
                                           NULL);
    retval += UNITTEST_TRUE(4, OK == status);

exit:
    DIGI_CMS_A_freeDataInfo (&info1);
    return retval;
}

int moccms_asn_test_callSeqDataReturn()
{
    MSTATUS status;
    int retval = 0;
    ubyte4 bytesRead;

    MAsn1Element* pTest = NULL;
    /* Sequence with OID and encoded data under explicit tag */
    MAsn1TypeAndCount def[3] =
    {
         { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_ENCODED | MASN1_EXPLICIT, 0 },
    };

    MOC_CMS_DataInfo info1 = { NULL, NULL, NULL, 0, 0, 1, 0 };

    /* Test data */
    ubyte encodedE[] = { 0 }; /* empty */

    ubyte encodedP1[] = { 0x30, 0x12 }; /* SEQUENCE */

    ubyte encodedP2[] =
    {
            /* OID */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03
    };

    ubyte encodedP3[] =
    {
            /* EXPLICIT */
            0xA0, 0x05,
            /* SEQUENCE */
            0x30, 0x03,
            /* INTEGER */
            0x02, 0x01, 0x00
    };

    /* Create the 'test' ASN1 */
    status = MAsn1CreateElementArray (def, 3, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pTest);
    retval += UNITTEST_STATUS(0, status);
    retval += UNITTEST_VALIDPTR(0, pTest);
    if (retval > 0)
        goto exit;

    /* Perform test call back with 'empty' data */
    status = DIGI_CMS_A_decodeSeqDataReturn((void*)&info1,
                                           encodedE,
                                           0,
                                           pTest);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_TRUE(10, NULL == info1.pElement);
    retval += UNITTEST_TRUE(10, NULL == info1.pData);
    retval += UNITTEST_TRUE(10, 0 == info1.len);
    if (retval > 0)
       goto exit;

    /* Perform test call back with first 'partial' data */
    status = DIGI_CMS_A_decodeSeqDataReturn ((void*)&info1,
                                            encodedP1,
                                            sizeof (encodedP1),
                                            pTest);
    retval += UNITTEST_STATUS(11, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_TRUE(11, pTest == info1.pElement);
    retval += UNITTEST_TRUE(11, NULL != info1.pData);
    retval += UNITTEST_TRUE(11, sizeof (encodedP1) == info1.len);
    if (retval > 0)
       goto exit;

    /* Perform test call back with second 'partial' data */
    status = DIGI_CMS_A_decodeSeqDataReturn ((void*)&info1,
                                            encodedP2,
                                            sizeof (encodedP2),
                                            pTest);
    retval += UNITTEST_STATUS(12, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_TRUE(12, pTest == info1.pElement);
    retval += UNITTEST_TRUE(12, NULL != info1.pData);
    retval += UNITTEST_TRUE(12, (sizeof (encodedP2)+sizeof (encodedP1)) == info1.len);
    if (retval > 0)
       goto exit;

    /* Perform test call back with third 'partial' data */
    status = DIGI_CMS_A_decodeSeqDataReturn ((void*)&info1,
                                            encodedP3,
                                            sizeof (encodedP3),
                                            pTest);
    retval += UNITTEST_STATUS(13, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_TRUE(13, pTest == info1.pElement);
    retval += UNITTEST_TRUE(13, NULL != info1.pData);
    retval += UNITTEST_TRUE(13, (sizeof (encodedP3)+sizeof (encodedP2)+sizeof (encodedP1)) == info1.len);
    if (retval > 0)
       goto exit;

    /* Did the code correctly concatenate? */
    status = MAsn1Decode (info1.pData, info1.len,
                          pTest,
                          &bytesRead);
    retval += UNITTEST_STATUS(20, status);
    if (retval > 0)
        goto exit;

    /* Check stored data in ASN1 */
    retval += UNITTEST_TRUE(20, bytesRead == (sizeof (encodedP3)+sizeof (encodedP2)+sizeof (encodedP1)));
    retval += UNITTEST_TRUE(20, pTest[1].valueLen == encodedP2[1]);
    retval += UNITTEST_TRUE(20, pTest[2].valueLen == encodedP3[1]);

exit:
    MAsn1FreeElementArray (&pTest);
    DIGI_CMS_A_freeDataInfo (&info1);
    return retval;
}

int moccms_asn_test_createCollectData()
{
    MSTATUS status;
    int retval = 0;

    MOC_CMS_CollectData* pData = NULL;

    /* Create with NULL */
    status = DIGI_CMS_A_createCollectData (&pData,
                                          NULL, NULL);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_VALIDPTR(10, pData);
    if (retval > 0)
        goto exit;

    /* Free the instance */
    status = DIGI_CMS_A_freeCollectData (&pData);
    retval += UNITTEST_STATUS(11, status);
    retval += UNITTEST_TRUE(11, NULL == pData);
    if (retval > 0)
        goto exit;

    /* Create with simulated pointer -> Will cause error when FREE() is attempted */
    status = DIGI_CMS_A_createCollectData (&pData,
                                          (MAsn1Element *)0x55,
                                          (MAsn1Element *)0xaa);
    retval += UNITTEST_STATUS(12, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_VALIDPTR(12, pData);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_TRUE(12, (MAsn1Element *)0xaa == pData->pElement);
    retval += UNITTEST_TRUE(12, (MAsn1Element *)0x55 == pData->pParent);

exit:
    DIGI_CMS_A_freeCollectData (&pData);
    return retval;
}

int moccms_asn_test_collectEncoded()
{
    MSTATUS status;
    int retval = 0;
    sbyte4 cmpResult = -1;
    ubyte4 bytesRead;
    intBoolean done;
    ubyte4 copied;

    MAsn1Element* pTest = NULL;

    /* Sequence with OID and encoded data under explicit tag */
    MAsn1TypeAndCount def[3] =
    {
         { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_ENCODED | MASN1_EXPLICIT, 0 },
    };

    /* input data with integer 'payload' */
    ubyte encoded[] =
    {       /* SEQUENCE */
            0x30, 0x12,
            /* OID */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
            /* EXPLICIT */
            0xA0, 0x05,
            /* SEQUENCE */
            0x30, 0x03,
            /* INTEGER */
            0x02, 0x01, 0x00
    };

    MOC_CMS_CollectData* pData = NULL;

    /* Create the 'test' ASN1 */
    status = MAsn1CreateElementArray (def, 3, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pTest);
    retval += UNITTEST_STATUS(0, status);
    retval += UNITTEST_VALIDPTR(0, pTest);
    if (retval > 0)
        goto exit;

    /* Create with given ASN1 elements */
    status = DIGI_CMS_A_createCollectData(&pData,
                                         pTest,
                                         pTest+2);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_VALIDPTR(10, pData);
    if (retval > 0)
        goto exit;

    /* Read ASN1 byte-by-byte */
    for (copied = 0; copied < sizeof (encoded); ++copied)
    {
        status = MAsn1DecodeUpdateFlag (encoded+copied, 1, MASN1_DECODE_UPDATE,
                                        pTest,
                                        &bytesRead, &done);

        retval += UNITTEST_STATUS(100 + copied, status);
        if (retval > 0)
            goto exit;

        if (FALSE == pData->keepDone)
        {
            status = DIGI_CMS_A_collectEncoded (pData);
            retval += UNITTEST_STATUS(200 + copied, status);
            if (retval > 0)
                goto exit;
        }
    }

    /* Check result inside 'pData' */
    retval += UNITTEST_TRUE(90, pData->keepDone);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT(90, pData->keepDataLen, 5);
    DIGI_MEMCMP (pData->pKeepData, encoded+15, pData->keepDataLen, &cmpResult);
    retval += UNITTEST_INT(90, cmpResult, 0);

exit:
    DIGI_CMS_A_freeCollectData (&pData);
    MAsn1FreeElementArray (&pTest);
    return retval;
}

int moccms_asn_test_collectOID()
{
    MSTATUS status;
    int retval = 0;
    sbyte4 cmpResult = -1;
    ubyte4 bytesRead;
    intBoolean done;
    ubyte4 copied;

    MAsn1Element* pTest = NULL;

    /* Sequence with OID and encoded data under explicit tag */
    MAsn1TypeAndCount def[3] =
    {
         { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_ENCODED | MASN1_EXPLICIT, 0 },
    };

    /* input data with integer 'payload' */
    ubyte encoded[] =
    {       /* SEQUENCE */
            0x30, 0x12,
            /* OID */
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
            /* EXPLICIT */
            0xA0, 0x05,
            /* SEQUENCE */
            0x30, 0x03,
            /* INTEGER */
            0x02, 0x01, 0x00
    };

    MOC_CMS_CollectData* pData = NULL;

    /* Create the 'test' ASN1 */
    status = MAsn1CreateElementArray (def, 3, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pTest);
    retval += UNITTEST_STATUS(0, status);
    retval += UNITTEST_VALIDPTR(0, pTest);
    if (retval > 0)
        goto exit;

    /* Create with given ASN1 elements */
    status = DIGI_CMS_A_createCollectData(&pData,
                                         pTest,
                                         pTest+1);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_VALIDPTR(10, pData);
    if (retval > 0)
        goto exit;

    /* Read ASN1 byte-by-byte */
    for (copied = 0; copied < sizeof (encoded); ++copied)
    {
        status = MAsn1DecodeUpdateFlag (encoded+copied, 1, MASN1_DECODE_UPDATE,
                                        pTest,
                                       &bytesRead, &done);

        retval += UNITTEST_STATUS(100 + copied, status);
        if (retval > 0)
            goto exit;

        if (FALSE == pData->keepDone)
        {
            status = DIGI_CMS_A_collectOid (pData);
            retval += UNITTEST_STATUS(200 + copied, status);
            if (retval > 0)
                goto exit;
        }
    }

    /* Check result inside 'pData' */
    retval += UNITTEST_TRUE(90, pData->keepDone);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT(90, pData->keepDataLen, 11);
    DIGI_MEMCMP (pData->pKeepData, encoded+2, pData->keepDataLen, &cmpResult);
    retval += UNITTEST_INT(90, cmpResult, 0);

exit:
    DIGI_CMS_A_freeCollectData (&pData);
    MAsn1FreeElementArray (&pTest);
    return retval;
}

int moccms_asn_test_collectSetOF()
{
    MSTATUS status;
    int retval = 0;
    sbyte4 cmpResult = -1;
    ubyte4 bytesRead;
    intBoolean done;
    ubyte4 copied;

    MAsn1Element* pTest = NULL;

    /* SET OF encoded data under implicit tag '0' */
    MAsn1TypeAndCount def[2] =
    {
      {  MASN1_TYPE_SET_OF | MASN1_IMPLICIT | MASN1_OPTIONAL, 1},
        { MASN1_TYPE_ENCODED, 0 },
    };

    /* SET OF input data with SEQ and INTEGER 'payload' */
    ubyte encoded[] =
    {       /* SEQUENCE */
            0xA0, 0x0E,
              /* SEQUENCE 1 */
              0x30, 0x05,
                /* SEQUENCE */
                0x30, 0x03,
                  /* INTEGER */
                  0x02, 0x01, 0x01,
              /* SEQUENCE 2 */
              0x30, 0x05,
                /* SEQUENCE */
                0x30, 0x03,
                  /* INTEGER */
                  0x02, 0x01, 0x02
    };

    MOC_CMS_CollectData* pData = NULL;

    /* Create the 'test' ASN1 */
    status = MAsn1CreateElementArray (def, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pTest);
    retval += UNITTEST_STATUS(0, status);
    retval += UNITTEST_VALIDPTR(0, pTest);
    if (retval > 0)
        goto exit;

    /* Create with given ASN1 elements */
    status = DIGI_CMS_A_createCollectData (&pData,
                                          pTest,
                                          pTest+1);
    retval += UNITTEST_STATUS(10, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_VALIDPTR(10, pData);
    if (retval > 0)
        goto exit;

    /* Read ASN1 byte-by-byte */
    for (copied = 0; copied < sizeof (encoded); ++copied)
    {
        status = MAsn1DecodeUpdateFlag (encoded+copied, 1, MASN1_DECODE_UPDATE,
                                        pTest,
                                        &bytesRead, &done);

        retval += UNITTEST_STATUS(100 + copied, status);
        if (retval > 0)
            goto exit;

        if (FALSE == pData->keepDone)
        {
            status = DIGI_CMS_A_collectSetOF (pData);
            retval += UNITTEST_STATUS(200 + copied, status);
            if (retval > 0)
                goto exit;
        }
    }

    /* Check result inside 'pData' */
    retval += UNITTEST_TRUE(90, pData->keepDone);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT(90, pData->keepDataLen, 14);
    DIGI_MEMCMP (pData->pKeepData, encoded+2, pData->keepDataLen, &cmpResult);
    retval += UNITTEST_INT(90, cmpResult, 0);

exit:
    DIGI_CMS_A_freeCollectData (&pData);
    MAsn1FreeElementArray (&pTest);
    return retval;
}
