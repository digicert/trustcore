
/*
 * crypto_utils_test.c
 *
 * crypto_utils.c test
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
#include "../../common/base64.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/crypto_utils.h"

#define JSON_SIGNATURE "\"signature\" : "

typedef struct
{
    sbyte *pCa;
    sbyte *pKey;
    sbyte *pCert;
} crypto_utils_test_data;

static crypto_utils_test_data pCryptoUtilTestData[] = {
    {
        (sbyte *) "testRsaJsonCert.der",
        (sbyte *) "testRsaJsonKey.pem",
        (sbyte *) "testRsaJsonCert.pem"
    },
    {
        (sbyte *) "testEccJsonCert.der",
        (sbyte *) "testEccJsonKey.pem",
        (sbyte *) "testEccJsonCert.pem"
    },
    {
        (sbyte *) "testJsonCaCert.der",
        (sbyte *) "testJsonKey.pem",
        (sbyte *) "testJsonCert.pem"
    }
};

static int encapsulated_test(sbyte *pCaFile, sbyte *pKeyFile, sbyte *pCertFile)
{
    MSTATUS status;
    ubyte4 verifyStatus;
    ubyte *pKey = NULL, *pCert = NULL, *pSig = NULL, *pTemp = NULL;
    ubyte *pCa = NULL;
    ubyte4 keyLen = 0, certLen = 0, sigLen = 0, caLen = 0;
    ubyte pData[] = {
        0x01, 0x02, 0x03
    };
    certStorePtr pCertStore = NULL;

    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pCaFile)
    {
        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGICERT_readFile((const char *) pCaFile, &pCa, &caLen);
        if (OK != status)
        {
            goto exit;
        }

        status = CERT_STORE_addTrustPoint(pCertStore, pCa, caLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = DIGICERT_readFile(
        (const char *) pCertFile, &pCert, &certLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_readFile(
        (const char *) pKeyFile, &pKey, &keyLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_signJson(
        pData, sizeof(pData), pKey, keyLen, ht_sha1, pCert, certLen,
        &pSig, &sigLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pTemp, sigLen + DIGI_STRLEN((sbyte *) JSON_SIGNATURE) + 2);
    if (OK != status)
    {
        goto exit;
    }

    pTemp[0] = '{';
    pTemp[1 + DIGI_STRLEN((sbyte *) JSON_SIGNATURE) + sigLen] = '}';

    status = DIGI_MEMCPY(pTemp + 1, JSON_SIGNATURE, DIGI_STRLEN((sbyte *) JSON_SIGNATURE));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pTemp + 1 + DIGI_STRLEN((sbyte *) JSON_SIGNATURE), pSig, sigLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_verifyJson(
        pData, sizeof(pData), pTemp, sigLen + DIGI_STRLEN((sbyte *) JSON_SIGNATURE),
        pCertStore, &verifyStatus);
    if (OK != status)
    {
        goto exit;
    }
    
    if (OK != verifyStatus)
    {
        status = verifyStatus;
    }

exit:

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }

    DIGI_FREE((void **) &pSig);
    DIGI_FREE((void **) &pTemp);
    DIGICERT_freeReadFile(&pCa);
    DIGICERT_freeReadFile(&pCert);
    DIGICERT_freeReadFile(&pKey);
    DIGICERT_freeDigicert();

    return (int) status;
}

static int basic_test(sbyte *pCaFile, sbyte *pKeyFile, sbyte *pCertFile)
{
    MSTATUS status;
    ubyte4 verifyStatus;
    ubyte *pKey = NULL, *pCert = NULL, *pSig = NULL;
    ubyte *pCa = NULL;
    ubyte4 keyLen = 0, certLen = 0, sigLen = 0, caLen = 0;
    ubyte pData[] = {
        0x01, 0x02, 0x03
    };
    certStorePtr pCertStore = NULL;

    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pCaFile)
    {
        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGICERT_readFile((const char *) pCaFile, &pCa, &caLen);
        if (OK != status)
        {
            goto exit;
        }

        status = CERT_STORE_addTrustPoint(pCertStore, pCa, caLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = DIGICERT_readFile(
        (const char *) pCertFile, &pCert, &certLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_readFile(
        (const char *) pKeyFile, &pKey, &keyLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_signJson(
        pData, sizeof(pData), pKey, keyLen, ht_sha1, pCert, certLen,
        &pSig, &sigLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_verifyJson(
        pData, sizeof(pData), pSig, sigLen,
        pCertStore, &verifyStatus);
    if (OK != status)
    {
        goto exit;
    }
    
    if (OK != verifyStatus)
    {
        status = verifyStatus;
        goto exit;
    }

    DIGI_FREE((void **) &pSig);

    status = CRYPTO_UTILS_signJsonMin(
        pData, sizeof(pData), pKey, keyLen, ht_sha1, pCert, certLen,
        &pSig, &sigLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_verifyJsonMin(
        pData, sizeof(pData), pCert, certLen, pSig, sigLen, &verifyStatus);
    if (OK != status)
    {
        goto exit;
    }
    
    if (OK != verifyStatus)
    {
        status = verifyStatus;
        goto exit;
    }

exit:

    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }

    DIGI_FREE((void **) &pSig);
    DIGICERT_freeReadFile(&pCa);
    DIGICERT_freeReadFile(&pCert);
    DIGICERT_freeReadFile(&pKey);
    DIGICERT_freeDigicert();

    return (int) status;
}

int multi_sig_test(crypto_utils_test_data *pTestData, ubyte4 testDataLen)
{
    MSTATUS status;
    ubyte4 index;
    certStorePtr pStore = NULL;
    ubyte *pCa = NULL, *pCert = NULL, *pKey = NULL;
    ubyte4 caLen, certLen, keyLen;
    ubyte pData[] = {
        0x01, 0x02, 0x03
    };
    ubyte *pMultiSig = NULL, *pIndex;
    ubyte4 multiSigLen = 0;
    ubyte **ppSigs = NULL;
    ubyte4 *pSigsLen = NULL;
    ubyte4 verifyStatus = 1;

    status = DIGICERT_initDigicert();
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &ppSigs, testDataLen * sizeof(ubyte *));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pSigsLen, testDataLen * sizeof(ubyte4));
    if (OK != status)
    {
        goto exit;
    }

    for (index = 0; index < testDataLen; index++)
    {
        if (NULL != pTestData[index].pCa)
        {
            if (NULL == pStore)
            {
                status = CERT_STORE_createStore(&pStore);
                if (OK != status)
                {
                    goto exit;
                }
            }

            DIGI_FREE((void **) &pCa);

            status = DIGICERT_readFile(
                (const char *) pTestData[index].pCa, &pCa, &caLen);
            if (OK != status)
            {
                goto exit;
            }

            status = CERT_STORE_addTrustPoint(pStore, pCa, caLen);
            if (OK != status)
            {
                goto exit;
            }
        }

        DIGI_FREE((void **) &pCert);

        status = DIGICERT_readFile(
            (const char *) pTestData[index].pCert, &pCert, &certLen);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pKey);

        status = DIGICERT_readFile(
            (const char *) pTestData[index].pKey, &pKey, &keyLen);
        if (OK != status)
        {
            goto exit;
        }

        status = CRYPTO_UTILS_signJson(
            pData, sizeof(pData), pKey, keyLen, ht_sha1, pCert, certLen,
            ppSigs + index, pSigsLen + index);
        if (OK != status)
        {
            goto exit;
        }

        multiSigLen += pSigsLen[index];
    }

    multiSigLen += (2 * (testDataLen - 1));

    status = DIGI_MALLOC((void **) &pMultiSig, multiSigLen);
    if (OK != status)
    {
        goto exit;
    }

    pIndex = pMultiSig;
    for (index = 0; index < testDataLen; index++)
    {
        DIGI_MEMCPY(pIndex, ppSigs[index], pSigsLen[index]);
        pIndex += pSigsLen[index];
        if (index != (testDataLen - 1))
        {
            *pIndex++ = ',';
            *pIndex++ = '\n';
        }

        DIGI_FREE((void **) ppSigs + index);
    }

    DIGICERT_writeFile("temp.sig", pMultiSig, multiSigLen);

    status = CRYPTO_UTILS_verifyJsonMultiSig(
        pData, sizeof(pData), pMultiSig, multiSigLen, pStore, &verifyStatus);
    if (OK != status)
    {
        goto exit;
    }

    if (OK != verifyStatus)
    {
        status = verifyStatus;
    }

exit:

    if (NULL != pStore)
    {
        CERT_STORE_releaseStore(&pStore);
    }

    DIGI_FREE((void **) &pCert);
    DIGI_FREE((void **) &pKey);
    DIGI_FREE((void **) &pCa);
    DIGI_FREE((void **) &pMultiSig);
    DIGI_FREE((void **) &pSigsLen);
    DIGI_FREE((void **) &ppSigs);
    DIGICERT_freeDigicert();

    return status;
}

int crypto_utils_test_main()
{
    int ret = 0;

    ret += basic_test(NULL, (sbyte *) "testRsaJsonKey.pem", (sbyte *) "testRsaJsonCert.pem");
    ret += basic_test(NULL, (sbyte *) "testEccJsonKey.pem", (sbyte *) "testEccJsonCert.pem");
    ret += basic_test(
        (sbyte *) "testJsonCaCert.der", (sbyte *) "testJsonKey.pem", (sbyte *) "testJsonCert.pem");
    ret += basic_test(NULL, (sbyte *) "testRsaJsonKey.pem", (sbyte *) "testRsaJsonCert.der");
    ret += basic_test(NULL, (sbyte *) "testEccJsonKey.pem", (sbyte *) "testEccJsonCert.der");
    ret += basic_test(
        (sbyte *) "testJsonCaCert.der", (sbyte *) "testJsonKey.pem", (sbyte *) "testJsonCert.der");

    ret += encapsulated_test(NULL, (sbyte *) "testRsaJsonKey.pem", (sbyte *) "testRsaJsonCert.pem");
    ret += encapsulated_test(NULL, (sbyte *) "testEccJsonKey.pem", (sbyte *) "testEccJsonCert.pem");
    ret += encapsulated_test(
        (sbyte *) "testJsonCaCert.der", (sbyte *) "testJsonKey.pem", (sbyte *) "testJsonCert.pem");

    ret += multi_sig_test(pCryptoUtilTestData, COUNTOF(pCryptoUtilTestData));

    return ret;
}
