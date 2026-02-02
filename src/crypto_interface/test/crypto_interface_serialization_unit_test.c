/*
 * crypto_interface_serialization_unit_test.c
 *
 * test file for serialization and deserialization sub routines
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/sizedbuffer.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/derencoder.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/crypto.h"
#include "../../crypto/rsa.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto/dsa.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/malgo_id.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/sec_key.h"
#include "../../crypto/keyblob.h"
#ifdef __RTOS_LINUX__
#include <stdio.h>
#endif
static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

typedef struct
{
    char *pKeyFile;
    ubyte4 keyType;
    char *pCertFile;
    MAlgoOid oidFlag;
    union
    {
        RsaSsaPssAlgIdParams rsaSsaPssParams;
        EcPublicKeyAlgIdParams ecPublicKeyParams;
        void *pParams;
    } oidParams;
} TestAlgoIdData;

static TestAlgoIdData pAlgoIdTestData[] = {
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    {
        "openssl_keys/dsa_1024_pri_key_p8.der",
        akt_dsa,
        "openssl_keys/dsa_1024_cert.der",
        ALG_ID_DSA_OID,
        { .pParams = NULL }
    },
    {
        "openssl_keys/dsa_2048_pri_key_p8.der",
        akt_dsa,
        "openssl_keys/dsa_2048_cert.der",
        ALG_ID_DSA_OID,
        { .pParams = NULL }
    },
#endif
    {
        "openssl_keys/ecc_192_pri_key_p8.der",
        akt_ecc,
        "openssl_keys/ecc_192_cert.der",
        ALG_ID_EC_PUBLIC_KEY_OID,
        {
            .ecPublicKeyParams = {
                cid_EC_P192
            }
        },
    },
    {
        "openssl_keys/ecc_224_pri_key_p8.der",
        akt_ecc,
        "openssl_keys/ecc_224_cert.der",
        ALG_ID_EC_PUBLIC_KEY_OID,
        {
            .ecPublicKeyParams = {
                cid_EC_P224
            }
        },
    },
    {
        "openssl_keys/ecc_256_pri_key_p8.der",
        akt_ecc,
        "openssl_keys/ecc_256_cert.der",
        ALG_ID_EC_PUBLIC_KEY_OID,
        {
            .ecPublicKeyParams = {
                cid_EC_P256
            }
        }
    },
    {
        "openssl_keys/ecc_384_pri_key_p8.der",
        akt_ecc,
        "openssl_keys/ecc_384_cert.der",
        ALG_ID_EC_PUBLIC_KEY_OID,
        {
            .ecPublicKeyParams = {
                cid_EC_P384
            }
        }
    },
    {
        "openssl_keys/ecc_521_pri_key_p8.der",
        akt_ecc,
        "openssl_keys/ecc_521_cert.der",
        ALG_ID_EC_PUBLIC_KEY_OID,
        {
            .ecPublicKeyParams = {
                cid_EC_P521
            }
        },
    },
    {
        "openssl_keys/rsa_1024_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_1024_cert.der",
        ALG_ID_RSA_ENC_OID,
        { .pParams = NULL }
    },
    {
        "openssl_keys/rsa_2048_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_2048_cert.der",
        ALG_ID_RSA_ENC_OID,
        { .pParams = NULL }
    },
    {
        "openssl_keys/rsa_3072_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_3072_cert.der",
        ALG_ID_RSA_ENC_OID,
        { .pParams = NULL }
    },
    {
        "openssl_keys/rsa_4096_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_4096_cert.der",
        ALG_ID_RSA_ENC_OID,
        { .pParams = NULL }
    },
    {
        "openssl_keys/rsa_pss_default_1024_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_default_1024_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                20,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_default_2048_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_default_2048_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                20,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_default_3072_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_default_3072_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                20,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_default_4096_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_default_4096_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                20,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_digest_1024_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_digest_1024_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                32,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_digest_2048_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_digest_2048_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                32,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_digest_3072_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_digest_3072_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                32,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_digest_4096_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_digest_4096_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                32,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_mgf_1024_pri_key_p8.der",
        akt_rsa,
        NULL,
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha256,
                20,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_mgf_2048_pri_key_p8.der",
        akt_rsa,
        NULL,
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha256,
                20,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_mgf_3072_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_mgf_3072_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha256,
                32,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_mgf_4096_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_mgf_4096_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha384,
                55,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_salt_1024_pri_key_p8.der",
        akt_rsa,
        NULL,
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha1,
                MOC_PKCS1_ALG_MGF1,
                ht_sha1,
                33,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_salt_2048_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_salt_2048_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha256,
                33,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_salt_3072_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_salt_3072_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha512,
                33,
                0xBC
            }
        }
    },
    {
        "openssl_keys/rsa_pss_non_default_salt_4096_pri_key_p8.der",
        akt_rsa,
        "openssl_keys/rsa_pss_non_default_salt_4096_cert.der",
        ALG_ID_RSA_SSA_PSS_OID,
        {
            .rsaSsaPssParams = {
                ht_sha256,
                MOC_PKCS1_ALG_MGF1,
                ht_sha384,
                45,
                0xBC
            }
        }
    },
};


static MSTATUS compareMAlgoId(MAlgoId *pParams, TestAlgoIdData *pTestData, intBoolean mustBeNull)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if (TRUE == mustBeNull)
    {
        if (NULL == pParams)
        {
            return OK;
        }
        else
        {
            return ERR_INVALID_INPUT;
        }
    }

    if (NULL == pParams || NULL == pTestData)
        return ERR_NULL_POINTER;

    if (pParams->oidFlag != pTestData->oidFlag)
        return ERR_INVALID_INPUT;

    switch (pTestData->oidFlag)
    {
        case ALG_ID_RSA_ENC_OID:
        case ALG_ID_DSA_OID:
            if (pTestData->oidParams.pParams == pParams->pParams)
            {
                status = OK;
            }
            break;

        case ALG_ID_EC_PUBLIC_KEY_OID:
            if (((EcPublicKeyAlgIdParams *) pParams->pParams)->curveId == pTestData->oidParams.ecPublicKeyParams.curveId)
            {
                status = OK;
            }
            else
            {
                status = ERR_INVALID_INPUT;
            }
            break;

        case ALG_ID_RSA_SSA_PSS_OID:
            if (((RsaSsaPssAlgIdParams *) pParams->pParams)->digestId == pTestData->oidParams.rsaSsaPssParams.digestId &&
                ((RsaSsaPssAlgIdParams *) pParams->pParams)->mgfAlgo == pTestData->oidParams.rsaSsaPssParams.mgfAlgo &&
                ((RsaSsaPssAlgIdParams *) pParams->pParams)->mgfDigestId == pTestData->oidParams.rsaSsaPssParams.mgfDigestId &&
                ((RsaSsaPssAlgIdParams *) pParams->pParams)->saltLen == pTestData->oidParams.rsaSsaPssParams.saltLen &&
                ((RsaSsaPssAlgIdParams *) pParams->pParams)->trailerField == pTestData->oidParams.rsaSsaPssParams.trailerField)
            {
                status = OK;
            }
            else
            {
                status = ERR_INVALID_INPUT;
            }
            break;

        default:
            break;
    }

    return status;
}


static MSTATUS testKeyBlob(
    TestAlgoIdData *pTestData, AsymmetricKey *pKey1, AsymmetricKey *pKey2)
{
    MSTATUS status;
    ubyte *pKeyBuf = NULL, *pKeyBuf2 = NULL;
    ubyte4 keyBufLen = 0, keyBuf2Len = 0;
    sbyte4 cmpRes = -1;
    MKeySerialize pRsaSupport[] = {
        KeySerializeRsa
    };
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    MKeySerialize pDsaSupport[] = {
        KeySerializeDsa
    };
#endif
    MKeySerialize pEccSupport[] = {
        KeySerializeEcc
    };
    MKeySerialize *pSupport;

    if (pTestData->keyType != pKey1->type || pTestData->keyType != pKey2->type)
    {
        status = ERR_BAD_KEY_TYPE;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

    status = KEYBLOB_makeKeyBlobEx(pKey1, &pKeyBuf, &keyBufLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    if (akt_dsa == pTestData->keyType)
    {
        pSupport = pDsaSupport;
    }
#endif
    if (akt_rsa == pTestData->keyType)
    {
        pSupport = pRsaSupport;
    }
    if (akt_ecc == pTestData->keyType)
    {
        pSupport = pEccSupport;
    }

    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
        pKey2, pSupport, 1, mocanaBlobVersion2, &pKeyBuf2, &keyBuf2Len);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    if (keyBuf2Len != keyBufLen)
    {
        status = ERR_BAD_LENGTH;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

    status = DIGI_MEMCMP(pKeyBuf, pKeyBuf2, keyBufLen, &cmpRes);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pKeyBuf2, keyBuf2Len, pSupport, 1, pKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(pKey2->pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = KEYBLOB_extractKeyBlobEx(pKeyBuf2, keyBufLen, pKey1);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(pKey1->pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pKeyBuf);
    DIGI_FREE((void **) &pKeyBuf2);

    return status;
}

static MSTATUS testPkcs8(
    TestAlgoIdData *pTestData, AsymmetricKey *pKey1, AsymmetricKey *pKey2)
{
    MSTATUS status;
    ubyte *pKeyBuf = NULL, *pKeyBuf2 = NULL;
    ubyte4 keyBufLen = 0, keyBuf2Len = 0;
    sbyte4 cmpRes = -1;
    MKeySerialize pRsaSupport[] = {
        KeySerializeRsa
    };
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    MKeySerialize pDsaSupport[] = {
        KeySerializeDsa
    };
#endif
    MKeySerialize pEccSupport[] = {
        KeySerializeEcc
    };
    MKeySerialize *pSupport;

    if (pTestData->keyType != pKey1->type || pTestData->keyType != pKey2->type)
    {
        status = ERR_BAD_KEY_TYPE;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    if (akt_dsa == pTestData->keyType)
    {
        pSupport = pDsaSupport;
    }
#endif
    if (akt_rsa == pTestData->keyType)
    {
        pSupport = pRsaSupport;
    }
    if (akt_ecc == pTestData->keyType)
    {
        pSupport = pEccSupport;
    }

    if (akt_dsa != pKey1->type)
    {
        status = PKCS_setPKCS8Key(MOC_HW(gpHwAccelCtx) 
            pKey1, NULL, 0, 0, NULL, 0, &pKeyBuf, &keyBufLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
            pKey1, pSupport, 1, privateKeyInfoDer, &pKeyBuf, &keyBufLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
        pKey2, pSupport, 1, privateKeyInfoDer, &pKeyBuf2, &keyBuf2Len);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    if (pTestData->keyType != akt_ecc)
    {
        if (keyBuf2Len != keyBufLen)
        {
            status = ERR_BAD_LENGTH;
            UNITTEST_STATUS(OK, status);
            goto exit;
        }

        status = DIGI_MEMCMP(pKeyBuf, pKeyBuf2, keyBufLen, &cmpRes);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        if (0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(OK, status);
            goto exit;
        }
    }

    status = CRYPTO_uninitAsymmetricKey(pKey2, NULL);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pKeyBuf2, keyBuf2Len, pSupport, 1, pKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(pKey2->pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = PKCS_getPKCS8Key(MOC_ASYM(gpHwAccelCtx) pKeyBuf, keyBufLen, pKey1);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(pKey1->pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pKeyBuf);
    DIGI_FREE((void **) &pKeyBuf2);

    return status;
}

/*------------------------------------------------------------------*/

static int testCIAsymKeyApis(TestAlgoIdData *pTestData)
{
    int ret = 0;
    MSTATUS status;
    ubyte *pDerKey = NULL, *pMocDer = NULL;
    ubyte4 derKeyLen = 0, mocDerLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKey2 = { 0 };

    status = DIGICERT_readFile(pTestData->pKeyFile, &pDerKey, &derKeyLen);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pDerKey, derKeyLen, NULL,
        &asymKey);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &asymKey, mocanaBlobVersion2, &pMocDer, &mocDerLen);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pMocDer, mocDerLen, NULL,
        &asymKey2);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    DIGI_FREE((void **) &pMocDer);
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &asymKey2, mocanaBlobVersion2, &pMocDer, &mocDerLen);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testPkcs8(pTestData, &asymKey, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = testKeyBlob(pTestData, &asymKey, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }
exit:

    if (NULL != pDerKey)
    {
        ret += UNITTEST_STATUS(OK, DIGICERT_freeReadFile(&pDerKey));
    }
    if (NULL != pMocDer)
    {
        ret += UNITTEST_STATUS(OK, DIGI_FREE((void **) &pMocDer));
    }
    ret += UNITTEST_STATUS(OK, CRYPTO_uninitAsymmetricKey(&asymKey, NULL));
    ret += UNITTEST_STATUS(OK, CRYPTO_uninitAsymmetricKey(&asymKey2, NULL));

    return ret;
}


/*------------------------------------------------------------------*/

static int testKeyFile(char *pFile)
{
    int ret = 0;
    MSTATUS status;
    ubyte *pDerKey = NULL, *pMocDer = NULL;
    ubyte4 derKeyLen = 0, mocDerLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKey2 = { 0 };
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
        KeySerializeDsa,
#endif
        KeySerializeEcc
    };
    
    status = DIGICERT_readFile(pFile, &pDerKey, &derKeyLen);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PKCS_getPKCS8Key(MOC_ASYM(gpHwAccelCtx) pDerKey, derKeyLen, &asymKey);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;


    status = PKCS_setPKCS8Key(MOC_HW(gpHwAccelCtx) &asymKey, NULL, 0, 0, NULL, 0, &pMocDer, &mocDerLen);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (NULL != pMocDer)
    {
        status = DIGI_FREE((void **) &pMocDer);
        ret += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) pDerKey, derKeyLen, pSupported, COUNTOF(pSupported),
        &asymKey2);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;



    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) &asymKey2, pSupported, COUNTOF(pSupported),
        privateKeyInfoDer, &pMocDer, &mocDerLen);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pDerKey)
    {
        ret += UNITTEST_STATUS(OK, DIGICERT_freeReadFile(&pDerKey));
    }
    if (NULL != pMocDer)
    {
        ret += UNITTEST_STATUS(OK, DIGI_FREE((void **) &pMocDer));
    }
    ret += UNITTEST_STATUS(OK, CRYPTO_uninitAsymmetricKey(&asymKey, NULL));
    ret += UNITTEST_STATUS(OK, CRYPTO_uninitAsymmetricKey(&asymKey2, NULL));

    return ret;
}

static int testReadingAllKeyFiles()
{
    int ret = 0;

    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_default_1024_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_default_2048_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_default_3072_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_default_4096_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_digest_1024_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_digest_2048_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_digest_3072_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_digest_4096_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_mgf_1024_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_mgf_2048_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_mgf_3072_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_mgf_4096_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_salt_1024_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_salt_2048_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_salt_3072_pri_key_p8.der");
    ret += testKeyFile("../../crypto/test/openssl_keys/rsa_pss_non_default_salt_4096_pri_key_p8.der");

    return ret;
}

static MSTATUS validateCertApi(
    TestAlgoIdData *pTestData
    )
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    ASN1_ITEMPTR pCertItem = NULL, pItem, pVersion, pSubjectPublicKeyInfo;
    AsymmetricKey asymKey = { 0 }, asymKey2 = { 0 }, asymKeyCopy = { 0 };

    if (NULL == pTestData->pCertFile)
    {
        status = OK;
        goto exit;
    }

    status = DIGICERT_readFile(
        pTestData->pCertFile, &pDerCert, &derCertLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    MF_attach(&mf, derCertLen, pDerCert);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pCertItem);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) 
        ASN1_FIRST_CHILD(pCertItem), cs, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD(ASN1_FIRST_CHILD(pCertItem));

    status = ASN1_GetChildWithTag(pItem, 0, &pVersion);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = ASN1_GetNthChild(pItem, pVersion ? 7 : 6, &pSubjectPublicKeyInfo);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    if (akt_rsa == asymKey.type)
    {
        status = X509_extractRSAKey(MOC_RSA(gpHwAccelCtx) 
            pSubjectPublicKeyInfo, cs, &asymKey2);
        UNITTEST_STATUS(OK, status);
    }
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    else if (akt_dsa == asymKey.type)
    {
        status = X509_extractDSAKey(MOC_DSA(gpHwAccelCtx) 
            pSubjectPublicKeyInfo, cs, &asymKey2);
        UNITTEST_STATUS(OK, status);
    }
#endif
    else if (akt_ecc == asymKey.type)
    {
        status = X509_extractECCKey(MOC_ECC(gpHwAccelCtx) 
            pSubjectPublicKeyInfo, cs, &asymKey2);
        UNITTEST_STATUS(OK, status);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(OK, status);
    }
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey2.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    CRYPTO_uninitAsymmetricKey(&asymKeyCopy, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    if (NULL != pCertItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pCertItem);
    }
    DIGI_FREE((void **) &pDerCert);

    return status;
}

static MSTATUS validateNonPkcs8Format(TestAlgoIdData *pTestData)
{
    MSTATUS status;
    ubyte *pDerKey = NULL;
    ubyte4 derKeyLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKeyCopy = { 0 };
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
        KeySerializeDsa,
#endif
        KeySerializeEcc
    };
    TestAlgoIdData rsaEncParams = {
        NULL,
        akt_rsa,
        NULL,
        ALG_ID_RSA_ENC_OID,
        { .pParams = NULL }
    };
    TestAlgoIdData dsaParams = {
        NULL,
        akt_dsa,
        NULL,
        ALG_ID_DSA_OID,
        { .pParams = NULL }
    };
    TestAlgoIdData ecPublicKeyParams = {
        NULL,
        akt_ecc,
        NULL,
        ALG_ID_EC_PUBLIC_KEY_OID,
        { .ecPublicKeyParams = {
                0
            }
        }
    };

    status = DIGICERT_readFile(pTestData->pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pDerKey, derKeyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_FREE((void **) &pDerKey);

    if (akt_rsa == asymKey.type)
    {
        status = PKCS_setPKCS1Key(MOC_RSA(gpHwAccelCtx) &asymKey, &pDerKey, &derKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = PKCS_getPKCS1Key(MOC_RSA(gpHwAccelCtx) pDerKey, derKeyLen, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = compareMAlgoId(asymKey.pAlgoId, &rsaEncParams, TRUE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = compareMAlgoId(asymKeyCopy.pAlgoId, &rsaEncParams, TRUE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    else if (akt_dsa == asymKey.type)
    {
        status = PKCS_setDsaDerKey(MOC_DSA(gpHwAccelCtx) 
            &asymKey, &pDerKey, &derKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = PKCS_getDSAKey(MOC_DSA(gpHwAccelCtx) pDerKey, derKeyLen, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = compareMAlgoId(asymKey.pAlgoId, &dsaParams, TRUE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = compareMAlgoId(asymKeyCopy.pAlgoId, &dsaParams, TRUE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }
#endif
    else if (akt_ecc == asymKey.type)
    {
        status = SEC_setKey(MOC_ASYM(gpHwAccelCtx) 
            &asymKey, &pDerKey, &derKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = SEC_getKey(MOC_ECC(gpHwAccelCtx) pDerKey, derKeyLen, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        ecPublicKeyParams.oidParams.ecPublicKeyParams.curveId = CRYPTO_getECCurveId(&asymKey);

        status = compareMAlgoId(asymKey.pAlgoId, &ecPublicKeyParams, TRUE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = compareMAlgoId(asymKeyCopy.pAlgoId, &ecPublicKeyParams, TRUE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:

    CRYPTO_uninitAsymmetricKey(&asymKeyCopy, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    DIGI_FREE((void **) &pDerKey);

    return status;
}

static MSTATUS validatePkcs8Api(TestAlgoIdData *pTestData)
{
    MSTATUS status;
    ubyte *pDerKey = NULL, *pMocKey = NULL;
    ubyte4 derKeyLen = 0, mocKeyLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKeyCopy = { 0 };
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
        KeySerializeDsa,
#endif
        KeySerializeEcc
    };

    status = DIGICERT_readFile(
        pTestData->pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = PKCS_getPKCS8Key(MOC_ASYM(gpHwAccelCtx) pDerKey, derKeyLen, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    if (akt_dsa != asymKey.type)
    {
        status = PKCS_setPKCS8Key(MOC_HW(gpHwAccelCtx) 
            &asymKey, NULL, 0, 0, NULL, 0, &pMocKey, &mocKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = PKCS_getPKCS8Key(MOC_ASYM(gpHwAccelCtx) pMocKey, mocKeyLen, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pMocKey);

        status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pDerKey, derKeyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
        &asymKey, pSupported, COUNTOF(pSupported), privateKeyInfoDer, &pMocKey,
        &mocKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pMocKey, mocKeyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pMocKey);
    DIGI_FREE((void **) &pDerKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKeyCopy, NULL);

    return status;
}

static MSTATUS validateKeyBlobApi(TestAlgoIdData *pTestData)
{
    MSTATUS status;
    ubyte *pDerKey = NULL, *pMocKey = NULL;
    ubyte4 derKeyLen = 0, mocKeyLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKeyCopy = { 0 };

    status = DIGICERT_readFile(
        pTestData->pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = PKCS_getPKCS8Key(MOC_ASYM(gpHwAccelCtx) 
        pDerKey, derKeyLen, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = KEYBLOB_makeKeyBlobEx(&asymKey, &pMocKey, &mocKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    status = KEYBLOB_extractKeyBlobEx(pMocKey, mocKeyLen, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_copyAsymmetricKey(&asymKeyCopy, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKeyCopy.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pMocKey);
    DIGI_FREE((void **) &pDerKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKeyCopy, NULL);

    return status;
}

/* APIs to test
 * - X509_extractRSAKey
 * - X509_extractDSAKey
 * - X509_extractECCKey
 * - X509_setKeyFromSubjectPublicKeyInfo
 * - KEYBLOB_makeKeyBlobEx
 * - KEYBLOB_extractKeyBlobEx
 * - PKCS_getPKCS8Key
 * - PKCS_getPKCS8KeyEx
 * - PKCS_setPKCS8Key
 * - CRYPTO_copyAsymmetricKey
 * - CRYPTO_uninitAsymmetricKey
 * - CRYPTO_serializeKey
 * - CRYPTO_deserializeKey
 */
static int testAsymKeyApis(TestAlgoIdData *pTestData)
{
    MSTATUS status;
    int ret = 0;
    ubyte *pDerKey = NULL;
    ubyte4 derKeyLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKey2 = { 0 };
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
        KeySerializeDsa,
#endif
        KeySerializeEcc
    };

    status = DIGICERT_readFile(
        pTestData->pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = PKCS_getPKCS8Key(MOC_ASYM(gpHwAccelCtx) pDerKey, derKeyLen, &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pDerKey, derKeyLen, pSupported, 3, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = compareMAlgoId(asymKey.pAlgoId, pTestData, FALSE);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = testPkcs8(pTestData, &asymKey, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = testKeyBlob(pTestData, &asymKey, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }


exit:

    if (OK != status)
    {
        ret = 1;
    }

    DIGI_FREE((void **) &pDerKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);

    return ret;
}

/* APIs which handle AsymmetricKeys (Not all of them, just the relevant ones)
 *
 * X509_extractRSAKey
 *     Create AsymmetricKey from SubjectPublicKeyInfo
 * X509_extractDSAKey
 *     Create AsymmetricKey from SubjectPublicKeyInfo
 * X509_extractECCKey
 *     Create AsymmetricKey from SubjectPublicKeyInfo
 * X509_setKeyFromSubjectPublicKeyInfo
 *     Create AsymmetricKey from Certificate
 * CA_MGMT_makeKeyBlobEx - just calls KEYBLOB_makeKeyBlobEx
 *     Convert AsymmetricKey to key blob
 * CA_MGMT_extractKeyBlobEx - just calls KEYBLOB_extractKeyBlobEx
 *     Create AsymmetricKey from key blob
 * KEYBLOB_makeKeyBlobEx
 *     Convert AsymmetricKey to key blob
 * KEYBLOB_extractKeyBlobEx
 *     Create AsymmetricKey from key blob
 * KEYBLOB_readDSAKeyPart
 *     Create AsymmetricKey from version 1 key blob
 * KEYBLOB_readECCKeyPart
 *     Create AsymmetricKey from version 1 key blob
 * KEYBLOB_readRSAKeyPart
 *     Create AsymmetricKey from version 1 key blob
 * KEYBLOB_readDSAKeyPartV2
 *     Create AsymmetricKey from version 2 key blob
 * KEYBLOB_readECCKeyPartV2
 *     Create AsymmetricKey from version 2 key blob
 * KEYBLOB_readRSAKeyPartV2
 *     Create AsymmetricKey from version 2 key blob
 * KEYBLOB_readOldRSAKeyBlob
 *     Create AsymmetricKey from old key blob
 * KEYBLOB_readHSMRSAKeyPart
 *     Create AsymmetricKey from key blob
 * PKCS_getPKCS1Key
 *     Create AsymmetricKey from PKCS#1 RSA key
 * PKCS_getDSAKey
 *     Create AsymmetricKey from raw DSA key
 * PKCS_getPKCS8Key
 *     Create AsymmetricKey from PKCS#8
 * PKCS_getPKCS8KeyEx
 *     Create AsymmetricKey from PKCS#8
 * PKCS_setPKCS1Key
 *     Convert AsymmetricKey to PKCS#1 RSA key
 * PKCS_setDsaDerKey
 *     Convert AsymmetricKey to raw DSA key
 * PKCS_setPKCS8Key
 *     Convert AsymmetricKey to PKCS#8
 * CRYPTO_copyAsymmetricKey
 *     Copy AsymmetricKey to another AsymmetricKey
 * CRYPTO_uninitAsymmetricKey
 *     Free AsymmetricKey data
 * CRYPTO_serializeKey
 * CRYPTO_deserializeKey
 *     KeySerializeRsa
 *         Convert AsymmetricKey to PKCS#8 or SubjectPublicKeyInfo
 *         Create AsymmetricKey from PKCS#1, PKCS#8, or blob
 *     KeySerializeDsa
 *         Convert AsymmetricKey to PKCS#8 or SubjectPublicKeyInfo
 *         Create AsymmetricKey from raw, PKCS#8, or blob
 *     KeySerializeEcc
 *         Convert AsymmetricKey to PKCS#8 or SubjectPublicKeyInfo
 *         Create AsymmetricKey from SEC1, PKCS#8, or blob
 * SEC_getKey
 *     Create AsymmetricKey from SEC1 buffer
 * SEC_getPrivateKey
 *     Create AsymmetricKey from SEC1 ASN.1 object
 * SEC_setKey
 *     Convert AsymmetricKey to SEC1 with curve
 * SEC_setKeyEx
 *     Convert AsymmetricKey to SEC1 with or without curve
 */
int testLoadingAllKeys()
{
    int ret = 0;
    ubyte4 i;

    for (i = 0; i < COUNTOF(pAlgoIdTestData); i++)
    {
        ret += testAsymKeyApis(pAlgoIdTestData + i);
        ret += testCIAsymKeyApis(pAlgoIdTestData + i);
        ret += ((OK == validateKeyBlobApi(pAlgoIdTestData + i)) ? 0 : 1);
        ret += ((OK == validatePkcs8Api(pAlgoIdTestData + i)) ? 0 : 1);
        ret += ((OK == validateNonPkcs8Format(pAlgoIdTestData + i)) ? 0 : 1);
        ret += ((OK == validateCertApi(pAlgoIdTestData + i)) ? 0 : 1);
    }

    return ret;
}


#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

/* Points to qa-m-products/ssl_test/keystore
 */
#define KEYSTORE_DIR STRINGIZE_VALUE_OF(QA_M_PRODUCTS_DIR) "/ssl_test/keystore/"

static MSTATUS testQAKeyFile(char *pKeyFile)
{
    MSTATUS status;
    ubyte *pKey = NULL;
    ubyte4 keyLen;
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
        KeySerializeDsa,
#endif
        KeySerializeEcc
    };
    AsymmetricKey asymKey = { 0 };

    status = DIGICERT_readFile(pKeyFile, &pKey, &keyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pKey, keyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    DIGICERT_freeReadFile(&pKey);

    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
        &asymKey, pSupported, COUNTOF(pSupported), privateKeyInfoDer,
        &pKey, &keyLen);
    UNITTEST_STATUS(OK, status);

exit:

    DIGICERT_freeReadFile(&pKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

int testQAProductsKeys()
{
#ifdef QA_M_PRODUCTS_DIR
    int ret = 0;

    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ClientECCCertCA384Key.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ClientECCCertCA384Key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ClientECCCertCA384Key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ClientRSACertKey.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ClientRSACertKey.der"));
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ClientRSACertKey.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "DSACertCA1024Key.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "DSACertCA1024Key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "DSACertCA1024Key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "DSACertCAKey.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "DSACertCAKey.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "DSACertCAKey.pem"));
#endif
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ECCCertCA384Key.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ECCCertCA384Key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ECCCertCA384Key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "ipaddr_server_pemkey.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_ec_ca_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_ecdsa_cert_rsa_ca_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_ecdsa_key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_ecdsa_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_rsa_key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_rsa_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_rsa_nocrypt_pkcs8_key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "openssl_rsa_nocrypt_pkcs8_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "opt123_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "qa_est2_ecdsa_sw_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "RSACertCAKey.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "RSACertCAKey.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "RSACertCAKey.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_client_key.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_client_key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_client_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_key_ecdsa.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_key_rsa.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_server_key.dat"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_server_key.der"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "titan_server_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "uri_server_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "xerox_ecdsa_key.pem"));
    ret += UNITTEST_STATUS(OK, testQAKeyFile(KEYSTORE_DIR "xerox_sample_key.pem"));

    return ret;
#else
#ifdef __RTOS_LINUX__
    printf("Skipping testQAProductsKeys test...\n");
#endif
    return 0;
#endif
}

/* Test to load in a certificate and test whether the certificate can be
 * searched for with RSA SSA-PSS.
 */
static int testRsaPssCertKeyPair(char *pCertFile, char *pKeyFile)
{
    MSTATUS status;
    int ret = 0;
    certStorePtr pCertStore = NULL;
    ubyte *pCert = NULL, *pKey = NULL;
    ubyte4 certLen, keyLen, certCount;
    SizedBuffer certificate;
    const AsymmetricKey *pPrivateKey = NULL;
    const SizedBuffer *pCertificates = NULL;
    void *pIterator = NULL;

    status = CERT_STORE_createStore(&pCertStore);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(pCertFile, &pCert, &certLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(pKeyFile, &pKey, &keyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    certificate.length = certLen;
    certificate.data = pCert;

    status = CERT_STORE_addIdentityWithCertificateChain(
            pCertStore, &certificate, 1, pKey, keyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CERT_STORE_addIdentityWithCertificateChain(
            pCertStore, &certificate, 1, pKey, keyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* Call without the RSA PSS key type. This should not find any identities.
     */
    status = CERT_STORE_findIdentityCertChainFirstEx(
            pCertStore, akt_rsa, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA, &pPrivateKey, &pCertificates, &certCount,
            &pIterator);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if ( (NULL != pPrivateKey) || (NULL != pCertificates) || (0 != certCount) )
    {
        status = ERR_CERT_STORE;
        goto exit;
    }

    /* Call with the RSA PSS key type. This should find the certificate and key.
     */
    status = CERT_STORE_findIdentityCertChainFirstEx(
            pCertStore, akt_rsa_pss, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_INTRINSIC,
            &pPrivateKey, &pCertificates, &certCount, &pIterator);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if ( (NULL == pPrivateKey) || (NULL == pCertificates) || (0 == certCount) )
    {
        status = ERR_CERT_STORE;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

    pPrivateKey = NULL;
    pCertificates = NULL;
    certCount = 0;

    /* Get the next identity. The same identity was added twice so it should be
     * picked up again.
     */
    status = CERT_STORE_findIdentityCertChainNextEx(
            pCertStore, akt_rsa_pss, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_INTRINSIC,
            &pPrivateKey, &pCertificates, &certCount, &pIterator);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if ( (NULL == pPrivateKey) || (NULL == pCertificates) || (0 == certCount) )
    {
        status = ERR_CERT_STORE;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* There should be no more identities.
     */
    status = CERT_STORE_findIdentityCertChainNextEx(
            pCertStore, akt_rsa_pss, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA, &pPrivateKey, &pCertificates, &certCount,
            &pIterator);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if ( (NULL != pPrivateKey) || (NULL != pCertificates) || (0 != certCount) )
    {
        status = ERR_CERT_STORE;
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

exit:

    ret += UNITTEST_STATUS(OK, DIGICERT_freeReadFile(&pKey));
    ret += UNITTEST_STATUS(OK, DIGICERT_freeReadFile(&pCert));
    ret += UNITTEST_STATUS(OK, CERT_STORE_releaseStore(&pCertStore));

    return ret;
}


/*------------------------------------------------------------------*/

/* This function takes a self signed certificate and validates its
 * signature. */
static int verifyRsaSignatureTest(char *pCertFile)
{
    MSTATUS status = ERR_NULL_POINTER;
    CStream cs;
    MemFile mf;
    MAlgoId *pAlgoId = NULL;
    intBoolean isPrivate;
    ubyte *pDerCert = NULL, *pGetAlgId = NULL;
    ubyte4 derCertLen = 0, algIdLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKey2 = { 0 };
    ASN1_ITEMPTR pCertItem = NULL, pItem, pVersion, pSubjectPublicKeyInfo;
    ubyte pRsaPssOid[MOP_RSA_PSS_OID_LEN] = {
        MOP_RSA_PSS_OID
    };

    if (NULL == pCertFile)
    {
        UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* read certificate file */
    status = DIGICERT_readFile(pCertFile, &pDerCert, &derCertLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, derCertLen, pDerCert);
    CS_AttachMemFile(&cs, &mf);

    /* get ASN1_ITEMPTR to certificate */
    status = ASN1_Parse(cs, &pCertItem);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* get public key from certificate */
    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) 
        ASN1_FIRST_CHILD(pCertItem), cs, &asymKey2);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* verify signature in certificate with public key */
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    status = X509_verifySignature(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pCertItem), cs, &asymKey2);
    UNITTEST_STATUS(OK, status);
#endif
    
exit:
    CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    DIGI_FREE((void **) &pDerCert);
    if (NULL != pCertItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pCertItem);
    }
    if (OK != status)
        return 1;
    return 0;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
static int testEdKeys(int hint, char *pKeyFile, serializedKeyFormat format, byteBoolean checkReserialization)
{
    MSTATUS status;
    int ret = 0;
    ubyte *pDerKey = NULL;
    ubyte4 derKeyLen = 0;
    AsymmetricKey asymKey = {0};
    AsymmetricKey asymKey2 = {0};
    MKeySerialize pSupported[] =
    {
        KeySerializeRsa,
#if defined(__ENABLE_DIGICERT_DSA__ ) && !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
        KeySerializeDsa,
#endif
        KeySerializeEcc
    };

    ubyte *pReserializedKey = NULL;
    ubyte4 reserializedKeyLen = 0;
    sbyte4 compare = -1;
    byteBoolean isEqual = FALSE;
    
    status = DIGICERT_readFile(pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(hint, status);
    if (OK != status)
    {
        goto exit;
    }
  
    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) pDerKey, derKeyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(hint, status);
    if (OK != status)
    {
        goto exit;
    }
  
    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) &asymKey, pSupported, COUNTOF(pSupported), format, &pReserializedKey, &reserializedKeyLen);
    UNITTEST_STATUS(hint, status);
    if (OK != status)
    {
        goto exit;
    }
    
    if (checkReserialization)
    {
        if (reserializedKeyLen != derKeyLen)
        {
            UNITTEST_STATUS(hint, -1);
            ret = 1;
            goto exit;
        }
        
        status = DIGI_MEMCMP(pReserializedKey, pDerKey, reserializedKeyLen, &compare);
        UNITTEST_STATUS(hint, status);
        if (OK != status)
        {
            goto exit;
        }
        
        if (compare)
        {
            UNITTEST_STATUS(hint, -1);
            ret = 1;
            goto exit;
        }
    }
    
    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) pReserializedKey, reserializedKeyLen, pSupported, COUNTOF(pSupported), &asymKey2);
    UNITTEST_STATUS(hint, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(gpHwAccelCtx) asymKey2.key.pECC, asymKey.key.pECC, &isEqual);
    UNITTEST_STATUS(hint, status);
    if (OK != status)
    {
        goto exit;
    }
    
    if (!isEqual)
    {
        UNITTEST_STATUS(hint, -1);
        ret = 1;
        goto exit;
    }

exit:
    
    if (OK != status)
    {
        ret = 1;
    }
    
    DIGI_FREE((void **) &pDerKey);
    DIGI_FREE((void **) &pReserializedKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    
    return ret;
}
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */


int crypto_interface_serialization_unit_test_init()
{
    int errorCount = 0;
    MSTATUS status = ERR_NULL_POINTER;
    
    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
#endif

    errorCount += testReadingAllKeyFiles();
    errorCount += testLoadingAllKeys();
    errorCount += testQAProductsKeys();
    errorCount += testRsaPssCertKeyPair(
        "../../crypto/test/rsa_pss_pss_leaf_cert.der", "../../crypto/test/rsa_pss_leaf_key.dat");
    /* Test disabled since saltLen for cert is 94, greater than the hashLen, not allowed by FIPS 186-5. 
    errorCount += verifyRsaSignatureTest(
        "../../crypto/test/openssl_keys/rsa_pss_default_1024_cert.der"); */
    errorCount += verifyRsaSignatureTest(
        "../../crypto/test/openssl_keys/rsa_2048_cert.der");
  
/* EdDSA still goes through crypto interface only. Otherwise some pubcrypto methods will not work */
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    errorCount += testEdKeys(0, "key25519.der", mocanaBlobVersion2, FALSE);
    errorCount += testEdKeys(1, "key25519wpub.der", mocanaBlobVersion2, FALSE);
    errorCount += testEdKeys(2, "key25519withExtra.der", mocanaBlobVersion2, FALSE);
    errorCount += testEdKeys(3, "pubkey25519.der", mocanaBlobVersion2, FALSE);
  
    errorCount += testEdKeys(4, "key25519.der", privateKeyInfoDer, FALSE);
#ifdef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
    errorCount += testEdKeys(5, "key25519wpub.der", privateKeyInfoDer, TRUE);
#else
    errorCount += testEdKeys(5, "key25519wpub.der", privateKeyInfoDer, FALSE);
#endif
    errorCount += testEdKeys(6, "key25519withExtra.der", privateKeyInfoDer, FALSE);
    errorCount += testEdKeys(7, "pubkey25519.der", publicKeyInfoDer, TRUE);
  
    errorCount += testEdKeys(8, "key25519.der", privateKeyPem, FALSE);
    errorCount += testEdKeys(9, "key25519wpub.der", privateKeyPem, FALSE);
    errorCount += testEdKeys(10, "key25519withExtra.der", privateKeyPem, FALSE);
    errorCount += testEdKeys(11, "pubkey25519.der", publicKeyPem, FALSE);
#endif
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    errorCount += testEdKeys(12, "key448.der", mocanaBlobVersion2, FALSE);
    errorCount += testEdKeys(13, "key448wpub.der", mocanaBlobVersion2, FALSE);
    errorCount += testEdKeys(14, "pubkey448.der", mocanaBlobVersion2, FALSE);
  
    errorCount += testEdKeys(15, "key448.der", privateKeyInfoDer, FALSE);
#ifdef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
    errorCount += testEdKeys(16, "key448wpub.der", privateKeyInfoDer, TRUE);
#else
    errorCount += testEdKeys(16, "key448wpub.der", privateKeyInfoDer, FALSE);
#endif
    errorCount += testEdKeys(17, "pubkey448.der", publicKeyInfoDer, TRUE);
  
    errorCount += testEdKeys(18, "key448.der", privateKeyPem, FALSE);
    errorCount += testEdKeys(19, "key448wpub.der", privateKeyPem, FALSE);
    errorCount += testEdKeys(20, "pubkey448.der", publicKeyPem, FALSE);
#endif
    
exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);

    return errorCount;
}

