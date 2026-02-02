/*
 * malgo_id_test.c
 *
 * unit test for malgo_id.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

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

#include "../../../unit_tests/unittest.h"

static int testKeyFile(char *pFile)
{
    int ret = 0;
    ubyte *pDerKey = NULL, *pMocDer = NULL;
    ubyte4 derKeyLen = 0, mocDerLen = 0;
    AsymmetricKey asymKey = { 0 }, asymKey2 = { 0 };
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
        KeySerializeDsa,
        KeySerializeEcc
    };

    UNITTEST_STATUS_GOTO(
        OK, DIGICERT_readFile(pFile, &pDerKey, &derKeyLen), ret, exit);

    UNITTEST_STATUS_GOTO(
        OK, PKCS_getPKCS8Key(pDerKey, derKeyLen, &asymKey), ret, exit);

    UNITTEST_STATUS_GOTO(
        OK, PKCS_setPKCS8Key(
            &asymKey, NULL, 0, 0, NULL, 0, &pMocDer, &mocDerLen), ret,
        exit);

    if (NULL != pMocDer)
    {
        UNITTEST_STATUS_GOTO(OK, DIGI_FREE((void **) &pMocDer), ret, exit);
    }

    UNITTEST_STATUS_GOTO(
        OK, CRYPTO_deserializeKey(
            pDerKey, derKeyLen, pSupported, COUNTOF(pSupported), &asymKey2),
        ret, exit);

    UNITTEST_STATUS_GOTO(
        OK, CRYPTO_serializeKey(&asymKey2, pSupported, COUNTOF(pSupported),
            privateKeyInfoDer, &pMocDer, &mocDerLen), ret, exit);

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

int malgo_id_test_init()
{
    int ret = 0;

    ret += testKeyFile("openssl_keys/rsa_pss_default_1024_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_default_2048_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_default_3072_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_default_4096_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_digest_1024_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_digest_2048_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_digest_3072_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_digest_4096_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_mgf_1024_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_mgf_2048_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_mgf_3072_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_mgf_4096_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_salt_1024_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_salt_2048_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_salt_3072_pri_key_p8.der");
    ret += testKeyFile("openssl_keys/rsa_pss_non_default_salt_4096_pri_key_p8.der");

    return ret;
}

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

    status = X509_setKeyFromSubjectPublicKeyInfo(
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

    if (akt_dsa == asymKey.type)
    {
        status = X509_extractDSAKey(
            pSubjectPublicKeyInfo, cs, &asymKey2);
        UNITTEST_STATUS(OK, status);
    }
    else if (akt_rsa == asymKey.type)
    {
        status = X509_extractRSAKey(
            pSubjectPublicKeyInfo, cs, &asymKey2);
        UNITTEST_STATUS(OK, status);
    }
    else if (akt_ecc == asymKey.type)
    {
        status = X509_extractECCKey(
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
        KeySerializeDsa,
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

    status = CRYPTO_deserializeKey(
        pDerKey, derKeyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_FREE((void **) &pDerKey);

    if (akt_rsa == asymKey.type)
    {
        status = PKCS_setPKCS1Key(&asymKey, &pDerKey, &derKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = PKCS_getPKCS1Key(pDerKey, derKeyLen, &asymKey);
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
    else if (akt_dsa == asymKey.type)
    {
        status = PKCS_setDsaDerKey(
            &asymKey, &pDerKey, &derKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = PKCS_getDSAKey(pDerKey, derKeyLen, &asymKey);
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
    else if (akt_ecc == asymKey.type)
    {
        status = SEC_setKey(
            &asymKey, &pDerKey, &derKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = SEC_getKey(pDerKey, derKeyLen, &asymKey);
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
        KeySerializeDsa,
        KeySerializeEcc
    };

    status = DIGICERT_readFile(
        pTestData->pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = PKCS_getPKCS8Key(pDerKey, derKeyLen, &asymKey);
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
        status = PKCS_setPKCS8Key(
            &asymKey, NULL, 0, 0, NULL, 0, &pMocKey, &mocKeyLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        status = PKCS_getPKCS8Key(pMocKey, mocKeyLen, &asymKey);
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

    status = CRYPTO_deserializeKey(
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

    status = CRYPTO_serializeKey(
        &asymKey, pSupported, COUNTOF(pSupported), privateKeyInfoDer, &pMocKey,
        &mocKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    status = CRYPTO_deserializeKey(
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

    status = PKCS_getPKCS8Key(
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
    MKeySerialize pDsaSupport[] = {
        KeySerializeDsa
    };
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

    if (akt_dsa == pTestData->keyType)
    {
        pSupport = pDsaSupport;
    }
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
        status = PKCS_setPKCS8Key(
            pKey1, NULL, 0, 0, NULL, 0, &pKeyBuf, &keyBufLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        status = CRYPTO_serializeKey(
            pKey1, pSupport, 1, privateKeyInfoDer, &pKeyBuf, &keyBufLen);
        UNITTEST_STATUS(OK, status);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = CRYPTO_serializeKey(
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

    status = CRYPTO_deserializeKey(
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

    status = PKCS_getPKCS8Key(pKeyBuf, keyBufLen, pKey1);
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
    MKeySerialize pDsaSupport[] = {
        KeySerializeDsa
    };
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

    if (akt_dsa == pTestData->keyType)
    {
        pSupport = pDsaSupport;
    }
    if (akt_rsa == pTestData->keyType)
    {
        pSupport = pRsaSupport;
    }
    if (akt_ecc == pTestData->keyType)
    {
        pSupport = pEccSupport;
    }

    status = CRYPTO_serializeKey(
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

    status = CRYPTO_deserializeKey(
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
        KeySerializeDsa,
        KeySerializeEcc
    };

    status = DIGICERT_readFile(
        pTestData->pKeyFile, &pDerKey, &derKeyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = PKCS_getPKCS8Key(pDerKey, derKeyLen, &asymKey);
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

    status = CRYPTO_deserializeKey(
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
int malgo_id_test_loading_keys()
{
    int ret = 0;
    ubyte4 i;

    for (i = 0; i < COUNTOF(pAlgoIdTestData); i++)
    {
        ret += testAsymKeyApis(pAlgoIdTestData + i);
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

static MSTATUS testKeyFileAll(char *pKeyFile)
{
    MSTATUS status;
    ubyte *pKey = NULL;
    ubyte4 keyLen;
    MKeySerialize pSupported[] = {
        KeySerializeRsa,
        KeySerializeDsa,
        KeySerializeEcc
    };
    AsymmetricKey asymKey = { 0 };

    status = DIGICERT_readFile(pKeyFile, &pKey, &keyLen);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_deserializeKey(
        pKey, keyLen, pSupported, COUNTOF(pSupported), &asymKey);
    UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        goto exit;
    }

    DIGICERT_freeReadFile(&pKey);

    status = CRYPTO_serializeKey(
        &asymKey, pSupported, COUNTOF(pSupported), privateKeyInfoDer,
        &pKey, &keyLen);
    UNITTEST_STATUS(OK, status);

exit:

    DIGICERT_freeReadFile(&pKey);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

int malgo_id_test_qa_m_products()
{
#ifdef QA_M_PRODUCTS_DIR
    int ret = 0;

    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ClientECCCertCA384Key.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ClientECCCertCA384Key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ClientECCCertCA384Key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ClientRSACertKey.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ClientRSACertKey.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ClientRSACertKey.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "DSACertCA1024Key.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "DSACertCA1024Key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "DSACertCA1024Key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "DSACertCAKey.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "DSACertCAKey.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "DSACertCAKey.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ECCCertCA384Key.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ECCCertCA384Key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ECCCertCA384Key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "ipaddr_server_pemkey.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_ec_ca_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_ecdsa_cert_rsa_ca_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_ecdsa_key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_ecdsa_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_rsa_key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_rsa_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_rsa_nocrypt_pkcs8_key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "openssl_rsa_nocrypt_pkcs8_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "opt123_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "qa_est2_ecdsa_sw_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "RSACertCAKey.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "RSACertCAKey.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "RSACertCAKey.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_client_key.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_client_key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_client_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_key_ecdsa.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_key_rsa.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_server_key.dat"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_server_key.der"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "titan_server_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "uri_server_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "xerox_ecdsa_key.pem"));
    ret += UNITTEST_STATUS(OK, testKeyFileAll(KEYSTORE_DIR "xerox_sample_key.pem"));

    return ret;
#else
#ifdef __RTOS_LINUX__
    printf("Skipping test...\n");
#endif
    return 0;
#endif
}
