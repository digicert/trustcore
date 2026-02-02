/*
 * crypto_interface_cv_cert_test.c
 *
 * test cases for cvcert.h 
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

#ifdef __ENABLE_DIGICERT_CV_CERT__

#include "../../common/initmocana.h"
#include "../../common/mocana.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/crypto.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto/cvcert.h"

#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#include "../../crypto_interface/crypto_interface_ecc.h"

#include "../../crypto/cert_store.h"
#include "../../crypto/cert_chain.h"

#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/* prototype for method in crypto_keygen.c */ 
int KEYGEN_main(int argc, char *argv[]);

#define TOTAL_TESTS 19
#define MAX_ARGS 28
#define SELF_SIGNED_TESTS 9

#define CERT_NAME_INDEX 8
#define PARENT_CERT_NAME_INDEX 26

/* If test fails with ERR_CERT_EXPIRED, update this date */
#ifndef TODAYS_DATE
#define TODAYS_DATE "231022"
#endif

static char *gpTest[TOTAL_TESTS][MAX_ARGS] =
{
    /* self signed 0 to 8 */
    {"tc_keygen","-a","ECC","-c","P192","-o","cv_key192","-cvc","cv_cert192","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghz",
    "-cvs","z192y","-cva","060904007f0007030102015301c3","-da","10958","-kd","sha1", },

    {"tc_keygen","-a","ECC","-c","P224","-o","cv_key224","-cvc","cv_cert224","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghy",
    "-cvs","z224y","-cva","060904007f0007030102015301c3","-da","7305","-kd","sha224", },

    {"tc_keygen","-a","ECC","-c","P256","-o","cv_key256","-cvc","cv_cert256","-cve",TODAYS_DATE,"-cvo","KR","-cvm","abcdefghx",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","10593","-kd","sha256", },

    {"tc_keygen","-a","ECC","-c","P384","-o","cv_key384","-cvc","cv_cert384","-cve",TODAYS_DATE,"-cvo","FR","-cvm","abcdefghw",
    "-cvs","z384y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha384", },

    {"tc_keygen","-a","ECC","-c","P521","-o","cv_key521","-cvc","cv_cert521","-cve",TODAYS_DATE,"-cvm","abcdefght",
    "-cvs","z521y","-cva","060904007f0007030102015301c3","-da","18263","-kd","sha512", },

    {"tc_keygen","-a","RSA","-s","1024","-o","cv_key1024","-cvc","cv_cert1024","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghr",
    "-cvs","z192y","-cva","060904007f0007030102015301c3","-da","10958","-kd","sha1", },

    {"tc_keygen","-a","RSA","-s","1024","-o","cv_key1024pss","-cvc","cv_cert1024pss","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghs",
    "-cvs","z192y","-cva","060904007f0007030102015301c3","-da","10958","-kd","sha1","-pss", },

    {"tc_keygen","-a","RSA","-s","2048","-o","cv_key2048","-cvc","cv_cert2048","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghq",
    "-cvs","z192y","-cva","060904007f0007030102015301c3","-da","10958","-kd","sha256", },

    {"tc_keygen","-a","RSA","-s","2048","-o","cv_key2048pss","-cvc","cv_cert2048pss","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghp",
    "-cvs","z192y","-cva","060904007f0007030102015301c3","-da","10958","-kd","sha256","-pss", },

    /* signed by P256 index 2 */
    {"tc_keygen","-a","ECC","-c","P256","-o","cv_key256_s256","-cvc","cv_cert256_s256","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefgha",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key256","-sc","cv_cert256", },

    {"tc_keygen","-a","ECC","-c","P521","-o","cv_key521_s256","-cvc","cv_cert521_s256","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghb",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key256","-sc","cv_cert256", },

    {"tc_keygen","-a","RSA","-s","1024","-o","cv_key1024_s256","-cvc","cv_cert1024_s256","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghc",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key256","-sc","cv_cert256", },

    {"tc_keygen","-a","RSA","-s","2048","-o","cv_key2048pss_s256","-cvc","cv_cert2048pss_s256","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghd",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key256","-sc","cv_cert256","-pss"},

    /* signed by RSA2048 index 7 */
    {"tc_keygen","-a","ECC","-c","P256","-o","cv_key256_s2048","-cvc","cv_cert256_s2048","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghe",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key2048","-sc","cv_cert2048", },

    {"tc_keygen","-a","RSA","-s","1024","-o","cv_key1024_s2048","-cvc","cv_cert1024_s2048","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghf",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key2048","-sc","cv_cert2048", },

    {"tc_keygen","-a","RSA","-s","2048","-o","cv_key2048pss_s2048","-cvc","cv_cert2048pss_s2048","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghg",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key2048","-sc","cv_cert2048","-pss"},

    /* signed by RSA2048pss index 8 */
    {"tc_keygen","-a","ECC","-c","P256","-o","cv_key256_s2048pss","-cvc","cv_cert256_s2048pss","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghh",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key2048pss","-sc","cv_cert2048pss", },

    {"tc_keygen","-a","RSA","-s","1024","-o","cv_key1024_s2048pss","-cvc","cv_cert1024_s2048pss","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghi",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key2048pss","-sc","cv_cert2048pss", },

    {"tc_keygen","-a","RSA","-s","2048","-o","cv_key2048pss_s2048pss","-cvc","cv_cert2048pss_s2048pss","-cve",TODAYS_DATE,"-cvo","US","-cvm","abcdefghj",
    "-cvs","z256y","-cva","060904007f0007030102015301c3","-da","9132","-kd","sha256","-sk","cv_key2048pss","-sc","cv_cert2048pss","-pss"}
};

static int gTestLen[TOTAL_TESTS] =
{
    23,23,23,23,21,23,24,23,24,27,27,27,28,27,27,28,27,27,28
};

/*----------------------------------------------------------------------------*/

int cv_cert_store_test_ex(char *pCertFile, char *pKeyFile)
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    certStorePtr pCertStore = 0;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    AsymmetricKey key = {0};
    ubyte *pBlob = NULL;
    ubyte4 blobLen = 0;
    AsymmetricKey *pFoundKey = NULL;
    ubyte *pFoundCert = NULL;
    ubyte4 foundLen = 0;
    CV_CERT *pCertData = NULL;
    sbyte4 cmp = 0;

    status = CERT_STORE_createStore(&pCertStore);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Read the key and cert */
    status = DIGICERT_readFile(pCertFile, &pCert, &certLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pKeyFile, &pKey, &keyLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Turn key into a blob */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKey, keyLen, NULL, &key);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &key, mocanaBlobVersion2, &pBlob, &blobLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Add to the cert store */
    status = CERT_STORE_addIdentityEx(pCertStore, "test", 4, pCert, certLen, pBlob, blobLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Find by alias */
    status = CERT_STORE_findIdentityByAlias(pCertStore, "test", 4, &pFoundKey, &pFoundCert, &foundLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (foundLen != certLen)
    {
        status = ERR_CMP;
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCMP(pCert, pFoundCert, foundLen, &cmp);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmp)
    {
        status = ERR_CMP;
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Reset and find by issuer serial */
    pFoundCert = NULL;
    foundLen = 0;
    cmp = 1;

    status = CV_CERT_parseCert(pCert, certLen, &pCertData);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CERT_STORE_findCertificateByIssuerSerialNumber (
        pCertStore, pCertData->pCertAuthRef, pCertData->certAuthRefLen, pCertData->pCertHolderRef,
        pCertData->certHolderRefLen, (const ubyte **)&pFoundCert, &foundLen, (const struct AsymmetricKey **)&pFoundKey);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (foundLen != certLen)
    {
        status = ERR_CMP;
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCMP(pCert, pFoundCert, foundLen, &cmp);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmp)
    {
        status = ERR_CMP;
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CRYPTO_matchPublicKey(&key, pFoundKey);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }
    if (NULL != pKey)
    {
        DIGI_FREE((void **)&pKey);
    }
    if (NULL != pBlob)
    {
        DIGI_FREE((void **)&pBlob);
    }
    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }
    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return retVal;
}

static int cv_cert_store_test_ex2(char *pCaCertName, char *pLeafCertName, char *pLeafKeyName, 
                                  ubyte4 keyType, ubyte2 keyUsage, ubyte4 algoFlag, ubyte4 expectedFound)
{
    int retVal = 0;
    MSTATUS status;
    certChainPtr pChain = NULL;
    certStorePtr pCertStore = 0;
    certDescriptor desc[1]; 
    ValidationConfig vc = { 0};
    ubyte *pCaCert = NULL;
    ubyte4 caCertLen = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;
    AsymmetricKey key = {0};
    AsymmetricKey *pFoundKey = NULL;
    ubyte *pBlob = NULL;
    ubyte4 blobLen = 0;
    SizedBuffer certs[2];
    SizedBuffer *pFoundCerts = NULL;
    ubyte4 foundCount = 0;

    status = DIGICERT_readFile(pCaCertName, &pCaCert, &caCertLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pLeafCertName, &pCert, &certLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pLeafKeyName, &pKey, &keyLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Turn key into a blob */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKey, keyLen, NULL, &key);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &key, mocanaBlobVersion2, &pBlob, &blobLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CERT_STORE_createStore(&pCertStore);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    certs[0].data = pCert;
    certs[0].length = certLen;

    certs[1].data = pCaCert;
    certs[1].length = caCertLen;

    status = CERT_STORE_addIdentityWithCertificateChainEx (
        pCertStore, "test", 4, certs, 2, pBlob, blobLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CERT_STORE_findIdentityCertChainFirstEx (
        pCertStore, keyType, keyUsage, algoFlag, (const struct AsymmetricKey **)&pFoundKey, 
        (const struct SizedBuffer **)&pFoundCerts, &foundCount, NULL);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (foundCount != expectedFound)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

exit:

    if (NULL != pCaCert)
    {
        DIGI_FREE((void **)&pCaCert);
    }
    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }
    if (NULL != pKey)
    {
        DIGI_FREE((void **)&pKey);
    }
    if (NULL != pBlob)
    {
        DIGI_FREE((void **)&pBlob);
    }
    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return retVal;
}

int cv_cert_store_test()
{
    int retVal = 0;

    retVal += cv_cert_store_test_ex("cv_cert192", "cv_key192");
    retVal += cv_cert_store_test_ex("cv_cert224", "cv_key224");
    retVal += cv_cert_store_test_ex("cv_cert256", "cv_key256");
    retVal += cv_cert_store_test_ex("cv_cert384", "cv_key384");
    retVal += cv_cert_store_test_ex("cv_cert521", "cv_key521");

    retVal += cv_cert_store_test_ex("cv_cert1024", "cv_key1024");
    retVal += cv_cert_store_test_ex("cv_cert1024pss", "cv_key1024pss");
    retVal += cv_cert_store_test_ex("cv_cert2048", "cv_key2048");
    retVal += cv_cert_store_test_ex("cv_cert2048pss", "cv_key2048pss");


    retVal += cv_cert_store_test_ex2 (
        "cv_cert256", "cv_cert256_s256", "cv_key256_s256", 
        akt_ecc, (1 << digitalSignature | 1 << keyAgreement), 
        (CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC256 | CERT_STORE_ALGO_FLAG_SHA256), 2);
    retVal += cv_cert_store_test_ex2 (
        "cv_cert256", "cv_cert521_s256", "cv_key521_s256", 
        akt_ecc, (1 << digitalSignature | 1 << keyAgreement), 
        (CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC521 | CERT_STORE_ALGO_FLAG_SHA256), 2);
    retVal += cv_cert_store_test_ex2 (
        "cv_cert256", "cv_cert1024_s256", "cv_key1024_s256", 
        akt_rsa, (1 << digitalSignature), 
        (CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_SHA256), 2);
    retVal += cv_cert_store_test_ex2 (
        "cv_cert256", "cv_cert2048pss_s256", "cv_key2048pss_s256", 
        akt_rsa_pss, (1 << digitalSignature), 
        (CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_INTRINSIC| CERT_STORE_ALGO_FLAG_SHA256), 2);
    retVal += cv_cert_store_test_ex2 (
        "cv_cert2048", "cv_cert256_s2048", "cv_key256_s2048", 
        akt_ecc, (1 << digitalSignature | 1 << keyAgreement), 
        (CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC256 | CERT_STORE_ALGO_FLAG_SHA256), 2);
    retVal += cv_cert_store_test_ex2 (
        "cv_cert2048", "cv_cert2048pss_s2048", "cv_key2048pss_s2048", 
        akt_rsa_pss, (1 << digitalSignature), 
        (CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_INTRINSIC| CERT_STORE_ALGO_FLAG_SHA256), 2);
    retVal += cv_cert_store_test_ex2 (
        "cv_cert2048pss", "cv_cert256_s2048pss", "cv_key256_s2048pss", 
        akt_ecc, (1 << digitalSignature | 1 << keyAgreement), 
        (CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC256 | CERT_STORE_ALGO_FLAG_SHA256), 2);


    return retVal;
}

/*----------------------------------------------------------------------------*/

int cv_cert_chain_test_ex2(char *pCaCertName, char *pLeafCertName)
{
    int retVal = 0;
    MSTATUS status;
    certChainPtr pChain = NULL;
    certStorePtr pCertStore = 0;
    certDescriptor desc[1]; 
    ValidationConfig vc = { 0};
    ubyte *pCaCert = NULL;
    ubyte4 caCertLen = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    TimeDate td;

    status = DIGICERT_readFile(pCaCertName, &pCaCert, &caCertLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pLeafCertName, &pCert, &certLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CERT_STORE_createStore(&pCertStore);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = CERT_STORE_CVC_addTrustPoint(pCertStore, pCaCert, caCertLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    desc[0].pCertificate = pCert;
    desc[0].certLength = certLen;

    status = CERTCHAIN_createFromCVC(MOC_ASYM(gpHwAccelCtx) &pChain, (struct certDescriptor *)&desc, 1);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = RTOS_timeGMT(&td);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    vc.td = &td;
    vc.pCertStore = pCertStore;

    status = CERTCHAIN_CVC_validate(MOC_ASYM(gpHwAccelCtx) pChain, &vc);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pCaCert)
    {
        DIGI_FREE((void **)&pCaCert);
    }
    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }
    if (NULL != pChain)
    {
        CERTCHAIN_delete(&pChain);
    }
    if (NULL != pCertStore)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }

    return retVal;
}

int cv_cert_chain_test_ex1(char *pCaCertName, char *pLeafCertName)
{
    int retVal = 0;
    MSTATUS status;
    certChainPtr pChain = NULL;
    certDescriptor desc[2]; 
    ValidationConfig vc = { 0};
    ubyte *pCaCert = NULL;
    ubyte4 caCertLen = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    TimeDate td;

    status = DIGICERT_readFile(pCaCertName, &pCaCert, &caCertLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pLeafCertName, &pCert, &certLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    desc[0].pCertificate = pCert;
    desc[0].certLength = certLen;

    desc[1].pCertificate = pCaCert;
    desc[1].certLength = caCertLen;

    status = CERTCHAIN_createFromCVC(MOC_ASYM(gpHwAccelCtx) &pChain, (struct certDescriptor *)&desc, 2);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = RTOS_timeGMT(&td);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    vc.td = &td;

    status = CERTCHAIN_CVC_validate(MOC_ASYM(gpHwAccelCtx) pChain, &vc);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pCaCert)
    {
        DIGI_FREE((void **)&pCaCert);
    }
    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }
    if (NULL != pChain)
    {
        CERTCHAIN_delete(&pChain);
    }

    return retVal;
}

int cv_cert_chain_test_ex1_fail(char *pCaCertName, char *pLeafCertName)
{
    int retVal = 0;
    MSTATUS status;
    certChainPtr pChain = NULL;
    certDescriptor desc[2]; 
    ubyte *pCaCert = NULL;
    ubyte4 caCertLen = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;

    status = DIGICERT_readFile(pCaCertName, &pCaCert, &caCertLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pLeafCertName, &pCert, &certLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* The signature is always at the end, modify a bit in the signature 
     * and check to make sure it fails */
    pCert[certLen - 2]++;

    desc[0].pCertificate = pCert;
    desc[0].certLength = certLen;

    desc[1].pCertificate = pCaCert;
    desc[1].certLength = caCertLen;

    status = CERTCHAIN_createFromCVC(MOC_ASYM(gpHwAccelCtx) &pChain, (struct certDescriptor *)&desc, 2);
    if (OK == status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pCaCert)
    {
        DIGI_FREE((void **)&pCaCert);
    }
    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }
    if (NULL != pChain)
    {
        CERTCHAIN_delete(&pChain);
    }

    return retVal;
}

int cv_cert_chain_test_ex2_fail(char *pCaCertName, char *pLeafCertName)
{
    int retVal = 0;
    MSTATUS status;
    certChainPtr pChain = NULL;
    certDescriptor desc[2]; 
    ubyte *pCaCert = NULL;
    ubyte4 caCertLen = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    CV_CERT *pCertData = NULL;

    status = DIGICERT_readFile(pCaCertName, &pCaCert, &caCertLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGICERT_readFile(pLeafCertName, &pCert, &certLen);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Modify the CAR to ensure it fails */
    status = CV_CERT_parseCert(pCert, certLen, &pCertData);
    if (OK != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    pCertData->pCertAuthRef[0]++;

    desc[0].pCertificate = pCert;
    desc[0].certLength = certLen;

    desc[1].pCertificate = pCaCert;
    desc[1].certLength = caCertLen;

    status = CERTCHAIN_createFromCVC(MOC_ASYM(gpHwAccelCtx) &pChain, (struct certDescriptor *)&desc, 2);
    if (ERR_CERT_INVALID_PARENT_CERTIFICATE != status)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pCaCert)
    {
        DIGI_FREE((void **)&pCaCert);
    }
    if (NULL != pCert)
    {
        DIGI_FREE((void **)&pCert);
    }
    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }
    if (NULL != pChain)
    {
        CERTCHAIN_delete(&pChain);
    }

    return retVal;
}

int cv_cert_chain_test_ex(char *pCaCertName, char *pLeafCertName)
{
    int retVal = 0;

    retVal += cv_cert_chain_test_ex1(pCaCertName, pLeafCertName);
    retVal += cv_cert_chain_test_ex2(pCaCertName, pLeafCertName);
    retVal += cv_cert_chain_test_ex1_fail(pCaCertName, pLeafCertName);
    retVal += cv_cert_chain_test_ex2_fail(pCaCertName, pLeafCertName);

    return retVal;
}

int cv_cert_chain_test()
{
    int retVal = 0;

    retVal += cv_cert_chain_test_ex("cv_cert256", "cv_cert256_s256");
    retVal += cv_cert_chain_test_ex("cv_cert256", "cv_cert521_s256");
    retVal += cv_cert_chain_test_ex("cv_cert256", "cv_cert1024_s256");
    retVal += cv_cert_chain_test_ex("cv_cert256", "cv_cert2048pss_s256");

    retVal += cv_cert_chain_test_ex("cv_cert2048", "cv_cert256_s2048");
    retVal += cv_cert_chain_test_ex("cv_cert2048", "cv_cert1024_s2048");
    retVal += cv_cert_chain_test_ex("cv_cert2048", "cv_cert2048pss_s2048");

    retVal += cv_cert_chain_test_ex("cv_cert2048pss", "cv_cert256_s2048pss");
    retVal += cv_cert_chain_test_ex("cv_cert2048pss", "cv_cert1024_s2048pss");
    retVal += cv_cert_chain_test_ex("cv_cert2048pss", "cv_cert2048pss_s2048pss");

    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_CV_CERT__) */

/*----------------------------------------------------------------------------*/

int crypto_interface_cv_cert_test_init()
{
    int retVal = 0;
#if defined(__ENABLE_DIGICERT_CV_CERT__)
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pParentCert = NULL;
    ubyte4 parentCertLen = 0;
    CV_CERT *pCvCert = NULL;
    CV_CERT *pParentCvCert = NULL;
    AsymmetricKey pubKey = {0};
    ubyte4 hashAlgo = 0;
    byteBoolean isPss = FALSE;
    intBoolean isValid = FALSE;
    ubyte4 vStatus = 1;
    byteBoolean isSelfSignied = FALSE;

    InitMocanaSetupInfo setupInfo = {0};
    setupInfo.flags = MOC_NO_AUTOSEED;

    /* generate all certs, skip step if hwAccel is defined */

    for (i = 0; i < TOTAL_TESTS; i++)
    {    
        status = (MSTATUS) KEYGEN_main(gTestLen[i], gpTest[i]);
        retVal += UNITTEST_STATUS(i, status);
        if (OK != status)
            goto exit;
    }

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS(0, status);
    if (OK != status)
        goto exit;

/* here for future use */
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    retVal += cv_cert_store_test();
    retVal += cv_cert_chain_test();

    /* verify certificates */
    for (i = 0; i < TOTAL_TESTS; i++)
    {    
        /* first clear old vars keys */
        if (NULL != pCert)
        {
            status = DIGI_FREE((void **) &pCert);
            if (OK != status)
                goto exit;
        }
        
        if (NULL != pParentCert)
        {
            status = DIGI_FREE((void **) &pParentCert);
            if (OK != status)
                goto exit;
        }

        /* clear parent first before changing the child ptr */
        if (NULL != pParentCvCert && (uintptr) pParentCvCert != (uintptr) pCvCert)
        {
            status = DIGI_FREE((void **) &pParentCvCert);
            if (OK != status)
                goto exit;
        }

        if (NULL != pCvCert)
        {
            status = DIGI_FREE((void **) &pCvCert);
            if (OK != status)
                goto exit;
        }

        status = CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
        retVal += UNITTEST_STATUS(i, status);
        if (OK != status)
            goto exit;

        /* get the cert we're testing */
        status = DIGICERT_readFile(gpTest[i][CERT_NAME_INDEX], &pCert, &certLen);
        retVal += UNITTEST_STATUS(i, status);
        if (OK != status)
            goto exit;

        status = CV_CERT_parseCert(pCert, certLen, &pCvCert);
        retVal += UNITTEST_STATUS(i, status);
        if (OK != status)
            goto exit;

        if (i < SELF_SIGNED_TESTS)
        {
            /* validate it is a root cert */
            status = CV_CERT_isRootCert(pCvCert);
            retVal += UNITTEST_STATUS(i, status);
            if (OK != status)
                goto exit;        
            
            pParentCvCert = pCvCert;
        }
        else
        {
            /* validate it is NOT a root cert */
            status = CV_CERT_isRootCert(pCvCert);
            if (status != ERR_FALSE)
            {
                retVal += UNITTEST_STATUS(i, -1);
            }

            /* get the parent cert */
            status = DIGICERT_readFile(gpTest[i][PARENT_CERT_NAME_INDEX], &pParentCert, &parentCertLen);
            retVal += UNITTEST_STATUS(i, status);
            if (OK != status)
                goto exit;

            status = CV_CERT_parseCert(pParentCert, parentCertLen, &pParentCvCert);
            retVal += UNITTEST_STATUS(i, status);
            if (OK != status)
                goto exit;
        }

        status = CRYPTO_initAsymmetricKey(&pubKey);
        retVal += UNITTEST_STATUS(i, status);
        if (OK != status)
            goto exit;

        status = CV_CERT_parseKey(MOC_ASYM(gpHwAccelCtx) pParentCvCert->pCvcKey, pParentCvCert->cvcKeyLen, &pubKey, &hashAlgo, &isPss);
        retVal += UNITTEST_STATUS(i, status);
        if (OK != status)
            goto exit;

        if (akt_rsa == pubKey.type)
        {
            if (!isPss)
            {
                ubyte pHash[SHA256_RESULT_SIZE] = {0}; /* big enough for either sha */
                ubyte4 hashLen = SHA256_RESULT_SIZE;
                ubyte *pDigestInfo = NULL;
                ubyte4 digestInfoLen = 0;

                /* Hash the Cert Body */
                if (ht_sha1 == (ubyte) hashAlgo)
                {
                    hashLen = SHA1_RESULT_SIZE;
                    status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(gpHwAccelCtx) pCvCert->pCertBody, pCvCert->certBodyLen, pHash);
                    retVal += UNITTEST_STATUS(i, status);
                    if (OK != status)
                        goto exit;
                }
                else if (ht_sha256 == (ubyte) hashAlgo)
                {
                    status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(gpHwAccelCtx) pCvCert->pCertBody, pCvCert->certBodyLen, pHash);
                    retVal += UNITTEST_STATUS(i, status);
                    if (OK != status)
                        goto exit;
                }

                status = ASN1_buildDigestInfoAlloc (pHash, hashLen, hashAlgo, &pDigestInfo, &digestInfoLen);
                retVal += UNITTEST_STATUS(i, status);
                if (OK != status)
                    goto exit;

                status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pubKey.key.pRSA, pDigestInfo, digestInfoLen, pCvCert->pSig, pCvCert->sigLen, &isValid, NULL);
                (void) DIGI_MEMSET_FREE(&pDigestInfo, digestInfoLen);
                retVal += UNITTEST_STATUS(i, status);
                if (OK != status)
                    goto exit;
                
                if (!isValid)
                {
                    retVal += UNITTEST_STATUS(i, -1);
                }
            }
            else
            {
                status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt(MOC_RSA(gpHwAccelCtx) pubKey.key.pRSA, (ubyte) hashAlgo, MOC_PKCS1_ALG_MGF1, (ubyte) hashAlgo,
                                                                pCvCert->pCertBody, pCvCert->certBodyLen, pCvCert->pSig, pCvCert->sigLen, 
                                                                ht_sha256 == (ubyte) hashAlgo ? SHA256_RESULT_SIZE : SHA1_RESULT_SIZE, &vStatus, NULL);
                retVal += UNITTEST_STATUS(i, status);
                if (OK != status)
                    goto exit;

                retVal += UNITTEST_STATUS(i, vStatus);
            }
        }
        else if (akt_ecc == pubKey.type)
        {
            status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(MOC_ECC(gpHwAccelCtx) pubKey.key.pECC, (ubyte) hashAlgo, pCvCert->pCertBody, pCvCert->certBodyLen, 
                                                             pCvCert->pSig, pCvCert->sigLen, &vStatus, NULL);
            retVal += UNITTEST_STATUS(i, status);
            if (OK != status)
                goto exit;

            retVal += UNITTEST_STATUS(i, vStatus);
        }
        else
        {
            retVal += UNITTEST_STATUS(i, -1);
        }
    }

exit:

    status = CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    retVal += UNITTEST_STATUS(0, status);

    if (NULL != pCert)
    {
        status = DIGI_FREE((void **) &pCert);
        retVal += UNITTEST_STATUS(0, status);
    }

    if (NULL != pParentCert)
    {
        status = DIGI_FREE((void **) &pParentCert);
        if (OK != status)
            goto exit;
    }

    /* clear parent first before changing the child ptr */
    if (NULL != pParentCvCert && (uintptr) pParentCvCert != (uintptr) pCvCert)
    {
        status = DIGI_FREE((void **) &pParentCvCert);
        if (OK != status)
            goto exit;
    }

    if (NULL != pCvCert)
    {
        status = DIGI_FREE((void **) &pCvCert);
        retVal += UNITTEST_STATUS(0, status);
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(0, status);

#endif /* defined(__ENABLE_DIGICERT_CV_CERT__) */
    return retVal;
}
