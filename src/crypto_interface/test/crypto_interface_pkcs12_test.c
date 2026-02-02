/*
 * crypto_interface_pkcs12_test.c
 *
 * Tests pkcs12 document creation (for 2 of the APIs, nothing else)
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../common/mocana.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs12.h"
#include "../../crypto/pkcs_key.h"
#include "../../asn1/oiddefs.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static int compareKeys(
    ubyte *pKey1, ubyte4 key1Len, ubyte *pKey2, ubyte4 key2Len, int hint)
{
    MSTATUS status;
    int retVal = 0;
    AsymmetricKey asymKey1 = { 0 };
    AsymmetricKey asymKey2 = { 0 };
    ubyte *pK1 = NULL, *pK2 = NULL;
    ubyte4 k1Len = 0, k2Len = 0;
    sbyte4 cmpRes;

    CRYPTO_initAsymmetricKey(&asymKey1);
    CRYPTO_initAsymmetricKey(&asymKey2);

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKey1, key1Len, NULL, &asymKey1);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKey2, key2Len, NULL, &asymKey2);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx)
        &asymKey1, privateKeyInfoDer, &pK1, &k1Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx)
        &asymKey2, privateKeyInfoDer, &pK2, &k2Len);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (k1Len != k2Len)
    {
        status = ERR_BAD_LENGTH;
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }

    status = DIGI_MEMCMP(pK1, pK2, k1Len, &cmpRes);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pK1);
    DIGI_FREE((void **) &pK2);
    CRYPTO_uninitAsymmetricKey(&asymKey1, NULL);
    CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);

    return retVal;
}

static int testPwBased(SizedBuffer *pCerts, ubyte4 certCount, ubyte *pKeyBlob, ubyte4 keyBlobLen, ubyte *pCA, ubyte4 caLen, 
                       ubyte4 pkcs12EncryptionType, char *pEncPw, char *pPrivacyPw, char *pIntPw, char *pOutFileName, int hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte *pOut = NULL;
    ubyte4 outLen = 0;
    SizedBuffer *pCertsOut = NULL;
    ubyte4 certOutCount = 0;
    ubyte *pKeyOut = NULL;
    ubyte4 keyOutLen = 0;
    ubyte4 i;
    sbyte4 cmpRes;

    status = PKCS12_EncryptPFXPduPwMode( MOC_HW(gpHwAccelCtx) NULL, pCerts, certCount, pKeyBlob, keyBlobLen, pCA, caLen, (ubyte *) pEncPw, DIGI_STRLEN(pEncPw),
                                         pkcs12EncryptionType, (ubyte *) pPrivacyPw, DIGI_STRLEN(pPrivacyPw), (ubyte *) pIntPw, DIGI_STRLEN(pIntPw), &pOut, &outLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

#ifdef __CI_TEST_PRINT_PKCS12__
    status = DIGICERT_writeFile((const sbyte *) pOutFileName, pOut, outLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;
#endif

    if (NULL != pIntPw)
    {
        status = PKCS12_DecryptPFXPduPwMode( MOC_HW(gpHwAccelCtx)
            pOut, outLen, (ubyte *) pEncPw, DIGI_STRLEN(pEncPw),
            (ubyte *) pPrivacyPw, DIGI_STRLEN(pPrivacyPw),
            (ubyte *) pIntPw, DIGI_STRLEN(pIntPw), &pCertsOut, &certOutCount,
            NULL, NULL);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if ( (NULL == pCertsOut) || (0 == certOutCount) )
        {
            status = ERR_NULL_POINTER;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }

        if ( (NULL == pCA) && (certOutCount != certCount) )
        {
            status = ERR_BAD_LENGTH;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }
        else if ( (NULL != pCA) && (certOutCount - 1 != certCount) )
        {
            status = ERR_BAD_LENGTH;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }

        for (i = 0; i < certCount; i++)
        {
            if (pCerts[i].length != pCertsOut[i].length)
            {
                status = ERR_BAD_LENGTH;
                retVal += UNITTEST_STATUS(hint, status);
                goto exit;
            }
            status = DIGI_MEMCMP(
                pCerts[i].data, pCertsOut[i].data, pCerts[i].length, &cmpRes);
            retVal += UNITTEST_STATUS(hint, status);
            if (OK != status)
                goto exit;

            if (0 != cmpRes)
            {
                status = ERR_CMP;
                UNITTEST_STATUS(__MOC_LINE__, status);
                goto exit;
            }
        }

        if (NULL != pCA)
        {
            if (caLen != pCertsOut[certOutCount - 1].length)
            {
                status = ERR_BAD_LENGTH;
                retVal += UNITTEST_STATUS(hint, status);
                goto exit;
            }
            status = DIGI_MEMCMP(
                pCA, pCertsOut[certOutCount - 1].data, caLen, &cmpRes);
            retVal += UNITTEST_STATUS(hint, status);
            if (OK != status)
                goto exit;

            if (0 != cmpRes)
            {
                status = ERR_CMP;
                UNITTEST_STATUS(__MOC_LINE__, status);
                goto exit;
            }
        }

        if (NULL != pCertsOut)
        {
            for (i = 0; i < certOutCount; i++)
            {
                DIGI_FREE((void **) &((pCertsOut + i)->data));
            }
            DIGI_FREE((void **) &pCertsOut);
        }

        status = PKCS12_DecryptPFXPduPwMode( MOC_HW(gpHwAccelCtx)
            pOut, outLen, (ubyte *) pEncPw, DIGI_STRLEN(pEncPw),
            (ubyte *) pPrivacyPw, DIGI_STRLEN(pPrivacyPw),
            (ubyte *) pIntPw, DIGI_STRLEN(pIntPw), NULL, NULL,
            &pKeyOut, &keyOutLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if ( (NULL == pKeyOut) || (0 == keyOutLen) )
        {
            status = ERR_NULL_POINTER;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }

        retVal += compareKeys(pKeyOut, keyOutLen, pKeyBlob, keyBlobLen, hint);
        if (retVal)
            goto exit;

        if (NULL != pKeyOut)
        {
            DIGI_FREE((void **) &pKeyOut);
        }

        status = PKCS12_DecryptPFXPduPwMode( MOC_HW(gpHwAccelCtx)
            pOut, outLen, (ubyte *) pEncPw, DIGI_STRLEN(pEncPw),
            (ubyte *) pPrivacyPw, DIGI_STRLEN(pPrivacyPw),
            (ubyte *) pIntPw, DIGI_STRLEN(pIntPw), &pCertsOut, &certOutCount,
            &pKeyOut, &keyOutLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        if ( (NULL == pCertsOut) || (0 == certOutCount) || (NULL == pKeyOut) || (0 == keyOutLen) )
        {
            status = ERR_NULL_POINTER;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }

        retVal += compareKeys(pKeyOut, keyOutLen, pKeyBlob, keyBlobLen, hint);
        if (retVal)
            goto exit;

        if ( (NULL == pCA) && (certOutCount != certCount) )
        {
            status = ERR_BAD_LENGTH;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }
        else if ( (NULL != pCA) && (certOutCount - 1 != certCount) )
        {
            status = ERR_BAD_LENGTH;
            retVal += UNITTEST_STATUS(hint, status);
            goto exit;
        }

        for (i = 0; i < certCount; i++)
        {
            if (pCerts[i].length != pCertsOut[i].length)
            {
                status = ERR_BAD_LENGTH;
                retVal += UNITTEST_STATUS(hint, status);
                goto exit;
            }
            status = DIGI_MEMCMP(
                pCerts[i].data, pCertsOut[i].data, pCerts[i].length, &cmpRes);
            retVal += UNITTEST_STATUS(hint, status);
            if (OK != status)
                goto exit;

            if (0 != cmpRes)
            {
                status = ERR_CMP;
                UNITTEST_STATUS(__MOC_LINE__, status);
                goto exit;
            }
        }

        if (NULL != pCA)
        {
            if (caLen != pCertsOut[certOutCount - 1].length)
            {
                status = ERR_BAD_LENGTH;
                retVal += UNITTEST_STATUS(hint, status);
                goto exit;
            }
            status = DIGI_MEMCMP(
                pCA, pCertsOut[certOutCount - 1].data, caLen, &cmpRes);
            retVal += UNITTEST_STATUS(hint, status);
            if (OK != status)
                goto exit;

            if (0 != cmpRes)
            {
                status = ERR_CMP;
                UNITTEST_STATUS(__MOC_LINE__, status);
                goto exit;
            }
        }
    }

exit:

    if (NULL != pKeyOut)
    {
        DIGI_FREE((void **) &pKeyOut);
    }

    if (NULL != pCertsOut)
    {
        for (i = 0; i < certOutCount; i++)
        {
            DIGI_FREE((void **) &((pCertsOut + i)->data));
        }
        DIGI_FREE((void **) &pCertsOut);
    }

    if (NULL != pOut)
    {
        DIGI_FREE((void **) &pOut);
    }

    return retVal;
}

/*******************************************************************************************/

#ifndef __DISABLE_3DES_CIPHERS__
static int testPubKeyBased(SizedBuffer *pCerts, ubyte4 certCount, ubyte *pKeyBlob, ubyte4 keyBlobLen, ubyte *pCA, ubyte4 caLen, char *pEncPw, 
                           const ubyte *pOid, char *pOutFileName, int hint)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte *pOut = NULL;
    ubyte4 outLen = 0;

    ubyte *pEncKeyCert = NULL;
    ubyte4 encKeyCertLen = 0;

    status = DIGICERT_readFile(FILE_PATH("../../crypto/test/ecc_selfcert2.der"), &pEncKeyCert, &encKeyCertLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    /* re-use the cert and key for the integrity cert and key */
    status = PKCS12_EncryptPFXPduCertMode(MOC_HW(gpHwAccelCtx) NULL, pCerts, certCount, pKeyBlob, keyBlobLen, pCA, caLen, (ubyte *) pEncPw, DIGI_STRLEN(pEncPw),
                                          PCKS8_EncryptionType_pkcs12_sha_3des, pEncKeyCert, encKeyCertLen,
                                          pOid, pKeyBlob, keyBlobLen, pEncKeyCert, encKeyCertLen, sha256_OID, &pOut, &outLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

#ifdef __CI_TEST_PRINT_PKCS12__
    status = DIGICERT_writeFile((const sbyte *) pOutFileName, pOut, outLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;
#endif

exit:

    if (NULL != pOut)
    {
        DIGI_FREE((void **) &pOut);
    }

    if (NULL != pEncKeyCert)
    {
        DIGI_FREE((void **) &pEncKeyCert);
    }

    return retVal;
}
#endif

/*******************************************************************************************/

static int testPkcs12(void)
{
    int retVal = 0;
    MSTATUS status = OK;

    SizedBuffer certs[2] = {0};
    ubyte4 certCount = 2;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    ubyte *pCA = NULL;
    ubyte4 caLen = 0;

    status = DIGICERT_readFile(FILE_PATH("../../crypto/test/ecc_keyblobFile2.dat"), &pKeyBlob, &keyBlobLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(FILE_PATH("../../crypto/test/CA5.cacert.der"), &pCA, &caLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
   
    /* we make use of the CA again to test additional cert data objects being added to the pkcs12 doc */
    certs[0].data = pCA;
    certs[0].length = caLen;
    certs[1].data = pCA;
    certs[1].length = caLen;

#ifndef __DISABLE_3DES_CIPHERS__
    retVal += testPwBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, "MyPassword", "MyPrivPw", "MyIntegrityPw", "P12_3des.der", 1);
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, NULL, "MyPrivPw", "MyIntegrityPw", "P12_3des_011.der", 2);
    retVal += testPwBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, "MyPassword", NULL, "MyIntegrityPw", "P12_3des_101.der", 3);
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, NULL, NULL, "MyIntegrityPw", "P12_3des_001.der", 4);
    retVal += testPwBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, "MyPassword", "MyPrivPw", NULL, "P12_3des_110.der", 5);
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, NULL, "MyPrivPw", NULL, "P12_3des_010.der", 6);
    retVal += testPwBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, "MyPassword", NULL, NULL, "P12_3des_100.der", 7);
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_3des, NULL, NULL, NULL, "P12_3des_000.der", 8);
#endif
#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_2des, "MyPassword", "MyPrivPw", "MyIntegrityPw", "P12_2des.der", 9);
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_rc2_40, "MyPassword", "MyPrivPw", "MyIntegrityPw", "P12_rc2_40", 10);
    retVal += testPwBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_rc2_128, "MyPassword", "MyPrivPw", "MyIntegrityPw", "P12_rc2_128",11);
#endif
    retVal += testPwBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_rc4_40, "MyPassword", "MyPrivPw", "MyIntegrityPw", "P12_rc4_40", 12);
    retVal += testPwBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, PCKS8_EncryptionType_pkcs12_sha_rc4_128, "MyPassword", "MyPrivPw", "MyIntegrityPw", "P12_rc4_128", 13);
#endif /* __ENABLE_DIGICERT_MBED_SYM_OPERATORS__ */

    /* pkcs7 portion of the encoding only accepts aes, not des/tdes, PCKS8_EncryptionType_pkcs12_sha_3des still used though */
#ifndef __DISABLE_3DES_CIPHERS__
    retVal += testPubKeyBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, "MyPassword", aes128CBC_OID, "P12_pub_aes128", 1);
    retVal += testPubKeyBased(certs, 1, pKeyBlob, keyBlobLen, pCA, caLen, NULL, aes192CBC_OID, "P12_pub_aes192", 2);
    retVal += testPubKeyBased(certs, 2, pKeyBlob, keyBlobLen, pCA, caLen, "MyPassword", aes256CBC_OID, "P12_pub_aes256", 3);
#endif

exit:

    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void **) &pKeyBlob);
    }

    if (NULL != pCA)
    {
        DIGI_FREE((void **) &pCA);
    }

    return retVal;
}

/*******************************************************************************************/

int crypto_interface_pkcs12_test_init()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

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

    errorCount += testPkcs12();

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
