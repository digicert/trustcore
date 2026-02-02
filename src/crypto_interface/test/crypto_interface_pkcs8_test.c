/*
 * crypto_interface_pkcs8_test.c
 *
 * Tests pkcs8 document encode and decode
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
#include "../../crypto/pkcs8.h"
#include "../../crypto/pkcs_key.h"

static MocCtx gpMocCtx = NULL;


/*******************************************************************************************/

static int testPkcs8(int hint, ubyte *pKeyBlob, ubyte4 keyBlobLen, byteBoolean isPem, char *pPassword, ubyte4 encAlgo, ubyte4 prfAlgo)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte4 compare = -1;
    ubyte4 passwordLen = DIGI_STRLEN(pPassword);

    ubyte *pRetKeyBlob = NULL;
    ubyte4 retKeyBlobLen = 0;

    ubyte *pPkcs8 = NULL;
    ubyte4 pkcs8Len = 0;
 
    if (isPem)
    {
        status = PKCS8_encodePrivateKeyPEM(g_pRandomContext, pKeyBlob, keyBlobLen, (enum PKCS8EncryptionType) encAlgo, (enum PKCS8PrfType) prfAlgo, (ubyte *) pPassword, passwordLen, &pPkcs8, &pkcs8Len);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
 
 #ifdef __CI_TEST_PRINT_PKCS8__
        /* so we can visually verify a pkcs8 file */
        status = DIGICERT_writeFile((const sbyte *) pPassword ? "pkcs8_encKey.pem" : "pkcs8_noEnc.pem", pPkcs8, pkcs8Len);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
 #endif /* __CI_TEST_PRINT_PKCS8__ */

        status = PKCS8_decodePrivateKeyPEMEx((const ubyte*) pPkcs8, pkcs8Len, (ubyte *) pPassword, passwordLen, &pRetKeyBlob, &retKeyBlobLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    }
    else /* isDer */
    {
        status = PKCS8_encodePrivateKeyDER(g_pRandomContext, pKeyBlob, keyBlobLen, (enum PKCS8EncryptionType) encAlgo, (enum PKCS8PrfType) prfAlgo, (ubyte *) pPassword, passwordLen, &pPkcs8, &pkcs8Len);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;

        status = PKCS8_decodePrivateKeyDEREx((const ubyte*) pPkcs8, pkcs8Len, (ubyte *) pPassword, passwordLen, &pRetKeyBlob, &retKeyBlobLen);
        retVal += UNITTEST_STATUS(hint, status);
        if (OK != status)
            goto exit;
    }

    retVal += UNITTEST_INT(hint, retKeyBlobLen, keyBlobLen);
    
    status = DIGI_MEMCMP(pRetKeyBlob, pKeyBlob, keyBlobLen, &compare);
    retVal += UNITTEST_STATUS(hint, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(hint, compare, 0);

exit:

    if (NULL != pRetKeyBlob)
    {
        DIGI_FREE((void **) &pRetKeyBlob);
    }

    if (NULL != pPkcs8)
    {
        DIGI_FREE((void **) &pPkcs8);
    }

    return retVal;
}

/*******************************************************************************************/

int crypto_interface_pkcs8_test_init()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;

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

    status = DIGICERT_readFile(FILE_PATH("../../crypto/test/eccKeyBlobV2.dat"), &pKeyBlob, &keyBlobLen);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    errorCount += testPkcs8(1, pKeyBlob, keyBlobLen, FALSE, NULL, PCKS8_EncryptionType_pkcs5_v2_aes128, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
#ifdef __ENABLE_DIGICERT_MD2__
    errorCount += testPkcs8(2, pKeyBlob, keyBlobLen, FALSE, "MyPass", PCKS8_EncryptionType_pkcs5_v1_md2_des, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#endif
    errorCount += testPkcs8(3, pKeyBlob, keyBlobLen, FALSE, "MyPass2", PCKS8_EncryptionType_pkcs5_v1_md5_des, PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest);
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    errorCount += testPkcs8(4, pKeyBlob, keyBlobLen, FALSE, "MyPass4", PCKS8_EncryptionType_pkcs5_v2_des, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#endif
#endif
#ifndef __DISABLE_3DES_CIPHERS__
    errorCount += testPkcs8(5, pKeyBlob, keyBlobLen, FALSE, "MyPass3", PCKS8_EncryptionType_pkcs5_v2_3des, PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest);
#endif
    errorCount += testPkcs8(6, pKeyBlob, keyBlobLen, FALSE, "MyPass5", PCKS8_EncryptionType_pkcs5_v2_aes128, PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest);
    errorCount += testPkcs8(7, pKeyBlob, keyBlobLen, FALSE, "MyPass6", PCKS8_EncryptionType_pkcs5_v2_aes192, PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest);
    errorCount += testPkcs8(8, pKeyBlob, keyBlobLen, FALSE, "MyPass7", PCKS8_EncryptionType_pkcs5_v2_aes256, PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest);
#ifndef __DISABLE_3DES_CIPHERS__
    errorCount += testPkcs8(9, pKeyBlob, keyBlobLen, FALSE, NULL, PCKS8_EncryptionType_pkcs12_sha_3des, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#endif
#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
    errorCount += testPkcs8(10, pKeyBlob, keyBlobLen, FALSE, "MyPass", PCKS8_EncryptionType_pkcs12_sha_rc4_40, PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest);
    errorCount += testPkcs8(11, pKeyBlob, keyBlobLen, FALSE, "MyPass", PCKS8_EncryptionType_pkcs12_sha_rc4_128, PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest);
#endif

    errorCount += testPkcs8(14, pKeyBlob, keyBlobLen, TRUE, NULL, PCKS8_EncryptionType_pkcs5_v2_aes128, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
#ifdef __ENABLE_DIGICERT_MD2__
    errorCount += testPkcs8(15, pKeyBlob, keyBlobLen, TRUE, "MyPass", PCKS8_EncryptionType_pkcs5_v1_md2_des, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#endif
    errorCount += testPkcs8(16, pKeyBlob, keyBlobLen, TRUE, "MyPass2", PCKS8_EncryptionType_pkcs5_v1_md5_des, PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest);
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    errorCount += testPkcs8(17, pKeyBlob, keyBlobLen, TRUE, "MyPass4", PCKS8_EncryptionType_pkcs5_v2_des, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#endif
#endif 
#ifndef __DISABLE_3DES_CIPHERS__
    errorCount += testPkcs8(18, pKeyBlob, keyBlobLen, TRUE, "MyPass3", PCKS8_EncryptionType_pkcs5_v2_3des, PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest); 
#endif  
    errorCount += testPkcs8(19, pKeyBlob, keyBlobLen, TRUE, "MyPass5", PCKS8_EncryptionType_pkcs5_v2_aes128, PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest);
    errorCount += testPkcs8(20, pKeyBlob, keyBlobLen, TRUE, "MyPass6", PCKS8_EncryptionType_pkcs5_v2_aes192, PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest);
    errorCount += testPkcs8(21, pKeyBlob, keyBlobLen, TRUE, "MyPass7", PCKS8_EncryptionType_pkcs5_v2_aes256, PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest);
#ifndef __DISABLE_3DES_CIPHERS__
    errorCount += testPkcs8(22, pKeyBlob, keyBlobLen, TRUE, NULL, PCKS8_EncryptionType_pkcs12_sha_3des, PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest);
#endif
#ifndef __ENABLE_DIGICERT_MBED_SYM_OPERATORS__
    errorCount += testPkcs8(23, pKeyBlob, keyBlobLen, TRUE, "MyPass", PCKS8_EncryptionType_pkcs12_sha_rc4_40, PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest);
    errorCount += testPkcs8(24, pKeyBlob, keyBlobLen, TRUE, "MyPass", PCKS8_EncryptionType_pkcs12_sha_rc4_128, PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest);
#endif

exit:

    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void **) &pKeyBlob);
    }

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
