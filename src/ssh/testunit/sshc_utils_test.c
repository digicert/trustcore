/*
 * sshc_utils_test.c
 *
 * Test utility code for storing and retrieving keys
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/utils.h"
#define __IN_DIGICERT_C__    /* FOR TESTING PURPOSES --- ENABLES BASE64 init/free */
#include "../../common/base64.h"
#include "../../crypto/dsa.h"
#include "../../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_utils.h"
#include "../../ssh/ssh.h"

/*------------------------------------------------------------------*/
/* Helper Functions */
/*------------------------------------------------------------------*/

static MSTATUS
parseAndComparePubKey(sbyte *pKeyFile, ubyte4 fileSize, AsymmetricKey *pOrigKey)
{
    AsymmetricKey   pKeyDescr;
    MSTATUS         status;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    if (OK != status)
        goto exit;

    status = SSHC_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    if (OK != status)
        goto exit;

    status = CRYPTO_matchPublicKey(&pKeyDescr, pOrigKey);

exit:
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
    return status;
}

/*------------------------------------------------------------------*/
/* Key Parsing Function Tests */
/*------------------------------------------------------------------*/

static void test_SSHC_UTILS_sshParseAuthPublicKeyFile_null_params(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey keyDescr;
    MSTATUS status;
    sbyte testKeyFile[] = "ssh-rsa AAAAB3NzaC1yc2EAAAA test@example.com";

    status = CRYPTO_initAsymmetricKey(&keyDescr);
    assert_int_equal(OK, status);

    /* Test null key file */
    status = SSHC_UTILS_sshParseAuthPublicKeyFile(NULL, 100, &keyDescr);
    assert_int_not_equal(OK, status);

    /* Test null key descriptor */
    status = SSHC_UTILS_sshParseAuthPublicKeyFile(testKeyFile, DIGI_STRLEN(testKeyFile), NULL);
    assert_int_not_equal(OK, status);

    /* Test zero file size */
    status = SSHC_UTILS_sshParseAuthPublicKeyFile(testKeyFile, 0, &keyDescr);
    assert_int_not_equal(OK, status);

    CRYPTO_uninitAsymmetricKey(&keyDescr, NULL);
}

static void test_SSHC_UTILS_sshParseAuthPublicKey_null_params(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey keyDescr;
    MSTATUS status;
    sbyte testKeyBlob[] = {0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2d, 0x72, 0x73, 0x61};

    status = CRYPTO_initAsymmetricKey(&keyDescr);
    assert_int_equal(OK, status);

    /* Test null key blob */
    status = SSHC_UTILS_sshParseAuthPublicKey(NULL, sizeof(testKeyBlob), &keyDescr);
    assert_int_not_equal(OK, status);

    /* Test null key descriptor */
    status = SSHC_UTILS_sshParseAuthPublicKey((sbyte*)testKeyBlob, sizeof(testKeyBlob), NULL);
    assert_int_not_equal(OK, status);

    /* Test zero blob length */
    status = SSHC_UTILS_sshParseAuthPublicKey((sbyte*)testKeyBlob, 0, &keyDescr);
    assert_int_not_equal(OK, status);

    CRYPTO_uninitAsymmetricKey(&keyDescr, NULL);
}

/*------------------------------------------------------------------*/
/* Buffer Manipulation Tests */
/*------------------------------------------------------------------*/

static void test_SSHC_UTILS_getByte_success(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte buffer[] = {0x12, 0x34, 0x56, 0x78, 0x9A};
    ubyte4 bufIndex = 0;
    ubyte retByte;
    MSTATUS status;

    /* Get first byte */
    status = SSHC_UTILS_getByte(buffer, sizeof(buffer), &bufIndex, &retByte);
    assert_int_equal(OK, status);
    assert_int_equal(0x12, retByte);
    assert_int_equal(1, bufIndex);

    /* Get second byte */
    status = SSHC_UTILS_getByte(buffer, sizeof(buffer), &bufIndex, &retByte);
    assert_int_equal(OK, status);
    assert_int_equal(0x34, retByte);
    assert_int_equal(2, bufIndex);
}

static void test_SSHC_UTILS_getByte_buffer_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte buffer[] = {0x12, 0x34};
    ubyte4 bufIndex = 2;
    ubyte retByte;
    MSTATUS status;

    status = SSHC_UTILS_getByte(buffer, sizeof(buffer), &bufIndex, &retByte);
    assert_int_equal(ERR_SFTP_BAD_PAYLOAD_LENGTH, status);
}

static void test_SSHC_UTILS_getInteger_success(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte buffer[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    ubyte4 bufIndex = 0;
    ubyte4 retInteger;
    MSTATUS status;

    status = SSHC_UTILS_getInteger(buffer, sizeof(buffer), &bufIndex, &retInteger);
    assert_int_equal(OK, status);
    assert_int_equal(0x12345678, retInteger);
    assert_int_equal(4, bufIndex);
}

static void test_SSHC_UTILS_getInteger_insufficient_buffer(void **ppState)
{
    MOC_UNUSED(ppState);
    ubyte buffer[3] = {0x01, 0x02, 0x03};
    ubyte4 index = 0;
    ubyte4 ret;
    MSTATUS status;

    status = SSHC_UTILS_getInteger((ubyte *)buffer, sizeof(buffer), &index, &ret);
    assert_int_equal(ERR_SFTP_BAD_PAYLOAD_LENGTH, status);
}

static void test_SSHC_UTILS_getInteger64_success(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte buffer[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    ubyte4 bufIndex = 0;
    ubyte8 retInteger64;
    MSTATUS status;

    status = SSHC_UTILS_getInteger64(buffer, sizeof(buffer), &bufIndex, &retInteger64);
    assert_int_equal(OK, status);
#if __DIGICERT_MAX_INT__ == 64
    assert_int_equal(0x0123456789ABCDEF, retInteger64);
#else
    assert_int_equal(0x89ABCDEF, retInteger64.lower32);
    assert_int_equal(0x01234567, retInteger64.upper32);
#endif
    assert_int_equal(8, bufIndex);
}

static void test_SSHC_UTILS_getInteger64_buffer_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte buffer[7] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD};
    ubyte4 bufIndex = 0;
    ubyte8 retInteger64;
    MSTATUS status;

    status = SSHC_UTILS_getInteger64(buffer, sizeof(buffer), &bufIndex, &retInteger64);
    assert_int_equal(ERR_SFTP_BAD_PAYLOAD_LENGTH, status);
}

static void test_SSHC_UTILS_setByte_success(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte payload[10] = {0};
    ubyte4 bufIndex = 0;
    MSTATUS status;

    status = SSHC_UTILS_setByte(payload, sizeof(payload), &bufIndex, 0xAB);
    assert_int_equal(OK, status);
    assert_int_equal(0xAB, payload[0]);
    assert_int_equal(1, bufIndex);

    status = SSHC_UTILS_setByte(payload, sizeof(payload), &bufIndex, 0xCD);
    assert_int_equal(OK, status);
    assert_int_equal(0xCD, payload[1]);
    assert_int_equal(2, bufIndex);
}

static void test_SSHC_UTILS_setByte_buffer_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte payload[2] = {0};
    ubyte4 bufIndex = 2;
    MSTATUS status;

    status = SSHC_UTILS_setByte(payload, sizeof(payload), &bufIndex, 0xAB);
    assert_int_equal(ERR_SFTP_PAYLOAD_TOO_SMALL, status);
}

static void test_SSHC_UTILS_setInteger_success(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte payload[4] = {0};
    ubyte4 bufIndex = 0;
    ubyte4 testValue = 0x12345678;
    MSTATUS status;

    status = SSHC_UTILS_setInteger(payload, sizeof(payload), &bufIndex, testValue);
    assert_int_equal(OK, status);
    assert_int_equal(4, bufIndex);

    /* Verify big-endian encoding */
    assert_int_equal(0x12, payload[0]);
    assert_int_equal(0x34, payload[1]);
    assert_int_equal(0x56, payload[2]);
    assert_int_equal(0x78, payload[3]);
}

static void test_SSHC_UTILS_setInteger_buffer_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte payload[3] = {0};
    ubyte4 bufIndex = 0;
    MSTATUS status;

    status = SSHC_UTILS_setInteger(payload, sizeof(payload), &bufIndex, 0x12345678);
    assert_int_equal(ERR_SFTP_PAYLOAD_TOO_SMALL, status);
}

static void test_SSHC_UTILS_setInteger64_success(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte payload[8] = {0};
    ubyte4 bufIndex = 0;
    ubyte8 testValue;
    MSTATUS status;

#if __DIGICERT_MAX_INT__ == 64
    testValue = 0x0123456789ABCDEF;
#else
    testValue.lower32 = 0x89ABCDEF;
    testValue.upper32 = 0x01234567;
#endif
    status = SSHC_UTILS_setInteger64(payload, sizeof(payload), &bufIndex, &testValue);
    assert_int_equal(OK, status);
    assert_int_equal(8, bufIndex);

    /* Verify big-endian encoding */
    assert_int_equal(0x01, payload[0]);
    assert_int_equal(0x23, payload[1]);
    assert_int_equal(0x45, payload[2]);
    assert_int_equal(0x67, payload[3]);
    assert_int_equal(0x89, payload[4]);
    assert_int_equal(0xAB, payload[5]);
    assert_int_equal(0xCD, payload[6]);
    assert_int_equal(0xEF, payload[7]);
}

static void test_SSHC_UTILS_setInteger64_buffer_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    ubyte payload[7] = {0};
    ubyte4 bufIndex = 0;
    ubyte8 testValue;
    MSTATUS status;

#if __DIGICERT_MAX_INT__ == 64
    testValue = 0x0123456789ABCDEF;
#else
    testValue.lower32 = 0x89ABCDEF;
    testValue.upper32 = 0x01234567;
#endif
    status = SSHC_UTILS_setInteger64(payload, sizeof(payload), &bufIndex, &testValue);
    assert_int_equal(ERR_SFTP_PAYLOAD_TOO_SMALL, status);
}

/*------------------------------------------------------------------*/
/* File based tests */
/*------------------------------------------------------------------*/

static void sshcClientFileECDSA256(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey   pKeyDescr;
    MSTATUS         status;
    ubyte*          pKeyFile = NULL;
    ubyte4          fileSize = 0;
    ubyte*          pSerKeyFile = NULL;
    ubyte4          serKeyFileSize = 0;
    ubyte*          pEncodedPubKey = NULL;
    ubyte4          encodedPubKeySize = 0;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ecdsa256.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
}

static void sshcClientFileECDSA384(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey   pKeyDescr;
    MSTATUS         status;
    ubyte*          pKeyFile = NULL;
    ubyte4          fileSize = 0;
    ubyte*          pSerKeyFile = NULL;
    ubyte4          serKeyFileSize = 0;
    ubyte*          pEncodedPubKey = NULL;
    ubyte4          encodedPubKeySize = 0;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ecdsa384.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);
    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
}

static void sshcClientFileECDSA521(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey   pKeyDescr;
    MSTATUS         status;
    ubyte*          pKeyFile = NULL;
    ubyte4          fileSize = 0;
    ubyte*          pSerKeyFile = NULL;
    ubyte4          serKeyFileSize = 0;
    ubyte*          pEncodedPubKey = NULL;
    ubyte4          encodedPubKeySize = 0;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ecdsa521.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);
    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
}

static void sshcClientFileED25519(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey   pKeyDescr;
    MSTATUS         status;
    ubyte*          pKeyFile = NULL;
    ubyte4          fileSize = 0;
    ubyte*          pSerKeyFile = NULL;
    ubyte4          serKeyFileSize = 0;
    ubyte*          pEncodedPubKey = NULL;
    ubyte4          encodedPubKeySize = 0;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ed25519.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);
    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
}

static void sshcClientFileRSA4096(void **ppState)
{
    MOC_UNUSED(ppState);

    AsymmetricKey   pKeyDescr;
    MSTATUS         status;
    ubyte*          pKeyFile = NULL;
    ubyte4          fileSize = 0;
    ubyte*          pSerKeyFile = NULL;
    ubyte4          serKeyFileSize = 0;
    ubyte*          pEncodedPubKey = NULL;
    ubyte4          encodedPubKeySize = 0;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_rsa4096.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSHC_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
}

/*------------------------------------------------------------------*/
/* Test Setup and Teardown */
/*------------------------------------------------------------------*/

static int testSetup(void **ppState)
{
    MOC_UNUSED(ppState);
    MSTATUS status;

    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

    status = SSHC_STR_HOUSE_initStringBuffers();
    if (OK != status)
        goto exit;

    status = BASE64_initializeContext();

exit:
    return (OK == status) ? 0 : -1;
}

static int testTeardown(void **ppState)
{
    MOC_UNUSED(ppState);
    MSTATUS status;

    status = BASE64_freeContext();
    if (OK != status)
        goto exit;

    status = SSHC_STR_HOUSE_freeStringBuffers();
    if (OK != status)
        goto exit;

    status = DIGICERT_freeDigicert();

exit:
    return (OK == status) ? 0 : -1;
}

/*------------------------------------------------------------------*/
/* Main Test Runner */
/*------------------------------------------------------------------*/

int main(int argc, char* argv[])
{
    MOC_UNUSED(argc);
    MOC_UNUSED(argv);
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    const struct CMUnitTest tests[] = {
        /* Parameter validation tests */
        cmocka_unit_test(test_SSHC_UTILS_sshParseAuthPublicKeyFile_null_params),
        cmocka_unit_test(test_SSHC_UTILS_sshParseAuthPublicKey_null_params),

        /* Buffer manipulation tests */
        cmocka_unit_test(test_SSHC_UTILS_getByte_success),
        cmocka_unit_test(test_SSHC_UTILS_getByte_buffer_overflow),
        cmocka_unit_test(test_SSHC_UTILS_getInteger_success),
        cmocka_unit_test(test_SSHC_UTILS_getInteger_insufficient_buffer),
        cmocka_unit_test(test_SSHC_UTILS_getInteger64_success),
        cmocka_unit_test(test_SSHC_UTILS_getInteger64_buffer_overflow),
        cmocka_unit_test(test_SSHC_UTILS_setByte_success),
        cmocka_unit_test(test_SSHC_UTILS_setByte_buffer_overflow),
        cmocka_unit_test(test_SSHC_UTILS_setInteger_success),
        cmocka_unit_test(test_SSHC_UTILS_setInteger_buffer_overflow),
        cmocka_unit_test(test_SSHC_UTILS_setInteger64_success),
        cmocka_unit_test(test_SSHC_UTILS_setInteger64_buffer_overflow),

        /* File based tests */
        cmocka_unit_test(sshcClientFileECDSA256),
        cmocka_unit_test(sshcClientFileECDSA384),
        cmocka_unit_test(sshcClientFileECDSA521),
        cmocka_unit_test(sshcClientFileED25519),
        cmocka_unit_test(sshcClientFileRSA4096),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */