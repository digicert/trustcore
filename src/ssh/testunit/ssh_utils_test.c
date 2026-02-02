/*
 * ssh_utils_test.c
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
#define __IN_DIGICERT_C__     /* FOR TESTING PURPOSES --- ENABLES BASE64 init/free */
#include "../../common/base64.h"
#include "../../crypto/dsa.h"
#include "../../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/ssh_str_house.h"
#include "../../ssh/ssh_utils.h"
#include "../../ssh/ssh.h"

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__))

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__)
#include <stdio.h>
#include <string.h>
#define PRINTF1      printf
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF1(X)
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_SERVER__
static MSTATUS
parseAndComparePubKey(sbyte *pKeyFile, ubyte4 fileSize, AsymmetricKey *pOrigKey)
{
    AsymmetricKey   pKeyDescr;
    MSTATUS         status;

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_matchPublicKey(&pKeyDescr, pOrigKey);
    assert_int_equal(OK, status);

exit:
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);

    return status;

} /* parseAndComparePubKey */
#endif /* (defined(__ENABLE_DIGICERT_SSH_SERVER__)) */


/*------------------------------------------------------------------*/

void openSSHFileECDSA256(void **ppState)
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
    ubyte           MD5FP[16];
    ubyte           SHA1FP[20];

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ecdsa256.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = SSH_publicKeyFingerPrints(pSerKeyFile, serKeyFileSize, MD5FP, SHA1FP);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
} /* openSSHFileECDSA256 */


/*------------------------------------------------------------------*/

void openSSHFileECDSA384(void **ppState)
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
    ubyte           MD5FP[16];
    ubyte           SHA1FP[20];

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ecdsa384.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = SSH_publicKeyFingerPrints(pSerKeyFile, serKeyFileSize, MD5FP, SHA1FP);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
} /* openSSHFileECDSA384 */


/*------------------------------------------------------------------*/

void openSSHFileECDSA521(void **ppState)
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
    ubyte           MD5FP[16];
    ubyte           SHA1FP[20];

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ecdsa521.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = SSH_publicKeyFingerPrints(pSerKeyFile, serKeyFileSize, MD5FP, SHA1FP);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
} /* openSSHFileECDSA521 */


/*------------------------------------------------------------------*/

void openSSHFileED25519(void **ppState)
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
    ubyte           MD5FP[16];
    ubyte           SHA1FP[20];

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_ed25519.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = SSH_publicKeyFingerPrints(pSerKeyFile, serKeyFileSize, MD5FP, SHA1FP);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
} /* openSSHFileED25519 */


/*------------------------------------------------------------------*/

void openSSHFileRSA4096(void **ppState)
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
    ubyte           MD5FP[16];
    ubyte           SHA1FP[20];

    status = CRYPTO_initAsymmetricKey(&pKeyDescr);
    assert_int_equal(OK, status);

    status = DIGICERT_readFile("../test/key_rsa4096.pub", &pKeyFile, &fileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_sshParseAuthPublicKeyFile(pKeyFile, fileSize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = CRYPTO_serializeAsymKey(&pKeyDescr, mocanaBlobVersion2, &pSerKeyFile, &serKeyFileSize);
    assert_int_equal(OK, status);

    status = SSH_UTILS_generateHostKeyFile(pSerKeyFile, serKeyFileSize, &pEncodedPubKey, &encodedPubKeySize);
    assert_int_equal(OK, status);

    status = parseAndComparePubKey(pEncodedPubKey, encodedPubKeySize, &pKeyDescr);
    assert_int_equal(OK, status);

    status = SSH_publicKeyFingerPrints(pSerKeyFile, serKeyFileSize, MD5FP, SHA1FP);
    assert_int_equal(OK, status);

    DIGI_FREE((void **) &pKeyFile);
    DIGI_FREE((void **) &pSerKeyFile);
    DIGI_FREE((void **) &pEncodedPubKey);
    CRYPTO_uninitAsymmetricKey(&pKeyDescr, NULL);
} /* openSSHFileRSA4096 */


static int testSetup(void **ppState)
{
    MOC_UNUSED(ppState);
    MSTATUS status;

    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

    status = SSH_STR_HOUSE_initStringBuffers();
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

    status = SSH_STR_HOUSE_freeStringBuffers();
    if (OK != status)
        goto exit;

    status = DIGICERT_freeDigicert();

exit:
    return (OK == status) ? 0 : -1;
}
#endif /* __ENABLE_DIGICERT_SSH_SERVER__ */

int main(int argc, char* argv[])
{
    MOC_UNUSED(argc);
    MOC_UNUSED(argv);
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(openSSHFileECDSA256),
        cmocka_unit_test(openSSHFileECDSA384),
        cmocka_unit_test(openSSHFileECDSA521),
        cmocka_unit_test(openSSHFileED25519),
        cmocka_unit_test(openSSHFileRSA4096),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}
