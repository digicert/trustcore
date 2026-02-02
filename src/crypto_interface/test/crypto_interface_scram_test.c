/*
 * crypto_interface_scram_test.c
 *
 * SCRAM Test
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

#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__

#include "../../common/initmocana.h"
#include "../../crypto/crypto.h"
#include "../../crypto/scram_client.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/*--------------------------------------------------------------------------*/

typedef struct
{
    sbyte *pUsername;
    sbyte *pPassword;
    ubyte hash;
    sbyte *pClientNonce;
    sbyte *pClientFirst;
    sbyte *pServerFirst;
    sbyte *pClientFinal;
    sbyte *pServerSignature;
} ScramKAT;

/*--------------------------------------------------------------------------*/

static ScramKAT gpScramKAT[] = {
    {
        /* Vector from RFC 5802 */
        "user",
        "pencil",
        ht_sha1,
        "fyko+d2lbbFgONRv9qkxdawL",
        "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
        "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
        "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
        "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="
    },
    {
        /* Vector from RFC 7677 */
        "user",
        "pencil",
        ht_sha256,
        "rOprNGfwEbeRWgbNEkqO",
        "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    }
};

/*--------------------------------------------------------------------------*/

static int scram_test_kat(ScramKAT *pTest)
{
    int retVal = 0;
    MSTATUS status;
    ScramCtx *pCtx = NULL;
    byteBoolean verify = FALSE;
    ubyte *pClientFirst = NULL, *pClientFinal = NULL;
    ubyte4 clientFirstLen = 0, clientFinalLen = 0;
    sbyte4 cmpRes;

    status = SCRAM_newCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = SCRAM_buildClientFirstData(
        pCtx, pTest->pUsername,
        pTest->pClientNonce, DIGI_STRLEN(pTest->pClientNonce),
        &pClientFirst, &clientFirstLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, clientFirstLen, DIGI_STRLEN(pTest->pClientFirst));
    if (retVal)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pClientFirst, pTest->pClientFirst, clientFirstLen, &cmpRes);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, cmpRes, 0);
    if (retVal)
        goto exit;

    status = SCRAM_buildClientFinal(MOC_HASH(gpHwAccelCtx)
        pCtx, pTest->pServerFirst, DIGI_STRLEN(pTest->pServerFirst),
        pTest->pPassword, DIGI_STRLEN(pTest->pPassword), pTest->hash,
        &pClientFinal, &clientFinalLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, clientFinalLen, DIGI_STRLEN(pTest->pClientFinal));
    if (retVal)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pClientFinal, pTest->pClientFinal, clientFinalLen, &cmpRes);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, cmpRes, 0);
    if (retVal)
        goto exit;

    status = SCRAM_verifyServerSignature(MOC_HASH(gpHwAccelCtx)
        pCtx, pTest->pPassword, DIGI_STRLEN(pTest->pPassword),
        pTest->pServerSignature, DIGI_STRLEN(pTest->pServerSignature), &verify);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, verify, TRUE);
    if (retVal)
        goto exit;

exit:

    if (pClientFinal != NULL) {
        DIGI_FREE((void **) &pClientFinal);
    }

    status = SCRAM_freeCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    return retVal;
}

/*--------------------------------------------------------------------------*/

static int scram_kat(void)
{
    MSTATUS status;
    int i, retVal = 0;

    for (i = 0; i < COUNTOF(gpScramKAT); i++)
    {
        retVal += scram_test_kat(gpScramKAT + i);
    }

    return retVal;
}
#endif

/*--------------------------------------------------------------------------*/

int crypto_interface_scram_test_all()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
    MSTATUS status;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        retVal = 1;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    
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

    retVal += scram_kat();

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
#endif    
    return retVal;
}
