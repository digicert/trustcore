/*
 * fips_priv.h
 *
 * FIPS 140 Compliance
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


#ifndef __FIPS_PRIV_HEADER__
#define __FIPS_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__KERNEL__))
#include <linux/kernel.h>       /* for printk */
#define FIPS_PRINT              printk
#else
#include <stdio.h>              /* for printf */
#define FIPS_PRINT              printf
#endif

#ifdef __ENABLE_MOCANA_FIPS_MODULE__

MOC_EXTERN MSTATUS FIPS_INTEG_TEST_hash_memory(
    ubyte* hashReturn, ubyte* data, ubyte4 dataLen);

/* Sub FIPS Tests */
MOC_EXTERN MSTATUS FIPS_knownAnswerTests(void);
#if (!defined(__ENABLE_MOCANA_CRYPTO_KERNEL_MODULE_FIPS__))
MOC_EXTERN MSTATUS FIPS_pairwiseConsistencyTests(void);
#endif

/* Run-time support for operational testing.
 *
 */
#ifdef __FIPS_OPS_TEST__
MOC_EXTERN void FIPS_resetStartupFail(void);
#endif

#define DO_ENCRYPT 1
#define DO_DECRYPT 0

enum FIPSStartupState
{
    FIPS_SS_INIT,
    FIPS_SS_INPROCESS,
    FIPS_SS_DONE
};

typedef struct FIPSStartupStatus
{
    MSTATUS           integrityTestStatus;
    MSTATUS           globalFIPS_powerupStatus;
    enum FIPSStartupState  startupState;
    int               startupShouldFail;
    ubyte4            startupFailTestNumber;
    intBoolean        algoEnabled[NUM_FIPS_ALGONAME_VALUES];
    MSTATUS           algoStatus[NUM_FIPS_ALGONAME_VALUES];
    ubyte             fingerPrint[32];
} FIPSStartupStatus;


/* This (FIPSAlgoTestNames) set gives more granularity for testing than the FIPSAlgoNames defined in fips.h */

/* Note: If any Algo Test Names are added, the TestSetupMap table in crypto_example
 * must be updated. */

enum FIPSAlgoTestNames
{
    /* KAT Test Names */
    FIPS_RNG_DRBG_CTR_TESTNUM = 0,

    FIPS_MD2_TESTNUM = 1,
    FIPS_MD4_TESTNUM = 2,
    FIPS_MD5_TESTNUM = 3,
    FIPS_AES_XCB_MAC96_TESTNUM = 4,
    FIPS_AES_EAX_TESTNUM = 5,

    FIPS_SHA1_TESTNUM = 6,
    FIPS_SHA224_TESTNUM = 7,
    FIPS_SHA256_TESTNUM = 8,
    FIPS_SHA384_TESTNUM = 9,
    FIPS_SHA512_TESTNUM = 10,

    FIPS_SHA3_224_TESTNUM = 11,
    FIPS_SHA3_256_TESTNUM = 12,
    FIPS_SHA3_384_TESTNUM = 13,
    FIPS_SHA3_512_TESTNUM = 14,
    FIPS_SHAKE_128_TESTNUM = 15,
    FIPS_SHAKE_256_TESTNUM = 16,

    FIPS_HMAC_SHA1_TESTNUM = 17,
    FIPS_HMAC_SHA224_TESTNUM = 18,
    FIPS_HMAC_SHA256_TESTNUM = 19,
    FIPS_HMAC_SHA384_TESTNUM = 20,
    FIPS_HMAC_SHA512_TESTNUM = 21,

    FIPS_HMAC_SHA3_224_TESTNUM = 22,
    FIPS_HMAC_SHA3_256_TESTNUM = 23,
    FIPS_HMAC_SHA3_384_TESTNUM = 24,
    FIPS_HMAC_SHA3_512_TESTNUM = 25,

    FIPS_HMAC_KDF_SHA1_TESTNUM = 26,
    FIPS_HMAC_KDF_SHA224_TESTNUM = 27,
    FIPS_HMAC_KDF_SHA256_TESTNUM = 28,
    FIPS_HMAC_KDF_SHA384_TESTNUM = 29,
    FIPS_HMAC_KDF_SHA512_TESTNUM = 30,

    FIPS_HMAC_KDF_SHA3_224_TESTNUM = 31,
    FIPS_HMAC_KDF_SHA3_256_TESTNUM = 32,
    FIPS_HMAC_KDF_SHA3_384_TESTNUM = 33,
    FIPS_HMAC_KDF_SHA3_512_TESTNUM = 34,

    FIPS_AES_ECB_TESTNUM = 35,
    FIPS_AES_CBC_TESTNUM = 36,
    FIPS_AES_CFB_TESTNUM = 37,
    FIPS_AES_OFB_TESTNUM = 38,
    FIPS_AES_CCM_TESTNUM = 39,
    FIPS_AES_CTR_TESTNUM = 40,
    FIPS_AES_CMAC_TESTNUM = 41,
    FIPS_AES_GCM_TESTNUM = 42,
    FIPS_AES_XTS_TESTNUM = 43,

    FIPS_3DES_CBC_TESTNUM = 44,

    FIPS_DH_TESTNUM = 45,
    FIPS_ECDH_TESTNUM = 46,
    FIPS_EDDH_TESTNUM = 47,

    /* PCT Test Names */
    FIPS_RSA_TESTNUM = 48,
    FIPS_RSA_WRAPPER_TESTNUM = 49,
    FIPS_DSA_TESTNUM = 50,
    FIPS_ECDSA_TESTNUM = 51,
    FIPS_EDDSA_TESTNUM = 52,

    /* Failure Test Names */
    FIPS_BREAK_PUBLIC_KEY_TESTNUM = 53,
    FIPS_DSA_CONSISTANCY_TESTNUM = 54,
    FIPS_RSA_CONSISTANCY_TESTNUM = 55,
    FIPS_ECDSA_CONSISTANCY_TESTNUM = 56,
    FIPS_EDDSA_CONSISTANCY_TESTNUM = 57,
    FIPS_FORCE_FAIL_DRBG_CTR_RNG_TESTNUM = 58,
    FIPS_FORCE_FAIL_NO_ENTROPY_ADDED_TESTNUM = 59,
    FIPS_FORCE_FAIL_ENTROPY_LIMIT_TESTNUM = 60,

    /* Integrity Test Names */
    FIPS_INTEGRITY_CHECK_TESTNUM = 61,
    FIPS_INTEGRITY_FAIL_AND_CHECK_TESTNUM = 62,

    FIPS_MAX_TEST_COUNT = 63
};

#define FIRST_KAT_TEST  FIPS_RNG_DRBG_CTR_TESTNUM
#define LAST_KAT_TEST   FIPS_EDDH_TESTNUM
#define FIRST_PCT_TEST  FIPS_RSA_TESTNUM
#define LAST_PCT_TEST   FIPS_EDDSA_TESTNUM

typedef struct FIPS_InternalTestSetup
{
    enum FIPS_TestActions  action;
    intBoolean             enc_dec_pattern;
    intBoolean             failurePowerup;
    intBoolean             enc_failurePowerup;
    intBoolean             dec_failurePowerup;
} FIPS_InternalTestSetup;

typedef struct FIPS_InternalPowerupTestConfig
{
    FIPS_InternalTestSetup test[FIPS_MAX_TEST_COUNT];
} FIPS_InternalPowerupTestConfig;

extern FIPS_InternalPowerupTestConfig sInternalCurrPowerupTestConfig;

#define FIPS_STATUS_MUTEX   100

#define ALGO_POWERUP_ALGOIDSHOULDRUN(ALGOID) \
    ( (sCurrAlgoTestConfig.test[ALGOID].action == FIPS_FORCE) )

#define POWERUP_ALGOTESTNUMSHOULDRUN(ALGOTESTNUM) \
    ( (sInternalCurrPowerupTestConfig.test[ALGOTESTNUM].action == FIPS_FORCE) )

/*------------------------------------------------------------------*/
#define FIPS_FORCE_FAIL_BREAK_PUBLIC_KEY_TESTNUM       0x00    /* startup & ops */
#define FIPS_FORCE_FAIL_DSA_CONSISTANCY_TESTNUM        0x01    /* startup & ops */
#define FIPS_FORCE_FAIL_RSA_CONSISTANCY_TESTNUM        0x02    /* startup & ops */
#define FIPS_FORCE_FAIL_ECDSA_CONSISTANCY_TESTNUM      0x03    /* startup & ops */
#define FIPS_FORCE_FAIL_EDDSA_CONSISTANCY_TESTNUM      0x04    /* startup & ops */
#define FIPS_FORCE_FAIL_DRBG_TESTNUM                   0x05    /* startup & ops */

#define ALGO_POWERUP_TESTSHOULDFAIL(ALGOID) \
    ( (sInternalCurrPowerupTestConfig.test[ALGOID].failurePowerup == TRUE) )

#define ALGO_POWERUP_ENC_TESTSHOULDFAIL(ALGOID) \
    ( (sInternalCurrPowerupTestConfig.test[ALGOID].enc_failurePowerup == TRUE) )

#define ALGO_POWERUP_DEC_TESTSHOULDFAIL(ALGOID) \
    ( (sInternalCurrPowerupTestConfig.test[ALGOID].dec_failurePowerup == TRUE) )

#define FIPS_FORCE_FAIL_DRBG_CTR_TEST          (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_RNG_DRBG_CTR_TESTNUM))

#define FIPS_FORCE_FAIL_SHA1_TEST              (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA1_TESTNUM))
#define FIPS_FORCE_FAIL_SHA224_TEST            (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA224_TESTNUM))
#define FIPS_FORCE_FAIL_SHA256_TEST            (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA256_TESTNUM))
#define FIPS_FORCE_FAIL_SHA384_TEST            (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA384_TESTNUM))
#define FIPS_FORCE_FAIL_SHA512_TEST            (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA512_TESTNUM))

#define FIPS_FORCE_FAIL_SHA3_224_TEST          (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA3_224_TESTNUM))
#define FIPS_FORCE_FAIL_SHA3_256_TEST          (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA3_256_TESTNUM))
#define FIPS_FORCE_FAIL_SHA3_384_TEST          (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA3_384_TESTNUM))
#define FIPS_FORCE_FAIL_SHA3_512_TEST          (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHA3_512_TESTNUM))
#define FIPS_FORCE_FAIL_SHAKE_128_TEST         (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHAKE_128_TESTNUM))
#define FIPS_FORCE_FAIL_SHAKE_256_TEST         (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SHAKE_256_TESTNUM))


#define FIPS_FORCE_FAIL_HMAC_SHA1_TEST         (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA1_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA224_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA224_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA256_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA256_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA384_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA384_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA512_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA512_TESTNUM))

#define FIPS_FORCE_FAIL_HMAC_SHA3_224_TEST     (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA3_224_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA3_256_TEST     (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA3_256_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA3_384_TEST     (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA3_384_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_SHA3_512_TEST     (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_SHA3_512_TESTNUM))

#define FIPS_FORCE_FAIL_HMAC_KDF_SHA1_TEST     (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA1_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA224_TEST   (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA224_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA256_TEST   (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA256_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA384_TEST   (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA384_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA512_TEST   (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA512_TESTNUM))

#define FIPS_FORCE_FAIL_HMAC_KDF_SHA3_224_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA3_224_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA3_256_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA3_256_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA3_384_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA3_384_TESTNUM))
#define FIPS_FORCE_FAIL_HMAC_KDF_SHA3_512_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_HMAC_KDF_SHA3_512_TESTNUM))

#define FIPS_FORCE_FAIL_AES_ECB_ENC_TEST       (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_AES_ECB_TESTNUM))
#define FIPS_FORCE_FAIL_AES_ECB_DEC_TEST       (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_AES_ECB_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CBC_ENC_TEST       (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_AES_CBC_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CBC_DEC_TEST       (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_AES_CBC_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CFB_ENC_TEST       (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_AES_CFB_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CFB_DEC_TEST       (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_AES_CFB_TESTNUM))
#define FIPS_FORCE_FAIL_AES_OFB_ENC_TEST       (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_AES_OFB_TESTNUM))
#define FIPS_FORCE_FAIL_AES_OFB_DEC_TEST       (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_AES_OFB_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CTR_ENC_TEST       (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_AES_CTR_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CTR_DEC_TEST       (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_AES_CTR_TESTNUM))
#define FIPS_FORCE_FAIL_AES_GCM_ENC_TEST       (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_AES_GCM_TESTNUM))
#define FIPS_FORCE_FAIL_AES_GCM_DEC_TEST       (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_AES_GCM_TESTNUM))

#define FIPS_FORCE_FAIL_AES_CCM_TEST           (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_AES_CCM_TESTNUM))
#define FIPS_FORCE_FAIL_AES_CMAC_TEST          (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_AES_CMAC_TESTNUM))
#define FIPS_FORCE_FAIL_AES_XTS_TEST           (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_AES_XTS_TESTNUM))

#define FIPS_FORCE_FAIL_3DES_CBC_ENC_TEST      (ALGO_POWERUP_ENC_TESTSHOULDFAIL(FIPS_3DES_CBC_TESTNUM))
#define FIPS_FORCE_FAIL_3DES_CBC_DEC_TEST      (ALGO_POWERUP_DEC_TESTSHOULDFAIL(FIPS_3DES_CBC_TESTNUM))

#define FIPS_FORCE_FAIL_DH_TEST                (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_DH_TESTNUM))
#define FIPS_FORCE_FAIL_ECDH_TEST              (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_ECDH_TESTNUM))
#define FIPS_FORCE_FAIL_EDDH_TEST              (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_EDDH_TESTNUM))

#define FIPS_FORCE_FAIL_RSA_TEST               (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_RSA_TESTNUM))
#define FIPS_FORCE_FAIL_RSA_WRAPPER_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_RSA_WRAPPER_TESTNUM)) /* Not used */
#define FIPS_FORCE_FAIL_DSA_TEST               (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_DSA_TESTNUM))
#define FIPS_FORCE_FAIL_ECDSA_TEST             (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_ECDSA_TESTNUM))
#define FIPS_FORCE_FAIL_EDDSA_TEST             (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_EDDSA_TESTNUM))

/* =========================================================================================================== */
/* FIPS Integrity Tests and Others                                                                                     */
/* =========================================================================================================== */
/* Used by a few algos to set a fatal error condition. (e.g. DRBG, DSA, ECDSA, etc..) */
MOC_EXTERN void setFIPS_Status(int fips_algoid, MSTATUS statusValue);

/* Used to get AlgoId from SHA3 or AES Mode */
MOC_EXTERN int FIPS_SHA3AlgoFromMode(ubyte4 sha3_mode);
MOC_EXTERN int FIPS_AESAlgoFromMode(ubyte4 aes_mode);

MOC_EXTERN void setFIPS_Status_Once(int fips_algoid, MSTATUS statusValue);

MOC_EXTERN MSTATUS FIPS_INTEG_TEST(void);
MOC_EXTERN MSTATUS FIPS_INTEG_TESTO(ubyte* pOut, ubyte4 outLen);
MOC_EXTERN void FIPS_startTestMsg(const char *pFunctionName, const char *pTestName);
MOC_EXTERN void FIPS_endTestMsg(const char *pFunctionName, const char *pTestName, MSTATUS status);

MOC_EXTERN MSTATUS FIPS_INTEG_TEST_hash_binSkip(
    ubyte* hashReturn, const char* optionalBinFileName, ubyte4 offset);

MOC_EXTERN MSTATUS FIPS_persistReadStatus(FIPSStartupStatus *pStatus);
MOC_EXTERN MSTATUS FIPS_persistWriteStatus(FIPSStartupStatus *pStatus);

MOC_EXTERN void FIPS_DumpStartupStatusData(void);
MOC_EXTERN MSTATUS FIPS_InitializeBeforeIntegrityChk(void);
MOC_EXTERN MSTATUS FIPS_InitializeAfterIntegrityChk(void);
MOC_EXTERN MSTATUS FIPS_Finalize(void);

/* Main FIPS Startup tests */
MOC_EXTERN MSTATUS FIPS_powerupSelfTest(void);
MOC_EXTERN MSTATUS FIPS_powerupSelfTestEx(FIPSRuntimeConfig *pfips_config);
MOC_EXTERN MSTATUS FIPS_StatusImport(void);
MOC_EXTERN MSTATUS FIPS_getDefaultConfig(FIPSRuntimeConfig *pfips_config);


/* Internal Test interface used in CMVP Operational testing, exported because it is useful when debugging... */
MOC_EXTERN MSTATUS FIPS_InternalCopyStartupStatus(FIPSStartupStatus *pCopyOfStatus);

#ifdef __FIPS_OPS_TEST__
/* Test interfaces used only in CMVP Operational testing. */
MOC_EXTERN MSTATUS FIPS_InternalStartupSelftest(FIPS_InternalPowerupTestConfig* testConfig);

MOC_EXTERN MSTATUS FIPS_InternalResetInitialAlgoStatus(int fips_algoid);
#endif

/* =========================================================================================================== */
/* FIPS Known Answer Tests                                                                                     */
/* =========================================================================================================== */

MOC_EXTERN MSTATUS FIPS_nistRngKat(void);
MOC_EXTERN MSTATUS FIPS_rsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_dsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_ecdsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_eddsaKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_sha1Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha224Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha384Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha512Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha224_256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha384_512Kat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_sha3_224Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha3_256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha3_384Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha3_512Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha3_shake128Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_sha3_shake256Kat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_hmacSha1Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha224Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha384Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha512Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacShaAllKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_hmacSha3_224Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha3_256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha3_384Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacSha3_512Kat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_aes256CbcKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_aesCfbKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_aes256CtrKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_aesOfbKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_aes256EcbKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_aesXtsKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_aesCcmKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_aesCmacKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_tdesCbcKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_aesGcmKat(hwAccelDescr hwAccelCtx);

#ifndef __ENABLE_MOCANA_CRYPTO_KERNEL_MODULE_FIPS__
MOC_EXTERN MSTATUS FIPS_dhKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_ecdhKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_eddhKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_hmacKdfSha1Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha224Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha384Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha512Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfAll_Kat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_hmacKdfSha3_224Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha3_256Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha3_384Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_hmacKdfSha3_512Kat(hwAccelDescr hwAccelCtx);

#endif

/* =========================================================================================================== */
/* FIPS Pairwise Consistency Tests                                                                             */
/* =========================================================================================================== */

#ifdef __ENABLE_MOCANA_FIPS_LEGACY_PCT__
#ifndef __ENABLE_MOCANA_CRYPTO_KERNEL_MODULE_FIPS__
MOC_EXTERN MSTATUS FIPS_dsaPct(hwAccelDescr hwAccelCtx, randomContext *pRandomContext);
MOC_EXTERN MSTATUS FIPS_ecdsaPct(hwAccelDescr hwAccelCtx, randomContext *pRandomContext);
MOC_EXTERN MSTATUS FIPS_eddsaPct(hwAccelDescr hwAccelCtx, randomContext *pRandomContext);
#endif 
#endif /* __ENABLE_MOCANA_FIPS_LEGACY_PCT__ */

/* =========================================================================================================== */
/* FIPS Algorithm Logging functions (called within FIPS boundary.                                              */
/* =========================================================================================================== */

MOC_EXTERN void FIPS_logAlgoEvent(enum FIPS_EventTypes eventType,
    const enum FIPSAlgoNames algoId, ubyte4* eventSessionId,
    ubyte4 keySize);

/* =========================================================================================================== */
/* FIPS Power-up status check, FIPS Event / Algorithm logging & related #defines are defined in moptions.h     */
/* =========================================================================================================== */

#endif /* __ENABLE_MOCANA_FIPS_MODULE__ */

#ifdef __cplusplus
}
#endif

#endif /* __FIPS_PRIV_HEADER__ */
