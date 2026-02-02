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

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

MOC_EXTERN MSTATUS FIPS_INTEG_TEST_hash_memory(
    ubyte* hashReturn, ubyte* data, ubyte4 dataLen);

/* Sub FIPS Tests */
MOC_EXTERN MSTATUS FIPS_knownAnswerTests(void);

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

    FIPS_RSA_TESTNUM = 48,
    FIPS_RSA_WRAPPER_TESTNUM = 49,
    FIPS_DSA_TESTNUM = 50,
    FIPS_ECDSA_TESTNUM = 51,
    FIPS_EDDSA_TESTNUM = 52,
    FIPS_MLKEM_KEY_TESTNUM = 53,
    FIPS_MLKEM_ENCAP_TESTNUM = 54,
    FIPS_MLKEM_DECAP_TESTNUM = 55,
    FIPS_MLDSA_KEY_TESTNUM = 56,
    FIPS_MLDSA_SIGN_TESTNUM = 57,
    FIPS_MLDSA_VERIFY_TESTNUM = 58,
    FIPS_SLHDSA_SHA2_KEY_TESTNUM = 59,
    FIPS_SLHDSA_SHA2_SIGN_TESTNUM = 60,
    FIPS_SLHDSA_SHA2_VERIFY_TESTNUM = 61,
    FIPS_SLHDSA_SHAKE_KEY_TESTNUM = 62,
    FIPS_SLHDSA_SHAKE_SIGN_TESTNUM = 63,
    FIPS_SLHDSA_SHAKE_VERIFY_TESTNUM = 64,

    /* Failure Test Names */
    FIPS_BREAK_PUBLIC_KEY_TESTNUM = 65,
    FIPS_DSA_CONSISTANCY_TESTNUM = 66,
    FIPS_RSA_CONSISTANCY_TESTNUM = 67,
    FIPS_ECDSA_CONSISTANCY_TESTNUM = 68,
    FIPS_EDDSA_CONSISTANCY_TESTNUM = 69,
    FIPS_MLDSA_CONSISTANCY_TESTNUM = 70,
    FIPS_SLHDSA_CONSISTANCY_TESTNUM = 71,
    FIPS_MLKEM_CONSISTANCY_TESTNUM = 72,

    FIPS_FORCE_FAIL_DRBG_CTR_RNG_TESTNUM = 73,
    FIPS_FORCE_FAIL_NO_ENTROPY_ADDED_TESTNUM = 74,
    FIPS_FORCE_FAIL_ENTROPY_LIMIT_TESTNUM = 75,

    /* Integrity Test Names */
    FIPS_INTEGRITY_CHECK_TESTNUM = 76,
    FIPS_INTEGRITY_FAIL_AND_CHECK_TESTNUM = 77,

    FIPS_MAX_TEST_COUNT = 78
};

#define FIRST_KAT_TEST  FIPS_RNG_DRBG_CTR_TESTNUM
#define LAST_KAT_TEST   FIPS_SLHDSA_SHAKE_VERIFY_TESTNUM

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
#define FIPS_CONFIG_MUTEX   101

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
#define FIPS_FORCE_FAIL_MLDSA_CONSISTANCY_TESTNUM      0x05    /* startup & ops */
#define FIPS_FORCE_FAIL_SLHDSA_CONSISTANCY_TESTNUM     0x06    /* startup & ops */
#define FIPS_FORCE_FAIL_MLKEM_CONSISTANCY_TESTNUM      0x07    /* startup & ops */
#define FIPS_FORCE_FAIL_DRBG_TESTNUM                   0x08    /* startup & ops */

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
#define FIPS_FORCE_FAIL_MLKEM_KEY_TEST         (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_MLKEM_KEY_TESTNUM))
#define FIPS_FORCE_FAIL_MLKEM_ENCAP_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_MLKEM_ENCAP_TESTNUM))
#define FIPS_FORCE_FAIL_MLKEM_DECAP_TEST       (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_MLKEM_DECAP_TESTNUM))
#define FIPS_FORCE_FAIL_MLDSA_KEY_TEST         (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_MLDSA_KEY_TESTNUM))
#define FIPS_FORCE_FAIL_MLDSA_SIGN_TEST        (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_MLDSA_SIGN_TESTNUM))
#define FIPS_FORCE_FAIL_MLDSA_VERIFY_TEST      (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_MLDSA_VERIFY_TESTNUM))
#define FIPS_FORCE_FAIL_SLHDSA_SHA2_KEY_TEST   (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SLHDSA_SHA2_KEY_TESTNUM))
#define FIPS_FORCE_FAIL_SLHDSA_SHA2_SIGN_TEST  (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SLHDSA_SHA2_SIGN_TESTNUM))
#define FIPS_FORCE_FAIL_SLHDSA_SHA2_VERIFY_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SLHDSA_SHA2_VERIFY_TESTNUM))
#define FIPS_FORCE_FAIL_SLHDSA_SHAKE_KEY_TEST  (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SLHDSA_SHAKE_KEY_TESTNUM))
#define FIPS_FORCE_FAIL_SLHDSA_SHAKE_SIGN_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SLHDSA_SHAKE_SIGN_TESTNUM))
#define FIPS_FORCE_FAIL_SLHDSA_SHAKE_VERIFY_TEST (ALGO_POWERUP_TESTSHOULDFAIL(FIPS_SLHDSA_SHAKE_VERIFY_TESTNUM))

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

/* =========================================================================================================== */
/* FIPS Known Answer Tests                                                                                     */
/* =========================================================================================================== */

MOC_EXTERN MSTATUS FIPS_nistRngKat(void);
MOC_EXTERN MSTATUS FIPS_rsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_dsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_ecdsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_eddsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mldsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsaKat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mlkemKat(hwAccelDescr hwAccelCtx);

MOC_EXTERN MSTATUS FIPS_mldsa_key_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mldsa_sign_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mldsa_verify_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsa_sha2_key_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsa_sha2_sign_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsa_sha2_verify_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsa_shake_key_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsa_shake_sign_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_slhdsa_shake_verify_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mlkem_key_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mlkem_decap_Kat(hwAccelDescr hwAccelCtx);
MOC_EXTERN MSTATUS FIPS_mlkem_encap_Kat(hwAccelDescr hwAccelCtx);

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

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
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
/* FIPS Algorithm Logging functions (called within FIPS boundary.                                              */
/* =========================================================================================================== */

MOC_EXTERN void FIPS_logAlgoEvent(enum FIPS_EventTypes eventType,
    const enum FIPSAlgoNames algoId, ubyte4* eventSessionId,
    ubyte4 keySize);

/* =========================================================================================================== */
/* FIPS Power-up status check, FIPS Event / Algorithm logging & related #defines are defined in moptions.h     */
/* =========================================================================================================== */

/* Types to access 'hidden' functions via privileged call 
 * Types s_fct and FIPS_entry_fct are in mtypes.h so they will 
 * be available to all crypto source folders */

/* Run-time support for operational testing.
 * Accessed via the "privileged" API.
 */
#define FIPS_RESET_STARTUP_FAIL_F_ID        1
#define FIPS_INTERNAL_STARTUP_SELFTEST_F_ID 2
#define FIPS_INTERNAL_RESET_INITIAL_F_ID    3
#define FIPS_FILL_INTERNAL_POWERUP_F_ID     4

typedef MSTATUS (fips_internal_startup_selftest)(FIPS_InternalPowerupTestConfig* testConfig);
typedef MSTATUS (fips_internal_reset_initial)(int fips_algoid);
typedef MSTATUS (fips_fill_internal_powerup)(FIPS_InternalPowerupTestConfig* testConfig);

MOC_EXTERN const FIPS_entry_fct* FIPS_getPrivileged(void);

MOC_EXTERN MSTATUS FIPS_locateFunction(const FIPS_entry_fct *table, int id, s_fct **ppOut);

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#ifdef __cplusplus
}
#endif

#endif /* __FIPS_PRIV_HEADER__ */
