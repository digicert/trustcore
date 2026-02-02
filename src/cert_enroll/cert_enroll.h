/*
 * cert_enroll.h
 *
 * Implementation of cert enrollment generation.
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

#ifndef __CERT_ENROLL_HEADER__
#define __CERT_ENROLL_HEADER__

#include "../common/mjson.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../crypto_interface/cryptointerface.h"
#include "../tap/tap_smp.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    certEnrollAlgUndefined = -1,
    rsa2048 = 0,
    rsa3072 = 1,
    rsa4096 = 2,
    ecdsaP256 = 8,
    ecdsaP384 = 9,
    ecdsaP521 = 10,
    eddsaEd25519 = 16,
    eddsaEd448 = 17,
    mldsa44 = 30,
    mldsa65 = 31,
    mldsa87 = 32,
    fndsa1024 = 64,
    slhdsaSha128f = 128,
    slhdsaSha128s = 129,
    slhdsaSha192f = 130,
    slhdsaSha192s = 131,
    slhdsaSha256f = 132,
    slhdsaSha256s = 133,
    slhdsaShake128f = 134,
    slhdsaShake128s = 135,
    slhdsaShake192f = 136,
    slhdsaShake192s = 137,
    slhdsaShake256f = 138,
    slhdsaShake256s = 139

} CertEnrollAlg;

typedef enum
{
    CE_FORMAT_UNDEFIND = -1,
    CE_FORMAT_PKCS10 = 0,
    CE_FORMAT_CMC = 1
} CertEnrollFormat;

typedef enum
{
    CE_UNDEFINED = -1,
    CE_SCEP = 0,
    CE_TPM2_ATTEST = 1,
    CE_SKG = 2,
    CE_TRUSTED_SIGNER = 3

} CertEnrollMode;

typedef enum
{
    JSON = 0,
    TOML = 1,
    JSON_ALT = 2

} CsrFormat;

typedef enum
{
  smimeCapabilities = 0,
  decryptKeyIdentifier = 1,
  asymDecryptKeyIdentifier = 2,
  renewalCert = 3,
  challengePassword = 4

} ReqAttrType;

typedef enum ExtendedEnrollFlow
{
    EXT_ENROLL_FLOW_NONE = 0,
    EXT_ENROLL_FLOW_TPM2_IDEVID,
    EXT_ENROLL_FLOW_TPM2_IAK
} ExtendedEnrollFlow;

typedef MSTATUS (*CertSignData)(void *pCbInfo,
                                const ubyte *digestAlgoOID,
                                const ubyte *pDataToSign,
                                ubyte4 dataToSignLen,
                                ubyte *pSigBuffer,
                                ubyte4 sigBufferLen);

typedef MSTATUS (*CertDecryptData)(void *pCbInfo,
                                   const ubyte *pDataToDecrypt,
                                   ubyte4 dataToDecryptLen,
                                   ubyte *pPlainText,
                                   ubyte4 plainTextLen);

typedef MSTATUS (*EvalFunction)(void *pEvalFunctionArg,
                                byteBoolean *pUseDefault,
                                sbyte *pExpression,
                                ubyte4 expressionLen,
                                sbyte *pOutput,
                                ubyte4 *pOutputLen);

typedef struct _CertKeyHandle
{
    ubyte *pKey;
    ubyte4 keyLen;
    ubyte *pNonce;
    ubyte4 nonceLen;

} CertKeyHandle;

typedef struct _CertKeyCtx
{
    AsymmetricKey *pKey;
    union
    {
        CertSignData signFun;
        CertDecryptData decFun;
    } cb;
 
    CertEnrollAlg keyAlgorithm;
    ubyte4 secureModuleId;
    byteBoolean primary;

    ubyte *pPassword;
    ubyte4 passwordLen;
    CertKeyHandle handle;

} CertKeyCtx;

typedef struct _CertCsrCtx
{
    certDistinguishedName *pCertSubjectInfo;
    requestAttributesEx reqAttr;
    byteBoolean processSigAlgs;
    ubyte4 hashId;
    ubyte4 keyType;
    AsymmetricKey *pKey;
    CertEnrollAlg keyAlgorithm;
    EvalFunction evalFunction;
    void *pEvalFunctionArg;
    void *pTAPCallback;
    ExtendedEnrollFlow extFlow;
} CertCsrCtx;

#ifdef __ENABLE_DIGICERT_TAP__
typedef struct _CertTapKeyCtx
{
    TAP_PROVIDER source;
    TAP_KEY_USAGE keyUsage;
    TAP_SIG_SCHEME sigScheme;
    TAP_ENC_SCHEME encScheme;

} CertTapKeyCtx;
#endif

typedef struct _CertExtCMCCtx
{
     void *empty; /* TODO */
} CertExtCMCCtx;

typedef struct _CertSignAttrCtx
{
    void *empty; /* TODO */
} CertSignAttrCtx;

typedef struct _CertExtCtx
{
    void *empty; /* TODO */
} CertExtCtx;

MOC_EXTERN MSTATUS CERT_ENROLL_addKeyCertAttributes(
    CertKeyCtx *pKeyCtx,
    AsymmetricKey *pKey,
    CertSignData signFun,
    CertDecryptData decFun,
    CertEnrollAlg keyAlgorithm,
    ubyte4 secureModuleId,
    byteBoolean primary,
    ubyte *pPassword,
    ubyte4 passwordLen,
    CertKeyHandle *pHandles
);

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CERT_ENROLL_addTapKeyAttributes(
    CertTapKeyCtx *pTapKeyCtx,
    TAP_PROVIDER source,
    TAP_KEY_USAGE keyUsage,
    TAP_SIG_SCHEME sigScheme,
    TAP_ENC_SCHEME encScheme
);
#endif

MOC_EXTERN MSTATUS CERT_ENROLL_cleanupKeyCtx(
    CertKeyCtx *pKeyCtx
);

MOC_EXTERN MSTATUS CERT_ENROLL_addCsrAttributes(
    CertCsrCtx *pCsrCtx,
    CsrFormat format,
    CertEnrollMode cmcType,
    EvalFunction evalFunction,
    void *pEvalFunctionArg,
    AsymmetricKey *pKey,
    CertEnrollAlg keyAlgorithm,
    byteBoolean processSigAlgs,
    ubyte4 hashId,
    ubyte *pIn,
    ubyte4 inLen,
    CertExtCtx *pExtCtx,
    ExtendedEnrollFlow extFlow
);

/* exposed for direct use by the crypto keygen tool */
MOC_EXTERN MSTATUS CERT_ENROLL_addCsrAttributeTOML(
    ubyte *pIn, 
    ubyte4 inLen, 
    CertCsrCtx *pCsrCtx,
    certDistinguishedName **ppSubject, 
    certExtensions **ppExtensions
);

MOC_EXTERN MSTATUS CERT_ENROLL_addSubjectKeyIdentifier(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey, 
    certExtensions *pExtensions
);

MOC_EXTERN MSTATUS CERT_ENROLL_setCertDates(
    certDistinguishedName *pDest, 
    TimeDate *pStart, 
    TimeDate *pEnd
);

MOC_EXTERN void CERT_ENROLL_freeExtensions(
    certExtensions *pExtensions
);

MOC_EXTERN MSTATUS CERT_ENROLL_addReqAttribute(
    CertCsrCtx *pCsrCtx,
    ReqAttrType type,
    ubyte *pValue,
    ubyte4 valueLen
);

MOC_EXTERN MSTATUS CERT_ENROLL_cleanupCsrCtx(
    CertCsrCtx *pCsrCtx
);

MOC_EXTERN MSTATUS CERT_ENROLL_generateCMCRequest(
    CertKeyCtx *pKeyCtx,
    void *pTapKeyCtx,
    CertCsrCtx *pCsrCtx,
    CertExtCMCCtx *pExtCMCCtx,
    CertSignAttrCtx *pSignAttrCtx,
    CertEnrollMode cmcType,
    ubyte **ppCMC,
    ubyte4 *pCMCLen
);

MOC_EXTERN MSTATUS CERT_ENROLL_generateCSRRequest(
    CertKeyCtx *pKeyCtx,
    void *pTapKeyCtx,
    CertCsrCtx *pCsrCtx,
    CertEnrollMode cmcType,
    ubyte **ppCsr,
    ubyte4 *pCsrLen
);

MOC_EXTERN MSTATUS CERT_ENROLL_parseResponse(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pInput,
    ubyte4 inputLen,
    AsymmetricKey *pPrivKey,
    intBoolean chainOnly,
    certDescriptor **ppCertDescArray,
    ubyte4 *pCertDescArrayLen
);

MOC_EXTERN MSTATUS CERT_ENROLL_getFullPath(
    sbyte *pPath,
    sbyte *pSubDir,
    sbyte *pAlias, 
    sbyte *pSuffix,
    sbyte **ppFullPath
);

#if defined(__ENABLE_DIGICERT_TAP__)

typedef struct
{
    ubyte4 moduleId;
    byteBoolean primary;
    TAP_HIERARCHY_PROPERTY hierarchy;
    TAP_KEY_USAGE keyUsage;
    TAP_SIG_SCHEME sigScheme;
    TAP_ENC_SCHEME encScheme;
    TAP_Buffer *pKeyHandle;
    ubyte8 keyNonceHandle;
    ubyte8 certHandle;
} CertEnrollTAPAttributes;

MOC_EXTERN MSTATUS CERT_ENROLL_parseTAPAttributes(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    CertEnrollAlg alg,
    CertEnrollTAPAttributes *pAttributes);

MOC_EXTERN MSTATUS CERT_ENROLL_setTAPCallback(
    CertCsrCtx *pCsrCtx,
    pFuncPtrGetTapContext pTAPCallback);

#endif /* __ENABLE_DIGICERT_TAP__ */

#ifdef __cplusplus
}
#endif

#endif /* __CERT_ENROLL_HEADER__ */
