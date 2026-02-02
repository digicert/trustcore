/*
 * crypto_keygen.h
 *
 * key and cert gen API definitions
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

#ifndef __CRYPTO_KEYGEN_HEADER__
#define __CRYPTO_KEYGEN_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_KEYSTORE_PATH__

#ifndef KEYGEN_FOLDER_KEYS
#define KEYGEN_FOLDER_KEYS (sbyte *)"keys"
#endif
#ifndef KEYGEN_FOLDER_CERTS
#define KEYGEN_FOLDER_CERTS (sbyte *)"certs"
#endif
#ifndef KEYGEN_FOLDER_CONF
#define KEYGEN_FOLDER_CONF (sbyte *)"conf"
#endif
#ifndef KEYGEN_FOLDER_REQ
#define KEYGEN_FOLDER_REQ (sbyte *)"req"
#endif
#ifndef KEYGEN_FOLDER_CA
#define KEYGEN_FOLDER_CA (sbyte *)"ca"
#endif

#define KEYGEN_KEYSTORE_CA_MASK      0x01
#define KEYGEN_KEYSTORE_CERTS_MASK   (KEYGEN_KEYSTORE_CA_MASK    << 1)
#define KEYGEN_KEYSTORE_KEYS_MASK    (KEYGEN_KEYSTORE_CERTS_MASK << 1)
#define KEYGEN_KEYSTORE_REQ_MASK     (KEYGEN_KEYSTORE_KEYS_MASK  << 1)
#define KEYGEN_KEYSTORE_CONF_MASK    (KEYGEN_KEYSTORE_REQ_MASK   << 1)

#endif /* __ENABLE_KEYSTORE_PATH__ */

typedef struct _KeyGenArgs
{
    ubyte4 gKeyType;
    ubyte4 gKeySize;
    sbyte4 gHashAlgo;
    sbyte4 gSaltLen;
    byteBoolean gKeyIsPss; 
    sbyte4 gKeyHashAlgo;
    sbyte4 gKeySaltLen;
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    ubyte4 gQSize;
#endif
    ubyte4 gCurve;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4 gQsAlg;
#endif

    byteBoolean gTap;
#ifdef __ENABLE_DIGICERT_TAP__
    TAP_PROVIDER gTapProvider;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    sbyte *gpServer;
    ubyte4 gPort;
#endif
    byteBoolean gSignKeyTap;
    ubyte4 gModNum;
    byteBoolean gPrimary;
    TAP_HIERARCHY_PROPERTY gHierarchy;
    ubyte4 gKeyUsage;
    ubyte4 gEncScheme;
    ubyte4 gSigScheme;
    TAP_Buffer *gpKeyHandle;
    ubyte8 gKeyNonceHandle;
#endif /* __ENABLE_DIGICERT_TAP__ */

    sbyte *gpOutFile;
    sbyte *gpOutPubFile;
    ubyte gOutForm;
    ubyte gOutPubForm;
    sbyte *gpOutCertFile;
    sbyte *gpInCsrFile;
    ubyte4 gDays;
    TimeDate gStartDate;
    TimeDate gEndDate;
    byteBoolean gHasStartDate;
    sbyte *gpSigningCert;
    sbyte *gpSigningKey;

#ifdef __ENABLE_KEYSTORE_PATH__
    sbyte *gpKeyStorePath;
#endif

    ubyte *gpInCsrBuffer;
    ubyte4 gInCsrLen;
    ubyte *gpSigningCertBuffer;
    ubyte4 gSigningCertLen;
    ubyte *gpSigningKeyBuffer;
    ubyte4 gSigningKeyLen;

    ubyte gInForm;
    byteBoolean gCreateCsr;
    byteBoolean gProtected;
    ubyte *gpPkcs8Pw;
    ubyte4 gPkcs8PwLen;
    byteBoolean gVerbose;
    ubyte *gpPkcs12File;
    ubyte4 gPkcs12EncryptionType;
    byteBoolean gPkcs12GetIntegrityPw;
    byteBoolean gPkcs12GetPrivacyPw;
    byteBoolean gPkcs12GetKeyPw;
    byteBoolean gGetSigningKeyPw;

#ifdef __ENABLE_DIGICERT_CV_CERT__
    byteBoolean gIsCvc;
    CV_CERT_GEN_DATA gCvcData;
    byteBoolean gIsPrintCVCert;
#endif
byteBoolean gIsPrintCert;

} KeyGenArgs;

#ifdef __ENABLE_DIGICERT_TAP__
typedef struct _KeyGenTapArgs
{
    TAP_Context *gpTapCtx;
    TAP_EntityCredentialList *gpTapEntityCredList;
    TAP_CredentialList *gpTapCredList;
} KeyGenTapArgs;
#endif

MOC_EXTERN void KEYGEN_resetArgs(KeyGenArgs *pArgs);
MOC_EXTERN MSTATUS KEYGEN_generateKey(KeyGenArgs *pArgs, void *pKeyGenTapArgs, AsymmetricKey *pKey, randomContext *pRand);
MOC_EXTERN MSTATUS KEYGEN_outputPrivKey(KeyGenArgs *pArgs, AsymmetricKey *pKey, randomContext *pRand, 
                                        byteBoolean savePw, ubyte **ppKey, ubyte4 *pKeyLen);
MOC_EXTERN MSTATUS KEYGEN_outputPubKey(KeyGenArgs *pArgs, AsymmetricKey *pKey);
MOC_EXTERN MSTATUS KEYGEN_generateCertificate(KeyGenArgs *pArgs, AsymmetricKey *pKey, randomContext *pRand, ubyte **ppCert, ubyte4 *pCertLen);
MOC_EXTERN MSTATUS KEYGEN_generateCvCertificate(KeyGenArgs *pArgs, AsymmetricKey *pKey);
MOC_EXTERN MSTATUS KEYGEN_printCvCertificate(KeyGenArgs *pArgs);
MOC_EXTERN MSTATUS KEYGEN_printCertificateOrCsr(KeyGenArgs *pArgs);
MOC_EXTERN MSTATUS KEYGEN_createCSR(KeyGenArgs *pArgs);
MOC_EXTERN MSTATUS KEYGEN_calculateEndDate(KeyGenArgs *pArgs);
#ifdef __ENABLE_KEYSTORE_PATH__
/* pKeystoreBitMap corresponds each bit with a directory inside keystore path
 * Bit 0    -> CA
 * Bit 1    -> Certs
 * Bit 2    -> Keys
 * Bit 3    -> Req
 * Bit 4    -> Conf
 * Bit 5..7 -> Reserved
*/
MOC_EXTERN MSTATUS KEYGEN_validateKeystorePath(sbyte *pKeyStorePath, ubyte pKeystoreBitMap);
#endif

MOC_EXTERN MSTATUS KEYGEN_keyCertGen(
    sbyte *pKeyType, /* NULL terminated string specifying algorithm */
    ubyte *pCsr,
    ubyte4 csrLen,
    ubyte4 expireInYears,
    ubyte *pCAKey, /* Optional - if not provided assume self-signed */
    ubyte4 caKeyLen,
    ubyte *pCACert, /* Optional - if not provided assume self-signed */
    ubyte4 caCertLen,
    ubyte **ppKey,
    ubyte4 *pKeyLen,
    ubyte **ppCert,
    ubyte4 *pCertLen);

MOC_EXTERN MSTATUS KEYGEN_getPassword(
    ubyte **ppRetPassword,
    ubyte4 *pRetPasswordLen,
    char *pPwName,
    char *pFileName);

#ifdef __ENABLE_DIGICERT_TAP__

MOC_EXTERN MSTATUS KEYGEN_persistDataAtNVIndex(
    TAP_Context *pTapCtx,
    TAP_EntityCredentialList *pTapEntityCredList,
    ubyte8 index, ubyte *pData, ubyte4 dataLen,
    TAP_AUTH_CONTEXT_PROPERTY inputAuthProp);

MOC_EXTERN MSTATUS KEYGEN_addCreds(TAP_CredentialList *pCredList);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_KEYGEN_HEADER__ */
