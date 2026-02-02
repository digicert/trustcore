/*
 * crypto_utils.h
 *
 * Header file for crypto utility methods.
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

/**
@file       crypto_utils.h
@brief      Header file for crypto utility methods.
@details    This file provides the declaration for crypto helper methods. The
            APIs provided by this file do not actually perform any crypto
            itself. The APIs may take in cryptographic parameters but any
            cryptographic handling will be passed down to the Crypto Interface.

@filedoc    crypto_utils.h
*/

#ifndef __CRYPTO_UTILS_HEADER__
#define __CRYPTO_UTILS_HEADER__

#include "../crypto/pubcrypto.h"
#include "../common/sizedbuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_ALGO_ID     "algo_id"
#define JSON_SIG_VALUE   "sig_value"
#define JSON_SIG_CERT    "sig_cert"
#define JSON_CERT_ISSUER "certificateIssuerName"
#define JSON_CERT_SERIAL "certificateSerialNumber"
#define JSON_ALGO_ID_EX  "algoId"
#define JSON_DIGITAL_SIG "digitalSignature"

/* Retrieve the MOCANA_TRUSTED_CONFIG_FILE */
MOC_EXTERN char *CRYPTO_UTILS_getTrustedPath();

/**
 * Sign a JSON with a private key already in \c AsymmetricKey form.
 * This function takes in a JSON and digests the
 * JSON data then signs the digested data with the private key. A PEM or DER
 * certficiate must be provided to be included in the signature request. The
 * following will be returned for the signature:
 *
 *   {
 *     "algo_id": "<hash algo>",
 *     "sig_value": "<signature>",
 *     "sig_cert": "<certificate>"
 *   }
 *
 * where <hash algo> will be a string containing the algorithm ID. The
 * <signature> will be a string containing the signature as BASE 64 encoded. The
 * <certificate> field will be the certificate in PEM format. The caller must
 * free the returned JSON signature element.
 *
 * @param pData         Pointer to data to sign.
 * @param dataLen       Length of data to sign.
 * @param pAsymKey      Pointer to a private key to sign the data.
 * @param hashAlgo      Digest algorithm used to digest the JSON.
 * @param pCert         Certificate to be inserted into the signature. The
 *                      certificate can be PEM or DER.
 * @param certLen       The length of the certificate.
 * @param ppRetSig      Return signature element. This must be freed by the
 *                      caller.
 * @param pRetSigLen    Return signature element length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_signJsonFromAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    AsymmetricKey *pAsymKey,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    );

/**
 * Sign a JSON with a private key. This function takes in a JSON and digests the
 * JSON data then signs the digested data with the private key. A PEM or DER
 * certficiate must be provided to be included in the signature request. The
 * following will be returned for the signature:
 *
 *   {
 *     "algo_id": "<hash algo>",
 *     "sig_value": "<signature>",
 *     "sig_cert": "<certificate>"
 *   }
 *
 * where <hash algo> will be a string containing the algorithm ID. The
 * <signature> will be a string containing the signature as BASE 64 encoded. The
 * <certificate> field will be the certificate in PEM format. The caller must
 * free the returned JSON signature element.
 *
 * @param pData         Pointer to data to sign.
 * @param dataLen       Length of data to sign.
 * @param pKey          Private key to sign the data. Can be either DER or PEM.
 * @param keyLen        Length of the private key.
 * @param hashAlgo      Digest algorithm used to digest the JSON.
 * @param pCert         Certificate to be inserted into the signature. The
 *                      certificate must be PEM or DER.
 * @param certLen       The length of the certificate.
 * @param ppRetSig      Return signature element. This must be freed by the
 *                      caller.
 * @param pRetSigLen    Return signature element length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_signJson(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pKey,
    ubyte4 keyLen,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    );

/**
 * Verify a JSON with a public key. This function takes in a JSON and signature
 * element and verifies that the signature is valid. The public key will be
 * extracted from the certificate and used to verify the JSON data.
 *
 * @param pData         Pointer to data to verify.
 * @param dataLen       Length of data to verify.
 * @param pSig          Pointer to the signature element.
 * @param sigLen        Length of the signature element.
 * @param pCertStore    Certificate store used to verify the certificate within
 *                      the signature element.
 * @param pVerifyStatus Signature verification status will be set here. If this
 *                      is 0 then the validation was successful, otherwise it
 *                      failed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h. The return status does indicate whether
 *                 the signature was valid or not. The pVerifyStatus variable
 *                 must be checked for the signature validity.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_verifyJson(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pSig,
    ubyte4 sigLen,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    );

/**
 * Verify a JSON with a public key. This function takes in a JSON and signature
 * element and verifies that the signature is valid. The public key will be
 * extracted from the certificate and used to verify the JSON data.
 *
 * @param pData         Pointer to data to verify.
 * @param dataLen       Length of data to verify.
 * @param pSig          Pointer to the signature element.
 * @param sigLen        Length of the signature element.
 * @param pCertStore    Certificate store used to verify the certificate within
 *                      the signature element.
 * @param pTeim         Optional time to use for verification.
 * @param pVerifyStatus Signature verification status will be set here. If this
 *                      is 0 then the validation was successful, otherwise it
 *                      failed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h. The return status does indicate whether
 *                 the signature was valid or not. The pVerifyStatus variable
 *                 must be checked for the signature validity.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_verifyJsonAux(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pSig,
    ubyte4 sigLen,
    certStorePtr pCertStore,
    TimeDate *pTime,
    ubyte4 *pVerifyStatus
    );

/**
 * Verify a comma separated JSON signature file with 1 or more signatures. This
 * function takes in data that has been signed and the signature data which must
 * be comma separated and verfies each of the signatures. Note that the
 * certificate store MUST contain all the set of certificates required to
 * validate each of the certificates in the signature data. If a NULL
 * certificate store is provided then the certificates in the signature data are
 * not verified against a root of trust.
 *
 * The data with the multiple signatures must be constructed and passed in as
 * follows.
 *
 *   {
 *     "algo_id": "<hash algo>",
 *     "sig_value": "<signature>",
 *     "sig_cert": "<certificate>"
 *   }
 *   ,
 *   {
 *     "algo_id": "<hash algo>",
 *     "sig_value": "<signature>",
 *     "sig_cert": "<certificate>"
 *   }
 *   ...
 *
 * At least one or more signatures are required.
 *
 * @param pData         Pointer to data to verify.
 * @param dataLen       Length of data to verify.
 * @param pSig          Pointer to the signature element. May contain 1 or more
 *                      signatures.
 * @param sigLen        Length of all the signatures.
 * @param pCertStore    Certificate store used to verify the certificate(s)
 *                      within the signature element.
 * @param pVerifyStatus Signature verification status will be set here. If this
 *                      is 0 then the validation was successful, otherwise it
 *                      failed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h. The return status does indicate whether
 *                 the signature was valid or not. The pVerifyStatus variable
 *                 must be checked for the signature validity.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_verifyJsonMultiSig(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pSig,
    ubyte4 sigLen,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    );

/**
 * This function is the same as CRYPTO_UTILS_verifyJsonMultiSig but it takes in
 * the file name and expects to find an equivalent file with a .sig.json
 * extension with the set of signatures to verify.
 *
 * The file with the signature(s) must contain the following.
 *
 *   {
 *     "algo_id": "<hash algo>",
 *     "sig_value": "<signature>",
 *     "sig_cert": "<certificate>"
 *   }
 *   ,
 *   {
 *     "algo_id": "<hash algo>",
 *     "sig_value": "<signature>",
 *     "sig_cert": "<certificate>"
 *   }
 *   ...
 *
 * At least one or more signatures are required.
 *
 * @param pFile         File containing the data to be verified.
 * @param pCertStore    Certificate store used to verify the certificate(s)
 *                      within the signature element.
 * @param pVerifyStatus Signature verification status will be set here. If this
 *                      is 0 then the validation was successful, otherwise it
 *                      failed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h. The return status does indicate whether
 *                 the signature was valid or not. The pVerifyStatus variable
 *                 must be checked for the signature validity.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_verifyJsonMultiSigByFileExt(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    sbyte *pFile,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    );

typedef struct
{
    sbyte *pHttpProxy;
    sbyte *pRootDir;
    sbyte *pBinDir;
    sbyte *pConfDir;
    sbyte *pKeystoreDir;
    sbyte *pTruststoreDir;
} TrustedConfig;

/**
 * This function checks if trusted configuration file exists.
 *
 * @return         \c TRUE if the file exists otherwise \c FALSE
 */
MOC_EXTERN intBoolean CRYPTO_UTILS_configFileExists();

/**
 * This function reads trusted configuration values. TrustedConfig structure
 * must be freed using CRYPTO_UTILS_deleteTrustedConfig.
 *
 * @param ppConfig      Location where allocated structure is stored containing
 *                      the trusted configuration values.
 * @param verify        Validate trusted config using data protect.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readTrustedConfig(
    TrustedConfig **ppConfig,
    byteBoolean verify);

/**
 * This function frees memory allocated to the TrustedConfig structure.
 *
 * @param ppConfig      TrustedConfig structure to free.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_deleteTrustedConfig(
    TrustedConfig **ppConfig);

/**
 * This function is obselete. Use CRYPTO_UTILS_readTrustedConfig instead.
 *
 * Reads conf, keystore, truststore, and bin path from trusted config file.
 *
 * @param ppRetConfPath     Location where conf path is stored.
 * @param ppKeystorePath    Location where keystore path is stored.
 * @param ppTrustStorePath  Location where truststore path is stored.
 * @param ppBinPath         Location where bin path is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readTrustedPaths(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath
    );

/**
 * This function is obselete. Use CRYPTO_UTILS_readTrustedConfig instead.
 *
 * Same as CRYPTO_UTILS_readTrustedPaths but does not perform verification of
 * trusted configuration using data protect.
 *
 * @param ppRetConfPath     Location where conf path is stored.
 * @param ppKeystorePath    Location where keystore path is stored.
 * @param ppTrustStorePath  Location where truststore path is stored.
 * @param ppBinPath         Location where bin path is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readTrustedPathsNoVerify(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath
    );

/**
 * This function is obselete. Use CRYPTO_UTILS_readTrustedConfig instead.
 *
 * Reads conf, keystore, truststore, bin, and proxy values from trusted config
 * file.
 *
 * @param ppRetConfPath     Location where conf path is stored.
 * @param ppKeystorePath    Location where keystore path is stored.
 * @param ppTrustStorePath  Location where truststore path is stored.
 * @param ppBinPath         Location where bin path is stored.
 * @param ppProxyURL        Location where proxy URL is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readTrustedPathsWithProxyURL(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath,
    sbyte **ppProxyURL
    );

/**
 * This function is obselete. Use CRYPTO_UTILS_readTrustedConfig instead.
 *
 * Same as CRYPTO_UTILS_readTrustedPathsWithProxyURL but does not perform
 * verification of trusted configuration using data protect.
 *
 * @param ppRetConfPath     Location where conf path is stored.
 * @param ppKeystorePath    Location where keystore path is stored.
 * @param ppTrustStorePath  Location where truststore path is stored.
 * @param ppBinPath         Location where bin path is stored.
 * @param ppProxyURL        Location where proxy URL is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readTrustedPathsWithProxyURLNoVerify(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath,
    sbyte **ppProxyURL
    );

/**
 * This function reads in the trusted certificates into the provided certificate
 * store from the trusted config file. The caller provides two certificate
 * stores. One for loading in non-expired certificates and one for loading
 * expired certificates.
 *
 * If verifyOnly is TRUE then the certificates in the CA directory are verified
 * using the file protect APIs. An error is only thrown if a certificate has an
 * invalid signature file or if an internal system error occured. Certificates
 * without signatures files are skipped. The caller must not provide a
 * certificate store when calling this API with verifyOnly as TRUE.
 *
 * If verifyOnly is FALSE then the caller must provide the non-expired
 * certificate store. Any certificates with a valid signature file are loaded
 * into the store. If an invalid signature file is found then an error is
 * thrown.
 *
 * @param pStore            Certificate store to load in non-expired
 *                          certificates. Optional.
 * @param pExpired          Certificate store to load in expired certificates.
 *                          Optional.
 * @param pTrustedCertsPath Path to CA certificate directory. Optional.
 * @param verifyOnly        Boolean TRUE or FALSE value which specifies whether
 *                          the valid certificates should be loaded into the
 *                          certificate store.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readTrustedConfigCerts(
    certStorePtr pStore,
    certStorePtr pExpired,
    sbyte *pTrustedCertsPath,
    intBoolean verifyOnly
    );

/**
 * This API is similar to CRYPTO_UTILS_signJsonFromAsymKey. The signature output
 * is slightly different. The following will be returned for the signature:
 *
 *   {
 *     "certificateIssuerName" : "<issuer>",
 *     "certificateSerialNumber" : "<serial>",
 *     "algoId" : "<sign_algo>",
 *     "digitalSignature" : "<signature>"
 *   }
 *
 * where <sign_algo> will be a string containing the algorithm ID. The
 * <signature> will be a string containing the signature as BASE 64 encoded. The
 * <issuer> field will be the certificate's issuer. The <serial> field will be
 * the certificates serial number. The caller must free the returned JSON
 * signature element.
 *
 * @param pData         Pointer to data to sign.
 * @param dataLen       Length of data to sign.
 * @param pAsymKey      Pointer to a private key to sign the data.
 * @param hashAlgo      Digest algorithm used to digest the JSON.
 * @param pCert         Certificate to be inserted into the signature. The
 *                      certificate must be PEM or DER.
 * @param certLen       The length of the certificate.
 * @param ppRetSig      Return signature element. This must be freed by the
 *                      caller.
 * @param pRetSigLen    Return signature element length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_signJsonMinFromAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    AsymmetricKey *pAsymKey,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    );

/**
 * This API si the same as CRYPTO_UTILS_signJsonMinFromAsymKey but takes in a
 * serialized key buffer.
 *
 * @param pData         Pointer to data to sign.
 * @param dataLen       Length of data to sign.
 * @param pKey          Private key to sign the data. Can be either DER or PEM.
 * @param keyLen        Length of the private key.
 * @param hashAlgo      Digest algorithm used to digest the JSON.
 * @param pCert         Certificate to be inserted into the signature. The
 *                      certificate must be PEM or DER.
 * @param certLen       The length of the certificate.
 * @param ppRetSig      Return signature element. This must be freed by the
 *                      caller.
 * @param pRetSigLen    Return signature element length.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_signJsonMin(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pKey,
    ubyte4 keyLen,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    );

/**
 * Verify a JSON with a public key. This function takes in a JSON and signature
 * element and verifies that the signature is valid. The public key will be
 * extracted from the certificate and used to verify the JSON data.
 *
 * This API can only be used to verify signatures generate by
 * CRYPTO_UTILS_signJsonMinFromAsymKey and CRYPTO_UTILS_signJsonMin.
 *
 * @param pData         Pointer to data to verify.
 * @param dataLen       Length of data to verify.
 * @param pCert         PEM or DER certificate which contains the public key to
 *                      verify the signature with.
 * @param certLen       Length of certificate.
 * @param pSig          Pointer to the signature element.
 * @param sigLen        Length of the signature element.
 * @param pVerifyStatus Signature verification status will be set here. If this
 *                      is 0 then the validation was successful, otherwise it
 *                      failed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h. The return status does indicate whether
 *                 the signature was valid or not. The pVerifyStatus variable
 *                 must be checked for the signature validity.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_verifyJsonMin(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte *pSig,
    ubyte4 sigLen,
    ubyte4 *pVerifyStatus
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_isRootCertificate(
    ubyte *pCert,
    ubyte4 certLen
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_readCertificates(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCerts,
    ubyte4 certsLen,
    SizedBuffer **ppRetCerts,
    ubyte4 *pRetCount
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_createPemChainFromDerChain(
    SizedBuffer *pDerChain,
    ubyte4 derChainCount,
    SizedBuffer **ppPemChain
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_getTrustedChain(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCert,
    ubyte4 certLen,
    certStorePtr pStore,
    SizedBuffer **ppRetCerts,
    ubyte4 *pRetCertCount
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_freeCertificates(
    SizedBuffer **ppCerts,
    ubyte4 certCount
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_getCertificateSizeFromCRTBuffer(
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pCertLen
    );

/**
 * This API retrieves the key type, bit length, and provider from the provided
 * key data. If the key type indicates this is a TAP key then the provider will
 * be set to one of the TAP_PROVIDER values, otherwise the provider is set to
 * TAP_PROVIDER_UNDEFINED.
 *
 * @param pAsymKey      AsymmetricKey structure containing the key data.
 * @param pPassword     Password used for PKCS#8 encrypted keys.
 * @param passwordLen   Length of password in bytes.
 * @param pKeyType      Return pointer set to key type of the provided key. This
 *                      will be one of the akt_* values in ca_mgmt.h.
 * @param pBitLength    Return pointer set to the big length of the provided
 *                      key. For RSA keys it is the bit length of the modulus.
 *                      For EC keys it is the bit length of the underlying
 *                      curve.
 * @param pProvider     This is TAP provider. This will be one of the
 *                      TAP_PROVIDER_* values from tap_smp.h. For non TAP keys
 *                      this is set to TAP_PROVIDER_UNDEFINED.
 * @param pModuleId     This is the TAP module ID. For non TAP keys this is set
 *                      to 0.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_getAsymmetricKeyAttributes(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte4 *pKeyType,
    ubyte4 *pBitLength,
    ubyte2 *pProvider,
    ubyte4 *pModuleId
    );

/**
 * This API retrieves the key type, bit length, and provider from the provided
 * key data. If the key type indicates this is a TAP key then the provider will
 * be set to one of the TAP_PROVIDER values, otherwise the provider is set to
 * TAP_PROVIDER_UNDEFINED.
 *
 * @param pKey          Key data. This can be in PEM, DER or Mocana blob format.
 * @param keyLen        Length of the key data buffer in bytes.
 * @param pPassword     Password used for PKCS#8 encrypted keys.
 * @param passwordLen   Length of password in bytes.
 * @param pKeyType      Return pointer set to key type of the provided key. This
 *                      will be one of the akt_* values in ca_mgmt.h.
 * @param pBitLength    Return pointer set to the big length of the provided
 *                      key. For RSA keys it is the bit length of the modulus.
 *                      For EC keys it is the bit length of the underlying
 *                      curve.
 * @param pProvider     This is TAP provider. This will be one of the
 *                      TAP_PROVIDER_* values from tap_smp.h. For non TAP keys
 *                      this is set to TAP_PROVIDER_UNDEFINED.
 * @param pModuleId     This is the TAP module ID. For non TAP keys this is set
 *                      to 0.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_getAsymmetricKeyInfo(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pKey,
    ubyte4 keyLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    ubyte4 *pKeyType,
    ubyte4 *pBitLength,
    ubyte2 *pProvider,
    ubyte4 *pModuleId
    );

/**
 * This API loops through the certificates in the directory specified and loads
 * them into the certificate store. The following conditions must be met for the
 * certificate to be loaded into the store.
 *   - File must end in .pem or .der (case insensitive)
 *   - Certificate must not be expired
 *   - If data protection is enabled then the certificate must contain a valid
 *       signature file. Verification is optional and can be controlled by
 *       the verifySigFile argument.
 *
 * If the certificate is expired and an expired certificate store is provided
 * then the certificate will be loaded into that store.
 *
 * NOTE: If building with __ENABLE_DIGICERT_MINIMAL_CA__ flag then this API will
 * only load in the child certificates found from the provided directory.
 *
 * @param pStore        Certificate store to load in valid certificates found.
 * @param pExpiredStore Certificate store to load in expired certificates
 *                      (optional).
 * @param pDirPath      Directory to load in certificates from.
 * @param verifySigFile Boolean value used to identifiy whether to validate the
 *                      data protection signature file or not. Only applies to
 *                      data protect builds. TRUE will perform the signature
 *                      validation, FALSE will skip the signature validation.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_addTrustPointCertsByDir(
    certStorePtr pStore,
    certStorePtr pExpiredStore,
    sbyte *pDirPath,
    byteBoolean verifySigFile
    );

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS CRYPTO_UTILS_getIssuerAndSerial(
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppIssuer,
    ubyte4 *pIssuerLen,
    ubyte **ppSerial,
    ubyte4 *pSerialLen
    );

#ifndef __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__
MOC_EXTERN MSTATUS CRYPTO_UTILS_checkForUpgrade(
    sbyte *pConfPath, intBoolean *pUpgrading);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_UTILS_HEADER__ */
