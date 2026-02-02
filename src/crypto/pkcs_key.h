/*
 * pkcs_key.h
 *
 * PKCS#1 PKCS#8 Parser and utilities routines
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
@file       pkcs_key.h

@brief      Header file for Mocana SoT Platform source code for PKCS&nbsp;\#1
              and PKCS&nbsp;\#10 utility routines.
@details    Header file for Mocana SoT Platform source code for PKCS&nbsp;\#1
              and PKCS&nbsp;\#10 utility routines.

@filedoc    pkcs_key.h
*/

#ifndef __PKCS_KEY_HEADER__
#define __PKCS_KEY_HEADER__


/*------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

/* encryption types --- do not change the values associated with the constants */
enum PKCS8EncryptionType
{
    PCKS8_EncryptionType_undefined = 0,
#if defined(__ENABLE_DIGICERT_PKCS5__)
#if defined(__ENABLE_DES_CIPHER__)
    PCKS8_EncryptionType_pkcs5_v1_sha1_des  = 10, /* oid suffix */
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
    PCKS8_EncryptionType_pkcs5_v1_sha1_rc2  = 11, /* oid suffix */
#endif

#if defined(__ENABLE_DES_CIPHER__) && defined(__ENABLE_DIGICERT_MD2__)
    PCKS8_EncryptionType_pkcs5_v1_md2_des   = 1,   /* oid suffix */
#endif

#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
    PCKS8_EncryptionType_pkcs5_v1_md2_rc2   = 4,  /* oid suffix */
#endif

#if defined(__ENABLE_DES_CIPHER__)
    PCKS8_EncryptionType_pkcs5_v1_md5_des   = 3,  /* oid suffix */
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
    PCKS8_EncryptionType_pkcs5_v1_md5_rc2   = 6, /* oid suffix */
#endif

#if !defined(__DISABLE_3DES_CIPHERS__)
    PCKS8_EncryptionType_pkcs5_v2_3des      = 5000 + 1, /* no signification */
#endif

#if defined(__ENABLE_DES_CIPHER__)
    PCKS8_EncryptionType_pkcs5_v2_des       = 5000 + 2, /* no signification */
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
    PCKS8_EncryptionType_pkcs5_v2_rc2       = 5000 + 3, /* no signification */
#endif

#if !defined(__DISABLE_AES_CIPHERS__)

#if !defined(__DISABLE_AES128_CIPHER__)
    PCKS8_EncryptionType_pkcs5_v2_aes128    = 5000 + 4, /* no signification */
#endif

#if !defined(__DISABLE_AES192_CIPHER__)
    PCKS8_EncryptionType_pkcs5_v2_aes192    = 5000 + 5, /* no signification */
#endif

#if !defined(__DISABLE_AES256_CIPHER__)
    PCKS8_EncryptionType_pkcs5_v2_aes256    = 5000 + 6, /* no signification */
#endif

#endif /* !defined(__DISABLE_AES_CIPHERS__) */

#endif /*  __ENABLE_DIGICERT_PKCS5__  */

    PKCS8_EncryptionType_pkcs12             = 12000,
#if !defined(__DISABLE_3DES_CIPHERS__)
    PCKS8_EncryptionType_pkcs12_sha_2des    = PKCS8_EncryptionType_pkcs12 + 4, /* 12000 + oid suffix */
    PCKS8_EncryptionType_pkcs12_sha_3des    = PKCS8_EncryptionType_pkcs12 + 3, /* 12000 + oid suffix */
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
    PCKS8_EncryptionType_pkcs12_sha_rc2_40  = PKCS8_EncryptionType_pkcs12 + 6, /* 12000 + oid suffix */
    PCKS8_EncryptionType_pkcs12_sha_rc2_128 = PKCS8_EncryptionType_pkcs12 + 5, /* 12000 + oid suffix */
#endif

#if !defined(__DISABLE_ARC4_CIPHERS__)
    PCKS8_EncryptionType_pkcs12_sha_rc4_40  = PKCS8_EncryptionType_pkcs12 + 2, /* 12000 + oid suffix */
    PCKS8_EncryptionType_pkcs12_sha_rc4_128 = PKCS8_EncryptionType_pkcs12 + 1, /* 12000 + oid suffix */
#endif

};

enum PKCS8PrfType
{
    PKCS8_PrfType_undefined = 0,         /* default to PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest */

    /* suffixes of rsaDSI_OID */
    /* applicable only if PCKS8_EncryptionType_pkcs5_v2_* is chosen */
    PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest = 7,
    PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest = 8,
    PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest = 9,
    PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest = 10,
    PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest = 11
};

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

MOC_EXTERN MSTATUS PKCS_getPKCS1Key(MOC_RSA(hwAccelDescr hwAccelCtx)const ubyte* pPKCS1DER, ubyte4 pkcs1DERLen, AsymmetricKey* pKey);
#if defined(__ENABLE_DIGICERT_DSA__)
/* This read an unencrypted raw file like those produced by openssl */
MOC_EXTERN MSTATUS PKCS_getDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx)
                                  const ubyte* pDSAKeyDer, ubyte4 pDSAKeyDerLen, AsymmetricKey* pKey);
#endif
/**
@brief      Extract SoT Platform-formatted key from unencrypted PKCS&nbsp;\#8
            DER file.

@details    This function extracts an SoT Platform-formatted key from an
            unencrypted PKCS&nbsp;\#8 DER file.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must \b not be defined:
- \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__

@inc_file   pkcs_key.h

@param hwAccelCtx       For future use.
@param pPKCS8DER        Pointer to buffer containing PKCS&nbsp;\#8 DER file
                          contents.
@param pkcs8DERLen      Number of bytes in PKCS&nbsp;\#8 DER file (\p pPKCS8DER).
@param pKey             On return, pointer to Mocana-formatted key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs_key.h
*/
MOC_EXTERN MSTATUS PKCS_getPKCS8Key(MOC_ASYM(hwAccelDescr hwAccelCtx)const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen, AsymmetricKey* pKey);

/**
@brief      Extract SoT Platform-formatted key from PKCS&nbsp;\#8 DER file
            (encrypted or unencrypted).

@details    This function extracts an SoT Platform-formatted key from a
            PKCS&nbsp;\#8 DER file (which can be encrypted or unencrypted).

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must #not# be defined:
- \c \__DISABLE_DIGICERT_CERTIFICATE_PARSING__

@inc_file   pkcs_key.h

@param hwAccelCtx       For future use.
@param pPKCS8DER        Pointer to buffer containing PKCS&nbsp;\#8 DER file
                          contents.
@param pkcs8DERLen      Number of bytes in PKCS&nbsp;\#8 DER file (\p pPKCS8DER).
@param password         For an encrypted file, pointer to buffer contaning
                          password; otherwise NULL.
@param passwordLen      For an encrypted file, number of bytes in the password
                          (\p password); otherwise not used.
@param pKey             On return, pointer to Mocana SoT Platform-formatted key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs_key.h
*/
MOC_EXTERN MSTATUS PKCS_getPKCS8KeyEx(MOC_HW(hwAccelDescr hwAccelCtx) const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen,
                                      const ubyte* password, ubyte4 passwordLen, AsymmetricKey* pKey);

#if defined( __ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__)
MOC_EXTERN MSTATUS PKCS_setPKCS1Key(MOC_RSA(hwAccelDescr hwAccelCtx)
                                    const AsymmetricKey* pKey,
                                    ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);

#ifdef __ENABLE_DIGICERT_DSA__
MOC_EXTERN MSTATUS PKCS_setDsaDerKey(MOC_DSA(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey,
                                     ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);
#endif

#endif

#if defined( __ENABLE_DIGICERT_DER_CONVERSION__)
MOC_EXTERN MSTATUS PKCS_setPKCS8Key(MOC_HW(hwAccelDescr hwAccelCtx)
                                    const AsymmetricKey* pKey,
                                    randomContext* pRandomContext,
                                    enum PKCS8EncryptionType encType,
                                    enum PKCS8PrfType prfType,
                                    const ubyte* password, ubyte4 passwordLen,
                                    ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);
#endif

#endif /* !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__) */

#if defined(__ENABLE_DIGICERT_PKCS8__)

#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__)

/**
@brief      Extract a private key from a password protected PEM-encoded PKCS&nbsp;\#8 object.

@details    This function extracts a private key from a password protected PEM-encoded
            PKCS&nbsp;\#8 object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS8__
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file pkcs8.h

@param  pFilePemPkcs8       Pointer to the name of the file containing the
                              PEM-encoded PKCS&nbsp;\#8 object.
@param  fileSizePemPkcs8    Number of bytes in the PEM-encoded object file, \p
                              pFilePemPkcs8.
@param  pPassword           Buffer holding the password.
@param  passwordLen         The length of the password in bytes.
@param  ppKeyBlob           On return, pointer to address of buffer containing
                              the private key (in Mocana SoT Platform keyblob
                              format) extracted from the PEM-encoded
                              PKCS&nbsp;\#8 object.
@param  pKeyBlobLength      On return, pointer to length of the extracted key,
                              \p ppRsaKeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs8.h
*/
MOC_EXTERN MSTATUS PKCS8_decodePrivateKeyPEMEx(const ubyte* pFilePemPkcs8, ubyte4 fileSizePemPkcs8, ubyte *pPassword, ubyte4 passwordLen, 
                                               ubyte** ppKeyBlob, ubyte4 *pKeyBlobLength);

/**
@brief      Encode a private key as a PEM-encoded PKCS&nbsp;\#8 object.

@details    This function encodes a private key as a PEM-encoded PKCS&nbsp;\#8 object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS8__
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file pkcs8.h

@param  pRandomContext        (Optional) Pointer to a randomContext. If not provided
                              then this method attempts to use the global default.
@param  pKeyBlob              The key to be encoded in a keyblob buffer form.
@param  keyBlobLen            The length of the \c pKeyBlob buffer in bytes.
@param  encType               The encryption algorithm to use. One of the following identifiers
                              (provided the algorithm chosen is enabled)...
                              + \c PCKS8_EncryptionType_undefined
                              + \c PCKS8_EncryptionType_pkcs5_v1_sha1_rc2
                              + \c PCKS8_EncryptionType_pkcs5_v1_md2_des
                              + \c PCKS8_EncryptionType_pkcs5_v1_md2_rc2 
                              + \c PCKS8_EncryptionType_pkcs5_v1_md5_des
                              + \c PCKS8_EncryptionType_pkcs5_v1_md5_rc2
                              + \c PCKS8_EncryptionType_pkcs5_v2_3des
                              + \c PCKS8_EncryptionType_pkcs5_v2_des
                              + \c PCKS8_EncryptionType_pkcs5_v2_rc2
                              + \c PCKS8_EncryptionType_pkcs5_v2_aes128
                              + \c PCKS8_EncryptionType_pkcs5_v2_aes192
                              + \c PCKS8_EncryptionType_pkcs5_v2_aes256
                              + \c PKCS8_EncryptionType_pkcs12
                              + \c PCKS8_EncryptionType_pkcs12_sha_2des
                              + \c PCKS8_EncryptionType_pkcs12_sha_3des
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc4_40
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc4_128
@param  prfType               The pseudo random function type. One of the following identifiers
                              (provided its enabled)...
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest
@param  pPassword             (Optional) Buffer holding the encryption password.
@param  passwordLen           The length of the password in bytes.
@param  ppRetFilePemPkcs8     Location will receive a newly allocated buffer
                              holding the PEM form document.
@param  pRetFileSizePemPkcs8  Contents will be set to the length opf the PEM
                              form document in bytes.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs8.h
*/
MOC_EXTERN MSTATUS PKCS8_encodePrivateKeyPEM(
    randomContext *pRandomContext, 
    ubyte* pKeyBlob, 
    ubyte4 keyBlobLen, 
    enum PKCS8EncryptionType encType,
    enum PKCS8PrfType prfType, 
    ubyte *pPassword, 
    ubyte4 passwordLen, 
    ubyte** ppRetFilePemPkcs8, 
    ubyte4 *pRetFileSizePemPkcs8);

#endif /* __ENABLE_DIGICERT_PEM_CONVERSION__ */

#if defined(__ENABLE_DIGICERT_DER_CONVERSION__)

/**
@brief      Extract a private key from a password protected DER-encoded PKCS&nbsp;\#8 object.

@details    This function extracts a private key from a password protected DER-encoded
            PKCS&nbsp;\#8 object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS8__
+ \c \__ENABLE_DIGICERT_DER_CONVERSION__

@inc_file pkcs8.h

@param  pFileDerPkcs8       Pointer to the name of the file containing the
                              DER-encoded PKCS&nbsp;\#8 object.
@param  fileSizeDerPkcs8    Number of bytes in the DER-encoded object file, \p
                              pFileDerPkcs8.
@param  pPassword           Buffer holding the password.
@param  passwordLen         The length of the password in bytes.
@param  ppKeyBlob           On return, pointer to address of buffer containing
                              the private key (in Mocana SoT Platform keyblob
                              format) extracted from the DER-encoded
                              PKCS&nbsp;\#8 object.
@param  pKeyBlobLength      On return, pointer to length of the extracted key,
                              \p ppRsaKeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs8.h
*/
MOC_EXTERN MSTATUS PKCS8_decodePrivateKeyDEREx(const ubyte* pFileDerPkcs8, ubyte4 fileSizeDerPkcs8, ubyte *pPassword, ubyte4 passwordLen, 
                                               ubyte** ppKeyBlob, ubyte4 *pKeyBlobLength);

/**
@brief      Encode a private key as a DER-encoded PKCS&nbsp;\#8 object.

@details    This function encodes a private key as a DER-encoded PKCS&nbsp;\#8 object.

@ingroup    pkcs_functions

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS8__
+ \c \__ENABLE_DIGICERT_DER_CONVERSION__

@inc_file pkcs8.h

@param  pRandomContext        (Optional) Pointer to a randomContext. If not provided
                              then this method attempts to use the global default.
@param  pKeyBlob              The key to be encoded in a keyblob buffer form.
@param  keyBlobLen            The length of the \c pKeyBlob buffer in bytes.
@param  encType               The encryption algorithm to use. One of the following identifiers
                              (provided the algorithm chosen is enabled)...
                              + \c PCKS8_EncryptionType_undefined
                              + \c PCKS8_EncryptionType_pkcs5_v1_sha1_rc2
                              + \c PCKS8_EncryptionType_pkcs5_v1_md2_des
                              + \c PCKS8_EncryptionType_pkcs5_v1_md2_rc2 
                              + \c PCKS8_EncryptionType_pkcs5_v1_md5_des
                              + \c PCKS8_EncryptionType_pkcs5_v1_md5_rc2
                              + \c PCKS8_EncryptionType_pkcs5_v2_3des
                              + \c PCKS8_EncryptionType_pkcs5_v2_des
                              + \c PCKS8_EncryptionType_pkcs5_v2_rc2
                              + \c PCKS8_EncryptionType_pkcs5_v2_aes128
                              + \c PCKS8_EncryptionType_pkcs5_v2_aes192
                              + \c PCKS8_EncryptionType_pkcs5_v2_aes256
                              + \c PKCS8_EncryptionType_pkcs12
                              + \c PCKS8_EncryptionType_pkcs12_sha_2des
                              + \c PCKS8_EncryptionType_pkcs12_sha_3des
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc2_40
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc2_128
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc4_40
                              + \c PCKS8_EncryptionType_pkcs12_sha_rc4_128
@param  prfType               The pseudo random function type. One of the following identifiers
                              (provided its enabled)...
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest
                              + \c PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest
@param  pPassword             (Optional) Buffer holding the encryption password.
@param  passwordLen           The length of the password in bytes.
@param  ppRetFileDerPkcs8     Location will receive a newly allocated buffer
                              holding the DER form document.
@param  pRetFileSizeDerPkcs8  Contents will be set to the length opf the DER
                              form document in bytes.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs8.h
*/
MOC_EXTERN MSTATUS PKCS8_encodePrivateKeyDER(
    randomContext *pRandomContext, 
    ubyte* pKeyBlob,
    ubyte4 keyBlobLen, 
    enum PKCS8EncryptionType encType,
    enum PKCS8PrfType prfType, 
    ubyte *pPassword, 
    ubyte4 passwordLen, 
    ubyte** ppRetFileDerPkcs8, 
    ubyte4 *pRetFileSizeDerPkcs8);

#endif /* __ENABLE_DIGICERT_DER_CONVERSION__ */

#endif /* __ENABLE_DIGICERT_PKCS8__ */

#ifdef __cplusplus
}
#endif

#endif  /* __PKCS_KEY_HEADER__ */
