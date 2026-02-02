/*
 * ssh_utils.h
 *
 * Utility code for storing and retrieving keys
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


/*------------------------------------------------------------------*/

#ifndef __SSH_UTILS_HEADER__
#define __SSH_UTILS_HEADER__

/**
@brief      Takes a public key file as a buffer, and returns an AsymmetricKey object.

@details    This function takes a key file as a buffer, and returns an AsymmetricKey
            object. PEM format or OpenSSH format. Caller is responsible for freeing
            the AsymmetricKey object.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param pKeyFile         Pointer to buffer containing public key.
@param fileSize         Number of bytes in public key (\p pPubKey).
@param p_keyDescr       On return, pointer to AsymmetricKey object.

@inc_file ssh_utils.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh_utils.h
*/
MOC_EXTERN MSTATUS SSH_UTILS_sshParseAuthPublicKeyFile(sbyte* pKeyFile, ubyte4 fileSize, AsymmetricKey *p_keyDescr);

/**
@brief      Takes a serialized key as a buffer and generate an SSH2-formatted public key file.

@details    This function takes a serialized key buffer, and generate an SSH2-formatted public key file.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param pKeyFile         Pointer to buffer containing key.
@param keyBlobLength    Number of bytes in key.
@param ppRetHostFile    On return, pointer to buffer containing the generated SSH2-formatted public key file.
@param pRetHostFileLen  On return, pointer to number of bytes in the generated SSH2-formatted public key file.

@inc_file ssh_utils.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh_utils.h
*/
MOC_EXTERN MSTATUS SSH_UTILS_generateHostKeyFile(ubyte *pKeyFile, ubyte4 keyBlobLength, ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen);

/**
@brief      Takes a serialized key as a buffer, and generate an SSH2-formatted public key file.

@details    This function takes a serialized key as a buffer, and generate an SSH2-formatted public key file.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param pKeyBlob             Pointer to buffer containing key.
@param keyBlobLength        Number of bytes in key.
@param pRetMd5FingerPrint   On return, pointer to MD5 hash of key.
@param pRetHostFileLen      On return, pointer to SHA1 hash of key.

@inc_file ssh_utils.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh_utils.h
*/
MOC_EXTERN MSTATUS SSH_publicKeyFingerPrints(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte *pRetMd5FingerPrint, ubyte *pRetSha1FingerPrint);

/**
@brief      Generate an exportable public key from an internal public key BLOB.

@details    This function generates an exportable public key from the
            specified internal public key BLOB. For exportable public key
            format, see the IETF Internet-Draft for <em>SSH Public Key File
            Format</em>:
            http://tools.ietf.org/html/draft-ietf-secsh-publickeyfile-13.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param pKeyBlob                 Pointer to buffer containing key.
@param keyBlobLength            Number of bytes in key.
@param ppRetEncodedAuthKey      Pointer to address of encoded authentication
                                  key, which on return contains the user's
                                  public key.
@param pRetEncodedAuthKeyLen    Pointer to ubyte4, which on return contains
                                  the number of bytes in the user's public
                                  key (\p ppRetEncodedAuthKey).

@inc_file ssh_utils.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh_utils.h
*/
MOC_EXTERN MSTATUS SSH_UTILS_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen);

/**
@brief      Takes a key file buffer and frees the allocated memory.

@details    This function takes a key file buffer and frees the allocated memory.

@ingroup    func_ssh_core_server_security

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_SERVER__
+ \c \__ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__

@param ppRetEncodedAuthKey      Pointer to encoded authentication key file buffer.

@inc_file ssh_utils.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous servers.

@funcdoc ssh_utils.h
*/
MOC_EXTERN MSTATUS SSH_UTILS_freeGenerateServerAuthKeyFile(ubyte **ppFreeEncodedAuthKey);

#if defined(__ENABLE_DIGICERT_DSA__)
#if defined(__ENABLE_DIGICERT_SSH_OLD_DSA_CONVERSION__)
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_UTILS_extractKeyBlob(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte4 keyType, DSAKey *p_dsaContext);
#endif
#if defined(__ENABLE_DIGICERT_DER_CONVERSION__)
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_UTILS_dsaDerToKeyBlob(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pDerDsaKey, ubyte4 derDsaKeyLength, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength);
#endif
#endif

#endif /* __SSH_UTILS_HEADER__ */
