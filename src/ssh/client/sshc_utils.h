/*
 * sshc_utils.h
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
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __SSHC_UTILS_HEADER__
#define __SSHC_UTILS_HEADER__

/**
@brief      Parses an exportable public key and generates an AsymmetricKey
            object.

@details    This function takes an exportable public key file and generates
            a AsymmetricKey object. Format of file is algorithm identifier,
            followed by a white space, followed by the base64 encoded public key.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__

@inc_file sshc_utls.h

@param pKeyFile                 Pointer to buffer containing an SSH key file.
@param fileSize                 Number of bytes in key file buffer (\p pKeyFile).
@param p_keyDescr               Pointer to an AsymmetricKey object into which the
                                  key will be placed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc_utils.h
*/
MOC_EXTERN MSTATUS SSHC_UTILS_sshParseAuthPublicKeyFile(sbyte* pKeyFile, ubyte4 fileSize, AsymmetricKey *p_keyDescr);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSHC_UTILS_getByte(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte *pRetByte);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSHC_UTILS_getInteger(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte4 *pRetInteger);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSHC_UTILS_getInteger64(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte8 *pRetInteger64);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSHC_UTILS_setByte(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte byteValue);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSHC_UTILS_setInteger(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte4 integerValue);

/* This is for internal use only */
MOC_EXTERN MSTATUS SSHC_UTILS_setInteger64(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte8 *pIntegerValue64);

/**
@brief      Takes a serialized key and generate a RFC 4716 compliant key file.

@details    This function takes a serialized key, and generate a RFC 4716 compliant key file.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__

@inc_file sshc_utils.h

@param pKeyFile         Pointer to buffer containing key.
@param keyBlobLength    Number of bytes in key.
@param ppRetHostFile    On return, pointer to buffer containing the generated SSH2-formatted public key file.
@param pRetHostFileLen  On return, pointer to number of bytes in the generated SSH2-formatted public key file.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc_utils.h
*/
MOC_EXTERN MSTATUS SSHC_UTILS_generateHostKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen);

/**
@brief      Takes a serialized key and generate an AsymmetricKey.

@details    This function takes a serialized key and generate an AsymmetricKey.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__

@inc_file sshc_utils.h

@param pKeyFile         Pointer to key.
@param keyBlobLength    Number of bytes in key.
@param p_keyDescr       Pointer to an AsymmetricKey object into which the
                          key will be placed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc_utils.h
*/
MOC_EXTERN MSTATUS SSHC_UTILS_sshParseAuthPublicKey(sbyte* pKeyBlob, ubyte4 keyBlobLength, AsymmetricKey *p_keyDescr);

/**
@brief      Generate an exportable public key from a serialized key.

@details    This function generates an exportable public key from the
            specified internal public key BLOB. For exportable public key
            format, see the IETF Internet-Draft for <em>SSH Public Key File
            Format</em>:
            http://tools.ietf.org/html/draft-ietf-secsh-publickeyfile-13.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__

@inc_file sshc_utils.h

@param pPublicKeyBlob           Pointer to key blob.
@param publicKeyLen             Number of bytes in the key blob (\p pPublicKeyBlob).
@param ppRetEncodedAuthKey      Pointer to address of encoded authentication
                                  key, which on return contains the user's
                                  public key.
@param pRetEncodedAuthKeyLen    Pointer to ubyte4, which on return contains
                                  the number of bytes in the user's public
                                  key (\p ppRetEncodedAuthKey).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc_utils.h
*/
MOC_EXTERN MSTATUS SSHC_UTILS_generateServerAuthKeyFile(ubyte *pPublicKeyBlob, ubyte4 publicKeyLen, ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen);

/**
@brief      Takes a key file buffer and frees the allocated memory.

@details    This function takes a key file buffer and frees the allocated memory.

@ingroup    func_ssh_sftp_client_auth_key

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSH_CLIENT__

@inc_file sshc_utils.h

@param ppRetEncodedAuthKey      Pointer to address of encoded authentication
                                  key buffer to be freed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous NanoSSH clients.

@funcdoc    sshc_utils.h
*/
MOC_EXTERN MSTATUS SSHC_UTILS_freeGenerateServerAuthKeyFile(ubyte **ppFreeEncodedAuthKey);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_UTILS_convertDsaKeyDER(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pDerDsaKey, ubyte4 derDsaKeyLength, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength );

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_UTILS_convertDsaKeyPEM(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pPemRsaKey, ubyte4 pemRsaKeyLength, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength );

#endif /* __SSHC_UTILS_HEADER__ */


