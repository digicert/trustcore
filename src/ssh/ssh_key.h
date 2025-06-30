/*
 * ssh_key.h
 *
 * Functions encoding and decoding SSH formatted key blobs.
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
@file       ssh_key.h
@brief      SSH key encoding/decoding functions.
@details    This header file contains definitions and function declarations used
            for encoding and decoding SSH formatted key blobs.

@flags
Whether the following flag is defined determines which function declarations are
enabled:

*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/memory_debug.h"
#include "../common/asm_math.h"
#include "../ssh/ssh_str.h"
#ifndef __SSH_KEY_HEADER__
#define __SSH_KEY_HEADER__

/**
 * Writes a 4-byte integer to the payload buffer at the current index (big-endian).
 */
MOC_EXTERN MSTATUS
SSH_KEY_setInteger(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex,
    ubyte4 integerValue);

/**
 * Reads a 4-byte big-endian integer from the buffer at the current index.
 */
MOC_EXTERN MSTATUS
SSH_KEY_getInteger(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex,
    ubyte4 *pRetInteger);

/**
 * Extracts a public key and its type from a key blob.
 *
 * @param pKeyBlob                Input key blob.
 * @param keyBlobLength           Length of the key blob.
 * @param ppRetPublicKeyBlob      Output: pointer to allocated public key blob.
 * @param pRetPublicKeyBlobLength Output: length of the public key blob.
 * @param pRetKeyType             Output: key type (akt_ecc, akt_rsa, etc.).
 * @param pCurveId                Output: curve ID (if ECC/EdDSA), else 0.
 * @param pQsAlgId                Output: QS algorithm ID (if hybrid/QS), else 0.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
SSH_KEY_extractPublicKey(MOC_ASYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength,
    ubyte **ppRetPublicKeyBlob, ubyte4 *pRetPublicKeyBlobLength,
    ubyte4 *pRetKeyType, ubyte4 *pCurveId, ubyte4 *pQsAlgId);

/**
 * Generates an SSH host key file from an asymmetric key.
 *
 * @param pKey            Input: asymmetric key.
 * @param ppRetHostFile   Output: pointer to allocated host key file.
 * @param pRetHostFileLen Output: length of the host key file.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro. */
MOC_EXTERN MSTATUS
SSH_KEY_generateHostKeyFileAsymKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte **ppRetHostFile,
    ubyte4 *pRetHostFileLen);

/**
 * Generates an SSH host key file from a key blob.
 *
 * @param pKeyBlob        Input: public key blob.
 * @param keyBlobLength   Length of the key blob.
 * @param ppRetHostFile   Output: pointer to allocated host key file.
 * @param pRetHostFileLen Output: length of the host key file.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
SSH_KEY_generateHostKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength,
    ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen);

/**
 * Generates an SSH server authentication public key file from an asymmetric key.
 *
 * @param pKey                  Input: asymmetric key.
 * @param ppRetEncodedAuthKey   Output: pointer to allocated encoded key file.
 * @param pRetEncodedAuthKeyLen Output: length of the encoded key file.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
SSH_KEY_generateServerAuthKeyFileAsymKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
    ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen);

/**
 * Generates an SSH server authentication public key file from a key blob.
 *
 * @param pKeyBlob                Input: public key blob.
 * @param keyBlobLength           Length of the key blob.
 * @param ppRetEncodedAuthKey     Output: pointer to allocated encoded key file.
 * @param pRetEncodedAuthKeyLen   Output: length of the encoded key file.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
SSH_KEY_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength,
    ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen);

/**
 * Parses an SSH public key blob and fills the AsymmetricKey structure.
 *
 * @param pKeyBlob      Input: SSH public key blob.
 * @param keyBlobLength Length of the key blob.
 * @param p_keyDescr    Output: key descriptor to fill.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
SSH_KEY_sshParseAuthPublicKey(sbyte* pKeyBlob, ubyte4 keyBlobLength,
                                     AsymmetricKey *p_keyDescr);
/**
 * Parses an SSH public key file and fills the AsymmetricKey structure.
 *
 * @param pKeyFile     Input: SSH public key file buffer.
 * @param fileSize     Size of the file buffer.
 * @param p_keyDescr   Output: key descriptor to fill.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
SSH_KEY_sshParseAuthPublicKeyFile(sbyte* pKeyFile, ubyte4 fileSize,
                                     AsymmetricKey *p_keyDescr);

#endif /* __SSH_KEY_HEADER__ */
