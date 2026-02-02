/*
 * key_utils.h
 *
 * Mocana Initialization Header
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
@file       key_utils.h

@brief      Header file for Mocana SSH key utilities API.
@details    Header file for Mocana SSH key utilities API.

@flags
The following flags are required to enable this file's functions:
+ \c \__ENABLE_DIGICERT_KEY_UTILS__
+ \c \__ENABLE_DIGICERT_DSA__

*/


/*------------------------------------------------------------------*/

#ifndef __KEY_UTILS_HEADER__
#define __KEY_UTILS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_KEY_UTILS__

/**
 @brief      Determine whether a PEM key is encrypted.
 
 @details    This function searches the entire private key to determine whether
             it contains the word "ENCRYPTED".
 
 @ingroup    key_utils
 
 @flags      To enable this function, the following flag must be defined:
             + \c \__ENABLE_DIGICERT_KEY_UTILS__
 
 @inc_file key_utils.h
 
 @param  pPrivKey        Private key to examine.
 @param  privKeyLength   Length of the private key, \p pPrivKey.
 @param  retVal          On return, "1" if the key is encrypted; otherwise "0".
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc key_utils.h
 */
MOC_EXTERN void KEY_UTILS_PEMKeyIsEncrypted(ubyte *pPrivKey, ubyte4 privKeyLength, ubyte4 *retVal);


/**
 @brief      Determine whether a PEM-encoded private key is valid.
 
 @details    Determine whether a PEM-encoded private key is valid.
 
 @warning    To use function correctly, you must confirm that it returns OK (0)
             and that the \p retVal is "1". Otherwise the key is not valid.
 
 @ingroup    key_utils
 
 @flags      To enable this function, the following flag must be defined:
             + \c \__ENABLE_DIGICERT_KEY_UTILS__
 
 @inc_file key_utils.h
 
 @param  passphrase      Password for decrypting the private key.
 @param  pPrivKey        Private key to validate.
 @param  privKeyLength   Length of the private key, \p pPrivKey.
 @param  retVal          On return, "1" if the key is valid; otherwise "0".
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc key_utils.h
 */
MOC_EXTERN MSTATUS KEY_UTILS_PEMKeyIsValid(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *passphrase, ubyte *pPrivKey, ubyte4 privKeyLength, ubyte4 *retVal);

/**
 @brief      Create a keyblob from a PEM-encoded private key.
 
 @details    This function checks a passphrase to determine if a password exists.
             If a password exists, this function decodes the key and converts it
             to a keyblob. If the passphrase is NULL, this function tries to
             convert the private key as-is.
 
 @note       This function is thread-safe.
 
 @ingroup    key_utils
 
 @flags      To enable this function, the following flag must be defined:
             + \c \__ENABLE_DIGICERT_KEY_UTILS__
 
 @inc_file key_utils.h
 
 @param  passphrase          Password for decrypting the private key.
 @param  pPrivKey            Private key to be convert to keyblob.
 @param  privKeyLength       Length of the private key, \p pPrivKey.
 @param  pRetKeyBlob         On return, pointer to resultant keyblob.
 @param  pRetKeyBlobLength   On return, length of resultant keyblob,
                             \p pRetKeyBlob.
 @param  retVal              On return, "1" if the key is converted; otherwise "0".
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc key_utils.h
 */
MOC_EXTERN MSTATUS KEY_UTILS_CreateKeyBlobFromPEM(MOC_DSA(hwAccelDescr hwAccelCtx) ubyte *passphrase, ubyte *pPrivKey, ubyte4 privKeyLength, ubyte **pRetKeyBlob, ubyte4 *pRetKeyBlobLength, ubyte4 *retVal);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __KEY_UTILS_HEADER__ */
