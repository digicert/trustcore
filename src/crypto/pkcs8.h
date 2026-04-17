/*
 * pkcs8.h
 *
 * PKCS #8 Header
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */
/**
@file       pkcs8.h

@brief      Header file for SoT Platform PKCS&nbsp;\#8 convenience API.
@details    Header file for SoT Platform PKCS&nbsp;\#8 convenience API.

*/

#ifndef __PKCS8_HEADER__
#define __PKCS8_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PKCS8__
/**
@brief      Extract a private key from a PEM-encoded PKCS&nbsp;\#8 object.

@details    This function extracts a private key from a PEM-encoded
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
@param  ppRsaKeyBlob        On return, pointer to address of buffer containing
                              the private key (in Mocana SoT Platform keyblob
                              format) extracted from the PEM-encoded
                              PKCS&nbsp;\#8 object.
@param  pRsaKeyBlobLength   On return, pointer to length of the extracted key,
                              \p ppRsaKeyBlob.

@code
ubyte* keyBlob = NULL;
ubyte4 keyBlobLen;

if (OK > (status =
    PKCS8_decodePrivateKeyPEM(
        (ubyte*)content, contentLen, &keyBlob, &keyBlobLen)))
    goto exit;
@endcode

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs8.h
*/
MOC_EXTERN MSTATUS PKCS8_decodePrivateKeyPEM(const ubyte* pFilePemPkcs8, ubyte4 fileSizePemPkcs8, ubyte** ppRsaKeyBlob, ubyte4 *pRsaKeyBlobLength);

/**
@brief      Extract a private key from a DER-encoded PKCS&nbsp;\#8 object.

@details    This function extracts a private key from a DER-encoded
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
@param  ppRsaKeyBlob        On return, pointer to address of buffer containing
                              the private key (in Mocana SoT Platform keyblob
                              format) extracted from the DER-encoded
                              PKCS&nbsp;\#8 object.
@param  pRsaKeyBlobLength   On return, pointer to length of the extracted key,
                              \p ppRsaKeyBlob.


@code
ubyte* keyBlob = NULL;
ubyte4 keyBlobLen;

if (OK > (status =
    PKCS8_decodePrivateKeyDER(
        (ubyte*)content, contentLen, &keyBlob, &keyBlobLen)))
    goto exit;
@endcode

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs8.h
*/
MOC_EXTERN MSTATUS PKCS8_decodePrivateKeyDER(const ubyte* pFileDerPkcs8, ubyte4 fileSizeDerPkcs8, ubyte** ppRsaKeyBlob, ubyte4 *pRsaKeyBlobLength);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __PKCS8_HEADER__*/

