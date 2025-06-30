/*
 * gcm.h
 *
 * GCM Implementation
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
 * Code derived from public domain code on www.zork.org
 */
/**
@file       gcm.h
@brief      Header file for the Nanocrypto GCM API.

@details    Header file for the Nanocrypto GCM API.

*/


/*------------------------------------------------------------------*/

#ifndef __GCM_HEADER__
#define __GCM_HEADER__

#include "../cap/capdecl.h"

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_aes_gcm_priv.h"
#endif

#if defined(__ENABLE_MOCANA_GCM__)
#if !defined(__ENABLE_MOCANA_GCM_64K__) && !defined(__ENABLE_MOCANA_GCM_4K__) && !defined(__ENABLE_MOCANA_GCM_256B__)
#define __ENABLE_MOCANA_GCM_256B__   /*default implementation*/
#endif
#endif

#if defined(__ENABLE_MOCANA_GCM_64K__) || defined(__ENABLE_MOCANA_GCM_4K__)  || defined(__ENABLE_MOCANA_GCM_256B__)

#ifndef __ENABLE_MOCANA_GCM__
#define __ENABLE_MOCANA_GCM__
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_MOCANA_GCM_64K__

/* 64K -> fastest with big memory usage */

#define GCM_I_LIMIT      (16)
#define GCM_J_LIMIT      (0x100)

typedef struct gcm_ctx_64k {
    ubyte4            table[GCM_I_LIMIT][GCM_J_LIMIT][4];
    ubyte4            tag4[4];
    ubyte4            s[4];
    sbyte4            hashBufferIndex;
    ubyte             hashBuffer[AES_BLOCK_SIZE];
    ubyte4            alen;
    ubyte4            dlen;
    AES_CTR_Ctx      *pCtx;
    sbyte4            encrypt;
    sbyte4            initialized;
    sbyte4            aadFinalized;
    MocSymCtx         pMocSymCtx;
    ubyte4            enabled;
} gcm_ctx_64k;

/**
@brief      Create and return a context data structure for AES-GCM operations.

@details    This function creates and returns a context data structure for
            AES-GCM operations, and prepares the key schedule (intermediate
            key material). This is the first function your application calls
            when performing AES operations (encryption or decryption). Your
            application uses the returned structure in subsequent DoAES()
            functions.

The AES-GCM context data structure holds information such as key length, key
schedule, and mode of operation. To avoid memory leaks, your application code
must call GCM_deleteCtx_64k() after completing AES-GCM related operations
(because the AES-GCM context is dynamically allocated by this function during
context creation).

@warning    If NULL is returned for the context pointer, you cannot use it as
            input to any subsequent AES function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  key         Key material.
@param  keylen      Length of key material (\p key).
@param  encrypt     \c TRUE if context for encryption; otherwise \c FALSE
                      (context is for decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN BulkCtx GCM_createCtx_64k(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt);

/**
 * @brief      Sets the nonce in a previously created AES-GCM Context.
 *
 * @details    Sets the nonce in a previously created AES-GCM Context.
 *
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pNonce      Buffer holding the input nonce value.
 * @param  nonceLen    The length of the nonce in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_nonce_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen);

/**
 * @brief      Updates an AES-GCM context with additional authenticated data.
 *
 * @details    Updates an AES-GCM context with additional authenticated data. This method
 *             may be called as many times as necessary.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pAadData    Buffer holding the additional authenticated data.
 * @param  aadDataLen  The length of the aad in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_aad_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen);

/**
 * @brief      Updates an AES-GCM context with data to be encrypted or decrypted.
 *
 * @details    Updates an AES-GCM context with data to be encrypted or decrypted. Which direction
 *             depends on the \c encrypt flag passed into the context creation \c GCM_createCtx_64k
 *             method. The \c GCM_update_data_64k method may be called as many times as necessary.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pData       Buffer holding the data to be encrypted or decrypted. It will be
 *                     processed in place, ie this buffer will also hold the resulting
 *                     ciphertext or plaintext.
 * @param  dataLen     The length of the data in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_data_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_final_ex_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen);

/**
@brief      Delete an AES-GCM context.

@details    This function deletes an AES-GCM context previously created by
            GCM_createCtx_64k(). To avoid memory leaks, your application must
            call this function after completing AES-related operations for a given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         Pointer to AES-GCM context to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_deleteCtx_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      Initialize nonce and authentication data for AES-GCM context.

@details    This function initializes nonce and authentication data for an
            AES-GCM context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_64k().
@param  nonce       Nonce.
@param  nlen        Length of (\p nonce) in octets.
@param  adata       Additional authenticated data.
@param  alen        Length of additional authenticated data (\p aData) in octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_init_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen);


/**
@brief      Encrypt a data buffer and perform authentication.

@details    This function AES-GCM encrypts a data buffer and authenticates.
            Before calling this function, your application must call the
            GCM_createCtx_64k() function to dynamically create a valid AES
            context, and optionally call GCM_init_64k() to set a nonce or
            additional authentication data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_64k().
@param  data        Data to encrypt and protect.
@param  dlen        Length of data to encrypt and protect (\p data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_update_encrypt_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen);

/**
@brief      Decrypt data buffer and perform authentication.

@details    This function AES-GCM decrypts a data buffer and authenticates.
            Before calling this function, your application must call the
            GCM_createCtx_64k() function to dynamically create a valid AES
            context, and optionally call GCM_init_64k() to set a nonce or
            additional authentication data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_64k().
@param  ct          Cipher text to decrypt and authenticate.
@param  ctlen       Length of cipher text to decrypt and authenticate
                      (\p data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_update_decrypt_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *ct, ubyte4 ctlen);

/**
@brief      Write authentication tag after message encryption.

@details    This function writes the authentication tag upon completion of
            encrypting a message.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_64k().
@param  tag         Pointer to write authentication tag of AES_BLOCK_SIZE octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_final_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/]);

/**
@brief      AES-GCM encrypt or decrypt a data buffer.

@details    This function AES-GCM encrypts or AES-GCM decrypts a data buffer.
            Before calling this function, your application must call the
            GCM_createCtx_64k() function to dynamically create a valid AES-GCM
            context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_64K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_64k().
@param  nonce       Nonce.
@param  nlen        Length of (\p nonce) in octets.
@param  adata       Additional authenticated data.
@param  alen        Length of additional authenticated data (\p aData) in octets.
@param  data        Data to encrypt and protect.
@param  dlen        Length of data to encrypt and protect (\p data).
@param  verifyLen   Length of the authentication tag.
@param  encrypt     \c TRUE if context for encryption; otherwise \c FALSE
                      (context is for decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_cipher_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen,
                            ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt);


/**
 * Clone a AES-GCM context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS GCM_clone_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);
#endif /* __ENABLE_MOCANA_GCM_64K__ */

#ifdef __ENABLE_MOCANA_GCM_4K__

/* 4K -> intermediate */
typedef struct gcm_ctx_4k {
    ubyte4            table[256][4];
    ubyte4            tag4[4];
    ubyte4            s[4];
    sbyte4            hashBufferIndex;
    ubyte             hashBuffer[AES_BLOCK_SIZE];
    ubyte4            alen;
    ubyte4            dlen;
    AES_CTR_Ctx      *pCtx;
    sbyte4            encrypt;
    sbyte4            initialized;
    sbyte4            aadFinalized;
    MocSymCtx         pMocSymCtx;
    ubyte4            enabled;
} gcm_ctx_4k;

/**
@brief      Create and return a context data structure for AES-GCM operations.

@details    This function creates and returns a context data structure for
            AES-GCM operations, and prepares the key schedule (intermediate
            key material). This is the first function your application calls
            when performing AES operations (encryption or decryption). Your
            application uses the returned structure in subsequent DoAES()
            functions.

The AES-GCM context data structure holds information such as key length, key
schedule, and mode of operation. To avoid memory leaks, your application code
must call GCM_deleteCtx_4k() after completing AES-GCM related operations
(because the AES-GCM context is dynamically allocated by this function during
context creation).

@warning    If NULL is returned for the context pointer, you cannot use it as
            input to any subsequent AES functions.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  key         Key material.
@param  keylen      Length of key material (\p key).
@param  encrypt     \c TRUE if context for encryption; otherwise \c FALSE
                      (context for decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN BulkCtx GCM_createCtx_4k(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt);

/**
 * @brief      Sets the nonce in a previously created AES-GCM Context.
 *
 * @details    Sets the nonce in a previously created AES-GCM Context.
 *
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pNonce      Buffer holding the input nonce value.
 * @param  nonceLen    The length of the nonce in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_nonce_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen);

/**
 * @brief      Updates an AES-GCM context with additional authenticated data.
 *
 * @details    Updates an AES-GCM context with additional authenticated data. This method
 *             may be called as many times as necessary.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pAadData    Buffer holding the additional authenticated data.
 * @param  aadDataLen  The length of the aad in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_aad_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_data_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_final_ex_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen);

/**
@brief      Delete an AES-GCM context.

@details    This function deletes an AES-GCM context previously created by
            GCM_createCtx_4k(). To avoid memory leaks, your application must
            call this function after completing AES-related operations for a
            given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         Pointer to AES-GCM context to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_deleteCtx_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      Initialize nonce and authentication data for AES-GCM context.

@details    This function initializes nonce and authentication data for an
            AES-GCM context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_4k().
@param  nonce       Nonce.
@param  nlen        Length of (\p nonce) in octets.
@param  adata       Additional authenticated data.
@param  alen        Length of additional authenticated data (\p aData) in octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_init_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen);

/**
@brief      Encrypt a data buffer and perform authentication.

@details    This function AES-GCM encrypts a data buffer and authenticates.
            Before calling this function, your application must call the
            GCM_createCtx_4k() function to dynamically create a valid AES
            context, and optionally call GCM_init_4k() to set a nonce or
            additional authentication data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_4k().
@param  data        Data to encrypt and protect.
@param  dlen        Length of data to encrypt and protect (\p data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_update_encrypt_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen);

/**
@brief      Decrypt data buffer and perform authentication.

@details    This function AES-GCM decrypts a data buffer and authenticates.
            Before calling this function, your application must call the
            GCM_createCtx_4k() function to dynamically create a valid AES
            context, and optionally call GCM_init_4k() to set a nonce or
            additional authentication data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_4k().
@param  ct          Cipher text to decrypt and authenticate.
@param  ctlen       Length of cipher text to decrypt and authenticate
                      (\p data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_update_decrypt_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *ct, ubyte4 ctlen);

/**
@brief      Write authentication tag after message encryption.

@details    This function writes the authentication tag upon completion of
            encrypting a message.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_4k().
@param  tag         Pointer to write authentication tag of AES_BLOCK_SIZE octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_final_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/]);

/**
@brief      AES-GCM encrypt or decrypt a data buffer.

@details    This function AES-GCM encrypts or AES-GCM decrypts a data buffer.
            Before calling this function, your application must call the
            GCM_createCtx_4k() function to dynamically create a valid AES-GCM
            context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_4K__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_4k().
@param  nonce       Nonce.
@param  nlen        Length of (\p nonce) in octets.
@param  adata       Additional authenticated data.
@param  alen        Length of additional authenticated data (\p aData) in octets.
@param  data        Data to encrypt and protect.
@param  dlen        Length of data to encrypt and protect (\p data).
@param  verifyLen   Length of the authentication tag.
@param  encrypt     \c TRUE if context for encryption; otherwise \c FALSE
                      (context is for decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_cipher_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen,
                            ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt);

/**
 * Clone a AES-GCM context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS GCM_clone_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#endif  /* __ENABLE_MOCANA_GCM_4K__ */

#ifdef __ENABLE_MOCANA_GCM_256B__

/* 256b -> slowest, less memory usage */

typedef struct gcm_ctx_256b {
    ubyte4            table[16][4];
    ubyte4            tag4[4];
    ubyte4            s[4];
    sbyte4            hashBufferIndex;
    ubyte             hashBuffer[AES_BLOCK_SIZE];
    ubyte4            alen;
    ubyte4            dlen;
    AES_CTR_Ctx      *pCtx;
    sbyte4            encrypt;
    sbyte4            initialized;
    sbyte4            aadFinalized;
    MocSymCtx         pMocSymCtx;
    ubyte4            enabled;
} gcm_ctx_256b;


/**
@brief      Create and return a context data structure for AES-GCM operations.

@details    This function creates and returns a context data structure for
            AES-GCM operations, and prepares the key schedule (intermediate
            key material). This is the first function your application calls
            when performing AES operations (encryption or decryption). Your
            application uses the returned structure in subsequent DoAES()
            functions.

The AES-GCM context data structure holds information such as key length, key
schedule, and mode of operation. To avoid memory leaks, your application code
must call GCM_deleteCtx_256b() after completing AES-GCM related operations
(because the AES-GCM context is dynamically allocated by this function during
context creation).

@warning    If NULL is returned for the context pointer, you cannot use it as
            input to any subsequent AES functions.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  key         Key material.
@param  keylen      Length of key material (\p key).
@param  encrypt     \c TRUE if context for encryption; otherwise \c FALSE
                      (context is for decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN BulkCtx GCM_createCtx_256b(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt);

/**
 * @brief      Sets the nonce in a previously created AES-GCM Context.
 *
 * @details    Sets the nonce in a previously created AES-GCM Context.
 *
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pNonce      Buffer holding the input nonce value.
 * @param  nonceLen    The length of the nonce in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_nonce_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen);

/**
 * @brief      Updates an AES-GCM context with additional authenticated data.
 *
 * @details    Updates an AES-GCM context with additional authenticated data. This method
 *             may be called as many times as necessary.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated context.
 * @param  pAadData    Buffer holding the additional authenticated data.
 * @param  aadDataLen  The length of the aad in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_aad_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_update_data_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen);

/**
 * @brief      Finalizes an AES-GCM context and verifies or outputs the tag.
 *
 * @details    Finalizes an AES-GCM context and verifies or outputs the tag. If the context
 *             was created for encryption the tag will be output. If the context was
 *             created for decryption the tag will be verified and a negative error code will
 *             be returned for an invalid tag.
 *
 * @ingroup    gcm_functions
 *
 * @flags      To enable this function, at least one of the following flags must be defined
 *             in moptions.h:
 *             + \c \__ENABLE_MOCANA_GCM_64K__
 *             + \c \__ENABLE_MOCANA_GCM__
 *
 * @inc_file   gcm.h
 *
 * @param  pCtx        Pointer to a previously allocated and updated context.
 * @param  pTag        For encrypt the resulting tag will be placed in this buffer. For decrypt
 *                     this buffer should contain the input tag.
 * @param  tagLen      For encrypt this is the length of the tag requested in bytes (at most 16 bytes).
 *                     For decrypt this is the length of the input tag in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    gcm.h
 */
MOC_EXTERN MSTATUS GCM_final_ex_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen);

/**
@brief      Delete an AES-GCM context.

@details    This function deletes an AES-GCM context previously created by
            GCM_createCtx_256b(). To avoid memory leaks, your application must
            call this function after completing AES-related operations for a
            given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         Pointer to AES-GCM context to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_deleteCtx_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      Initialize nonce and authentication data for AES-GCM context.

@details    This function initializes nonce and authentication data for an
            AES-GCM context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_256b().
@param  nonce       Nonce.
@param  nlen        Length of (\p nonce) in octets.
@param  adata       Additional authenticated data.
@param  alen        Length of additional authenticated data (\p aData) in octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_init_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen);

/**
@brief      Encrypt a data buffer and perform authentication.

@details    This function AES-GCM encrypts a data buffer and authenticates.
            Before calling this function, your application must call the
            GCM_createCtx_256b() function to dynamically create a valid AES
            context, and optionally call GCM_init_256b() to set a nonce or
            additional authentication data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_256b().
@param  data        Data to encrypt and protect.
@param  dlen        Length of data to encrypt and protect (\p data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_update_encrypt_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen);

/**
@brief      Decrypt data buffer and perform authentication.

@details    This function AES-GCM decrypts a data buffer and authenticates.
            Before calling this function, your application must call the
            GCM_createCtx_256b() function to dynamically create a valid AES
            context, and optionally call GCM_init_256b() to set a nonce or
            additional authentication data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_256b().
@param  ct          Cipher text to decrypt and authenticate.
@param  ctlen       Length of cipher text to decrypt and authenticate
                      (\p data).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_update_decrypt_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *ct, ubyte4 ctlen);

/**
@brief      Write authentication tag after message encryption.

@details    This function writes the authentication tag upon completion of
            encrypting a message.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_256b().
@param  tag         Pointer to write authentication tag of AES_BLOCK_SIZE octets.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_final_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/]);

/**
@brief      AES-GCM encrypt or decrypt a data buffer.

@details    This function AES-GCM encrypts or AES-GCM decrypts a data buffer.
            Before calling this function, your application must call the
            GCM_createCtx_256b() function to dynamically create a valid
            AES-GCM context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
</table>

@ingroup    gcm_functions

@flags
To enable this function, at least one of the following flags must be defined
in moptions.h:
+ \c \__ENABLE_MOCANA_GCM_256B__
+ \c \__ENABLE_MOCANA_GCM__

@inc_file   gcm.h

@param  ctx         AES-GCM context, previously created by GCM_createCtx_256b().
@param  nonce       Nonce.
@param  nlen        Length of (\p nonce) in octets.
@param  adata       Additional authenticated data.
@param  alen        Length of additional authenticated data (\p aData) in
                      octets.
@param  data        Data to encrypt and protect.
@param  dlen        Length of data to encrypt and protect (\p data).
@param  verifyLen   Length of the authentication tag.
@param  encrypt     \c TRUE if context for encryption; otherwise \c FALSE
                      (context is for decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    gcm.h
*/
MOC_EXTERN MSTATUS GCM_cipher_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen,
                            ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt);

/**
 * Clone a AES-GCM context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS GCM_clone_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#endif /* __ENABLE_MOCANA_GCM_256B__ */

#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_MOCANA_GCM_64K__) || defined(__ENABLE_MOCANA_GCM_4K__)  || defined(__ENABLE_MOCANA_GCM_256B__) */

#endif /* __GCM_HEADER__ */

