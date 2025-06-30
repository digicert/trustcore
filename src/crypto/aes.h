/*
 * aes.h
 *
 * AES Implementation
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
@file       aes.h

@brief      Header file for the NanoCrypto AES symmetric cipher
            functions API.
@details    Header file for the NanoCrypto AES symmetric cipher
            functions API.

*/



/*------------------------------------------------------------------*/

#ifndef __AES_HEADER__
#define __AES_HEADER__

#include "../cap/capdecl.h"

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_aes_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AES_MAXNR               14
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE          (16)
#endif

#define MOC_MAX_AES_KEY_SIZE    32
#define MOC_AES_256_KEY_LEN     32
#define MOC_AES_192_KEY_LEN     24
#define MOC_AES_128_KEY_LEN     16

/*  Generic Defines  */
#define MODE_ECB                1         /* Are we ciphering in ECB mode?   */
#define MODE_CBC                2         /* Are we ciphering in CBC mode?   */
#define MODE_CFB1               3         /* Are we ciphering in 1-bit CFB mode? */
#define MODE_CFB128             4         /* Are we ciphering in 128-bit CFB mode? */
#define MODE_OFB                5         /* Are we ciphering in OFB mode? */
#define MODE_CTR                6         /* Are we ciphering in CTR mode? */

/*------------------------------------------------------------------*/

/*
  The structure for key information

  IMPORTANT: if the size of this context is modified check that
  MOC_RAND_CTX_WRAPPER_STORAGE_SIZE does not need to be increased
  in random.h. That macro depends on the largest of two contexts,
  a des3ctx, and of this context. Right now des3ctx is still larger.
*/
typedef struct
{
    sbyte4              encrypt;                        /* Key used for encrypting or decrypting? */
    sbyte4              mode;                           /* MODE_ECB, MODE_CBC, MODE_CFB1 or MODE_OFB */
    sbyte4              keyLen;                         /* Length of the key  */
    sbyte4              Nr;                             /* key-length-dependent number of rounds */
    ubyte4              rk[4*(AES_MAXNR + 1)];          /* key schedule */

    MocSymCtx           pMocSymCtx;
    ubyte               enabled;
    ubyte	            initialized;
} aesCipherContext;


/*------------------------------------------------------------------*/

/* internal prototypes */

/**
 * @details Initialize a raw AES object for operation. Note that this should only be
 * used when constructing a larger cryptographic scheme that requires an AES
 * primitive. To use AES for encrypting/decrypting data in general, use one of
 * the CreateAES*Ctx functions instead. It is the callers
 * responsibility to delete this context after use by calling
 * AESALGO_clearKey.
 *
 * @param pCtx         Pointer to a caller allocated AES context to be initialized.
 * @param keyLen       Length in bytes of key material to use, must be
 *                     one of {16,24,32}.
 * @param pKeyMaterial Key material to use for this operation.
 * @param encrypt      \c TRUE to encrypt, \c FALSE to decrypt.
 * @param mode         The AES mode of operation to use. Must be one of
 *                     { MODE_ECB, MODE_CBC, MODE_CFB128, MODE_OFB }
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS AESALGO_makeAesKey(aesCipherContext *pAesContext, sbyte4 keyLen, const ubyte *keyMaterial, sbyte4 encrypt, sbyte4 mode);

/**
 * @details Encrypt some data using the provided AES context.
 *
 * @param pCtx       The context to use for this cipher operation.
 * @param pIv        Initialization vector to use for this operation,
 *                   optional for ECB mode. Must be 16 bytes for all
 *                   other modes.
 * @param pInput     Data to encrypt.
 * @param inputLen   Length in bytes of the input data, must be a multiple
 *                   of the AES block size (16).
 * @param pOutBuffer Buffer that will recieve the encrypted result, must be
 *                   as large as the input data.
 * @param pRetLength Pointer to the sbyte4 which will recieve the length of
 *                   the resulting ciphertext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS AESALGO_blockEncrypt(aesCipherContext *pAesContext, ubyte* iv, ubyte *input, sbyte4 inputLen, ubyte *outBuffer, sbyte4 *pRetLength);

/**
 * @details          Decrypt some data using the provided AES context.
 *
 * @param pCtx       The context to use for this cipher operation.
 * @param pIv        Initialization vector to use for this operation,
 *                   optional for ECB mode. Must be 16 bytes for all
 *                   other modes.
 * @param pInput     Data to decrypt.
 * @param inputLen   Length in bytes of the input data, must be a multiple
 *                   of the AES block size (16).
 * @param pOutBuffer Buffer that will recieve the decrypted result, must be
 *                   as large as the input data.
 * @param pRetLength Pointer to the sbyte4 which will recieve the length of
 *                   the resulting plaintext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS AESALGO_blockDecrypt(aesCipherContext *pAesContext, ubyte* iv, ubyte *input, sbyte4 inputLen, ubyte *outBuffer, sbyte4 *pRetLength);

/**
 * @details Delete an AES context previously initialized with
 * AESALGO_makeAesKey. Note that this function frees the
 * underlying context created by the crypto interface. Even though the
 * aesCipherContext pointer was originally allocated by the caller, failing to
 * call this function after use will result in a memory leak.
 *
 * @param pCtx Pointer to an AES context previously created with
 *             AESALGO_makeAesKey.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS AESALGO_clearKey(aesCipherContext *pAesContext);

/**
 * @details Initialize a raw AES object for operation. Note that this should only be
 * used when constructing a larger cryptographic scheme that requires an AES
 * primitive. To use AES for encrypting/decrypting data in general, use one of
 * the CreateAES*Ctx functions instead. It is the callers
 * responsibility to delete this context after use by calling
 * AESALGO_clearKey.
 *
 * @param hwAccelCtx   If a hardware acceleration flag is defined, this macro
 *                     expands to an additional parameter, "hwAccelDescr
 *                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 * @param pCtx         Pointer to a caller allocated AES context to be initialized.
 * @param keyLen       Length in bytes of key material to use, must be
 *                     one of {16,24,32}.
 * @param pKeyMaterial Key material to use for this operation.
 * @param encrypt      \c TRUE to encrypt, \c FALSE to decrypt.
 * @param mode         The AES mode of operation to use. Must be one of
 *                     { MODE_ECB, MODE_CBC, MODE_CFB128, MODE_OFB }
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS AESALGO_makeAesKeyEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  sbyte4 keyLen,
  const ubyte *keyMaterial,
  sbyte4 encrypt,
  sbyte4 mode
  );

/**
 * @details Encrypt some data using the provided AES context.
 *
 * @param hwAccelCtx  If a hardware acceleration flag is defined, this macro
 *                    expands to an additional parameter, "hwAccelDescr
 *                    hwAccelCtx". Otherwise, this macro resolves to nothing.
 * @param pCtx        The context to use for this cipher operation.
 * @param pIv         Initialization vector to use for this operation,
 *                    optional for ECB mode. Must be 16 bytes for all
 *                    other modes.
 * @param pInput      Data to encrypt.
 * @param inputLen    Length in bytes of the input data, must be a multiple
 *                    of the AES block size (16).
 * @param pOutBuffer  Buffer that will recieve the encrypted result, must be
 *                    as large as the input data.
 * @param pRetLength  Pointer to the sbyte4 which will recieve the length of
 *                    the resulting ciphertext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS AESALGO_blockEncryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  ubyte* iv,
  ubyte *input,
  sbyte4 inputLen,
  ubyte *outBuffer,
  sbyte4 *pRetLength
  );

/**
 * @details Decrypt some data using the provided AES context.
 *
 * @param hwAccelCtx   If a hardware acceleration flag is defined, this macro
 *                     expands to an additional parameter, "hwAccelDescr
 *                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 * @param pCtx         The context to use for this cipher operation.
 * @param pIv          Initialization vector to use for this operation,
 *                     optional for ECB mode. Must be 16 bytes for all
 *                     other modes.
 * @param pInput       Data to decrypt.
 * @param inputLen     Length in bytes of the input data, must be a multiple
 *                     of the AES block size (16).
 * @param pOutBuffer   Buffer that will recieve the decrypted result, must be
 *                     as large as the input data.
 * @param pRetLength   Pointer to the sbyte4 which will recieve the length of
 *                     the resulting plaintext.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h
 */
MOC_EXTERN MSTATUS AESALGO_blockDecryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesContext,
  ubyte* iv,
  ubyte *input,
  sbyte4 inputLen,
  ubyte *outBuffer,
  sbyte4 *pRetLength
  );

/*------------------------------------------------------------------*/

/**
@brief      Get a new AES CBC context data structure and prepare the key
            schedule.

This function creates and returns a context data structure for AES CBC
operations, and prepares the key schedule (intermediate key material). This
is the first function your application calls when performing AES operations
(encryption or decryption). Your application uses the returned structure in
subsequent DoAES functions.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cbc.jpg">AES-CBC</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The AES CBC context is an opaque data structure that holds information such as
key length, key schedule, and mode of operation. To avoid memory leaks, your
application code must call the DeleteAESCtx() function after completing
AES-CBC related operations (because the AES context is dynamically allocated by
this function during context creation).

@sa         For details about AES in CBC mode, see @ref section_overview_aes_cbc
            and @ref section_caveats_aes_cbc.

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent AES-CBC functions.

@ingroup    aes_cbc_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   aes.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes.{c,h} functions.

@param  keyMaterial AES key to use for encryption or decryption.
@param  keyLength   Number of bytes in AES key; valid key lengths are: 16
                      (for 128 bit key), 24 (for 192 bit key), and 32 (for
                      256 bit key).
@param encrypt      \c TRUE to prepare the key schedule for encryption;
                    \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created AES context.

@funcdoc    aes.h
*/
MOC_EXTERN BulkCtx  CreateAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
@brief      Delete AES context data structure.

@details    This function deletes an AES context previously created by
            CreateAESCtx(), CreateAESCFBCtx(), or CreateAESOFBCtx(). To avoid
            memory leaks, your application must call this function after
            completing AES-related operations for a given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cbc.jpg">AES-CBC</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_cbc_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   aes.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to AES context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes.h
*/
MOC_EXTERN MSTATUS  DeleteAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
 * @cond
 */
MOC_EXTERN MSTATUS  ResetAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);
/**
 * @endcond
 */

/**
@brief      AES-encrypt or AES-decrypt a data buffer.

@details    This function AES-encrypts or AES-decrypts a data buffer. Before
            calling this function, your application must call CreateAESCtx(),
            CreateAESCFBCtx(), or CreateAESOFBCtx() to dynamically create a
            valid, mode-appropriate AES context.

@warning    This function destroys the submitted IV.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cbc.jpg">AES-CBC</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_cbc_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   aes.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         AES context, previously created by CreateAESCtx(),
                      CreateAESCFBCtx(), or CreateAESOFBCtx().
@param data         Data to be encrypted or decrypted.
@param dataLength   Number of bytes of data to encrypt or decrypt (\p data).
@param encrypt      \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param iv           Unique IV for the AES operation. @warning For all modes,
                      it is essential that you never reuse an IV under the
                      same key. Otherwise, you will compromise
                      confidentiality for the mode.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes.h
*/
MOC_EXTERN MSTATUS  DoAES       (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/**
@todo_eng_review    This function's documentation was added since 5.3.1,
                    and should be reviewed for accuracy and appropriateness.

@brief      Get a new AES CFB-mode context data structure and prepare the key
            schedule.

@details    This function creates and returns a context data structure for
            AES operations (in the CFB mode) and prepares the key schedule
            (intermediate key material). This is the first function your
            application calls when performing AES CFB-mode operations
            (encryption or decryption). Your application uses the returned
            structure in subsequent DoAES functions.

@sa         For details about AES in CFB mode, see @ref section_overview_aes_cfb
            and @ref section_caveats_aes_cfb.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cfb.png">AES-CFB</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The AES CFB-mode context is an opaque data structure that holds information
such as key length, key schedule, and mode of operation. To avoid memory leaks,
your application code must call the DeleteAESCtx function after completing
AES-related CFB-mode operations (because the AES context is dynamically
allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent AES functions.

@ingroup    aes_cbc_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   aes.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param keyMaterial  AES key to use for encryption or decryption.
@param keyLength    Number of bytes in AES key; valid key lengths are:
                      16 (for 128 bit key), 24 (for 192 bit key), and 32 (for
                      256 bit key).
@param encrypt      \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created AES CFB-mode
            context.

@funcdoc    aes.h
*/
MOC_EXTERN BulkCtx CreateAESCFBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);


/**
 * Create a new AES-CFB1 context. Note it is the callers responsibility to
 * free this object after use by calling \c DeleteAESCtx.
 * Once created, you can use this context as input to \c DoAES
 * to encrypt or decrypt data.
 *
 * @inc_file   aes.h
 * @funcdoc    aes.h
 *
 * @param pKeyMaterial Key material to use for the cipher operation.
 * @param keyLength    Length in bytes of the key material, valid key lengths
 *                     are {16, 24, 32}.
 * @param encrypt      \c TRUE to prepare this context for encryption,
 *                     \c FALSE to prepare this context for decryption.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN BulkCtx CreateAESCFB1Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);


/**
@brief      Get a new AES OFB-mode context data structure and prepare the key
            schedule.

@details    This function creates and returns a context data structure for
            AES operations in OFB mode, and prepares the key schedule
            (intermediate key material).

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ofb.png">AES-OFB</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@todo_eng_review    This function and its documentation were added since 5.3.1,
                    and should be reviewed for accuracy and appropriateness.

This is the first function your application calls when performing AES OFB-mode
operations (encryption or decryption). Your application uses the returned
structure in subsequent DoAES() function calls.

The AES OFB-mode context is an opaque data structure that holds information
such as key length, key schedule, and mode of operation. To avoid memory leaks,
your application code must call the DeleteAESCtx() function after completing
AES-related OFB-mode operations (because the AES context is dynamically
allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent AES functions.


@ingroup    aes_cbc_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   aes.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param keyMaterial  AES key to use for encryption or decryption.
@param keyLength    Number of bytes in AES key; valid key lengths are:
                      16 (for 128 bit key), 24 (for 192 bit key), and 32 (for
                      256 bit key).
@param encrypt      \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created AES OFB-mode
            context.

@funcdoc    aes.h
*/
MOC_EXTERN BulkCtx CreateAESOFBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
 * Clone a AES context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CloneAESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#ifdef __cplusplus
}
#endif

#endif /* __AES_HEADER__ */

