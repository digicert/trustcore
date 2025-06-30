/*
 * aes_ccm.h
 *
 * AES-CCM Implementation
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
@file       aes_ccm.h

@brief      Header file for the NanoCrypto AES-CCM API.
@details    Header file for the NanoCrypto AES-CCM API.

*/


/*------------------------------------------------------------------*/

#ifndef __AES_CCM_HEADER__
#define __AES_CCM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/*  Function prototypes  */
/* AES Counter with CBC-MAC (CCM) -- cf RFC 3610 for explanations of parameters. encryption is in place */

/**
@brief      Encrypt and protect a data buffer using AES-CCM, as defined in
            RFC&nbsp;3610.

@details    This function encrypts a data buffer using AES-CCM. It also
            supports authentication for the submitted data by producing a
            <em>MAC</em>&nbsp;a message authentication code (generated using
            the AES cipher as defined in RFC&nbsp;3610).

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ccm.jpg">AES-CCM</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

Among the inputs accepted by this function, you can distinguish between two
different types of data:
+ \p encData parameter: data is encrypted and used as an input to the MAC.
+ \p authData parameter: data is not encrypted, but it is used as an input to
     the MAC.

If you want only a MAC, specify NULL for \p encData parameter.
If you have no data for authentication, specify NULL for \p authData.

@note       For details about the nonce, the \p L parameter, and the internal
            counter, see the <b>CCM Mode Overview</b> description in the @ref
            aes_ccm.dxd documentation.

@ingroup    aes_ccm_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ccm.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.

@param  M           Number of the most significant octets in the
                      authentication field&mdash;the MAC to return in \p U.
                      The maximum size is 16 octets. The larger the MAC, the
                      stronger the authentication, and the harder it will be
                      for somebody to modify the message without detection.
                      However, if the size of the message itself is quite
                      small, adding the overhead of 16 octets of MAC is hard
                      to justify, and you should specify a smaller MAC. And
                      again, how do you choose? For most applications,
                      RFC&nbsp;3610 recommends an M value of at least 8. Valid
                      values for M are 4, 6, 8, 10, 12, 14, and 16 octets.
@param  L           Number of octets in the length field&mdash;the internal
                      counter. This counter shares a 128-bit (16-octet) space
                      with the nonce. Therefore, the larger the value of \p L,
                      the smaller the length of the nonce. Conformant with
                      RFC&nbsp;3610, the NanoCrypto AES-CCM API allows integer
                      L values from 2 to 8 (inclusive). Which L value to use
                      depends on your application. For example, RFC&nbsp;4309,
                      <em>Using Advanced Encryption Standard (AES) CCM Mode
                      with IPsec Encapsulating Security Payload (ESP)</em>,
                      requires an L value of 4. This value is chosen because
                      it allows for a counter that is large enough to encrypt
                      an IPv6 Jumbogram.
@param  keyMaterial Key material.
@param  keyLength   Length of key material (\p keyMaterial).
@param  nonce       Unique nonce, of length 15-\p L octets.
                      @warning     This value must be unique for each message
                                   encrypted under the same key. Failure to
                                   use unique nonce values can destroy
                                   confidentiality.

@param  eData       Data to encrypt and include as input for the MAC. Specify
                      NULL if no data to encrypt.
@param  eDataLength Length in octets of data to encrypt (\p encData).
@param  aData       Data to input to MAC generation, but not for encryption.
                      Specify NULL if there is no authentication-only data.
@param  aDataLength  Length of authentication data (\p authData).
@param  U           On return, pointer to generated MAC, which is \p M octets
                      long.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ccm.h
*/
MOC_EXTERN MSTATUS  AESCCM_encrypt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L, ubyte* keyMaterial, sbyte4 keyLength,
                                    const ubyte* nonce, ubyte* encData, ubyte4 eDataLength,
                                    const ubyte* authData, ubyte4 aDataLength, ubyte U[/*M*/]);

/**
@brief      Decrypt and authenticate a data buffer using AES-CCM.

@details    This function uses AES in CCM mode (as defined in RFC&nbsp;3610)
            to decrypt and authenticate the submitted data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ccm.jpg">AES-CCM</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@note       For details about CCM Mode and related function parameters, see
            the <b>CCM Mode Overview</b> description in the @ref aes_ccm.dxd
            documentation.

@ingroup    aes_ccm_functions

@flags
There are no flag dependencies to enable this function.

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  M           Number of octets in the MAC specified in \p U.
@param  L           Number of octets in the length field&mdash;the internal
                      counter.
@param  keyMaterial Key material.
@param  keyLength   Length of key material (\p keyMaterial).
@param  nonce       Unique nonce, of length 15-\p L octets.
@param  eData       Data to decrypt an authenticate. Specify NULL if no data
                      to decrypt.
@param  eDataLength Length in octets of data to decrypt (\p encData).
@param  aData       Data to input to MAC generation, but not for decryption.
                      Specify NULL if there is no authentication-only data. To
                      perform authentication, this funciton generates the MAC
                      from the submitted data.
@param  aDataLength  Length of authentication data (\p authData).
@param  U            Pointer to the MAC, of \p M octets, of the data to decrypt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ccm.h
*/
MOC_EXTERN MSTATUS  AESCCM_decrypt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L, ubyte* keyMaterial, sbyte4 keyLength,
                                    const ubyte* nonce, ubyte* encData, ubyte4 eDataLength,
                                    const ubyte* authData, ubyte4 aDataLength, const ubyte U[/*M*/]);

/**
@brief      Create a new AES-CCM context for use in AESCCM_cipher.

@ingroup    aes_ccm_functions

@flags
There are no flag dependencies to enable this function.

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  key         The AES key material to instantiate the context with.
@param  keylen      Length in bytes of the AES key material, must be 16,
                    24, or 32 bytes long.
@param  encrypt     Unused.
@return             Pointer to the newly created context on success, NULL
                    on error.

@funcdoc    aes_ccm.h
*/
MOC_EXTERN BulkCtx AESCCM_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt);

/**
@brief      Delete an AES-CCM context created with AESCCM_createCtx.

@ingroup    aes_ccm_functions

@flags
There are no flag dependencies to enable this function.

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         The AES-CCM context to delete.
@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ccm.h
*/
MOC_EXTERN MSTATUS AESCCM_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      Encyrpt or decrypt data using AES in CCM mode.

@ingroup    aes_ccm_functions

@flags
There are no flag dependencies to enable this function.

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param ctx         AES-CCM context to use for this operation.
@param nonce       Nonce data to use for this operation.
@param nlen        Length in bytes of the nonce data.
@param aData       Data input for authentication but not cipher processing.
@param aDataLength Length in bytes of the authentication data.
@param data        Data to be encrypted or decrypted.
@param dataLength  Length in bytes of the data to be processed.
@param verifyLen   Length in bytes of the verification tag.
@param encrypt     TRUE to encrypt, FALSE to decrypt.

@funcdoc    aes_ccm.h
*/
MOC_EXTERN MSTATUS AESCCM_cipher(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* nonce, ubyte4 nlen, ubyte* aData, ubyte4 aDataLength, ubyte* data, ubyte4 dataLength, ubyte4 verifyLen, sbyte4 encrypt);

/**
@brief      Clone an AES-CCM context.

@param pCtx     Pointer to an instantiated BulkCtx.
@param ppNewCtx Double pointer to the BulkCtx to be created and populated with
                  the data from the source context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ccm.h
 */
MOC_EXTERN MSTATUS AESCCM_clone(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#ifdef __cplusplus
}
#endif

#endif /* __AES_CCM_HEADER__ */

