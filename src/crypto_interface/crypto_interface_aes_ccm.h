/*
 * crypto_interface_aes_ccm.h
 *
 * Cryptographic Interface header file for declaring AES-CCM methods
 * for the Crypto Interface.
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
@file       crypto_interface_aes_ccm.h
@brief      Cryptographic Interface header file for declaring AES-CCM methods.
@details    Add details here.

@filedoc    crypto_interface_aes_ccm.h
*/
#ifndef __CRYPTO_INTERFACE_AES_CCM_HEADER__
#define __CRYPTO_INTERFACE_AES_CCM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Encrypt and protect a data buffer using AES-CCM, as defined in
 *             RFC&nbsp;3610.
 * 
 * @details    This function encrypts a data buffer using AES-CCM. It also
 *             supports authentication for the submitted data by producing a
 *             <em>MAC</em>&nbsp;a message authentication code (generated using
 *             the AES cipher as defined in RFC&nbsp;3610).
 * 
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_aes_ccm.jpg">AES-CCM</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 * 
 * Among the inputs accepted by this function, you can distinguish between two
 * different types of data:
 * + \p pEncData parameter: data is encrypted and used as an input to the MAC.
 * + \p pAuthData parameter: data is not encrypted, but it is used as an input to
 *      the MAC.
 * 
 * If you want only a MAC, specify NULL for \p pEncData parameter.
 * If you have no data for authentication, specify NULL for \p pAuthData.
 * 
 * @note       For details about the nonce, the \p L parameter, and the internal
 *             counter, see the <b>CCM Mode Overview</b> description in the @ref
 *             aes_ccm.dxd documentation.
 * 
 * @ingroup    aes_ccm_functions
 * 
 * @flags
 * There are no flag dependencies to enable this function.
 * 
 * @inc_file crypto_interface_aes_ccm.h
 * 
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 *                       expands to an additional parameter, "hwAccelDescr
 *                       hwAccelCtx". Otherwise, this macro resolves to nothing.
 *                       @todo_eng_review  But... what does the user specify? In
 *                       the 5.3.1 docs, we just said that this was "Reserved
 *                       for future use." Ditto this for all aes_ccm.{c,h}
 *                       functions.
 * 
 * @param  M           Number of the most significant octets in the
 *                       authentication field&mdash;the MAC to return in \p U.
 *                       The maximum size is 16 octets. The larger the MAC, the
 *                       stronger the authentication, and the harder it will be
 *                       for somebody to modify the message without detection.
 *                       However, if the size of the message itself is quite
 *                       small, adding the overhead of 16 octets of MAC is hard
 *                       to justify, and you should specify a smaller MAC. And
 *                       again, how do you choose? For most applications,
 *                       RFC&nbsp;3610 recommends an M value of at least 8. Valid
 *                       values for M are 4, 6, 8, 10, 12, 14, and 16 octets.
 * @param  L           Number of octets in the length field&mdash;the internal
 *                       counter. This counter shares a 128-bit (16-octet) space
 *                       with the nonce. Therefore, the larger the value of \p L,
 *                       the smaller the length of the nonce. Conformant with
 *                       RFC&nbsp;3610, the NanoCrypto AES-CCM API allows integer
 *                       L values from 2 to 8 (inclusive). Which L value to use
 *                       depends on your application. For example, RFC&nbsp;4309,
 *                       <em>Using Advanced Encryption Standard (AES) CCM Mode
 *                       with IPsec Encapsulating Security Payload (ESP)</em>,
 *                       requires an L value of 4. This value is chosen because
 *                       it allows for a counter that is large enough to encrypt
 *                       an IPv6 Jumbogram.
 * @param  pKeyMaterial Key material.
 * @param  keyLength    Length of key material (\p pKeyMaterial).
 * @param  pNonce       Unique nonce, of length 15-\p L octets.
 *                       @warning     This value must be unique for each message
 *                                    encrypted under the same key. Failure to
 *                                    use unique nonce values can destroy
 *                                    confidentiality.
 * 
 * @param  pEncData       Data to encrypt and include as input for the MAC. Specify
 *                          NULL if no data to encrypt.
 * @param  encDataLength  Length in octets of data to encrypt (\p pEncData).
 * @param  pAuthData      Data to input to MAC generation, but not for encryption.
 *                          Specify NULL if there is no authentication-only data.
 * @param  authDataLength Length of authentication data (\p pAuthData).
 * @param  U                On return, pointer to generated MAC, which is \p M octets
 *                          long.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 * 
 * @funcdoc    crypto_interface_aes_ccm.c
 **/
MOC_EXTERN MSTATUS  CRYPTO_INTERFACE_AES_CCM_encrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L, ubyte* pKeyMaterial,
    sbyte4 keyLength, const ubyte* pNonce, ubyte* pEncData, ubyte4 encDataLength,
    const ubyte* pAuthData, ubyte4 authDataLength, ubyte U[/*M*/]);


/*------------------------------------------------------------------*/

/**
 * @brief      Decrypt and authenticate a data buffer using AES-CCM.
 * 
 * @details    This function uses AES in CCM mode (as defined in RFC&nbsp;3610)
 *             to decrypt and authenticate the submitted data.
 * 
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_aes_ccm.jpg">AES-CCM</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 * 
 * @note       For details about CCM Mode and related function parameters, see
 *             the <b>CCM Mode Overview</b> description in the @ref aes_ccm.dxd
 *             documentation.
 * 
 * @ingroup    aes_ccm_functions
 * 
 * @flags
 * There are no flag dependencies to enable this function.
 * 
 * @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
 *                       expands to an additional parameter, "hwAccelDescr
 *                       hwAccelCtx". Otherwise, this macro resolves to nothing.
 * @param  M           Number of octets in the MAC specified in \p U.
 * @param  L           Number of octets in the length field&mdash;the internal
 *                       counter.
 * @param  pKeyMaterial Key material.
 * @param  keyLength    Length of key material (\p pKeyMaterial).
 * @param  pNonce       Unique nonce, of length 15-\p L octets.
 * @param  pEncData     Data to decrypt an authenticate. Specify NULL if no data
 *                        to decrypt.
 * @param  encDataLength Length in octets of data to decrypt (\p pEncData).
 * @param  pAuthData     Data to input to MAC generation, but not for decryption.
 *                         Specify NULL if there is no authentication-only data. To
 *                         perform authentication, this funciton generates the MAC
 *                         from the submitted data.
 * @param  authDataLength Length of authentication data (\p pAuthData).
 * @param  U              Pointer to the MAC, of \p M octets, of the data to decrypt.
 * 
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 * 
 * @funcdoc    crypto_interface_aes_ccm.c
 **/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_CCM_decrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L, ubyte* pKeyMaterial,
    sbyte4 keyLength, const ubyte* pNonce, ubyte* pEncData, ubyte4 encDataLength,
    const ubyte* pAuthData, ubyte4 authDataLength, const ubyte U[/*M*/]);

/**
 * Create an AES-CCM context.
 *
 * @param pKeyMaterial   Buffer containing key material for context.
 * @param keyLength      Length of pKeyMaterial in bytes.          
 * @param encrypt        \c TRUE to prepare the context for encryption;
 *                       \c FALSE to prepare the context for decryption.
 * @funcdoc    crypto_interface_aes_ccm.c
*/
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_AES_CCM_createCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial, sbyte4 keyLength,
    sbyte4 encrypt);

/**
 * Deletes an AES-CCM context.
 *
 * @param ppCtx     Pointer to the BulkCtx to be deleted.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 * @funcdoc     crypto_interface_aes_ccm.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_CCM_deleteCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ppCtx);


/**
 * Perform an AES-CCM operation in one step.
 *
 * @param pCtx           Context to use for cipher operation.
 * @param  pNonce        Unique nonce, of length 15-\p L octets.
 * @param nLen           Length in bytes of 15-\p L octets.
 * @param  pAuthData     Data to input to MAC generation, but not for decryption.
 *                         Specify NULL if there is no authentication-only data. To
 *                         perform authentication, this funciton generates the MAC
 *                         from the submitted data.
 * @param  authDataLength Length of authentication data (\p pAuthData).
 * @param  pData          Data to encrypt and include as input for the MAC. Specify
 *                          NULL if no data to encrypt.
 * @param  dataLength    Length in octets of data to encrypt (\p pEncData).
 * @param verifyLen      Length of CBC-MAC.
 * @param encrypt        \c TRUE to prepare the context for encryption;
 *                       \c FALSE to prepare the context for decryption.
 *
 * @return      \c OK (0) if successful, otherwise a negative number
 *              error code from merrors.h.
 * @funcdoc     crypto_interface_aes_ccm.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_CCM_cipher(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte* pNonce, ubyte4 nLen,
    ubyte* pAuthData, ubyte4 authDataLength, ubyte* pData, ubyte4 dataLength,
    ubyte4 verifyLen, sbyte4 encrypt);

/**
@brief      Clone an AES-CCM context.

@param pCtx     Pointer to an instantiated BulkCtx.
@param ppNewCtx Double pointer to the BulkCtx to be created and populated with
                  the data from the source context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    crypto_interface_aes_ccm.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_CCM_clone(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_CCM_HEADER__ */
