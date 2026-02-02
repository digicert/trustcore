/*
 * aes_ecb.h
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
@file       aes_ecb.h

@brief      Header file for the NanoCrypto AES-ECB API.
@details    Header file for the NanoCrypto AES-ECB API.

*/


/*------------------------------------------------------------------*/

#ifndef __AES_ECB_HEADER__
#define __AES_ECB_HEADER__

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_aes_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/**
@brief      Get a new AES-ECB context data structure and prepare the key
            schedule.

@details    This function creates and returns a context data structure for
            AES operations, and prepares the key schedule (intermediate key
            material). This is the first function your application calls
            when performing AES operations (encryption or decryption). Your
            application uses the returned structure in subsequent DoAESECB()
            function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ecb.jpg">AES-ECB</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The AES-ECB context is an opaque data structure that holds information such as
key length, key schedule, and mode of operation. To avoid memory leaks, your
application code must call the DeleteAESECBCtx() function after completing
AES-related operations (because the AES-ECB context is dynamically allocated by
this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use
            it as input to any subsequent AES function calls.

@ingroup    aes_ecb_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_ecb.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ecb.{c,h}
                      functions.

@param  keyMaterial AES key to use for encryption or decryption.
@param  keyLength   Number of bytes in AES key; valid key lengths are: 128,
                      192, and 256.
@param  encrypt     \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created AES-ECB context.

@funcdoc    aes_ecb.h
*/
MOC_EXTERN BulkCtx CreateAESECBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
@brief      Delete AES-ECB context data structure.

@details    This function deletes an AES-ECB context previously created by
            CreateAESECBCtx(). To avoid memory leaks, your application must
            call this function after completing AES-related operations for a
            given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ecb.jpg">AES-ECB</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ecb_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_ecb.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param ctx          Pointer to the AES-ECB context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ecb.h
*/
MOC_EXTERN MSTATUS DeleteAESECBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      AES-encrypt or AES-decrypt a data buffer.

@details    This function AES-encrypts or AES-decrypts a data buffer. Before
            calling this function, your application must call the
            CreateAESECBCtx() function to dynamically create a valid AES-ECB
            context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ecb.jpg">AES-ECB</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ecb_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_ecb.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param ctx          AES-ECB context, previously created by CreateAESECBCtx().
@param data         Data to be encrypted or decrypted.
@param dataLength   Number of bytes of data to be encrypted or decrypted
                      (\p data).
@param encrypt      \c TRUE to encrypt the data; \c FALSE to decrypt the data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ecb.h
*/
MOC_EXTERN MSTATUS DoAESECB(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt);

#ifdef __cplusplus
}
#endif

#endif /* __AES_ECB_HEADER__ */

