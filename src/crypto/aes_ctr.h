/*
 * aes_ctr.h
 *
 * AES-CTR Implementation
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
@file       aes_ctr.h
@brief      Header file for the NanoCrypto AES-CTR API.
@details    Header file for the NanoCrypto AES-CTR API.

*/


/*------------------------------------------------------------------*/

#ifndef __AES_CTR_HEADER__
#define __AES_CTR_HEADER__

#include "../cap/capdecl.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_aes_ctr_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/*  The structure for key information */
typedef struct aesCTRCipherContext
{
    aesCipherContext     *pCtx;
    union
    {
        ubyte               counterBlock[AES_BLOCK_SIZE];   /* counter block */
        ubyte4              ctr[4];
    } u;
    ubyte               encBlock[AES_BLOCK_SIZE];       /* encrypted counter block */
    ubyte               offset;                         /* offset of unused byte in the encBlock */
    MocSymCtx         pMocSymCtx;
    ubyte             enabled;
} aesCTRCipherContext, AES_CTR_Ctx;



/*------------------------------------------------------------------*/

/*  Function prototypes  */
/* for AES CTR, the keyMaterial is key + block --- iv is NOT used in DoAESCTR */
/* for RFC3686, construct the block and do not pass the IV as the iv argument */
/* the block is incremented by 1 for each encryption so as to be compatible with RFC 3686
and the EAX mode -- */

/**
@brief      Create a new AES-CTR context data structure and prepare the key
            schedule.

@details    This function creates and returns a context data structure for AES
            operations, and prepares the key schedule (intermediate key
            material). This is the first function your application calls when
            performing AES-CTR operations (encryption or decryption). Your
            application uses the returned structure in subsequent DoAESCTR()
            function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The AES-CTR context is an opaque data structure that holds information such as
key length, key schedule, counter block, and mode of operation. To avoid memory
leaks, your application code must call the DeleteAESCTRCtx function after
completing AES-related operations (because the AES-CTR context is dynamically
allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to subsequent AES function calls.

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.

@param  keyMaterial Key material plus counter block.
@param  keyLength   Number of octets for AES key plus a fixed length counter
                      block (AES_BLOCK_SIZE). Valid key lengths are:
                      AES-CTR-128(16 + 16 = 32 octets), AES-CTR-192(40
                      octets), and AES-CTR-256 (48 octets).
@param encrypt      \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created AES-CTR context.

@todo_eng_review    Confirm that this function appears properly in the output;
                    it's in question given the compiler-controlled declarations.

@funcdoc    aes_ctr.h
*/
#ifdef __UCOS_DIRECT_RTOS__
/**
 * @cond
 */
MOC_EXTERN BulkCtx  CreateAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
/**
 * @endcond
 */
#else
MOC_EXTERN BulkCtx  CreateAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
#endif /* __UCOS_DIRECT_RTOS__ */

/**
@brief      Delete AES-CTR context data structure.

@details    This function deletes an AES-CTR context previously created by
            CreateAESCTRCtx(). To avoid memory leaks, your application must
            call this function after completing AES-CTR related operations for
            a given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to AES-CTR context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS  DeleteAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      AES-CTR encrypt or decrypt a data buffer.

@details    This function AES-CTR encrypts or decrypts a data buffer. Before
            calling this function, your application must call the
            CreateAESCTRCtx() function to dynamically create a valid AES-CTR
            context. For RFC&nbsp;3686 usage, the IV should be NULL. If the
            IV parameter is not NULL, the contents of the IV are copied to
            counter block context within AES-CTR context. The internal counter
            block is incremented for each block that is encrypted/decrypted.
            AES in CTR mode does not require that the submitted data buffer be
            an even multiple of the AES block size (128 bits). Therefore, no
            padding is required, which makes this mode compatible with stream
            data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         AES-CTR context, previously created by CreateAESCTRCtx().
@param  data        Data to be encrypted or decrypted.
@param  dataLength  Number of octets of data to encrypt or decrypt (\p data).
@param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv          Usually NULL, optionally used to pass in a new counter block
                      of AES_BLOCK_SIZE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS  DoAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/* this might be easier to use in some cases */

/**
@brief      Prepare the key schedule for an existing AES-CTR context.

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.
@param  aesCtrCtx   Pointer to an existing AES-CTR context.
@param  keyMaterial Key material plus counter block.
@param  keyLength   Number of octets for AES key plus a fixed length counter
                      block (AES_BLOCK_SIZE). Valid key lengths are:
                      AES-CTR-128(16 + 16 = 32 octets), AES-CTR-192(40
                      octets), and AES-CTR-256 (48 octets).
@param initCounter  The initial counter block to use for this operation.

@return     \c NULL if any error; otherwise pointer to created AES-CTR context.

@todo_eng_review    Confirm that this function appears properly in the output;
                    it's in question given the compiler-controlled declarations.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS AESCTRInit(MOC_SYM(hwAccelDescr hwAccelCtx) AES_CTR_Ctx* aesCtrCtx, const ubyte* keyMaterial, sbyte4 keyLength, const ubyte initCounter[AES_BLOCK_SIZE]);

/**
@brief      AES-CTR encrypt or decrypt a data buffer.

@details    This function AES-CTR encrypts or decrypts a data buffer. Before
            calling this function, your application must call the
            CreateAESCTRCtx() function to dynamically create a valid AES-CTR
            context. For RFC&nbsp;3686 usage, the IV should be NULL. If the
            IV parameter is not NULL, the contents of the IV are copied to
            counter block context within AES-CTR context. The internal counter
            block is incremented for each block that is encrypted/decrypted.
            AES in CTR mode does not require that the submitted data buffer be
            an even multiple of the AES block size (128 bits). Therefore, no
            padding is required, which makes this mode compatible with stream
            data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         AES-CTR context, previously created by CreateAESCTRCtx().
@param  data        Data to be encrypted or decrypted.
@param  dataLength  Number of octets of data to encrypt or decrypt (\p data).
@param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv          Usually NULL, optionally used to pass in a new counter block
                    of AES_BLOCK_SIZE.
@param limit        Specifies the last byte to increment -> AES_BLOCK_SIZE -> all bytes will be incremented
                    0 -> no bytes will be incremented

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS  DoAESCTREx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv, sbyte4 limit);

/**
@brief      AES-CTR get current counter block used in given context.

@details    This function takes an AES-CTR context, and writes the current
            counter block used to the given buffer, pCounterBuffer.

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx      If a hardware acceleration flag is defined, this macro
                        expands to an additional parameter, "hwAccelDescr
                        hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx             AES-CTR context, previously created by CreateAESCTRCtx().
@param  pCounterBuffer  Pointer to buffer that will store the counter block data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS  GetCounterBlockAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte pCounterBuffer[AES_BLOCK_SIZE]);

/**
 * Clone a AES-CTR context.
 *
 * @param pCtx     Pointer to an instantiated BulkCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CloneAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#ifdef __ENABLE_DIGICERT_IPSEC_SERVICE__
/**
@brief      Create a new AES-CTR context data structure and prepare the key
            schedule for using with IPsec Encapsulating Security Payload.

@details    This function creates and returns a context data structure for AES
            operations, and prepares the key schedule (intermediate key
            material). This is the first function your application calls when
            performing AES-CTR operations (encryption or decryption). Your
            application uses the returned structure in subsequent DoAesCtr()
            or DoAesCtrEx() function calls. Counter block must be initialized
            to one. Key material pointer must have 4 octet nonce following key.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The AES-CTR context is an opaque data structure that holds information such as
key length, key schedule, counter block, and mode of operation. To avoid memory
leaks, your application code must call the DeleteAESCTRCtx function after
completing AES-related operations (because the AES-CTR context is dynamically
allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to subsequent AES function calls.

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.

@param  keyMaterial Key material plus nonce blocks.
@param  keyLength   Number of octets for AES key plus a fixed length counter
                      block (AES_BLOCK_SIZE). Valid key lengths are:
                      AES-CTR-128(16 + 4 = 20 octets), AES-CTR-192(28
                      octets), and AES-CTR-256 (36 octets).
@param encrypt      \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created AES-CTR context.

@todo_eng_review    Confirm that this function appears properly in the output;
                    it's in question given the compiler-controlled declarations.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN BulkCtx  CreateAesCtrCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                                sbyte4 keyLength, sbyte4 encrypt);

/**
@brief      AES-CTR encrypt or decrypt a data buffer.

@details    This function AES-CTR encrypts or decrypts a data buffer. Before
            calling this function, your application must call the
            CreateAESCTRCtx() function to dynamically create a valid AES-CTR
            context. IV parameter must not be null, and must be at least 8 octets
            long. Note only first 8 bytes will be used.
            Counter block is incremented for each block that is encrypted/decrypted.
            AES in CTR mode does not require that the submitted data buffer be
            an even multiple of the AES block size (128 bits). Therefore, no
            padding is required, which makes this mode compatible with stream
            data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         AES-CTR context, previously created by CreateAesCtrCtx().
@param  data        Data to be encrypted or decrypted.
@param  dataLength  Number of octets of data to encrypt or decrypt (\p data).
@param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv          Must be 8 octets, will not override nonce or counter.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS  DoAesCtr(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
                         sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/**
@brief      AES-CTR encrypt or decrypt a data buffer.

@details    This function AES-CTR encrypts or decrypts a data buffer. Before
            calling this function, your application must call the
            CreateAESCTRCtx() function to dynamically create a valid AES-CTR
            context. IV parameter must not be null, and must be at least 8 octets
            long. Note only first 8 bytes will be used. Counter will be reset to
            1 and offset will be reset to 0 before encrypt/derypt operation.
            AES in CTR mode does not require that the submitted data buffer be
            an even multiple of the AES block size (128 bits). Therefore, no
            padding is required, which makes this mode compatible with stream
            data.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_ctr.jpg">AES-CTR</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_ctr_functions

@flags
There are no flag dependencies to enable this function.

@inc_file aes_ctr.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         AES-CTR context, previously created by CreateAesCtrCtx().
@param  data        Data to be encrypted or decrypted.
@param  dataLength  Number of octets of data to encrypt or decrypt (\p data).
@param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv          Must be 8 octets, will not override nonce or counter.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_ctr.h
*/
MOC_EXTERN MSTATUS  DoAesCtrEx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
                         sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
#endif


#ifdef __cplusplus
}
#endif

#endif /* __AES_CTR_HEADER__ */

