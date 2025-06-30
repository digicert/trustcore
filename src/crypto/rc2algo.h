/*
 * rc2algo.h
 *
 * RC2 Algorithm
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
 * @file       rc2algo.h
 * @brief      Header file for the NanoCrypto RC2 API.
 *
 * @details    This file contains the NanoCrypto RC2 API methods.
 *
 * @copydoc    overview_rc2algo
 *
 * @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined in moptions.h:
 *             + \c \__ENABLE_ARC2_CIPHERS__
 *
 *             Additionally, the following flag must \b not be defined:
 *             + \c \__ARC2_HARDWARE_CIPHER__
 *
 * @filedoc    rc2algo.h
 */

/*------------------------------------------------------------------*/

#ifndef __RC2ALGO_H__
#define __RC2ALGO_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_ARC2_CIPHERS__

/**
 @brief      Get a new RC2 context data structure and prepare the key schedule.
 
 @details    This function creates and returns a context data structure for RC2
             operations, and prepares the key schedule (intermediate key
             material). This is the first function your application calls when
             performing RC2 operations (encryption or decryption). Your
             application uses the returned structure in subsequent DoRC2()
             functions.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_rc2.jpg">RC2</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 The RC2 context is an opaque data structure that holds information such as key
 length, key schedule, and mode of operation. To avoid memory leaks, your
 application code must call the DeleteRC2Ctx() function after completing
 RC2-related operations (because the RC2 context is dynamically allocated by this
 function during context creation).
 
 @warning    If \c NULL is returned for the context pointer, you cannot use it as
             input to any subsequent RC2 function calls.
 
 @ingroup    rc2_functions
 
 @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined
             + \c \__ENABLE_ARC2_CIPHERS__
 
 @inc_file rc2algo.h
 
 @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                     expands to an additional parameter, "hwAccelDescr
                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 @todo_eng_review    But... what does the user specify? In
                     the 5.3.1 docs, we just said that this was "Reserved
                     for future use." Ditto this for all aes_ecb.{c,h}
                     functions.
 
 @param  keyMaterial RC2 key to use for encryption or decryption.
 @param  keyLength   Number of bytes in the RC2 key; must be a valid RC2 key
                     length (expected value is 16 bytes).
 @param  encrypt     Unused. An RC2 context is the same for encryption as it is for
                     decryption.
 
 @return     \c NULL if any error; otherwise pointer to created RC2 context.
 
 @funcdoc    rc2algo.h
 */
MOC_EXTERN BulkCtx  CreateRC2Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
 @brief      Get a new RC2 context data structure and prepare the key schedule with arbitrary
             effective bits.
 
 @details    This function creates and returns a context data structure for RC2
             operations, and prepares the key schedule (intermediate key
             material) with arbitrary effective bits. This is the first
             function your application calls when performing RC2 operations
             (encryption or decryption). Your application uses the returned
             structure in subsequent DoRC2() functions.

             The RC2 context is an opaque data structure that holds information such as key
             length, key schedule, and mode of operation. To avoid memory leaks, your
             application code must call the DeleteRC2Ctx() function after completing
             RC2-related operations (because the RC2 context is dynamically allocated by this
             function during context creation).
 
 @warning    If \c NULL is returned for the context pointer, you cannot use it as
             input to any subsequent RC2 function calls.
 
 @ingroup    rc2_functions
 
 @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined
             + \c \__ENABLE_ARC2_CIPHERS__
 
 @inc_file rc2algo.h
 
 @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                     expands to an additional parameter, "hwAccelDescr
                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 
 @param  keyMaterial RC2 key to use for encryption or decryption.
 @param  keyLength   Number of bytes in the RC2 key; must be a valid RC2 key
                     length (expected value is 16 bytes).
 @param  effectiveBits   The number of effective bits of key material to prepare.
 
 @return     \c NULL if any error; otherwise pointer to created RC2 context.
 
 @funcdoc    rc2algo.h
 */
MOC_EXTERN BulkCtx  CreateRC2Ctx2(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 effectiveBits);

/**
 @brief      Delete RC2 context data structure.
 
 @details    This function deletes an RC2 context previously created by
             CreateRC2Ctx(). To avoid memory leaks, your application must call
             this function after completing RC2-related operations for a given
             context.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_rc2.jpg">RC2</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    rc2_functions

 @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined
             + \c \__ENABLE_ARC2_CIPHERS__
 
 @inc_file rc2algo.h
 
 @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                     expands to an additional parameter, "hwAccelDescr
                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  ctx         Pointer to RC2 context to delete.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    rc2algo.h
 */
MOC_EXTERN MSTATUS  DeleteRC2Ctx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
 @brief      RC2-encrypt or RC2-decrypt a data buffer.
 
 @details    This function RC2-encrypts or RC2-decrypts a data buffer. Before
             calling this function, your application must call the
             CreateRC2Ctx() function to dynamically create a valid RC2 context.
             This function applies the RC2 cipher in CBC mode.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_rc2.jpg">RC2</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    rc2_functions
 
 @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined
             + \c \__ENABLE_ARC2_CIPHERS__
 
 @inc_file rc2algo.h
 
 @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                     expands to an additional parameter, "hwAccelDescr
                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  ctx         RC2 context, previously created by CreateRC2Ctx().
 @param  data        Data to be encrypted or decrypted in-place.
 @param  dataLength  Number of bytes of data to be encrypted or decrypted
                     (\p data).
 @param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
 @param  iv          Initialization vector.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    rc2algo.h
 */
MOC_EXTERN MSTATUS  DoRC2(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/**
 @brief      Clone an existing RC2 context.

 @details    This function clones the provided context and returns the cloned
             context to the caller. The cloned context is at the same state as
             the caller provided context.

             To avoid memory leaks, your application code must call the
             DeleteRC2Ctx() function after completing RC2-related operations
             on the cloned context.

 @ingroup    rc2_functions

 @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined
             + \c \__ENABLE_ARC2_CIPHERS__

 @inc_file rc2algo.h

 @param pCtx     Pointer to a BulkCtx returned by CreateRC2Ctx.
 @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
                 the key data from the source key.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    rc2algo.h
 */
MOC_EXTERN MSTATUS  CloneRC2Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#endif

#ifdef __cplusplus
}
#endif


#endif
