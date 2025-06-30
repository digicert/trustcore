/*
 * crypto_interface_hmac.h
 *
 * Cryptographic Interface header file for declaring HMAC functions
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
@file       crypto_interface_hmac.h
@brief      Cryptographic Interface header file for declaring HMAC functions.
@details    Add details here.

@filedoc    crypto_interface_hmac.h
*/
#ifndef __CRYPTO_INTERFACE_HMAC_HEADER__
#define __CRYPTO_INTERFACE_HMAC_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
@brief      Create HMAC context.

@details    This function creates an HMAC context and initializes data
            structure fields (function pointers) related to the hash function
            to be used within HMAC operations.

To avoid memory leaks, your application code must call the HmacDelete()
function after HMAC-related operations (because the HMAC context is
dynamically allocated by this function during context creation).

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

@warning    Be sure to check this function's return status. An unsuccessful
            return causes subsequent HMAC single-step operations to fail.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ppCtx        On return, pointer to resultant HMAC context.
@param  pBHAlgo     On return, pointer to collection of hash routines to be used
                      within HMAC.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacCreate (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **ppCtx,
  const BulkHashAlgo *pBHAlgo
  );

/**
@brief      Insert and process HMAC context's key.

@details    This function inserts and processes an HMAC context's key. After
            calling this function, your application should call HmacUpdate().

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx         Pointer to HMAC context.
@param  pKey         Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p key).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacKey (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  const ubyte *pKey,
  ubyte4 keyLen
  );

/**
@brief      Reset HMAC context.

@details    This function resets an HMAC context.

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx         Pointer to HMAC context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacReset (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx
  );

/**
@brief      Update intermediate HMAC value.

@details    This function updates the intermediate HMAC value in an HMAC
            context. Applications can repeatedly call this function to
            calculate an HMAC for different data items.

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx    If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx          Pointer to HMAC context.
@param  pData         Pointer to input data.
@param  dataLen       Number of bytes of input data (\p text).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacUpdate (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  const ubyte *pData,
  ubyte4 dataLen
  );

/**
@brief      Get final HMAC value.

@details    This function calculates a final HMAC value, and returns it
            through the \p result parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx         Pointer to HMAC context.
@param  pResult      On return, pointer to resultant HMAC value. <b>(The
                    calling function must allocate sufficient memory for the
                    result: at least equal to the output size of the
                    underlying hash function&mdash;for example, 20 bytes for
                    SHA1. Otherwise buffer overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacFinal (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  ubyte *pResult
  );

/**
@brief      Delete (free) HMAC context.

@details    This function deletes (frees) an HMAC context. Your application
            should call this function as soon as it is done using an HMAC
            context created by HmacCreate().

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ppCtx        Pointer to HMAC context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacDelete (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **ppCtx
  );

/**
 * @brief Allocates and makes a clone of a \c HMAC_CTX.
 *
 * @details Allocates and makes a clone of a \c HMAC_CTX. Make sure
 *          to call \c CRYPTO_INTERFACE_HmacDelete when finished with the new context.
 *
 * @param ppDest  Location that will recieve a pointer to a newly allocated context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacCloneCtx (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **ppDest,
  HMAC_CTX *pSrc
  );

/**
@brief      Calculate HMAC (with a single function call).

@details    This function completely calculates an HMAC, with no need to call
            multiple, "separate steps" methods. Before calling this function,
            allocate and assign the desired algorithm values to the \p pBHAlgo
            parameter. (Using values for SHA1 is the equivalent to calling the
            HMAC_SHA1() function.) The resultant HMAC value is returned through
            the \p pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuick (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuicker (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  HMAC_CTX *pCtx
  );

/**
@brief      Calculate HMAC with a single function call, using a prekeyed HMAC ctx.

@details    This function completely calculates an HMAC, with no need to call
            multiple, "separate steps" methods. Before calling this function,
            allocate and assign the desired algorithm values to the \p pBHAlgo
            parameter. (Using values for SHA1 is the equivalent to calling the
            HMAC_SHA1() function.) The resultant HMAC value is returned through
            the \p pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx        Pointer to previously created and keyed HMAC ctx.
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacSingle (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult
  );

/**
@brief      Calculate HMAC (with a single function call) for a message with
            extended data.

@details    This function completely calculates an HMAC for a message with
            extended data, with no need to call multiple, "separate steps"
            methods. Before calling this function, allocate and assign the
            desired algorithm values to the \p pBHAlgo parameter. (Using
            values for SHA1 is the equivalent to calling the HMAC_SHA1()
            function.) The resultant HMAC value is returned through the \p
            pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pOptText    Pointer to optional (extended) input data to append after
                      (\p pText); may be NULL to indicate none (which makes
                      this function equivalent to the HmacQuick() function).
@param  optTextLen  Number of bytes of optional input data (\p pOptText); may
                      be zero to indicate none.
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.c
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickEx (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pOptText,
  ubyte4 optTextLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickerEx (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pOptText,
  ubyte4 optTextLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  HMAC_CTX *pCtx
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickerInline (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  BulkCtx pContext
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickerInlineEx (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pOptText,
  sbyte4 optTextLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  BulkCtx pContext
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_MD5 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[MD5_DIGESTSIZE]
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_MD5_quick (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[SHA_HASH_RESULT_SIZE]
  );

/**
 * @brief Computes a hmac-sha1 truncated to 96 bits.
 *
 * @details Computes a hmac-sha1 truncated to 96 bits.
 *
 * @param pKey         Bufere holding the hmac key.
 * @param keyLen       The length of the key in bytes.
 * @param pText        The input data.
 * @param textLen      The length of the input data in bytes.
 * @param pTextOpt     Optional additional input data. 
 * @param textOptLen   The length of the optional input data in bytes.
 * @param pResult      Buffer that will be filled with the resulting mac. This
 *                     must be at least 12 bytes in length.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1_96 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte *pResult
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1_quick (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA256 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[SHA256_RESULT_SIZE]
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA512 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[SHA512_RESULT_SIZE]
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1Ex (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *ppTexts[],
  sbyte4 pTextLens[],
  sbyte4 numTexts,
  ubyte pResult[SHA_HASH_RESULT_SIZE]
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_HMAC_HEADER__ */
