/*
 * aes_cmac.h
 *
 * AES-CMAC Implementation
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
@file       aes_cmac.h

@brief      Header file for the Nanocrypto AES-CMAC API.
@details    Header file for the Nanocrypto AES-CMAC API.

*/


/*------------------------------------------------------------------*/

#ifndef __AES_CMAC_HEADER__
#define __AES_CMAC_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes_cmac_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CMAC_RESULT_SIZE AES_BLOCK_SIZE

typedef struct AES_OMAC_Ctx
{
    ubyte                   currBlock[AES_BLOCK_SIZE];
    /* bytes received -- we delay the processing until more bytes are
    received or final is called */
    ubyte                   pending[AES_BLOCK_SIZE] ;
    /* length of bytes received above <= AES_BLOCK_SIZE */
    ubyte                   pendingLen;
} AES_OMAC_Ctx;

typedef struct AESCMAC_Ctx
{
    aesCipherContext       *pAesCtx;
    AES_OMAC_Ctx            omacCtx;
    MocSymCtx               pMocSymCtx;
    ubyte                   enabled;

} AESCMAC_Ctx;

/*------------------------------------------------------------------*/

/*  Function prototypes  */
/* AES CMAC -- cf RFC 4493 for explanations of parameters. */
/* http://www.ietf.org/rfc/rfc4493.txt */

/**
@brief      Initialize a context data structure for AES-CMAC hash and prepare
            the key schedule.

@details    This function initializes a context data structure for AES-CMAC hash
            operation, and prepares the key schedule (intermediate key
            material). This is the first function your application calls when
            performing AES-CMAC hashing operations. Your application uses the
            initialized structure in subsequent AES-CMAC function calls.

The AES-CMAC context data structure holds information such as key length, key
schedule, and mode of operation.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cmac.jpg">AES-CMAC</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_cmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_cmac.h

@param  hwAccelCtx   If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_cmac.{c,h}
                      functions.

@param  pKeyMaterial Pointer to key material for AES-CMAC.
@param  keyLength    Number of bytes in AES key; valid key lengths are: 16
                      (for 128-bit key), 24 (for 192-bit key), and 32 (for
                      256-bit key).
@param  pCtx         Pointer to allocated AES-CMAC context data structure to
                      initialize.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_cmac.h
*/
MOC_EXTERN MSTATUS AESCMAC_init(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial, sbyte4 keyLength, AESCMAC_Ctx *pCtx);

/**
@brief      Calcluate intermediate AES-CMAC digest value.

@details    This function calculates an intermediate AES-CMAC digest value.

Applications can repeatedly call this function to calculate digests for
different data items. Every time this function is called, the intermediate
digest value is stored within the AES-CMAC context data structure.

The AES-CMAC context data structure holds information such as key length, key
schedule, and mode of operation.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cmac.jpg">AES-CMAC</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_cmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_cmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                    expands to an additional parameter, "hwAccelDescr
                    hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pData       Pointer to data to be hashed or digested.
@param  dataLength  Number of octets of data to hash or digest (\p pData).
@param  pCtx        Pointer to AES-CMAC context data strucutre that is
                    already initialized by AESCMAC_init().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_cmac.h
*/
MOC_EXTERN MSTATUS AESCMAC_update(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* pData, sbyte4 dataLength, AESCMAC_Ctx* pCtx);

/**
@brief      Calculate final CMAC digest value.

@details    This function calculates the final CMAC digest value.
            Applications must call this function after completing their calls
            to AESCMAC_update().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_aes_cmac.jpg">AES-CMAC</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_cmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_cmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  cmac        Pointer to buffer in which to write the final hash value,
                      of length CMAC_RESULT_SIZE octets.
@param  pCtx        Pointer to AES-CMAC context data strucutre that is
                      already initialized by AESCMAC_init().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_cmac.h
*/
MOC_EXTERN MSTATUS AESCMAC_final(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[CMAC_RESULT_SIZE], AESCMAC_Ctx* pCtx);

/**
@brief   Clear an existing AES-CMAC context so it is ready for re-use.

@ingroup    aes_cmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@inc_file aes_cmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx        Pointer to AES-CMAC context data structure to be cleared.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    aes_cmac.h
*/
MOC_EXTERN MSTATUS AESCMAC_clear(MOC_SYM(hwAccelDescr hwAccelCtx) AESCMAC_Ctx* pCtx);

/** @cond   Omit the following from Doxygen output. **/

/* These functions are for future use */
MOC_EXTERN MSTATUS AESCMAC_initExt(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial, sbyte4 keyLength, AESCMAC_Ctx *pCtx, void *pExtCtx);
MOC_EXTERN MSTATUS AESCMAC_updateExt(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* pData, sbyte4 dataLength, AESCMAC_Ctx* pCtx, void *pExtCtx);
MOC_EXTERN MSTATUS AESCMAC_finalExt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[CMAC_RESULT_SIZE], AESCMAC_Ctx* pCtx, void *pExtCtx);

/* reusable functions -- to be used internally by digicert only */
MOC_EXTERN MSTATUS AES_OMAC_init(AES_OMAC_Ctx* pOMACCtx);
MOC_EXTERN MSTATUS AES_OMAC_update(MOC_SYM(hwAccelDescr hwAccelCtx) aesCipherContext* pAESCtx, AES_OMAC_Ctx* pOMACCtx, const ubyte* data, sbyte4 dataLength);
MOC_EXTERN MSTATUS AES_OMAC_final( MOC_SYM(hwAccelDescr hwAccelCtx) aesCipherContext* pAESCtx, AES_OMAC_Ctx* pOMACCtx, ubyte cmac[CMAC_RESULT_SIZE]);
/** @endcond **/

#ifdef __cplusplus
}
#endif

#endif /* __AES_CMAC_HEADER__ */

