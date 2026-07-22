/*
 * fips_entropy.h
 *
 * FIPS Entropy Source API to obtain data
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
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
@file       fips_entropy.h

@brief      Header file for the FIPS Entropy access API.
@details    Header file for the FIPS Entropy access API.

*/

/*------------------------------------------------------------------*/

#ifndef __FIPS_ENTROPY_HEADER__
#define __FIPS_ENTROPY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

/* Forward declaration */
typedef struct FIPS_ENTROPY_st FIPS_ENTROPY_ctx;

/**
@brief      Initializes the External Entropy source mechanism (e.g. library or module).
            To be called during crypto-module initialization.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    fips_entropy.h
*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_initExternalEntropyConstructor(void);


/**
@brief      Create the memory section that can hold the 'FIPS_ENTROPY_ctx' data.

@param  ppCtx    Pointer to the memory where the context pointer will be stored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    fips_entropy.h
*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_allocateExternalEntropy(FIPS_ENTROPY_ctx **pCtx);

/**
@brief      Initializes the context to match the Entropy source used on this platform.
            The context must have been correctly allocated.

@param  pCtx     Pointer the FIPS ENTROPY context.
@param  retries_allowed
                 How often should a data 'read' retry, in case a temporary
                 error is returned by the Entropy source. (0 = unlimited tries)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    fips_entropy.h
*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_initExternalEntropy(FIPS_ENTROPY_ctx* pCtx, ubyte4 retries_allowed);

/*
 * This function will fill the provided memory for entropy data by reading
 * bytes from a platform-dependent, trusted Entropy source and copy them.
 */
/**
@brief      Gives access to entropy data to the caller. When successful, it returns
            the data in the memory that was passed. The memory must have the capacity for this
            number of writes.

@param  pCtx     Pointer a valid FIPS ENTROPY context.
@param  pOut     Memory where the data is to be stored.
@param  outLen   The amount of entropy requested. In bytes.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    fips_entropy.h	    
*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_readExternalEntropy(FIPS_ENTROPY_ctx* pCtx, ubyte *pOut, ubyte4 outLen);

/**
@brief      Free the memory section that holds the 'FIPS_ENTROPY_ctx' data.

@param  ppCtx    Pointer to the memory where the context pointer is be stored.
                 After this call it will have a NULL value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    fips_entropy.h
*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_freeExternalEntropy(FIPS_ENTROPY_ctx **ppCtx);

/**
@brief      Zeroizes any connection or context for the Entropy source. After this, the entropy source
            can no longer be used without re-initializing.

@param  pCtx     Pointer the FIPS ENTROPY context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    fips_entropy.h
*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_zeroizeExternalEntropy(void);

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#ifdef __cplusplus
}
#endif

#endif /* __FIPS_ENTROPY_HEADER__ */
