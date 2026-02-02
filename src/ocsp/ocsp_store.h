/*
 * ocsp_store.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#ifndef __OCSP_STORE_HEADER__
#define __OCSP_STORE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/

/* Default next update time if one is not provided in the response
 */
#ifndef OCSP_DEFAULT_NEXT_UPDATE_TIME
#define OCSP_DEFAULT_NEXT_UPDATE_TIME 5400
#endif

/*----------------------------------------------------------------------------*/

struct ocspStore;

/* Forward declaration
 */
typedef struct ocspStore* ocspStorePtr;

/*----------------------------------------------------------------------------*/

/**
@private
@internal

@brief      Create an OCSP store. If the OCSP store already exists then this
            function will exit without creating the OCSP store without an error.

@details    This function creates an OCSP store which is used to store cached
            OCSP responses for certificates. If the OCSP store pointer already
            contains an OCSP store then the function will exit without creating
            the OCSP store without an error.

@since 6.5
@version 6.5 and later

@flags
To enable this function, all of the following flags must be defined
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__
+ \c \__ENABLE_DIGICERT_OCSP_STORE__

@param ppNewStore   Double pointer where the reference to the newly created OCSP
                    store will be stored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ocsp_store.c
 */
MOC_EXTERN MSTATUS OCSP_STORE_createStore(ocspStorePtr *ppNewStore);

/*----------------------------------------------------------------------------*/

/**
@private
@internal

@brief      Free the OCSP store. This API should only be called if no one is
            attempting to access data within the store.

@details    This function deletes the OCSP store. Only invoke this API if there
            are no threads attempting to access data within the OCSP store.

@since 6.5
@version 6.5 and later

@flags
To enable this function, all of the following flags must be defined
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__
+ \c \__ENABLE_DIGICERT_OCSP_STORE__

@param ppStore      Double pointer which indicates the OCSP store to free.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ocsp_store.c
 */
MOC_EXTERN MSTATUS OCSP_STORE_releaseStore(ocspStorePtr *ppStore);

/*----------------------------------------------------------------------------*/

/**
@private
@internal

@brief      Retrieves an OCSP response for the specified certificate. Note that
            the issuer must be provided as well in case there is no valid
            response to return.

@details    This function attempts to retrieve a cached OCSP response from the
            OCSP store. If the OCSP store does not contain an entry for the
            specified certificate then it will create one. If an entry exists
            but there is no cached response or the cached response is invalid
            then the OCSP store will make the OCSP request to the responder
            and provide the response. If another thread is already attempting
            to retrieve a response then NULL/0 will be returned for the response
            with no error. Note that if any extended parameters are provided
            such as the responder URL or OCSP extensions then an OCSP request is
            always retrieved from the responder and it will not be cached in the
            OCSP store.

@since 6.5
@version 6.5 and later

@flags
To enable this function, all of the following flags must be defined
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__
+ \c \__ENABLE_DIGICERT_OCSP_STORE__

@param pStore           OCSP store to retrieve a response from. If no entry
                        exists for the current certificate then one will be
                        added.
@param pCert            The certificate to retrieve a response for. Must be in
                        DER format.
@param certLen          The length of the certificate.
@param pIssuerCert      The certificate which issued the certificate that the
                        OCSP response is being retrieved for. Must be in DER
                        format.
@param issuerCertLen    The length of the issuer certificate.
@param pResponderUrl    Optional NULL terminated string to the OCSP URL. If one
                        is not provided then the certificate is checked for an
                        OCSP URL.
@param pExt             Optional OCSP extensions array.
@param extLen           Number of OCSP extensions.
@param ppResponse       OCSP response will be returned here. The caller is
                        responsible for freeing this data. Response may be NULL.
@param pResponseLen     OCSP response length will be returned here. Length may
                        be 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ocsp_store.c
 */
MOC_EXTERN MSTATUS OCSP_STORE_findResponseByCert(
    ocspStorePtr pStore, ubyte *pCert, ubyte4 certLen, ubyte *pIssuerCert,
    ubyte4 issuerCertLen, sbyte *pResponderUrl, extensions *pExt, ubyte4 extLen,
    ubyte **ppResponse, ubyte4 *pResponseLen);

/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __OCSP_STORE_HEADER__ */
