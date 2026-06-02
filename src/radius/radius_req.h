/**
 * @file  radius_req.h
 * @brief RADIUS request API
 *
 * @details    RADIUS request interface functions
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Whether the following flags are defined determines which definitions are enabled:
 *             + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *             + \c \__ENABLE_RFC3576__
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __RADIUS_REQUEST_HEADER__
#define __RADIUS_REQUEST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RADIUS_requestNew
 *
 * Generates a new request. You specify to what server you will be
 * sending the request, and what type of request it is. Once a valid
 * *ppRequest has been returned to you, you append attributes to the request
 * and then finally call RADIUS_requestSend to send it.
 */
/**
@brief      Generate a new request.
@details    This function generates a new request. After a valid request is
            returned (as the \p ppRequest pointer), you append the necessary
            attributes to the request by calling the appropriate
            RADIUS_requestAppend* functions, and then call RADIUS_requestSend to
            send the message to the server.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@note       To prevent a memory leak, call RADIUS_requestRelease after the
            request is sucessfully sent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@param ppRequest    On return, pointer to a new descriptor for a RADIUS
                    authentication/accounting request.
@param serverID     ID of the RADIUS server (returned by
                    RADIUS_requestAppendAttribute) to send the request to.
@param code         Request type code (see @ref radius_attribute_types).

@code
static MSTATUS
RADIUS_EXAMPLE_sendClearTextPassword(int authServerID, MOC_IP_ADDRESS addr, ubyte *pName, ubyte *pPassword)
{
    RADIUS_RqstRecord*  pRadiusReq = NULL;
    MSTATUS             status;

    if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;
    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, pName)))
        goto exit;
    if (OK > (status = RADIUS_requestAppendUserPassword(pRadiusReq, (ubyte *)pPassword, (ubyte)DIGI_STRLEN((sbyte *)pPassword))))
        goto exit;
    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_NAS_IP_ADDRESS, addr)))
        goto exit;

    // send the request
    status = RADIUS_requestSend(pRadiusReq);

exit:
    return status;

} // RADIUS_EXAMPLE_sendClearTextPassword
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestNew(RADIUS_RqstRecord **ppRequest, sbyte4 serverID, ubyte code);

/*
 * RADIUS_requestRelease
 *
 * Once you are finished with the request, including the response data (if any)
 * call this to free memory and make available additional requests.
 */
/**
@brief      Free memory used by a previous request/response.
@details    This function frees the memory used by a previous request/response,
            including all the data to which they point. You should call this for
            every request/response once it has been fully processed.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param ppRequest    Pointer to the request whose memory you want to release.

@code
    while (pending)
    {
        RTOS_sleepMS(1);

        // Give RADIUS time. Do not rely on "result" to determine if
        // data is available, because multiple packets might have been
        // read in previously, and result == RADIUS_FOUND only if
        // NEW data is read in.
        if (OK > (status = RADIUS_pollForResponse(NULL, &result)))
        {
            goto exit;
        }

        if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))
        {
            status = ERR_RADIUS;
            goto exit;
        }

        switch (result)
        {
            case RADIUS_RETRIES_EXCEEDED:
                printf("Retries Exceeded.\n");
                if (OK == RADIUS_requestGetUsername(pRadiusReq, &nm, &nmLen))
                {
                    printf("request username: ");
                    radius_printChars(nm, nmLen);
                    printf("\n");
                }
                RADIUS_requestRelease(&pRadiusReq);
                pending--;
                break;

            case RADIUS_NOT_FOUND:
                continue;
        }
    }
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN void RADIUS_requestRelease(RADIUS_RqstRecord **ppRequest);

#ifdef __ENABLE_RFC3576__

/*
 * RADIUS_requestGetCode
 *
 * Returns the request code for the request.
 */
/**
@brief      Get a request's request code.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            request's request code.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param pCode    On return, pointer to result code (see @ref radius_result_codes).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
        goto exit;

    if (0 == responseCode)
    {
        // no forced response so we will sent ACK always in this example
        ubyte requestCode;
        if ( OK > (status = RADIUS_requestGetCode( pServerRequest, &requestCode)))
            goto exit;
        if (RADIUS_CODE_DISCONNECT_REQUEST == requestCode)
        {
            responseCode = RADIUS_CODE_DISCONNECT_ACK;
        }
        else if (RADIUS_CODE_COA_REQUEST  == requestCode)
        {
            responseCode = RADIUS_CODE_COA_ACK;
        }
        else
        {
            status = ERR_RADIUS_BAD_REQUEST;
            goto exit;
        }
    }

    // send a response with the response code
    if (OK > (status = RADIUS_responsePrepare( pServerRequest, responseCode)))
        goto exit;

    if (OK > (status = RADIUS_responseSend( pServerRequest)))
        goto exit;
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetCode(RADIUS_RqstRecord *pRequest, ubyte *pCode);

/*
 * RADIUS_requestCountAttributes
 *
 * Returns the number of attributes in the request.
 */
/**
@brief      Get the number of attributes in a request.
@details    This function (for RFC&nbsp;3576 support) returns the number of
            attributes in the specified request.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param pCount   On return, pointer to number of attributes in \p pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestCountAttributes(RADIUS_RqstRecord *pRequest, ubyte4 *pCount);

#endif /* __ENABLE_RFC3576__ */


/*
 * RADIUS_requestGetAttributeByType
 *
 */
/**
@brief      Get the first attribute of the specified type from a request.
@details    This function evaluates the specified request and returns the first
            attribute it finds that matches the specified type.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param type     Type of attribute to get (see @ref radius_attribute_types).
@param ppValue  On return, pointer to address of attributes's value.
@param pLength  On return, pointer to number of bytes in \p ppValue.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeByType(RADIUS_RqstRecord *pRequest, ubyte type, ubyte **ppValue, ubyte *pLength);

#ifdef __ENABLE_RFC3576__

/*
 * RADIUS_requestGetAttributeByIndex
 *
 * Index is zero-based.
 */
/**
@brief      Get the specified request attribute.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            zero-based index attribute.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param index    Zero-based index of attribute to get.
@param pType    On return, pointer to desired attribute's type (see "Attribute
                Types").
@param ppValue  On return, pointer to address of attribute's value.
@param pLength  On return, pointer to number of bytes in attribute's value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeByIndex(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte *pType, ubyte **ppValue, ubyte *pLength);

/*
 * RADIUS_requestGetAttributeAsCString
 *
 * You must RADIUS_requestFreeString ppStr once you are finished with it.
 */
/**
@brief      Get a C&nbsp;string attribute.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            attribute as a C&nbsp;string.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@note       To prevent a memory leak, call RADIUS_requestFreeString when you're
            done using the the returned \p ppStr.

@param pRequest     Descriptor for a RADIUS authentication/accounting request.
@param type         Type of attribute to get (see @ref radius_attribute_types).
@param ppStr        On return, pointer to address of desired attribute's
                    C&nbsp;string value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeAsCString(RADIUS_RqstRecord *pRequest, ubyte type, sbyte **ppStr);

/*
 * RADIUS_requestGetAttributeAsUByte4
 *
 * the size of the attribute's data must equal 4. If it does not, it will return
 * ERR_RADIUS_COERCION_ERROR. On successful return pValue is in host byte order.
 *
 */
/**
@brief      Get a \c ubyte4 attribute.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            attribute as a \c ubyte4 value. On successful return, the \p pValue
            data is in host byte order.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@note       The attribute's data size must equal 4. If it does not, the function
            returns an \c ERR_RADIUS_COERCION_ERROR status.

@param pRequest     Descriptor for a RADIUS authentication/accounting request.
@param type         Type of attribute to get (see @ref radius_attribute_types).
@param pValue       On return, pointer to attribute's \c ubyte4 value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeAsUByte4(RADIUS_RqstRecord *pRequest, ubyte type, ubyte4 *pValue);

/*
 * RADIUS_requestGetAttributeByIndexAsCString
 *
 * You must RADIUS_requestFreeString ppStr once you are finished with it.
 */
/**
@brief      Get the specified request attribute as a C&nbsp;string.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            zero-based index attribute as a C&nbsp;string.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@note       To prevent a memory leak, call RADIUS_requestFreeString when you're
            done using the returned \p ppStr.

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param index    Zero-based index of attribute to get.
@param ppStr    On return, pointer to address of desired attribute's
                C&nbsp;string value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeByIndexAsCString(RADIUS_RqstRecord *pRequest, sbyte4 index, sbyte **ppStr);

/*
 * RADIUS_requestGetAttributeByIndexAsUByte4
 *
 */
/**
@brief      Get the specified request attribute as a \c ubyte4.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            zero-based index attribute as \c ubyte4 value. On successful return,
            the \p pValue data is in host byte order.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@note       The attribute's data size must equal 4. If it does not, the function
            returns an \c ERR_RADIUS_COERCION_ERROR status.

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param index    Zero-based index of attribute to get.
@param pValue   On return, pointer to attribute's \c ubyte4 value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeByIndexAsUByte4(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte4 *pValue);

/*
 * RADIUS_requestGetAttributeByIndexAsVendorSpecific
 *
 */
/**
@brief      Get the specified request attribute.
@details    This function (for RFC&nbsp;3576 support) returns the specified
            zero-based index attribute.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param index    Zero-based index of attribute to get.
@param pVendor  Vendor ID as assigned by IANA; refer to the following Web page:
                "http://www.iana.org/assignments/enterprise-numbers2".
@param ppData   On return, pointer to address of desired attribute's value.
@param pLength  On return, pointer to number of bytes in \p ppData.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
 */
MOC_EXTERN sbyte4 RADIUS_requestGetAttributeByIndexAsVendorSpecific(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte4 *pVendor, ubyte **ppData, ubyte* pLength);

#endif /* __ENABLE_RFC3576__ */

/*
 * RADIUS_requestGetUsername
 *
 * The most likely attribute to want to retrieve from a request is the username.
 */
/**
@brief      Get a request's \c User-Name attribute.
@details    This function retrieves the \c User-Name attribute (the most %common
            attribute you'll need to retrieve) from a request.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param pRequest         Descriptor for a RADIUS authentication/accounting
                        request.
@param ppUsername       On successful return (\c RADIUS_FOUND), address of a
                        pointer to the \c User-Name attribute value. On failed
                        return, \c NULL.
@param pUsernameLength  On successful return (\c RADIUS_FOUND), pointer to
                        number of bytes in \p ppUsername. On failed return, \c 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    while (pending)
    {
        RTOS_sleepMS(1);

        // Give RADIUS time. Do not rely on "result" to determine if data is available
        // because multiple packets might have been previously read in, and
        // result == RADIUS_FOUND only if NEW data is read in.
        if (OK > (status = RADIUS_pollForResponse(NULL, &result)))
        {
            goto exit;
        }
        if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))
        {
            status = ERR_RADIUS;
            goto exit;
        }

        switch (result)
        {
            case RADIUS_RETRIES_EXCEEDED:
                printf("Retries Exceeded.\n");
                if (OK == RADIUS_requestGetUsername(pRadiusReq, &nm, &nmLen))
                {
                    printf("request username: ");
                    radius_printChars(nm, nmLen);
                    printf("\n");
                }
                RADIUS_requestRelease(&pRadiusReq);
                pending--;
                break;

            case RADIUS_NOT_FOUND:
                continue;
        }
    }
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestGetUsername(RADIUS_RqstRecord *pRequest, ubyte **ppUsername, ubyte *pUsernameLength);

/*
 * RADIUS_requestAppendAttribute
 *
 * Appends an attribute whose length is dataLength and whose data is pointed to by
 * pData.
 */
/**
@brief      Append an attribute to a request.
@details    This function appends the specified attribute (which can be any
            length) to the specified request.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param pRequest     Descriptor for a RADIUS authentication/accounting request.
@param type         Type of attribute to add (see @ref radius_attribute_types).
@param pData        Pointer to the buffer containing the attribute data to add.
@param dataLength   Attribute data length (number of bytes in \p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestAppendAttribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte *pData, ubyte dataLength);

/*
 * RADIUS_requestAppendUByte4Attribute
 *
 * Appends a 4 byte unsigned attribute. This routine puts value into network order.
 *
 */
/**
@brief      Append a 4-byte unsigned attribute to a request.
@details    This function appends a 4-byte unsigned attribute to the specified
            request. The input value is in host order&mdash;big endian or little
            endian; the result is in network order&mdash;big endian.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param type     Type of attribute to add (see @ref radius_attribute_types).
@param value    Value to add to \p pRequest, in host order.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    ubyte2  port;
    void*   pUDPCookie;

    if (OK > (status = RADIUS_requestNew(&pCookie, acctServerID, RADIUS_CODE_ACCOUNTING_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pCookie, RADIUS_ATTR_USER_NAME, papUserName)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pCookie, RADIUS_ATTR_NAS_IP_ADDRESS, addr)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pCookie, RADIUS_ATTR_ACCT_STATUS_TYPE,
                                                           RADIUS_ACCT_STATUS_TYPE_START)))
        goto exit;

    if (0 > (status = RADIUS_requestAppendUByte4Attribute(pCookie, RADIUS_ATTR_NAS_PORT, EXAMPLE_NAS_PORT)))
        goto exit;

    if (OK > (status = RADIUS_requestSend(pCookie)))
        goto exit;
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestAppendUByte4Attribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte4 value);

/*
 * RADIUS_requestAppendUserPassword
 *
 * Appends a User-Password attribute. This is encrypted and padded using the
 * algorithm described in the radius rfc, section 5.2.
 *
 */
/**
@brief      Append a user password attribute to a request.
@details    This function appends a user password attribute to the specified
            request. The password is encrypted and padded as mandated by the
            RADIUS RFC&nbsp;2685, section&nbsp;5.2.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@note       The RADIUS RFC states that a request cannot contain both a user and
            a CHAP password.

@sa         For more information about CHAP passwords and challenges, refer to
            RFC&nbsp;1994 (CHAP) and the principal RADIUS RFC&nbsp;2865
            (sections 2.2 and 5.3).

@param pRequest         Descriptor for a RADIUS authentication/accounting
                        request.
@param password         Pointer to the buffer containing the password.
@param passwordLength   Number of bytes in the password.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
static MSTATUS
RADIUS_EXAMPLE_sendClearTextPassword(int authServerID, MOC_IP_ADDRESS addr, ubyte *pName, ubyte *pPassword)
{
    RADIUS_RqstRecord*  pRadiusReq = NULL;
    ubyte*              pVSAttr = NULL;
    MSTATUS             status;

    if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, pName)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendUserPassword(pRadiusReq, (ubyte *)pPassword, (ubyte)DIGI_STRLEN((sbyte *)pPassword))))
        goto exit;

    ...

    // send the request
    status = RADIUS_requestSend(pRadiusReq);

exit:
    return status;

} // RADIUS_EXAMPLE_sendClearTextPassword
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestAppendUserPassword(RADIUS_RqstRecord *pRequest, ubyte* password, ubyte passwordLength);

/*
 * RADIUS_requestAppendStringAttribute
 *
 * Appends a value that is locally represented as a string. It DOES NOT copy the
 * null termination into the packet.
 *
 */
/**
@brief      Append a string to a request.
@details    This function appends a value that is locally represented as a
            string to the specified request.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@note       The string's terminating \c NULL is not copied into the request
            packet.

@param pRequest     Descriptor for a RADIUS authentication/accounting request.
@param type         Type of attribute to add (see @ref radius_attribute_types).
@param pString      Pointer to the string to add to \p pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, pName)))
        goto exit;
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestAppendStringAttribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte *pString);

/*
 * RADIUS_requestAppendCHAPPasswordAttributes
 *
 * Appends the Chap-Password and Chap-Challenge, given the passed parameters.
 * The RFC states that you may not have both a User-Password and Chap-Password
 * in the same request.
 */
/**
@brief      Append the CHAP-Password and CHAP-Challenge to a request.
@details    This function appends the CHAP -Password and CHAP-Challenge to the
            specified request.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@note       The RADIUS RFC states that a request cannot contain both a user and
            a CHAP password.

@sa         For more information about CHAP passwords and challenges, refer to
            RFC&nbsp;1994 (CHAP) and the principal RADIUS RFC&nbsp;2865
            (sections 2.2 and 5.3).

@param pRequest             Descriptor for a RADIUS authentication/accounting
                            request.
@param chapID               CHAP ID (a single byte).
@param pChapPassword        Pointer to the buffer containing the CHAP password.
@param chapPasswordLength   Number of bytes in the CHAP password.
@param pChapChallenge       Pointer to the CHAP challenge data to append to \p
                            pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, chapUserName)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendCHAPPasswordAttributes(pRadiusReq, chapID,
                        chapPassword, DIGI_STRLEN((sbyte *)chapPassword), chapChallenge)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_NAS_IP_ADDRESS, addr)))
        goto exit;

    if (OK > (status = RADIUS_requestSend(pRadiusReq)))
        goto exit;

    pending++;
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestAppendCHAPPasswordAttributes(RADIUS_RqstRecord *pRequest, ubyte chapID, ubyte *pChapPassword, ubyte4 chapPasswordLength, ubyte *pChapChallenge);

/*
 * RADIUS_requestAppendVendorSpecificAttributeBuffer
 *
 * After creating and appending a "VendorSpecificAttributeBuffer", use this
 * routine to insert the data into the request.
 */
/**
@brief      Append an existing vendor-specific attribute to a request.
@details    This function appends a previously created vendor-specific attribute
            buffer (see RADIUS_newVendorSpecificAttributeBuffer) to the
            specified request.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.
@param pAttr    Pointer to attribute data to add to \p pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    // create/bind a custom attribute to the request
    if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
        goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
        goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                            2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
        goto exit;

    if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
        goto exit;

    // send the request
    status = RADIUS_requestSend(pRadiusReq);

exit:
    if (NULL != pVSAttr)
        RADIUS_releaseVendorSpecificAttributeBuffer(pVSAttr);
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestAppendVendorSpecificAttributeBuffer(RADIUS_RqstRecord *pRequest, ubyte *pAttr);

/*
 * RADIUS_requestSend
 *
 * when you are finished adding attributes to the request, call RADIUS_requestSend
 * to deliver the packet. The underlying engine deals with retries, so you don't
 * have to, although you can change the RADIUS_RETRY_INTERVAL_MS and RADIUS_RETRY_COUNT
 * #defines in radius.h if you'd like.
 */
/**
@brief      Send a request.
@details    This function sends (transmits) the specified request. The request
            contains the destination %server, as well as all attributes added by
            calls to the \c RADIUS_requestAppend* functions.

This function automatically manages retries, although you can change the retry
interval and count during initial RADIUS Client code integration.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param pRequest Descriptor for a RADIUS authentication/accounting request.

@sa         For more information about CHAP passwords and challenges, refer to
            RFC&nbsp;1994 (CHAP) and the principal RADIUS RFC&nbsp;2865
            (sections 2.2 and 5.3).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, chapUserName)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendCHAPPasswordAttributes(pRadiusReq, chapID, chapPassword, DIGI_STRLEN((sbyte *)chapPassword), chapChallenge)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_NAS_IP_ADDRESS, addr)))
        goto exit;

    if (OK > (status = RADIUS_requestSend(pRadiusReq)))
        goto exit;

    pending++;
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestSend(RADIUS_RqstRecord *pRequest);

/**
@brief      Free memory used by a string.
@details    This function frees the memory used by the specified string.

@ingroup    radius_req_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_req.h

@param ppStr    Address of pointer to string to release.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    printf("%s\nType in your username: ", username);
    fgets(pRequest, 32, stdin);

    if (username != defaultUser)
        RADIUS_requestFreeString(&username);
@endcode

@funcdoc    radius_req.h
*/
MOC_EXTERN sbyte4 RADIUS_requestFreeString(sbyte **ppStr);

#ifdef __cplusplus
}
#endif

#endif /* __RADIUS_REQUEST_HEADER__ */
