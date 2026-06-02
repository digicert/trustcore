/**
 * @file  radius_resp.h
 * @brief RADIUS response API
 *
 * @details    RADIUS response interface functions
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

#ifndef __RADIUS_RESPONSE_HEADER__
#define __RADIUS_RESPONSE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

struct RADIUS_RqstRecord;

/* PUBLIC RADIUS ROUTINES */

/*
 * RADIUS_responseIsAuthenticated
 *
 * You MUST NOT trust a reponse that fails authentication. This means you should
 * free the request, and probably do something to indicate a potential security
 * violation. OR, if you are setting up the RADIUS server and client for the
 * first time, you need to check to make sure the shared secret is the same on
 * both sides.
 */
/**
@brief      Determine whether a response indicates successful %client
            authentication.
@details    This function determines from a response whether the %client has
            successfully authenticated against the RADIUS %server.

If \c FALSE is returned and you're setting up the RADIUS %server and %client
for the first time, check parameters such as both sides using the same shared
secret.

However, if \c FALSE is returned for a previously successful server-client pair,
you must not trust the response. You should call RADIUS_requestRelease to free
the request (which contains the response), and then take appropriate action to
indicate a potential security violation.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@note       A \c FALSE return value can indicate either failed authentication or
            no response.

@param pRequest Descriptor for a RADIUS authentication/accounting response.

@return     \c TRUE (1) if successful %client authentication; otherwise \c FALSE
            (0).

@code
    case RADIUS_FOUND:
        if (FALSE != RADIUS_responseIsAuthenticated(pRqst))
        {
            if (OK == RADIUS_responseGetCode(pRqst, &code))
            {
                status = (code == RADIUS_CODE_ACCESS_ACCEPT) ? AUTH_PASS : AUTH_FAIL;
                radius_freeRqstPtr(pRqst);
                RADIUS_requestRelease(&pRqst);
                break;
            }
        }
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN intBoolean RADIUS_responseIsAuthenticated(RADIUS_RqstRecord *pRequest);

/*
 * RADIUS_responseGetCode
 *
 * Returns the response code for the response.
 */
/**
@brief      Get a response's response code.
@details    This function retrieves the specified response's response code.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param pCode    On return, pointer to result code (see @ref radius_result_codes).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    RADIUS_responseGetCode(pRadiusReq, &code);
    printf("Response Code: %d\n", (int)code);
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetCode(RADIUS_RqstRecord *pRequest, ubyte *pCode);

/*
 * RADIUS_responseCountAttributes
 *
 * Returns the number of attributes in the response.
 */
/**
@brief      Get the number of attributes in a response.
@details    This function retrieves the number of attributes in the specified
            response.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param pCount   On return, pointer to number of attributes in \p pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseCountAttributes(RADIUS_RqstRecord *pRequest, ubyte4 *pCount);

/*
 * RADIUS_responseGetAttributeByType
 *
 */
/**
@brief      Get the first attribute of the specified type from a response.
@details    This function evaluates the specified response and returns the first
            attribute it finds that matches the specified type.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param type     Type of attribute to get (see @ref radius_attribute_types).
@param ppValue  On return, pointer to address of attributes's value.
@param pLength  On return, pointer to number of bytes in \p ppValue.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeByType(RADIUS_RqstRecord *pRequest, ubyte type, ubyte **ppValue, ubyte *pLength);

/*
 * RADIUS_responseGetAttributeByIndex
 *
 * Index is zero-based.
 */
/**
@brief      Get the specified response attribute.
@details    This function retrieves the specified zero-based index attribute.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param index    Zero-based index of attribute to get.
@param pType    On return, pointer to desired attribute's type (see "Attribute
                Types").
@param ppValue  On return, pointer to address of attribute's value.
@param pLength  On return, pointer to number of bytes in attribute's value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
// This is a generic RADIUS_ResponseGetAttribute* example
while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
{
    // demonstrate RADIUS_responseGetAttributeAsXXXX
    if (sizeof(ubyte4) == len)
    {
        if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            printf("Attribute as ubyte4 hex: %x\n", ubyte4Value);
    }
    else if (RADIUS_ATTR_VENDOR_SPECIFIC == type)
    {
        if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
        {
            printf("Vendor-Specific attribute\n");
            printf("Vendor ID: %d\n", vendorID);

            if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
            {
                printf("Attribute has sub-attributes\n");
                done = FALSE;
                j = 0;

                while (!done)
                {
                    if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                    {
                        printf("    Sub-Attribute: #%d\n", j);
                        printf("             Type: %d\n", (int)subType);
                        printf("            Value: ");
                        radius_printChars(pSubData, subLength);
                        printf("\n");
                        j++;
                    }
                    else
                    {
                        done = TRUE;
                    }
                }
            }
            else
            {
                printf("Attribute has no sub-attributes\n");
            }
        }
    }
    else
    {
        if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
            printf("Attribute as string: %s\n", pStringValue);

        RADIUS_responseFreeString(&pStringValue); // REMEMBER TO DO THIS !!!
    }
    i++;
}
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeByIndex(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte *pType, ubyte **ppValue, ubyte *pLength);

/*
 * RADIUS_responseGetAttributeAsCString
 *
 * You must RADIUS_responseFreeString ppStr once you are finished with it.
 */
/**
@brief      Get a C&nbsp;string attribute.
@details    This function retrieves the specified attribute as a C&nbsp;string.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@note       To prevent a memory leak, call RADIUS_responseFreeString when you're
            done using the the returned \p ppStr.

@param pRequest     Descriptor for a RADIUS authentication/accounting response.
@param type         Type of attribute to get (see @ref radius_attribute_types).
@param ppStr        On return, pointer to address of desired attribute's
                    C&nbsp;string value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
        printf("Attribute as string: %s\n", pStringValue);
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeAsCString(RADIUS_RqstRecord *pRequest, ubyte type, sbyte **ppStr);

/*
 * RADIUS_responseGetAttributeAsUByte4
 *
 * the size of the attribute's data must equal 4. If it does not, it will return
 * ERR_RADIUS_COERCION_ERROR. On successful return pValue is in host byte order.
 *
 */
/**
@brief      Get a \c ubyte4 attribute.
@details    This function retrieves the specified attribute as a \c ubyte4
            value. On successful return, the \p pValue data is in host byte
            order.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@note       The attribute's data size must equal 4. If it does not, the function
            returns an \c ERR_RADIUS_COERCION_ERROR status.

@inc_file radius_resp.h

@param pRequest     Descriptor for a RADIUS authentication/accounting response.
@param type         Type of attribute to get (see @ref radius_attribute_types).
@param pValue       On return, pointer to attribute's \c ubyte4 value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    if (sizeof(ubyte4) == len)
    {
        if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            printf("Attribute as ubyte4 hex: %lx\n", ubyte4Value);
    }
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeAsUByte4(RADIUS_RqstRecord *pRequest, ubyte type, ubyte4 *pValue);

/*
 * RADIUS_responseGetAttributeByIndexAsCString
 *
 * You must RADIUS_responseFreeString ppStr once you are finished with it.
 */
/**
@brief      Get the specified request attribute as a C&nbsp;string.
@details    This function retrieves the specified zero-based index attribute as
            a C&nbsp;string.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@note       To prevent a memory leak, call RADIUS_responseFreeString when you're
            done using the the returned \p ppStr.

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param index    Zero-based index of attribute to get.
@param ppStr    On return, pointer to address of desired attribute's
                C&nbsp;string value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
// This is a generic RADIUS_ResponseGetAttribute* example
while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
{
    // demonstrate RADIUS_responseGetAttributeAsXXXX
    if (sizeof(ubyte4) == len)
    {
        if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            printf("Attribute as ubyte4 hex: %x\n", ubyte4Value);
    }
    else if (RADIUS_ATTR_VENDOR_SPECIFIC == type)
    {
        if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
        {
            printf("Vendor-Specific attribute\n");
            printf("Vendor ID: %d\n", vendorID);

            if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
            {
                printf("Attribute has sub-attributes\n");
                done = FALSE;
                j = 0;

                while (!done)
                {
                    if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                    {
                        printf("    Sub-Attribute: #%d\n", j);
                        printf("             Type: %d\n", (int)subType);
                        printf("            Value: ");
                        radius_printChars(pSubData, subLength);
                        printf("\n");
                        j++;
                    }
                    else
                    {
                        done = TRUE;
                    }
                }
            }
            else
            {
                printf("Attribute has no sub-attributes\n");
            }
        }
    }
    else
    {
        if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
            printf("Attribute as string: %s\n", pStringValue);

        RADIUS_responseFreeString(&pStringValue); // REMEMBER TO DO THIS !!!
    }
    i++;
}
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeByIndexAsCString(RADIUS_RqstRecord *pRequest, sbyte4 index, sbyte **ppStr);

/*
 * RADIUS_responseGetAttributeByIndexAsUByte4
 *
 */
/**
@brief      Get the specified response attribute as a \c ubyte4.
@details    This function retrieves the specified zero-based index attribute as
            \c ubyte4 value. On successful return, the \p pValue data is in host
            byte order.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@note       The attribute's data size must equal 4. If it does not, the function
            returns an \c ERR_RADIUS_COERCION_ERROR status.

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param index    Zero-based index of attribute to get.
@param pValue   On return, pointer to attribute's \c ubyte4 value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
// This is a generic RADIUS_ResponseGetAttribute* example
while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
{
    // demonstrate RADIUS_responseGetAttributeAsXXXX
    if (sizeof(ubyte4) == len)
    {
        if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            printf("Attribute as ubyte4 hex: %x\n", ubyte4Value);
    }
    else if (RADIUS_ATTR_VENDOR_SPECIFIC == type)
    {
        if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
        {
            printf("Vendor-Specific attribute\n");
            printf("Vendor ID: %d\n", vendorID);

            if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
            {
                printf("Attribute has sub-attributes\n");
                done = FALSE;
                j = 0;

                while (!done)
                {
                    if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                    {
                        printf("    Sub-Attribute: #%d\n", j);
                        printf("             Type: %d\n", (int)subType);
                        printf("            Value: ");
                        radius_printChars(pSubData, subLength);
                        printf("\n");
                        j++;
                    }
                    else
                    {
                        done = TRUE;
                    }
                }
            }
            else
            {
                printf("Attribute has no sub-attributes\n");
            }
        }
    }
    else
    {
        if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
            printf("Attribute as string: %s\n", pStringValue);

        RADIUS_responseFreeString(&pStringValue); // REMEMBER TO DO THIS !!!
    }
    i++;
}
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeByIndexAsUByte4(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte4 *pValue);

/*
 * RADIUS_responseGetAttributeByIndexAsVendorSpecific
 *
 */
/**
@brief      Get the specified response attribute.
@details    This function retrieves the specified zero-based index attribute.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param index    Zero-based index of attribute to get.
@param pVendor  Vendor %ID as assigned by IANA.  See:
                http://www.iana.org/assignments/enterprise-numbers
@param ppData   On return, pointer to address of desired attribute's value.
@param pLength  On return, pointer to number of bytes in \p ppData.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
// This is a generic RADIUS_ResponseGetAttribute* example
while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
{
    // demonstrate RADIUS_responseGetAttributeAsXXXX
    if (sizeof(ubyte4) == len)
    {
        if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            printf("Attribute as ubyte4 hex: %x\n", ubyte4Value);
    }
    else if (RADIUS_ATTR_VENDOR_SPECIFIC == type)
    {
        if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
        {
            printf("Vendor-Specific attribute\n");
            printf("Vendor ID: %d\n", vendorID);

            if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
            {
                printf("Attribute has sub-attributes\n");
                done = FALSE;
                j = 0;

                while (!done)
                {
                    if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                    {
                        printf("    Sub-Attribute: #%d\n", j);
                        printf("             Type: %d\n", (int)subType);
                        printf("            Value: ");
                        radius_printChars(pSubData, subLength);
                        printf("\n");
                        j++;
                    }
                    else
                    {
                        done = TRUE;
                    }
                }
            }
            else
            {
                printf("Attribute has no sub-attributes\n");
            }
        }
    }
    else
    {
        if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
            printf("Attribute as string: %s\n", pStringValue);

        RADIUS_responseFreeString(&pStringValue); // REMEMBER TO DO THIS !!!
    }
    i++;
}
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseGetAttributeByIndexAsVendorSpecific(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte4 *pVendor, ubyte **ppData, ubyte* pLength);

#ifdef __ENABLE_RFC3576__

/*
 * RADIUS_responseAppendAttribute
 *
 * Appends an attribute whose length is dataLength and whose data is pointed to by
 * pData.
 */
/**
@brief      Append an attribute to a response.
@details    This function (for RFC&nbsp;3576 support) appends the specified
            attribute (which can be any length) to the specified response.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_resp.h

@param pRequest     Descriptor for a RADIUS authentication/accounting response.
@param type         Type of attribute to add (see @ref radius_attribute_types).
@param pData        Pointer to the buffer containing the attribute data to add.
@param dataLength   Number of bytes in \p pData (the length of the attribute
                    itself).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseAppendAttribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte *pData, ubyte dataLength);

/*
 * RADIUS_responseAppendUByte4Attribute
 *
 * Appends a 4 byte unsigned attribute. This routine puts value into network order.
 *
 */
/**
@brief      Append a 4-byte unsigned attribute to a response.
@details    This function (for RFC&nbsp;3576 support) appends a 4-byte unsigned
            attribute to the specified response. The input value is in host
            order&mdash;big endian or little endian; the result is in network
            order&mdash;big endian.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param type     Type of attribute to add (see @ref radius_attribute_types).
@param value    Value to add to \p pRequest, in host order.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseAppendUByte4Attribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte4 value);

/*
 * RADIUS_responseAppendStringAttribute
 *
 * Appends a value that is locally represented as a string. It DOES NOT copy the
 * null termination into the packet.
 *
 */
/**
@brief      Append a string to a response.
@details    This function (for RFC&nbsp;3576 support) appends a value that is
            locally represented as a string to the specified response.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_resp.h

@note       The string's terminating \c NULL is not copied into the response
            packet.

@param pRequest     Descriptor for a RADIUS authentication/accounting response.
@param type         Type of attribute to add (see @ref radius_attribute_types).
@param pString      Pointer to the string to add to \p pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseAppendStringAttribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte *pString);

/*
 * RADIUS_responseAppendVendorSpecificAttributeBuffer
 *
 * After creating and appending a "VendorSpecificAttributeBuffer", use this
 * routine to insert the data into the request.
 */
/**
@brief      Append an existing vendor-specific attribute to a response.
@details    This function (for RFC&nbsp;3576 support) appends a previously
            created vendor-specific attribute buffer (see
            RADIUS_newVendorSpecificAttributeBuffer) to the specified response.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
+ \c \__ENABLE_RFC3576__

@inc_file radius_resp.h

@param pRequest Descriptor for a RADIUS authentication/accounting response.
@param pAttr    Pointer to attribute data to add to \p pRequest.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseAppendVendorSpecificAttributeBuffer(RADIUS_RqstRecord *pRequest, ubyte *pAttr);

#endif /* __ENABLE_RFC3576__ */

/* Decrypt Password as per RFC 2868 */
/**
@brief      Decrypt a password (per RFC&nbsp;2868).
@details    This function decrypts a tunnel password per RFC&nbsp;2868,
            {RADIUS Attributes for Tunnel Protocol Support}. The first byte of
            the result buffer (\p ppPwd) is the length of the actual password
            buffer. Padded 0s are included in the result.

@ingroup    radius_resp_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@note       To prevent a memory leak, call RADIUS_responseFreeString when you're
            done using the the returned \p ppPwd.

@param pRequest Pointer to original request sent to the RADIUS server.
@param pBuf     Pointer to password to decrypt (the TUNNEL PASSWORD attribute
                value returned in the RADIUS response).
@param bufLen   Number of bytes in password to decrypt (\p pBuf).
@param ppPwd    On return, pointer to address of decrypted password.
@param pwdLen   On return, pointer to number of bytes in decrypted password (\p
                ppPwd).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseDecryptPassword(RADIUS_RqstRecord *pRequest, ubyte * pBuf,ubyte2 bufLen,ubyte **ppPwd,ubyte2 *pwdLen);

/**
@brief      Free memory used by a string.
@details    This function frees the memory used by the specified string.

@ingroup    radius_resp_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@param ppStr    Address of pointer to string to release.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
    printf("%s\nType in your response: ", prompt);
    fgets(pResponse, RADIUS_EXAMPLE_RESPONSE_MAX, stdin);

    if (prompt != defaultPrompt)
        RADIUS_responseFreeString(&prompt);
@endcode

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseFreeString(sbyte **ppStr);

/**
@brief      Decrypt an MPPE (Microsoft Point-to-Point Encryption) send or
            receive key.
@details    This function decrypts an MPPE (Microsoft Point-to-Point Encryption)
            send or receive key.

@ingroup    radius_resp_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@note       To prevent a memory leak, call RADIUS_responseFreeString when you're
            done using the the returned \p ppKey.

@param pRqst    Pointer to original request sent to the RADIUS server.
@param pBuf     Pointer to key to decrypt (the Send/Recv Key attribute value
                returned in the RADIUS response).
@param bufLen   Number of bytes in key to decrypt (\p pBuf).
@param ppKey    On return, pointer to address of decrypted key.
@param pKeyLen  On return, pointer to number of bytes in decrypted key (\p
                ppKey).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseDecryptMPPEKey(RADIUS_RqstRecord *pRqst,ubyte *pBuf, ubyte2 bufLen, ubyte **ppKey, ubyte2 *pKeyLen);

/**
@brief      Encrypt an MPPE (Microsoft Point-to-Point Encryption) send or
            receive key.
@details    This function Encrypts an MPPE (Microsoft Point-to-Point Encryption)
            send or receive key.

@ingroup    radius_resp_functions

@since 5.0
@version 5.0 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_resp.h

@note       To prevent a memory leak, call RADIUS_responseFreeString when you're
            done using the the returned \p ppKey.

@param pRqst    Pointer to original request sent to the RADIUS server.
@param salt     Pointer to 2 byte salt to be used with this encryption
@param pBuf     Pointer to key to Encrypt (the Send/Recv Key value ).
@param bufLen   Number of bytes in key to Encrypt (\p pBuf).
@param ppKey    On return, pointer to address of Encrypted key.
@param pKeyLen  On return, pointer to number of bytes in Encrypted key (\p
                ppKey).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_resp.h
*/
MOC_EXTERN sbyte4 RADIUS_responseEncryptMPPEKey(RADIUS_RqstRecord *pRqst, ubyte *salt, ubyte *pBuf, ubyte2 bufLen, ubyte **ppKey, ubyte2 *pKeyLen);

#ifdef __cplusplus
}
#endif

#endif /* __RADIUS_RESPONSE_HEADER__ */
