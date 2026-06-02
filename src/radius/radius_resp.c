/**
 * @file  radius_resp.c
 * @brief RADIUS response implementation
 *
 * @details    RADIUS response functions
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     Whether the following flags are defined determines which functions are enabled:
 *     +   \c \__ENABLE_RFC3576__
 *     +   \c \__ENABLE_RADIUS_SERVER__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
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


#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/hw_accel.h"
#include "../crypto/md5.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../radius/radius.h"
#include "../radius/radius_resp.h"


/*------------------------------------------------------------------*/

/*
 * RADIUS.C EXPORTS
 *
 * These are externed here. They should be considered 'protected', in
 * that the core radius files need them but users should not call them.
 */
extern intBoolean RADIUS_getResponseAuthenticated(RADIUS_RqstRecord *pRequest);
extern MSTATUS    RADIUS_countAttributes(ubyte* pBuffer, ubyte4 bufSize, ubyte4 *pCount);

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))

/*------------------------------------------------------------------*/

/*! Append an attribute to a response.
This function (for RFC&nbsp;3576 support) appends the specified attribute (which
can be any length) to the specified response.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRqst        Descriptor for a RADIUS authentication/accounting response.
\param type         Type of attribute to add (see "Attribute Types").
\param pData        Pointer to the buffer containing the attribute data to add.
\param dataLength   Number of bytes in $pData$ (the length of the attribute itself).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseAppendAttribute(RADIUS_RqstRecord *pRqst, ubyte type,
                                   ubyte *pData, ubyte dataLength)
{
    sbyte4              status;
    ubyte*              p;

    if ((NULL == pRqst) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if ((0 == type) || (0 == dataLength) ||
            (pRqst->rspLength < RADIUS_ATTRIBUTES_OFFSET))
    {
        status = RADIUS_ERROR;
        goto exit;
    }

    if (RADIUS_REQUEST_ALLOCATION < (pRqst->rspLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE + dataLength))
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    p = pRqst->rspData + pRqst->rspLength;

    *p++ = type;
    *p++ = (ubyte)(dataLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);

    DIGI_MEMCPY(p, pData, dataLength);

    p += dataLength;

    pRqst->rspLength = (ubyte2)(p - pRqst->rspData);

    status = OK;

 exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
RADIUS_responseAppendRawAttribute(RADIUS_RqstRecord *pRqst, ubyte *pAttr)
{
    ubyte               length;
    ubyte*              p;
    sbyte4              status = OK;

    if ((NULL == pRqst) || (NULL == pAttr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    length = *(pAttr + RADIUS_ATTRIBUTE_LENGTH_OFFSET);

    if (RADIUS_REQUEST_ALLOCATION < (pRqst->rspLength + length))
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    p = pRqst->rspData + pRqst->rspLength;
    DIGI_MEMCPY(p, pAttr, length);
    p += length;
    pRqst->rspLength = (ubyte2)(p - pRqst->rspData);

exit:
    return status;
}

#endif /* __ENABLE_RFC3576__ */

/*------------------------------------------------------------------*/

/*! Determine whether a response indicates successful %client authentication.
This function determines from a response whether the %client has successfully
authenticated against the RADIUS %server.

If $FALSE$ is returned and you're setting up the RADIUS %server and %client
for the first time, check parameters such as both sides using the same
shared secret.

However, if $FALSE$ is returned for a previously successful server-client pair,
you must not trust the response. You should call RADIUS_requestRelease to free
the request (which contains the response), and then take appropriate action to
indicate a potential security violation.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note A $FALSE$ return value can indicate either failed authentication or no response.

\param pRequest Descriptor for a RADIUS authentication/accounting response.

\return $TRUE$ (1) if successful %client authentication; otherwise $FALSE$ (0).

\example
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
\endexample
*/
extern intBoolean
RADIUS_responseIsAuthenticated(RADIUS_RqstRecord *pRequest)
{
    return RADIUS_getResponseAuthenticated(pRequest);
}


/*------------------------------------------------------------------*/

/*! Get a response's response code.
This function retrieves the specified response's response code.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param pCode    On return, pointer to result code (see "Request/Response Result Codes").

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
RADIUS_responseGetCode(pRadiusReq, &code);
printf("Response Code: %d\n", (int)code);
\endexample
*/
extern sbyte4
RADIUS_responseGetCode(RADIUS_RqstRecord *pRequest, ubyte *pCode)
{
    ubyte*  p;
    sbyte4  status = OK;

    if (NULL == pRequest)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p = RADIUS_getRequestResponseBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_RESPONSE;
        goto exit;
    }

    *pCode = *(p + RADIUS_CODE_OFFSET);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the number of attributes in a response.
This function retrieves the number of attributes in the specified response.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param pCount   On return, pointer to number of attributes in $pRequest$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseCountAttributes(RADIUS_RqstRecord *pRequest, ubyte4 *pCount)
{
    ubyte*  p;
    sbyte4  status = OK;

    if (NULL == pRequest)
        return ERR_NULL_POINTER;

    if (NULL == (p = RADIUS_getRequestResponseBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_RESPONSE;
        goto exit;
    }

    status = RADIUS_countAttributes(p, RADIUS_getRequestResponseBufferLength(pRequest), pCount);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the first attribute of the specified type from a response.
This function evaluates the specified response and returns the first attribute it
finds that matches the specified type.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param type     Type of attribute to get (see "Attribute Types").
\param ppValue  On return, pointer to address of attributes's value.
\param pLength  On return, pointer to number of bytes in $ppValue$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseGetAttributeByType(RADIUS_RqstRecord *pRequest, ubyte type,
                                  ubyte **ppValue, ubyte *pLength)
{
    ubyte*  p;
    ubyte2  length;
    sbyte4  status;

    *ppValue = NULL;
    *pLength = 0;

    if (NULL == pRequest)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p = RADIUS_getRequestResponseBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_RESPONSE;
        goto exit;
    }

    length = RADIUS_getRequestResponseBufferLength(pRequest);

    status = RADIUS_getAttributeByType(p, length, type, ppValue, pLength);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified response attribute.
This function retrieves the specified zero-based index attribute.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param index    Zero-based index of attribute to get.
\param pType    On return, pointer to desired attribute's type (see "Attribute Types").
\param ppValue  On return, pointer to address of attribute's value.
\param pLength  On return, pointer to number of bytes in attribute's value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\include resp_get_attrib_example.inc

*/
extern sbyte4
RADIUS_responseGetAttributeByIndex(RADIUS_RqstRecord *pRequest, sbyte4 index,
                                   ubyte *pType, ubyte **ppValue, ubyte *pLength)
{
    ubyte*  p;
    ubyte2  length;
    sbyte4     status;


    *pType = 0;
    *ppValue = NULL;
    *pLength = 0;

    if (NULL == pRequest)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p = RADIUS_getRequestResponseBuffer(pRequest)))
    {
        status = OK;
        goto exit;
    }

    length = RADIUS_getRequestResponseBufferLength(pRequest);

    status = RADIUS_getAttributeByIndex(p, length, index, pType, ppValue, pLength);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a C&nbsp;string attribute.
This function retrieves the specified attribute as a C&nbsp;string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note To prevent a memory leak, call RADIUS_responseFreeString when you're done using the
the returned $ppStr$.

\param pRequest     Descriptor for a RADIUS authentication/accounting response.
\param type         Type of attribute to get (see "Attribute Types").
\param ppStr        On return, pointer to address of desired attribute's
C&nbsp;string value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
                            printf("Attribute as string: %s\n", pStringValue);
\endexample

*/
extern sbyte4
RADIUS_responseGetAttributeAsCString(RADIUS_RqstRecord *pRequest, ubyte type, sbyte **ppStr)
{
    sbyte4  status;
    ubyte*  pValue;
    ubyte   length;

    *ppStr = NULL;

    if (OK > (status = RADIUS_responseGetAttributeByType(pRequest, type, &pValue, &length)))
       goto exit;

    if (RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE > length)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    if (NULL == (*ppStr = MALLOC(length + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)(*ppStr), pValue, (ubyte4)length);
    *(*ppStr + length) = 0;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a $ubyte4$ attribute.
This function retrieves the specified attribute as a
$ubyte4$ value. On successful return, the $pValue$ data is in host byte order.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\note The attribute's data size must equal 4. If it does not, the function
returns an $ERR_RADIUS_COERCION_ERROR$ status.

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest     Descriptor for a RADIUS authentication/accounting response.
\param type         Type of attribute to get (see "Attribute Types").
\param pValue       On return, pointer to attribute's $ubyte4$ value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (sizeof(ubyte4) == len)
{
    if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
        printf("Attribute as ubyte4 hex: %lx\n", ubyte4Value);
}
\endexample
*/
extern sbyte4
RADIUS_responseGetAttributeAsUByte4(RADIUS_RqstRecord *pRequest, ubyte type,
                                    ubyte4 *pValue)
{
    sbyte4             status;
    ubyte*          p;
    ubyte           length;
    ubyte4          tempL;

    if (OK > (status = RADIUS_responseGetAttributeByType(pRequest, type, &p, &length)))
        goto exit;

    if (sizeof(ubyte4) != length)
    {
        status = ERR_RADIUS_COERCION_ERROR;
        goto exit;
    }

    tempL = *p++;
    tempL = (tempL << 8) + *p++;
    tempL = (tempL << 8) + *p++;
    tempL = (tempL << 8) + *p++;

    *pValue = tempL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified request attribute as a C&nbsp;string.
This function retrieves the specified zero-based index attribute as a
C&nbsp;string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\note To prevent a memory leak, call RADIUS_responseFreeString when you're done using the
the returned $ppStr$.

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param index    Zero-based index of attribute to get.
\param ppStr    On return, pointer to address of desired attribute's C&nbsp;string value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\include resp_get_attrib_example.inc

*/
extern sbyte4
RADIUS_responseGetAttributeByIndexAsCString(RADIUS_RqstRecord *pRequest, sbyte4 index, sbyte **ppStr)
{
    sbyte4             status;
    ubyte*          pValue;
    ubyte           type;
    ubyte           length;

    *ppStr = NULL;

    if (OK > (status = RADIUS_responseGetAttributeByIndex(pRequest, index, &type, &pValue, &length)))
        goto exit;

    if (RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE > length)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    length -= RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE;

    if (NULL == (*ppStr = MALLOC(length + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)(*ppStr), pValue, (ubyte4)length);
    *(*ppStr + length) = 0;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified response attribute as a $ubyte4$.
This function retrieves the specified zero-based index attribute as $ubyte4$
value. On successful return, the $pValue$ data is in host byte order.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note The attribute's data size must equal 4. If it does not, the function
returns an $ERR_RADIUS_COERCION_ERROR$ status.

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param index    Zero-based index of attribute to get.
\param pValue   On return, pointer to attribute's $ubyte4$ value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\include resp_get_attrib_example.inc

*/
extern sbyte4
RADIUS_responseGetAttributeByIndexAsUByte4(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte4 *pValue)
{
    sbyte4          status;
    ubyte*          p;
    ubyte           length;
    ubyte4          tempL;
    ubyte           type;

    if (OK > (status = RADIUS_responseGetAttributeByIndex(pRequest, index, &type, &p, &length)))
        goto exit;

    if (sizeof(ubyte4) != (length - RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE))
    {
        status = ERR_RADIUS_COERCION_ERROR;
        goto exit;
    }

    tempL = *p++;
    tempL = (tempL << 8) + *p++;
    tempL = (tempL << 8) + *p++;
    tempL = (tempL << 8) + *p++;

    *pValue = tempL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified response attribute.
This function retrieves the specified zero-based index attribute.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param index    Zero-based index of attribute to get.
\param pVendor  Vendor %ID as assigned by IANA.  See: http://www.iana.org/assignments/enterprise-numbers
\param ppData   On return, pointer to address of desired attribute's value.
\param pLength  On return, pointer to number of bytes in $ppData$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\include resp_get_attrib_example.inc

*/
extern sbyte4
RADIUS_responseGetAttributeByIndexAsVendorSpecific(RADIUS_RqstRecord *pRequest, sbyte4 index,
                                                   ubyte4 *pVendor,
                                                   ubyte **ppData, ubyte* pLength)
{
    sbyte4  status;
    ubyte*  p;
    ubyte   length;
    ubyte4  tempL;
    ubyte   type;

    if (OK > (status = RADIUS_responseGetAttributeByIndex(pRequest, index, &type,
                                                          &p, &length)))
    {
        goto exit;
    }

    if ((RADIUS_ATTR_VENDOR_SPECIFIC != type) || (5 >= length))
    {
        status = ERR_RADIUS_COERCION_ERROR;
        goto exit;
    }

    tempL = *p++;     /* RFC says this should be zero */
    tempL = (tempL << 8) + *p++;
    tempL = (tempL << 8) + *p++;
    tempL = (tempL << 8) + *p++;

    *pVendor = tempL;
    *pLength = (ubyte)(length - RADIUS_ATTR_VENDOR_ID_FIELD_LENGTH);
    *ppData = p;

exit:
    return status;
}

#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))

/*------------------------------------------------------------------*/

/*! Append a 4-byte unsigned attribute to a response.
This function (for RFC&nbsp;3576 support) appends a 4-byte unsigned attribute to
the specified response. The input value is in host order&mdash;big endian or
little endian; the result is in network order&mdash;big endian.


\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param type     Type of attribute to add (see "Attribute Types").
\param val      Value to add to $pRequest$, in host order.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseAppendUByte4Attribute(RADIUS_RqstRecord *pRequest,
                                     ubyte type, ubyte4 val)
{
    ubyte   nval[4];

    nval[0] = (ubyte)(val >> 24);
    nval[1] = (ubyte)(val >> 16);
    nval[2] = (ubyte)(val >> 8);
    nval[3] = (ubyte)(val);

    return (sbyte4)RADIUS_responseAppendAttribute(pRequest, type, nval, COUNTOF(nval));
}


/*------------------------------------------------------------------*/

/*! Append a string to a response.
This function (for RFC&nbsp;3576 support) appends a value that is locally
represented as a string to the specified response.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note The string's terminating $NULL$ is not copied into the response packet.

\param pRequest     Descriptor for a RADIUS authentication/accounting response.
\param type         Type of attribute to add (see "Attribute Types").
\param pString      Pointer to the string to add to $pRequest$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseAppendStringAttribute(RADIUS_RqstRecord *pRequest,
                                     ubyte type, ubyte *pString)
{
    ubyte4 length = DIGI_STRLEN((sbyte *)pString);

    if (length > 255)
    {
        return ERR_BUFFER_OVERFLOW;
    }

    return (sbyte4)RADIUS_responseAppendAttribute(pRequest, type, pString, (ubyte)length);
}


/*------------------------------------------------------------------*/

/*! Append an existing vendor-specific attribute to a response.
This function (for RFC&nbsp;3576 support) appends a previously created
vendor-specific attribute buffer (see RADIUS_newVendorSpecificAttributeBuffer)
to the specified response.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $$__ENABLE_RFC3576__$$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param pRequest Descriptor for a RADIUS authentication/accounting response.
\param pAttr    Pointer to attribute data to add to $pRequest$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseAppendVendorSpecificAttributeBuffer(RADIUS_RqstRecord *pRequest,
                                                   ubyte *pAttr)
{
    return RADIUS_responseAppendRawAttribute(pRequest, pAttr);
}

#endif /* __ENABLE_RFC3576__ */


/*------------------------------------------------------------------*/

/*! Free memory used by a string.
This function frees the memory used by the specified string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\param ppStr    Address of pointer to string to release.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
printf("%s\nType in your response: ", prompt);
fgets(pResponse, RADIUS_EXAMPLE_RESPONSE_MAX, stdin);

if (prompt != defaultPrompt)
    RADIUS_responseFreeString(&prompt);
\endexample
*/
extern sbyte4
RADIUS_responseFreeString(sbyte **ppStr)
{
    MSTATUS status = OK;

    if (NULL == ppStr)
        status = ERR_NULL_POINTER;
    else if (NULL != *ppStr)
    {
        FREE(*ppStr);
        *ppStr = NULL;
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Decrypt a password (per RFC&nbsp;2868).
This function decrypts a tunnel password per RFC&nbsp;2868, }RADIUS Attributes
for Tunnel Protocol Support}. The first byte of the result buffer ($ppPwd$) is
the length of the actual password buffer. Padded 0s are included in the result.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note To prevent a memory leak, call RADIUS_responseFreeString when you're done
using the the returned $ppPwd$.

\param pRequest Pointer to original request sent to the RADIUS server.
\param pBuf     Pointer to password to decrypt (the TUNNEL PASSWORD attribute
value returned in the RADIUS response).
\param bufLen   Number of bytes in password to decrypt ($pBuf$).
\param ppPwd    On return, pointer to address of decrypted password.
\param pwdLen   On return, pointer to number of bytes in decrypted password ($ppPwd$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseDecryptPassword(RADIUS_RqstRecord *pRequest, ubyte * pBuf,ubyte2 bufLen,ubyte **ppPwd,ubyte2 *pwdLen)
{
    /* Decrypt as per RFC 2868  Pass it the full pValue of <TAG><SALT><PWD>*/
    /* This will return the full decrypted buffer including the first byte
     *  which has the datalength of the password actual buffer. The padded
     *  0s will also be returned
     */
    RADIUS_ServerRecord*    pServer;
    sbyte4                  status = OK;
    ubyte                   *encrPwd = pBuf + 3;
    ubyte2                  encrPwdLen = bufLen - 3;
    ubyte                   *pPwd;
    ubyte                   result[MD5_DIGESTSIZE];
    ubyte2                  i, j;
    MD5_CTX                 *pCtx = NULL;
    ubyte                   *S;
    ubyte2                  lS;
    ubyte                   *R;
    ubyte                   *A = pBuf+1; /* 2 Bytes */
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))
    hwAccelDescr            hwAccelCookie;
#endif

    /* This should be a multiple of 16 */
    if ((bufLen < 3) || (encrPwdLen % 16))
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    /* The Password is of 0 Length */
    if (!encrPwdLen)
    {
       pwdLen = 0;
       goto exit;
    }

    if (OK > (status = RADIUS_getServerRecordFromID(pRequest->serverID, &pServer)))
        goto exit;

    S  = pServer->sharedSecret;
    lS = pServer->sharedSecretLength;
    R  = pRequest->rqstData + RADIUS_AUTHENTICATOR_OFFSET;

    /* generate the Key */
    /*MD5(S + R + A) */
    status = MD5Alloc_m(MOC_HASH(hwAccelCookie)(BulkCtx *) &pCtx);
    if (OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(hwAccelCookie) pCtx);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, S, lS);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, R, RADIUS_AUTHENTICATOR_SIZE);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, A, 2);
    if (OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCookie) pCtx, result);
    if (OK != status)
        goto exit;

    /* Decrypt the First Byte to get Data Length */
    *pwdLen  = encrPwd[0]  ^ result[0];

    if (*pwdLen > encrPwdLen)
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    pPwd = MALLOC(encrPwdLen);

    if (!pPwd)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *ppPwd = pPwd;

    /* Each 16 Byte chunk decrypt */
    for (i = 0 ; i < encrPwdLen; i+=RADIUS_AUTHENTICATOR_SIZE)
    {
        for (j = 0 ; j < RADIUS_AUTHENTICATOR_SIZE;j++)
        {
            pPwd[i + j] = encrPwd [i + j] ^ result[j];
            if ((i + j) >= encrPwdLen )
            {
               break;
            }

        }

        /* Update the Digest for the Next Round */
        /* b(i) = MD5(S + c(i-1)) */
        status = MD5Init_m(MOC_HASH(hwAccelCookie) pCtx);
        if (OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, S, lS);
        if (OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, &encrPwd[i], RADIUS_AUTHENTICATOR_SIZE);
        if (OK != status)
            goto exit;

        status = MD5Final_m(MOC_HASH(hwAccelCookie) pCtx, result);
        if (OK != status)
            goto exit;
    }

exit:
    MD5Free_m(MOC_HASH(hwAccelCookie)(BulkCtx *) &pCtx);
    return status;

} /* RADIUS_responseDecryptPassword */


/*------------------------------------------------------------------*/

/*! Decrypt an MPPE (Microsoft Point-to-Point Encryption) send or receive key.
This function decrypts an MPPE (Microsoft Point-to-Point Encryption) send or
receive key.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note To prevent a memory leak, call RADIUS_responseFreeString when you're done
using the the returned $ppKey$.

\param pRqst    Pointer to original request sent to the RADIUS server.
\param pBuf     Pointer to key to decrypt (the Send/Recv Key attribute
value returned in the RADIUS response).
\param bufLen   Number of bytes in key to decrypt ($pBuf$).
\param ppKey    On return, pointer to address of decrypted key.
\param pKeyLen  On return, pointer to number of bytes in decrypted key ($ppKey$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseDecryptMPPEKey(RADIUS_RqstRecord *pRqst, ubyte *pBuf,
                                  ubyte2 bufLen, ubyte **ppKey,
                                  ubyte2 *pKeyLen)
{

    RADIUS_ServerRecord     *pSrvr;
    ubyte                   *pKey;
    ubyte                   *encrKey;
    ubyte2                  encrKeyLen;
    ubyte                   result[MD5_DIGESTSIZE];
    MSTATUS                 status = ERR_RADIUS;
    ubyte2                  i,j;
    MD5_CTX                 *pCtx = NULL;
    ubyte                   *S;
    ubyte2                  lS;
    ubyte                   *R;
    ubyte                   *A = pBuf;
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))
    hwAccelDescr            hwAccelCookie;
#endif

    if(18 > bufLen )
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }
    encrKey = pBuf + 2;
    encrKeyLen = bufLen - 2;

    if (encrKeyLen % 16)
    {
        goto exit;
    }

    if(OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID,&pSrvr)))
    {
        goto exit;
    }

    S = pSrvr->sharedSecret;
    lS = pSrvr->sharedSecretLength;
    R = pRqst->rqstData + RADIUS_AUTHENTICATOR_OFFSET;

    status = MD5Alloc_m(MOC_HASH(hwAccelCookie)(BulkCtx *) &pCtx);
    if (OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(hwAccelCookie) pCtx);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx,S,lS);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, R, RADIUS_AUTHENTICATOR_SIZE);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, A, 2);
    if (OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCookie) pCtx, result);
    if (OK != status)
        goto exit;


    *pKeyLen = encrKey[0] ^ result[0];

    if(*pKeyLen > encrKeyLen )
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    pKey = MALLOC(encrKeyLen + 1);

    if(!pKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *ppKey = pKey;

    for(i = 0; i < encrKeyLen; i += RADIUS_AUTHENTICATOR_SIZE)
    {
        for(j = 0; j < RADIUS_AUTHENTICATOR_SIZE; j++)
        {
            pKey[i + j] = encrKey [i+j] ^ result[j];
            if((i+j) >= encrKeyLen)
            {
                break;
            }
        }
        status = MD5Init_m(MOC_HASH(hwAccelCookie) pCtx);
        if (OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx,S, lS);
        if (OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx,&encrKey[i], RADIUS_AUTHENTICATOR_SIZE);
        if (OK != status)
            goto exit;

        status = MD5Final_m(MOC_HASH(hwAccelCookie) pCtx,result);
        if (OK != status)
            goto exit;

    }
exit:

    MD5Free_m(MOC_HASH(hwAccelCookie)(BulkCtx *) &pCtx);
    return status;
}

/*------------------------------------------------------------------*/

/*! Encrypt an MPPE (Microsoft Point-to-Point Encryption) send or receive key.
This function Encrypts an MPPE (Microsoft Point-to-Point Encryption) send or
receive key.

\since 5.0
\version 5.0 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_resp.h

\note To prevent a memory leak, call RADIUS_responseFreeString when you're done
using the the returned $ppKey$.

\param pRqst    Pointer to original request sent to the RADIUS server.
\param salt     Pointer to 2 byte salt to be used with this encryption
\param pBuf     Pointer to key to Encrypt (the Send/Recv Key value ).
\param bufLen   Number of bytes in key to Encrypt ($pBuf$).
\param ppKey    On return, pointer to address of Encrypted key.
\param pKeyLen  On return, pointer to number of bytes in Encrypted key ($ppKey$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_responseEncryptMPPEKey(RADIUS_RqstRecord *pRqst, ubyte *salt,
                                  ubyte *pBuf, ubyte2 bufLen, ubyte **ppKey,
                                  ubyte2 *pKeyLen)
{

    RADIUS_ServerRecord     *pSrvr;
    ubyte                   *pKey;
    ubyte                   *encrKey;
    ubyte2                  encrKeyLen;
    ubyte                   result[MD5_DIGESTSIZE];
    MSTATUS                 status = ERR_RADIUS;
    ubyte2                  i,j;
    MD5_CTX                 *pCtx = NULL;
    ubyte                   *S;
    ubyte2                  lS;
    ubyte                   *R;
    ubyte                   *A = salt;
#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))
    hwAccelDescr            hwAccelCookie;
#endif

    encrKey = pBuf ;
    encrKeyLen = bufLen;

    *pKeyLen = (encrKeyLen + 1 );
    if ((encrKeyLen + 1)%16)
        *pKeyLen += 16 -  ((encrKeyLen + 1)%16 );

    pKey = MALLOC(*pKeyLen + 2 ); /* 2 For the Salt */

    if(!pKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *ppKey = pKey;
    DIGI_MEMSET(pKey, 0, *pKeyLen + 2);
    DIGI_MEMCPY(pKey, salt, 2);
    pKey +=2;
    *pKey = encrKeyLen;
    DIGI_MEMCPY(pKey + 1, encrKey, encrKeyLen);

    if(OK > (status = RADIUS_getServerRecordFromID(pRqst->serverID,&pSrvr)))
    {
        goto exit;
    }

    S = pSrvr->sharedSecret;
    lS = pSrvr->sharedSecretLength;
    R = pRqst->rqstData + RADIUS_AUTHENTICATOR_OFFSET;

    status = MD5Alloc_m(MOC_HASH(hwAccelCookie)(BulkCtx *) &pCtx);
    if(OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(hwAccelCookie) pCtx);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, S, lS);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, R, RADIUS_AUTHENTICATOR_SIZE);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, A, 2);
    if(OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCookie) pCtx, result);
    if(OK != status)
        goto exit;


    for(i = 0; i < *pKeyLen; i += RADIUS_AUTHENTICATOR_SIZE)
    {
        for(j = 0; j < RADIUS_AUTHENTICATOR_SIZE; j++)
        {
            pKey[ i + j] = pKey [i+j] ^ result[j];
            if((i+j) >= *pKeyLen)
            {
                break;
            }
        }
        status = MD5Init_m(MOC_HASH(hwAccelCookie) pCtx);
        if(OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx,S, lS);
        if(OK != status)
            goto exit;

        status = MD5Update_m(MOC_HASH(hwAccelCookie) pCtx, &pKey[i], RADIUS_AUTHENTICATOR_SIZE);
        if(OK != status)
            goto exit;

        status = MD5Final_m(MOC_HASH(hwAccelCookie) pCtx,result);
        if(OK != status)
            goto exit;
    }
    *pKeyLen +=2; /* For Salt*/
exit:
    MD5Free_m(MOC_HASH(hwAccelCookie)(BulkCtx *) &pCtx);
    return status;
}
/*------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_RADIUS_CLIENT__ */


