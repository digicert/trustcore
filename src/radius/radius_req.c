/**
 * @file  radius_req.c
 * @brief RADIUS request implementation
 *
 * @details    RADIUS request functions
 * @since      1.41
 * @version    3.06 and later
 *
 * @flags      Compilation flags required:
 *     Whether the following flags are defined determines which functions are enabled:
 *     +   \c \__ENABLE_RFC3576__
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
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../crypto/hw_accel.h"
#include "../crypto/md5.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../radius/radius.h"
#include "../radius/radius_req.h"


/*------------------------------------------------------------------*/

/*
 * RADIUS.C EXPORTS
 *
 * These are externed here. They should be considered 'protected', in
 * that the core radius files need them but users should not call them.
 */

extern void    RADIUS_releaseRequest(RADIUS_RqstRecord *pRequest);
extern MSTATUS RADIUS_newRequestRecord(RADIUS_RqstRecord **ppRequest, sbyte4 serverID);
extern MSTATUS RADIUS_generateRequestHeader(RADIUS_RqstRecord *pRequest, ubyte code);
extern MSTATUS RADIUS_appendUserPassword(RADIUS_RqstRecord *pRequest, ubyte* password, ubyte passwordLength);
extern MSTATUS RADIUS_countAttributes(ubyte* pBuffer, ubyte4 bufSize, ubyte4 *pCount);

extern MSTATUS RADIUS_sendRequest(RADIUS_RqstRecord *pRequest);


/*------------------------------------------------------------------*/

/*! Generate a new request.
This function generates a new request. After a valid request is returned (as the
$ppRequest$ pointer), you append the necessary attributes to the request by
calling the appropriate $RADIUS_requestAppend*$ functions, and then call
RADIUS_requestSend to send the message to the server.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note To prevent a memory leak, call RADIUS_requestRelease after the request is
sucessfully sent.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\param ppRequest    On return, pointer to a new descriptor for a RADIUS authentication/accounting request.
\param serverID     ID of the RADIUS server (returned by RADIUS_requestAppendAttribute) to send the request to.
\param code         Request type code (see "Attribute Types").

\example
static MSTATUS RADIUS_EXAMPLE_sendClearTextPassword(int authServerID, MOC_IP_ADDRESS addr, ubyte *pName, ubyte *pPassword)
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
\endexample
*/
extern sbyte4
RADIUS_requestNew(RADIUS_RqstRecord **ppRequest, sbyte4 serverID, ubyte code)
{
    sbyte4              status;
    RADIUS_RqstRecord*  pRqst = NULL;

    *ppRequest = NULL;

    if (OK > (status = RADIUS_newRequestRecord(&pRqst, serverID)))
        goto exit;

    if (OK > (status = RADIUS_generateRequestHeader(pRqst, code)))
        goto exit;

    *ppRequest = pRqst;
    pRqst = NULL;

exit:
    if (NULL != pRqst)
        RADIUS_releaseRequest(pRqst);

    return status;
}


/*------------------------------------------------------------------*/

/*! Free memory used by a previous request/response.
This function frees the memory used by a previous request/response, including
all the data to which they point. You should call this for every
request/response once it has been fully processed.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

\param ppRequest    Pointer to the request whose memory you want to release.

\example
while (pending) {
    RTOS_sleepMS(1);

    // Give RADIUS time. Do not rely on "result" to determine if
    // data is available, because multiple packets might have been
    // read in previously, and result == RADIUS_FOUND only if
    // NEW data is read in.
    if (OK > (status = RADIUS_pollForResponse(NULL, &result)))     {
        goto exit;
    }

    if (OK > (result = RADIUS_getAResponse(&pRadiusReq)))     {
        status = ERR_RADIUS;
        goto exit;
    }

    switch (result)     {
        case RADIUS_RETRIES_EXCEEDED:
            printf("Retries Exceeded.\n");
            if (OK == RADIUS_requestGetUsername(pRadiusReq, &nm, &nmLen)) {
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
\endexample
*/
extern void
RADIUS_requestRelease(RADIUS_RqstRecord **ppRequest)
{
    if ((NULL != ppRequest) && (NULL != *ppRequest))
    {
        RADIUS_releaseRequest(*ppRequest);

        *ppRequest = NULL;
    }
}


/*------------------------------------------------------------------*/

/*! Append an attribute to a request.
This function appends the specified attribute (which can be any length) to the
specified request.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\param pRqst        Descriptor for a RADIUS authentication/accounting request.
\param type         Type of attribute to add (see "Attribute Types").
\param pData        Pointer to the buffer containing the attribute data to add.
\param dataLength   Attribute data length (number of bytes in $pData$).

*/
extern sbyte4
RADIUS_requestAppendAttribute(RADIUS_RqstRecord *pRqst, ubyte type,
                              ubyte *pData, ubyte dataLength)
{
    sbyte4              status;
    ubyte*              p;

    if ((NULL == pRqst) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == type) || (0 == dataLength) || (pRqst->rqstLength < RADIUS_ATTRIBUTES_OFFSET))
    {
        status = RADIUS_ERROR;
        goto exit;
    }

    if (RADIUS_REQUEST_ALLOCATION < (pRqst->rqstLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE + dataLength))
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    p = pRqst->rqstData + pRqst->rqstLength;

    *p++ = type;
    *p++ = (ubyte)(dataLength + RADIUS_ATTRIBUTE_TYPE_PLUS_LEN_SIZE);

    DIGI_MEMCPY(p, pData, dataLength);

    p += dataLength;

    pRqst->rqstLength = (ubyte2)(p - pRqst->rqstData);

    status = OK;

 exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
RADIUS_requestAppendRawAttribute(RADIUS_RqstRecord *pRqst, ubyte *pAttr)
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

    if (RADIUS_REQUEST_ALLOCATION < (pRqst->rqstLength + length))
    {
        status = ERR_RADIUS_LENGTH;
        goto exit;
    }

    p = pRqst->rqstData + pRqst->rqstLength;
    DIGI_MEMCPY(p, pAttr, length);
    p += length;
    pRqst->rqstLength = (ubyte2)(p - pRqst->rqstData);

exit:
    return status;
}


#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))

/*------------------------------------------------------------------*/

/*! Get a request's request code.
This function (for RFC&nbsp;3576 support) returns the specified request's
request code.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param pCode    On return, pointer to result code (see "Request/Response Result Codes").

\example
if (OK > (status = RADIUS_responseForcedCode( pServerRequest, &responseCode)))
    goto exit;

if (0 == responseCode) {
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
\endexample
*/
extern sbyte4
RADIUS_requestGetCode(RADIUS_RqstRecord *pRequest, ubyte *pCode)
{
    ubyte*  p;
    sbyte4  status = OK;

    if (NULL == pRequest)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p = RADIUS_getRequestRequestBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_REQUEST;
        goto exit;
    }

    *pCode = *(p + RADIUS_CODE_OFFSET);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the number of attributes in a request.
This function (for RFC&nbsp;3576 support) returns the number of attributes in the
specified request.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param pCount   On return, pointer to number of attributes in $pRequest$.

*/
extern sbyte4
RADIUS_requestCountAttributes(RADIUS_RqstRecord *pRequest, ubyte4 *pCount)
{
    ubyte*  p;
    sbyte4  status = OK;

    if (NULL == pRequest)
        return ERR_NULL_POINTER;

    if (NULL == (p = RADIUS_getRequestRequestBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_REQUEST;
        goto exit;
    }

    status = RADIUS_countAttributes(p, RADIUS_getRequestRequestBufferLength(pRequest), pCount);

exit:
    return status;
}

#endif /* __ENABLE_RFC3576__ */


/*------------------------------------------------------------------*/

/*! Get the first attribute of the specified type from a request.
This function evaluates the specified request and returns the first attribute it
finds that matches the specified type.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param type     Type of attribute to get (see "Attribute Types").
\param ppValue  On return, pointer to address of attributes's value.
\param pLength  On return, pointer to number of bytes in $ppValue$.

*/
extern sbyte4
RADIUS_requestGetAttributeByType(RADIUS_RqstRecord *pRequest, ubyte type,
                                 ubyte **ppValue, ubyte *pLength)
{
    ubyte*  p;
    sbyte4     status;

    *ppValue = NULL;
    *pLength = 0;

    if (NULL == pRequest)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p = RADIUS_getRequestRequestBuffer(pRequest)))
    {
        status = ERR_RADIUS_NO_REQUEST;
        goto exit;
    }

    status = RADIUS_getAttributeByType(p, RADIUS_getRequestRequestBufferLength(pRequest), type, ppValue, pLength);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a request's $User-Name$ attribute.
This function retrieves the $User-Name$ attribute (the most %common attribute
you'll need to retrieve) from a request.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\param pRequest         Descriptor for a RADIUS authentication/accounting request.
\param ppUsername       On successful return ($RADIUS_FOUND$), address of a pointer to the $User-Name$ attribute value. On failed return, $NULL$.
\param pUsernameLength  On successful return ($RADIUS_FOUND$), pointer to number of bytes in $ppUsername$. On failed return, $0$.

\example
while (pending) {
    RTOS_sleepMS(1);

    // Give RADIUS time. Do not rely on "result" to determine if data is available
    // because multiple packets might have been previously read in, and
    // result == RADIUS_FOUND only if NEW data is read in.
    if (OK > (status = RADIUS_pollForResponse(NULL, &result))) {
        goto exit;
    }
    if (OK > (result = RADIUS_getAResponse(&pRadiusReq))) {
        status = ERR_RADIUS;
        goto exit;
    }

    switch (result) {
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
\endexample
*/
extern sbyte4
RADIUS_requestGetUsername(RADIUS_RqstRecord *pRequest, ubyte **ppUsername,
                          ubyte *pUsernameLength)
{
    sbyte4   status;

    *ppUsername = NULL;
    *pUsernameLength = 0;

    if (NULL == pRequest)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = RADIUS_requestGetAttributeByType(pRequest, RADIUS_ATTR_USER_NAME, ppUsername, pUsernameLength);

exit:
    return status;
}


#if (defined( __ENABLE_RFC3576__) || defined(__ENABLE_RADIUS_SERVER__))

/*------------------------------------------------------------------*/

/*! Get the specified request attribute.
This function (for RFC&nbsp;3576 support) returns the specified zero-based index
attribute.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param index    Zero-based index of attribute to get.
\param pType    On return, pointer to desired attribute's type (see "Attribute Types").
\param ppValue  On return, pointer to address of attribute's value.
\param pLength  On return, pointer to number of bytes in attribute's value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_requestGetAttributeByIndex(RADIUS_RqstRecord *pRequest, sbyte4 index, ubyte *pType,
                                  ubyte **ppValue, ubyte *pLength)
{
    ubyte*  p;
    ubyte2  length;
    sbyte4  status;


    *pType = 0;
    *ppValue = NULL;
    *pLength = 0;

    if (NULL == pRequest)
{
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (p = RADIUS_getRequestRequestBuffer(pRequest)))
    {
        status = OK;
        goto exit;
    }

    length = RADIUS_getRequestRequestBufferLength(pRequest);

    status = RADIUS_getAttributeByIndex(p, length, index, pType, ppValue, pLength);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a C&nbsp;string attribute.
This function (for RFC&nbsp;3576 support) returns the specified attribute as a
C&nbsp;string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note To prevent a memory leak, call RADIUS_requestFreeString when you're done using the
the returned $ppStr$.

\param pRequest     Descriptor for a RADIUS authentication/accounting request.
\param type         Type of attribute to get (see "Attribute Types").
\param ppStr        On return, pointer to address of desired attribute's C&nbsp;string value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_requestGetAttributeAsCString(RADIUS_RqstRecord *pRequest, ubyte type,
                                    sbyte **ppStr)
{
    sbyte4  status;
    ubyte*  pValue;
    ubyte   length;

    *ppStr = NULL;

    if (OK > (status = RADIUS_requestGetAttributeByType(pRequest, type, &pValue, &length)))
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

/*! Get a $ubyte4$ attribute.
This function (for RFC&nbsp;3576 support) returns the specified attribute as a
$ubyte4$ value. On successful return, the $pValue$ data is in host byte order.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note The attribute's data size must equal 4. If it does not, the function
returns an $ERR_RADIUS_COERCION_ERROR$ status.

\param pRequest     Descriptor for a RADIUS authentication/accounting request.
\param type         Type of attribute to get (see "Attribute Types").
\param pValue       On return, pointer to attribute's $ubyte4$ value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_requestGetAttributeAsUByte4(RADIUS_RqstRecord *pRequest, ubyte type,
                                   ubyte4 *pValue)
{
    sbyte4          status;
    ubyte*          p;
    ubyte           length;
    ubyte4          tempL;

    if (OK > (status = RADIUS_requestGetAttributeByType(pRequest, type, &p, &length)))
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
This function (for RFC&nbsp;3576 support) returns the specified zero-based index
attribute as a C&nbsp;string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note To prevent a memory leak, call RADIUS_requestFreeString when you're done using the
the returned $ppStr$.

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param index    Zero-based index of attribute to get.
\param ppStr    On return, pointer to address of desired attribute's C&nbsp;string value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_requestGetAttributeByIndexAsCString(RADIUS_RqstRecord *pRequest, sbyte4 index,
                                           sbyte **ppStr)
{
    sbyte4          status;
    ubyte*          pValue;
    ubyte           type;
    ubyte           length;

    *ppStr = NULL;

    if (OK > (status = RADIUS_requestGetAttributeByIndex(pRequest, index, &type, &pValue, &length)))
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

/*! Get the specified request attribute as a $ubyte4$.
This function (for RFC&nbsp;3576 support) returns the specified zero-based index
attribute as $ubyte4$ value. On successful return, the $pValue$ data is in host
byte order.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note The attribute's data size must equal 4. If it does not, the function
returns an $ERR_RADIUS_COERCION_ERROR$ status.

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param index    Zero-based index of attribute to get.
\param pValue   On return, pointer to attribute's $ubyte4$ value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_requestGetAttributeByIndexAsUByte4(RADIUS_RqstRecord *pRequest, sbyte4 index,
                                          ubyte4 *pValue)
{
    sbyte4          status;
    ubyte*          p;
    ubyte           length;
    ubyte4          tempL;
    ubyte           type;

    if (OK > (status = RADIUS_requestGetAttributeByIndex(pRequest, index, &type, &p, &length)))
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

/*! Get the specified request attribute.
This function (for RFC&nbsp;3576 support) returns the specified zero-based index
attribute.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_RFC3576__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param index    Zero-based index of attribute to get.
\param pVendor  Vendor ID as assigned by IANA; refer to the following Web page: "http://www.iana.org/assignments/enterprise-numbers2".
\param ppData   On return, pointer to address of desired attribute's value.
\param pLength  On return, pointer to number of bytes in $ppData$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_requestGetAttributeByIndexAsVendorSpecific(RADIUS_RqstRecord *pRequest,
                                                  sbyte4 index, ubyte4 *pVendor,
                                                  ubyte **ppData, ubyte* pLength)
{
    sbyte4  status;
    ubyte*  p;
    ubyte   length;
    ubyte4  tempL;
    ubyte   type;

    if (OK > (status = RADIUS_requestGetAttributeByIndex(pRequest, index, &type,
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

#endif /* __ENABLE_RFC3576__ */


/*------------------------------------------------------------------*/

/*! Append a 4-byte unsigned attribute to a request.
This function appends a 4-byte unsigned attribute to the specified request. The
input value is in host order&mdash;big endian or little endian; the result is in
network order&mdash;big endian.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param type     Type of attribute to add (see "Attribute Types").
\param val      Value to add to $pRequest$, in host order.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
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

if (0 > (status = RADIUS_requestAppendUByte4Attribute(pCookie, RADIUS_ATTR_NAS_PORT, EXAMPLE_NAS_PORT)))
    goto exit;

if (OK > (status = RADIUS_requestSend(pCookie)))
    goto exit;
\endexample
*/
extern sbyte4
RADIUS_requestAppendUByte4Attribute(RADIUS_RqstRecord *pRequest, ubyte type,
                                        ubyte4 val)
{
    ubyte   nval[4];

    nval[0] = (ubyte)(val >> 24);
    nval[1] = (ubyte)(val >> 16);
    nval[2] = (ubyte)(val >> 8);
    nval[3] = (ubyte)(val);

    return (sbyte4)RADIUS_requestAppendAttribute(pRequest, type, nval, COUNTOF(nval));
}


/*------------------------------------------------------------------*/

/*! Append a user password attribute to a request.
This function appends a user password attribute to the specified request. The
password is encrypted and padded as mandated by the RADIUS RFC&nbsp;2685,
section&nbsp;5.2.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note The RADIUS RFC states that a request cannot contain both a user and a CHAP
password.

\sa For more information about CHAP passwords and challenges, refer to RFC&nbsp;1994 (CHAP)
and the principal RADIUS RFC&nbsp;2865 (sections 2.2 and 5.3).

\param pRequest         Descriptor for a RADIUS authentication/accounting request.
\param password         Pointer to the buffer containing the password.
\param passwordLength   Number of bytes in the password.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
static MSTATUS RADIUS_EXAMPLE_sendClearTextPassword(int authServerID, MOC_IP_ADDRESS addr, ubyte *pName, ubyte *pPassword)
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
\endexample
*/
extern sbyte4
RADIUS_requestAppendUserPassword(RADIUS_RqstRecord *pRequest, ubyte* password,
                                        ubyte passwordLength)
{
    return (sbyte4)RADIUS_appendUserPassword(pRequest, password, passwordLength);
}


/*------------------------------------------------------------------*/

/*! Append a string to a request.
This function appends a value that is locally represented as a string to the
specified request.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note The string's terminating $NULL$ is not copied into the request packet.

\param pRequest     Descriptor for a RADIUS authentication/accounting request.
\param type         Type of attribute to add (see "Attribute Types").
\param pString      Pointer to the string to add to $pRequest$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
    goto exit;

if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, pName)))
    goto exit;
\endexample
*/
extern sbyte4
RADIUS_requestAppendStringAttribute(RADIUS_RqstRecord *pRequest, ubyte type, ubyte *pString)
{
    ubyte4 length = DIGI_STRLEN((sbyte *)pString);

    if (length > 255)
    {
        return ERR_BUFFER_OVERFLOW;
    }

    return (sbyte4)RADIUS_requestAppendAttribute(pRequest, type, pString, (ubyte)length);
}

/*------------------------------------------------------------------*/

/*! Append the CHAP-Password and CHAP-Challenge to a request.
This function appends the CHAP -Password and CHAP-Challenge to the specified
request.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\note The RADIUS RFC states that a request cannot contain both a user and a CHAP
password.

\sa For more information about CHAP passwords and challenges, refer to RFC&nbsp;1994 (CHAP)
and the principal RADIUS RFC&nbsp;2865 (sections 2.2 and 5.3).

\param pRequest         Descriptor for a RADIUS authentication/accounting request.
\param chapID           CHAP ID (a single byte).
\param pChapPassword    Pointer to the buffer containing the CHAP password.
\param chapPasswordLength   Number of bytes in the CHAP password.
\param pChapChallenge   Pointer to the CHAP challenge data to append to $pRequest$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, chapUserName))) {
    goto exit;
}

if (OK > (status = RADIUS_requestAppendCHAPPasswordAttributes(pRadiusReq, chapID,
                  chapPassword, DIGI_STRLEN((sbyte *)chapPassword), chapChallenge))) {
    goto exit;
}

if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq,                RADIUS_ATTR_NAS_IP_ADDRESS, addr))) {
    goto exit;
}

if (OK > (status = RADIUS_requestSend(pRadiusReq)))
    goto exit;

pending++;
\endexample
*/
extern sbyte4
RADIUS_requestAppendCHAPPasswordAttributes(RADIUS_RqstRecord *pRequest, ubyte chapID,
                                    ubyte *pChapPassword, ubyte4 chapPasswordLength,
                                    ubyte *pChapChallenge)
{
    sbyte4     status;
    MD5_CTX *pCtx = NULL;
    ubyte   chapPWValue[1 + RADIUS_CHAP_DIGESTSIZE];

    status = MD5Alloc_m(MOC_HASH(gRADIUS_globals.hwAccelCtx)(BulkCtx *) &pCtx);
    if (OK != status)
        goto exit;
    
    status = MD5Init_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;
    
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, &chapID, sizeof(chapID));
    if (OK != status)
        goto exit;
    
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, pChapPassword, chapPasswordLength);
    if (OK != status)
        goto exit;
    
    status = MD5Update_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, pChapChallenge, RADIUS_CHAP_DIGESTSIZE);
    if (OK != status)
        goto exit;
    

    /* chapPWValue[0] will contain the chap identifier */
    status = MD5Final_m(MOC_HASH(gRADIUS_globals.hwAccelCtx) pCtx, &chapPWValue[1]);
    if (OK != status)
        goto exit;
    
    chapPWValue[0] = chapID;

    if (OK > (status = RADIUS_requestAppendAttribute(pRequest, RADIUS_ATTR_CHAP_PASSWORD,
                                     chapPWValue, 1 + RADIUS_CHAP_DIGESTSIZE)))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendAttribute(pRequest, RADIUS_ATTR_CHAP_CHALLENGE,
                                     pChapChallenge, RADIUS_CHAP_DIGESTSIZE)))
    {
        goto exit;
    }

    status = OK;

exit:
    MD5Free_m(MOC_HASH(gRADIUS_globals.hwAccelCtx)(BulkCtx *) &pCtx);
    return status;
}


/*------------------------------------------------------------------*/

/*! Append an existing vendor-specific attribute to a request.
This function appends a previously created vendor-specific attribute buffer
(see RADIUS_newVendorSpecificAttributeBuffer) to the specified request.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.
\param pAttr    Pointer to attribute data to add to $pRequest$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
// create/bind a custom attribute to the request
if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, ciscoVendorID)))
    goto exit;

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        1, subAttr1Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr1Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                        2, subAttr2Str, (ubyte)DIGI_STRLEN((sbyte *)subAttr2Str))))
{
    goto exit;
}

if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
    goto exit;

// send the request
status = RADIUS_requestSend(pRadiusReq);

exit:
if (NULL != pVSAttr)
    RADIUS_releaseVendorSpecificAttributeBuffer(pVSAttr);
\endexample
*/
extern sbyte4
RADIUS_requestAppendVendorSpecificAttributeBuffer(RADIUS_RqstRecord *pRequest, ubyte *pAttr)
{
    return RADIUS_requestAppendRawAttribute(pRequest, pAttr);
}


/*------------------------------------------------------------------*/

/*! Send a request.
This function sends (transmits) the specified request. The request contains the
destination %server, as well as all attributes added by calls to
the $RADIUS_requestAppend*$ functions.

This function automatically manages retries, although you can change the retry
interval and count during initial RADIUS Client code integration.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\param pRequest Descriptor for a RADIUS authentication/accounting request.

\sa For more information about CHAP passwords and challenges, refer to RFC&nbsp;1994 (CHAP)
and the principal RADIUS RFC&nbsp;2865 (sections 2.2 and 5.3).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
    goto exit;

if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, chapUserName))) {
    goto exit;
}

if (OK > (status = RADIUS_requestAppendCHAPPasswordAttributes(pRadiusReq, chapID, chapPassword, DIGI_STRLEN((sbyte *)chapPassword), chapChallenge))) {
    goto exit;
}

if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_NAS_IP_ADDRESS, addr))) {
    goto exit;
}

if (OK > (status = RADIUS_requestSend(pRadiusReq)))
    goto exit;

pending++;
\endexample
*/
extern sbyte4
RADIUS_requestSend(RADIUS_RqstRecord *pRequest)
{
    return (sbyte4)RADIUS_sendRequest(pRequest);
}


/*------------------------------------------------------------------*/

/*! Free memory used by a string.
This function frees the memory used by the specified string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_req.h

\param ppStr    Address of pointer to string to release.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
printf("%s\nType in your username: ", username);
fgets(pRequest, 32, stdin);

if (username != defaultUser)
    RADIUS_requestFreeString(&username);
\endexample
*/
extern sbyte4
RADIUS_requestFreeString(sbyte **ppStr)
{
    MSTATUS status = OK;

    if (NULL == ppStr)
        status = ERR_NULL_POINTER;
    else if (NULL != *ppStr)
    {
        FREE(*ppStr);
        *ppStr = NULL;
    }

    return (sbyte4)status;
}

#endif /* __ENABLE_DIGICERT_RADIUS_CLIENT__ */
