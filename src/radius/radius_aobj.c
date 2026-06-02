/**
 * @file  radius_aobj.c
 * @brief RADIUS attribute object handling implementation
 *
 * @details    RADIUS attribute object handling functions
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     Whether the following flags are defined determines which definitions are enabled:
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
#include "../radius/radius_resp.h"
#include "../radius/radius_aobj.h"


/*------------------------------------------------------------------*/

static RAO_AttributeBasicType radius_raoTypeToBasicType(ubyte type)
{
    RAO_AttributeBasicType  ret;

    switch (type)
    {
        /* Probably ISO-10646 bytes */
        case RADIUS_ATTR_USER_NAME:
        case RADIUS_ATTR_FILTER_ID:
        case RADIUS_ATTR_REPLY_MESSAGE:
        case RADIUS_ATTR_CALLBACK_NUMBER:
        case RADIUS_ATTR_FRAMED_ROUTE:
        case RADIUS_ATTR_CALLED_STATION_ID:
        case RADIUS_ATTR_CALLING_STATION_ID:
        case RADIUS_ATTR_ACCT_SESSION_ID:
        case RADIUS_ATTR_ACCT_MULTI_SESSION_ID:

        /* LAT string */
        case RADIUS_ATTR_LOGIN_LAT_SERVICE:
        case RADIUS_ATTR_LOGIN_LAT_NODE:
        case RADIUS_ATTR_LOGIN_LAT_PORT:

        /* octets */
        case RADIUS_ATTR_CALLBACK_ID:
        case RADIUS_ATTR_STATE:
        case RADIUS_ATTR_CLASS:
        case RADIUS_ATTR_NAS_IDENTIFIER:
        case RADIUS_ATTR_PROXY_STATE:
        case RADIUS_ATTR_LOGIN_LAT_GROUP:
        case RADIUS_ATTR_CHAP_CHALLENGE:

        /* CHAP id + MD5 hash */
        case RADIUS_ATTR_CHAP_PASSWORD:

        /* encrypted data */
        case RADIUS_ATTR_USER_PASSWORD:
            ret = RADIUS_ATTRIBUTE_TYPE_BYTES;              /* <--------------- */
            break;

        /* IPv4 Address or Mask */
        case RADIUS_ATTR_NAS_IP_ADDRESS:
        case RADIUS_ATTR_FRAMED_IP_ADDRESS:
        case RADIUS_ATTR_FRAMED_IP_NETMASK:
        case RADIUS_ATTR_LOGIN_IP_HOST:

        /* UDP TCP Port Type */
        case RADIUS_ATTR_NAS_PORT:
        case RADIUS_ATTR_LOGIN_TCP_PORT:

        /* IPX Network */
        case RADIUS_ATTR_FRAMED_IPX_NETWORK:

        /* Appletalk Network */
        case RADIUS_ATTR_FRAMED_APPLETALK_LINK:
        case RADIUS_ATTR_FRAMED_APPLETALK_NETWORK:

        /* enums */
        case RADIUS_ATTR_SERVICE_TYPE:
        case RADIUS_ATTR_FRAMED_PROTOCOL:
        case RADIUS_ATTR_FRAMED_ROUTING:
        case RADIUS_ATTR_FRAMED_COMPRESSION:
        case RADIUS_ATTR_LOGIN_SERVICE:
        case RADIUS_ATTR_TERMINATION_ACTION:
        case RADIUS_ATTR_ACCT_STATUS_TYPE:
        case RADIUS_ATTR_ACCT_ACCT_AUTHENTIC:
        case RADIUS_ATTR_ACCT_TERMINATE_CAUSE:
        case RADIUS_ATTR_NAS_PORT_TYPE:

        /* integers */
        case RADIUS_ATTR_FRAMED_MTU:
        case RADIUS_ATTR_SESSION_TIMEOUT:
        case RADIUS_ATTR_IDLE_TIMEOUT:
        case RADIUS_ATTR_ACCT_DELAY_TIME:
        case RADIUS_ATTR_ACCT_INPUT_OCTETS:
        case RADIUS_ATTR_ACCT_OUTPUT_OCTETS:
        case RADIUS_ATTR_ACCT_SESSION_TIME:
        case RADIUS_ATTR_ACCT_INPUT_PACKETS:
        case RADIUS_ATTR_ACCT_OUTPUT_PACKETS:
        case RADIUS_ATTR_ACCT_LINK_COUNT:
        case RADIUS_ATTR_PORT_LIMIT:
            ret = RADIUS_ATTRIBUTE_TYPE_UBYTE4;             /* <--------------- */
            break;

        case RADIUS_ATTR_VENDOR_SPECIFIC:
            ret = RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC;    /* <--------------- */
            break;

        default:
            ret = RADIUS_ATTRIBUTE_TYPE_UNKNOWN;            /* <--------------- */
            break;
    }

    return ret;
}


/*------------------------------------------------------------------*/

/*! Get the specified response attribute as a fully defined RAO.
This function examines the response data in the specified request-response
record, extracts the specified attribute, and returns it as a fully defined RAO
(through the $ppRAO$ parameter).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\param pRequest Descriptor for a RADIUS authentication/accounting request for
which a response has been received.
\param index    Zero-based index of attribute to get.
\param ppRAO    On return, pointer to address of RAO containing the extracted attribute.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
while (OK == RADIUS_raoResponseGetAttributeByIndexAsRAO(pRadiusReq, i, &pRAO))
{
    printf("Attribute         : #%d\n", i);
    if (OK == RADIUS_raoGetAttributeBasicType(pRAO, &basicType)) {
        printf("        Basic Type: ");
        radius_raoPrintBasicType(basicType);
    }

    if (OK == RADIUS_raoGetAttributeType(pRAO, &type)) {
        printf("              Type: %d\n", (int)type);
    }
    if (OK == (raoStatus = RADIUS_raoUByte4FromRAO(pRAO, &ubyte4Value))) {
        printf("    Value as ubyte4: %x\n", ubyte4Value);
    } else if (ERR_RADIUS_COERCION_ERROR == raoStatus) {
        printf("    Value cannot be represented by a 4 byte unsigned integer\n");
    } else goto exit;

    if (OK == (raoStatus = RADIUS_raoCStringFromRAO(pRAO, &pStringValue))) {
        printf("    Value as string: %s\n", pStringValue);
        free(pStringValue);
    } else if (ERR_RADIUS_COERCION_ERROR == raoStatus) {
        printf("    Value cannot be represented as a C string\n");
    } else goto exit;

    if (RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC == basicType) {
        radius_EXAMPLE_raoPrintVSAttribute(pRAO);
    } else {
        printf("    Value is not a Vendor-Specifc attribute\n");
    }
    RADIUS_raoReleaseRAO(pRAO);
    i++;
}
\endexample
*/
extern sbyte4
RADIUS_raoResponseGetAttributeByIndexAsRAO(RADIUS_RqstRecord *pRequest,
                                           sbyte4 index, RAO **ppRAO)
{
    ubyte                   type;
    ubyte*                  pData;
    ubyte*                  p;
    ubyte                   dataLength;
    RAO*                    pRAO;
    ubyte4                  needed;
    ubyte4                  tempL;
    RAO_AttributeBasicType  basicType;
    sbyte4                  status = OK;

    if (OK > (status = RADIUS_responseGetAttributeByIndex(pRequest, index, &type, &pData, &dataLength)))
        goto exit;

    needed = sizeof(RAO);
    basicType = radius_raoTypeToBasicType(type);

    if (RADIUS_ATTRIBUTE_TYPE_UBYTE4 != basicType)
        needed += dataLength;   /* append the data to the RAO and point to it */

    if (NULL == (pRAO = (RAO *)MALLOC(needed)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    switch (basicType)
    {
        case RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC:
        {
            p = pData;
            tempL = *p++;
            tempL = (tempL << 8) + *p++;
            tempL = (tempL << 8) + *p++;
            tempL = (tempL << 8) + *p++;
            dataLength -= RADIUS_ATTR_VENDOR_ID_FIELD_LENGTH;
            pRAO->u.vendorSpecific.vendorID = tempL;
            pRAO->u.vendorSpecific.hasSubAttributes = RADIUS_attributeHasSubAttributes(p, dataLength);
            DIGI_MEMCPY((ubyte*)(pRAO + 1), p, dataLength);
            pRAO->u.vendorSpecific.pData = (ubyte*)(pRAO + 1);
            break;
        }

        case RADIUS_ATTRIBUTE_TYPE_UBYTE4:
        {
            p = pData;
            tempL = *p++;
            tempL = (tempL << 8) + *p++;
            tempL = (tempL << 8) + *p++;
            tempL = (tempL << 8) + *p++;
            pRAO->u.ubyte4Value = tempL;
            break;
        }

        case RADIUS_ATTRIBUTE_TYPE_BYTES:
        default:
        {
            DIGI_MEMCPY((ubyte*)(pRAO + 1), pData, dataLength);
            pRAO->u.bytes.pData = (ubyte*)(pRAO + 1);
            break;
        }
    }

    pRAO->basicType = basicType;
    pRAO->type = type;
    pRAO->dataLength  = dataLength;
    *ppRAO = pRAO;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Free (release) memory used by an RAO.
This function frees (releases) the memory used by an RAO. You should call this
for every request/response once it has been fully processed.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\param pRAO    Pointer to the RAO whose memory you want to release.

\return None.

\example
while (OK == RADIUS_raoGetSubAttributeByIndex(pRAO, i, &pSubRAO))
{
    // not bothering with error checking, although should
    RADIUS_raoGetAttributeType(pSubRAO, &subType);
    RADIUS_raoGetAttributeData(pSubRAO, &pSubData, &subLength);
    printf(" Sub-Attribute: #%d\n", i);
    printf("          Type: %d\n", (int)subType);
    printf("         Value: ");
    radius_printChars(pSubData, subLength);
    printf("\n");
    RADIUS_raoReleaseRAO(pSubRAO);
    i++;
}
\endexample
*/
extern void RADIUS_raoReleaseRAO(RAO* pRAO)
{
    FREE(pRAO);
}


/*------------------------------------------------------------------*/

/*! Get an RAO's basic type.
This function retrieves the specified RAO's basic type.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\remark An RAO's }basic} type (such as $RADIUS_ATTRIBUTE_TYPE_BYTES$ or
$RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC$) is different from an RAO }attribute}
type (see "Attribute Types").

\param pRAO     Pointer to RAO.
\param pType    On return, pointer to $RAO_AttributeBasicType$ enumerated value
(see radius_aobj.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK == RADIUS_raoGetAttributeBasicType(pRAO, &basicType))
{
    printf("        Basic Type: ");
    radius_raoPrintBasicType(basicType);
}
\endexample
*/
extern sbyte4 RADIUS_raoGetAttributeBasicType(RAO *pRAO, RAO_AttributeBasicType* pType)
{
    MSTATUS status = OK;

    if ((NULL == pRAO) || (NULL == pType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pType = pRAO->basicType;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an RAO's attribute type.
This function retrieves the specified RAO's attribute type.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\remark An RAO's }attribute} type (see "Attribute Types") is different from its
}basic} type (such as $RADIUS_ATTRIBUTE_TYPE_BYTES$ or
$RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC$).

\param pRAO     Pointer to RAO.
\param pType    On return, pointer to value representing RAO's attribute type
(see "Attribute Types").

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
// not bothering with error checking, although should
RADIUS_raoGetAttributeType(pSubRAO, &subType);
RADIUS_raoGetAttributeData(pSubRAO, &pSubData, &subLength);
printf(" Sub-Attribute: #%d\n", i);
printf("          Type: %d\n", (int)subType);
printf("         Value: ");
radius_printChars(pSubData, subLength);
printf("\n");
RADIUS_raoReleaseRAO(pSubRAO);
\endexample
*/
extern sbyte4 RADIUS_raoGetAttributeType(RAO *pRAO, ubyte* pType)
{
    MSTATUS status = OK;

    if ((NULL == pRAO) || (NULL == pType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pType = pRAO->type;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an RAO's data.
This function copies the specified RAO's data to the a data buffer, and returns
the data buffer and its length through the $ppData$ and $pLength$ parameters,
respectively.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\param pRAO     Pointer to RAO.
\param ppData   On return, pointer to address of buffer containing the specified
RAO's data.
\param pLength  On return, pointer to length of returned data (the $ppData$
buffer).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
// not bothering with error checking, although should
RADIUS_raoGetAttributeType(pSubRAO, &subType);
RADIUS_raoGetAttributeData(pSubRAO, &pSubData, &subLength);
printf(" Sub-Attribute: #%d\n", i);
printf("          Type: %d\n", (int)subType);
printf("         Value: ");
radius_printChars(pSubData, subLength);
printf("\n");
RADIUS_raoReleaseRAO(pSubRAO);
\endexample
*/
extern sbyte4
RADIUS_raoGetAttributeData(RAO *pRAO, ubyte** ppData, ubyte *pLength)
{
    MSTATUS status = OK;

    if ((NULL == pRAO) || (NULL == ppData) || (NULL == pLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pLength = pRAO->dataLength;

    switch (pRAO->basicType)
    {
        case RADIUS_ATTRIBUTE_TYPE_UBYTE4:
        {
            *ppData = (ubyte*)&pRAO->u.ubyte4Value;  /* WARNING: HOST ORDER!!! */
            break;
        }
        default:
        {
            *ppData = (ubyte*)(pRAO + 1);
            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Determine whether an RAO has any subattributes.
This function determines whether an RAO has any subattributes (which can only be
true for RAOs of basic type $RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC$).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\param pRAO                 Pointer to RAO.
\param pHasSubAttributes    On return, pointer to $TRUE$ (1) if the RAO has any
subattributes; otherwise pointer to $FALSE$ (0).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK != RADIUS_raoGetHasSubAttributes(pRAO, &has))
    return;

if (FALSE == has)
{
    printf(" No sub-attributes.\n");
    return;
}

while (OK == RADIUS_raoGetSubAttributeByIndex(pRAO, i, &pSubRAO))
{
    // process subattributes
    i++;
}
\endexample
*/
extern sbyte4
RADIUS_raoGetHasSubAttributes(RAO *pRAO, intBoolean *pHasSubAttributes)
{
    MSTATUS status = OK;

    *pHasSubAttributes = FALSE;

    if (NULL == pRAO)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pRAO->basicType)
    {
        case RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC:
        {
            *pHasSubAttributes = pRAO->u.vendorSpecific.hasSubAttributes;
            break;
        }

        default:
        {
            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an RAO's vendor ID.
This function retrieves the specified RAO's vendor ID. The RAO's basic type must
be $RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC$.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\param pRAO         Pointer to RAO.
\param pVendorID    On return, pointer to value representing the RAO's vendor
ID, as assigned by IANA; refer to the following Web page:
"http://www.iana.org/assignments/enterprise-numbers2".

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern sbyte4
RADIUS_raoGetVendorID(RAO *pRAO, ubyte4 *pVendorID)
{
    MSTATUS status = OK;

    if ((NULL == pRAO) || (NULL == pVendorID))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pRAO->basicType != RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC)
    {
        status = ERR_RADIUS_COERCION_ERROR;
        goto exit;
    }

    *pVendorID = pRAO->u.vendorSpecific.vendorID;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get the specified subattribute from an RAO.
This function extracts the specified RAO subattribute (by calling
RADIUS_getSubAttributeByIndex), and returns it as a
fully defined RAO (with basic type RADIUS_ATTRIBUTE_TYPE_SUB_ATTRIBUTE) through
the $ppSubRAO$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\note You should call this function only for RAOs of basic type
RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC, and only if you know that the RAO has
subattributes.
\note If an invalid $index$ is specified, $ERR_INDEX_OOB$ is returned.

\param pRAO         Pointer to RAO.
\param index        Zero-based index of desired subattribute.
\param ppSubRAO     On return, pointer to desired subattribute.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK != RADIUS_raoGetHasSubAttributes(pRAO, &has))
    return;

if (FALSE == has)
{
    printf(" No sub-attributes.\n");
    return;
}

while (OK == RADIUS_raoGetSubAttributeByIndex(pRAO, i, &pSubRAO))
{
    // process subattributes
    i++;
}
\endexample

*/
extern sbyte4
RADIUS_raoGetSubAttributeByIndex(RAO *pRAO, sbyte4 index, RAO **ppSubRAO)
{
    MSTATUS status;
    ubyte *pData;
    ubyte  dataLength;
    ubyte subType;
    ubyte *pSubValue;
    ubyte subLength;
    RAO*  pSubRAO;

    if ((NULL == pRAO) || (NULL == ppSubRAO))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppSubRAO = NULL;

    if ((pRAO->basicType != RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC) ||
        (FALSE == pRAO->u.vendorSpecific.hasSubAttributes))
    {
        status = ERR_RADIUS_COERCION_ERROR;
        goto exit;
    }

    pData = pRAO->u.vendorSpecific.pData;
    dataLength = pRAO->dataLength;  /* doesn't include vendorID! */

    if (OK > (status = RADIUS_getSubAttributeByIndex(pData, dataLength, index,
                                        &subType, &pSubValue, &subLength)))
    {
        goto exit;
    }

    if (NULL == (pSubRAO = (RAO*)MALLOC(sizeof(RAO) + subLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pSubRAO->basicType = RADIUS_ATTRIBUTE_TYPE_SUB_ATTRIBUTE;
    pSubRAO->type = subType;
    pSubRAO->dataLength = subLength;
    DIGI_MEMCPY((ubyte*)(pSubRAO + 1), pSubValue, subLength);
    pSubRAO->u.bytes.pData = (ubyte*)(pSubRAO + 1);
    *ppSubRAO = pSubRAO;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a $ubyte4$ representation of an RAO data field.
This function retrieves a $ubyte4$ representation of a specified RAO's data
field. Regardless of the RAO's basic type, the retrieved data is returned
through the $pValue$ parameter in host order.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\note The data field's size must be the same size as a $ubyte4$. If it is not, the
function returns an $ERR_RADIUS_COERCION_ERROR$ status.

\param pRAO     Pointer to RAO.
\param pValue   On return, pointer to $ubyte4$ representation of the RAO data field.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK == (raoStatus = RADIUS_raoUByte4FromRAO(pRAO, &ubyte4Value)))
{
    printf("    Value as ubyte4: %x\n", ubyte4Value);
}
else if (ERR_RADIUS_COERCION_ERROR == raoStatus)
{
    printf("    Value cannot be represented by a 4 byte unsigned integer\n");
}
else
{
    goto exit;
}
\endexample
*/
extern sbyte4
RADIUS_raoUByte4FromRAO(RAO *pRAO, ubyte4 *pValue)
{
    ubyte*  pData;
    ubyte   dataLength;
    ubyte*  p;
    ubyte4  tempL;
    sbyte4  status;

    if ((NULL == pRAO) || (NULL == pValue))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = RADIUS_raoGetAttributeData(pRAO, &pData, &dataLength)))
        goto exit;

    if (sizeof(ubyte4) != dataLength)
    {
        status = ERR_RADIUS_COERCION_ERROR;
        goto exit;
    }

    switch (pRAO->basicType)
    {
        case RADIUS_ATTRIBUTE_TYPE_UBYTE4:
        {
            /* already in host order */
            *pValue = *((ubyte4*)pData);
            break;
        }

        default:
        {
            p = pData;
            tempL = *p++;
            tempL = (tempL << 8) + *p++;
            tempL = (tempL << 8) + *p++;
            tempL = (tempL << 8) + *p++;
            *pValue = tempL;
            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an RAO data field's C&nbsp;string representation.
This function retrieves a C&nbsp;string representation of an RAO data field for
any RAO type except $RADIUS_ATTRIBUTE_TYPE_UBYTE4$.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$

#Include %file:#&nbsp;&nbsp;radius_aobj.h

\note To prevent a memory leak, call RADIUS_responseFreeString when you're done using the
the returned $ppStr$.

\param pRAO     Pointer to RAO.
\param ppStr    On return, pointer to address of desired attribute's C&nbsp;string value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\example
if (OK == (raoStatus = RADIUS_raoCStringFromRAO(pRAO, &pStringValue)))
{
    printf("    Value as string: %s\n", pStringValue);
    free(pStringValue);
}
else if (ERR_RADIUS_COERCION_ERROR == raoStatus)
{
    printf("    Value cannot be represented as a C string\n");
}
else
{
    goto exit;
}
\endexample
*/
extern sbyte4
RADIUS_raoCStringFromRAO(RAO *pRAO, sbyte **ppStr)
{
    ubyte*  pStr;
    ubyte*  pData;
    ubyte   dataLength;
    sbyte4  status = OK;

    if ((NULL == pRAO) || (NULL == ppStr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppStr = NULL;

    switch (pRAO->basicType)
    {
        case RADIUS_ATTRIBUTE_TYPE_UBYTE4:
        {
            status = ERR_RADIUS_COERCION_ERROR;
            goto exit;
        }

        default:
        {
            if (OK > (status = RADIUS_raoGetAttributeData(pRAO, &pData, &dataLength)))
                goto exit;

            if (NULL == (pStr = MALLOC(dataLength + 1)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY(pStr, pData, dataLength);
            *(pStr + dataLength) = 0;
            *ppStr = (sbyte *)pStr;
            break;
        }
    }

    status = OK;

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_RADIUS_CLIENT__ */
