/**
 * @file  radius_aobj.h
 * @brief RADIUS attribute object handling API
 *
 * @details    RADIUS attribute object handling interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Whether the following flags are defined determines which definitions are enabled:
 *             + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
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

#ifndef __RAD_ATTR_OBJ_HEADER__
#define __RAD_ATTR_OBJ_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* RAO == Radius Attribute Object */

/** @private @internal */
typedef enum
{
    RADIUS_ATTRIBUTE_TYPE_BYTES,
    RADIUS_ATTRIBUTE_TYPE_UBYTE4,
    RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC,
    RADIUS_ATTRIBUTE_TYPE_SUB_ATTRIBUTE,
    RADIUS_ATTRIBUTE_TYPE_UNKNOWN,

} RAO_AttributeBasicType;

/** @private @internal */
typedef struct
{
    ubyte4                      vendorID;
    intBoolean                  hasSubAttributes;
    ubyte*                      pData;

}   RAO_VendorSpecificType;

/** @private @internal */
typedef struct
{
    ubyte*                      pData;

}   RAO_BytesType;

/** @private @internal */
typedef struct
{
    RAO_AttributeBasicType      basicType;
    ubyte                       type;
    ubyte                       dataLength;

    union
    {
        ubyte4                  ubyte4Value;
        RAO_BytesType           bytes;
        RAO_VendorSpecificType  vendorSpecific;
    } u;

} RadiusAttributeObject;

/** @private @internal */
typedef RadiusAttributeObject RAO;


/*------------------------------------------------------------------*/

/**
@brief      Get the specified response attribute as a fully defined RAO.
@details    This function examines the response data in the specified
            request-response record, extracts the specified attribute, an
            d returns it as a fully defined RAO (through the \p ppRAO parameter).

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@param pRequest Descriptor for a RADIUS authentication/accounting request for
                which a response has been received.
@param index    Zero-based index of attribute to get.
@param ppRAO    On return, pointer to address of RAO containing the extracted
                attribute.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
while (OK == RADIUS_raoResponseGetAttributeByIndexAsRAO(pRadiusReq, i, &pRAO))
{
    printf("Attribute         : #%d\n", i);
    if (OK == RADIUS_raoGetAttributeBasicType(pRAO, &basicType))
    {
        printf("        Basic Type: ");
        radius_raoPrintBasicType(basicType);
    }

    if (OK == RADIUS_raoGetAttributeType(pRAO, &type))
    {
        printf("              Type: %d\n", (int)type);
    }
    if (OK == (raoStatus = RADIUS_raoUByte4FromRAO(pRAO, &ubyte4Value)))
    {
        printf("    Value as ubyte4: %x\n", ubyte4Value);
    }
    else if (ERR_RADIUS_COERCION_ERROR == raoStatus)
    {
        printf("    Value cannot be represented by a 4 byte unsigned integer\n");
    }
    else goto exit;

    if (OK == (raoStatus = RADIUS_raoCStringFromRAO(pRAO, &pStringValue)))
    {
        printf("    Value as string: %s\n", pStringValue);
        free(pStringValue);
    }
    else if (ERR_RADIUS_COERCION_ERROR == raoStatus)
    {
        printf("    Value cannot be represented as a C string\n");
    }
    else goto exit;

    if (RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC == basicType)
    {
        radius_EXAMPLE_raoPrintVSAttribute(pRAO);
    }
    else
    {
        printf("    Value is not a Vendor-Specifc attribute\n");
    }
    RADIUS_raoReleaseRAO(pRAO);
    i++;
}
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoResponseGetAttributeByIndexAsRAO(RADIUS_RqstRecord *pRequest, sbyte4 index, RAO **ppRAO);

/**
@brief      Free (release) memory used by an RAO.
@details    This function frees (releases) the memory used by an RAO. You should
            call this for every request/response once it has been fully
            processed.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@param pRAO    Pointer to the RAO whose memory you want to release.

@return     None.

@code
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
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN void RADIUS_raoReleaseRAO(RAO* pRAO);

/**
@brief      Get an RAO's basic type.
@details    This function retrieves the specified RAO's basic type.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@remark     An RAO's }basic} type (such as \c RADIUS_ATTRIBUTE_TYPE_BYTES or
            \c RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC) is different from an RAO
            {attribute} type (see @ref radius_attribute_types).

@param pRAO     Pointer to RAO.
@param pType    On return, pointer to \c RAO_AttributeBasicType enumerated value
                (see radius_aobj.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
if (OK == RADIUS_raoGetAttributeBasicType(pRAO, &basicType))
{
    printf("        Basic Type: ");
    radius_raoPrintBasicType(basicType);
}
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoGetAttributeBasicType(RAO *pRAO, RAO_AttributeBasicType* pType);

/**
@brief      Get an RAO's attribute type.
@details    This function retrieves the specified RAO's attribute type.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@remark     An RAO's {attribute} type (see @ref radius_attribute_types) is
            different from its {basic} type (such as \c
            RADIUS_ATTRIBUTE_TYPE_BYTES or \c
            RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC).

@param pRAO     Pointer to RAO.
@param pType    On return, pointer to value representing RAO's attribute type
                (see @ref radius_attribute_types).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
// not bothering with error checking, although should
RADIUS_raoGetAttributeType(pSubRAO, &subType);
RADIUS_raoGetAttributeData(pSubRAO, &pSubData, &subLength);
printf(" Sub-Attribute: #%d\n", i);
printf("          Type: %d\n", (int)subType);
printf("         Value: ");
radius_printChars(pSubData, subLength);
printf("\n");
RADIUS_raoReleaseRAO(pSubRAO);
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoGetAttributeType(RAO *pRAO, ubyte* pType);

/**
@brief      Get an RAO's data.
@details    This function copies the specified RAO's data to the a data buffer,
            and returns the data buffer and its length through the \p ppData and
            \p pLength parameters, respectively.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@param pRAO     Pointer to RAO.
@param ppData   On return, pointer to address of buffer containing the specified
                RAO's data.
@param pLength  On return, pointer to length of returned data (the \p ppData
                buffer).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
// not bothering with error checking, although should
RADIUS_raoGetAttributeType(pSubRAO, &subType);
RADIUS_raoGetAttributeData(pSubRAO, &pSubData, &subLength);
printf(" Sub-Attribute: #%d\n", i);
printf("          Type: %d\n", (int)subType);
printf("         Value: ");
radius_printChars(pSubData, subLength);
printf("\n");
RADIUS_raoReleaseRAO(pSubRAO);
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoGetAttributeData(RAO *pRAO, ubyte** ppData, ubyte *pLength);

/**
@brief      Determine whether an RAO has any subattributes.
@details    This function determines whether an RAO has any subattributes (which
            can only be true for RAOs of basic type \c
            RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC).

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@param pRAO                 Pointer to RAO.
@param pHasSubAttributes    On return, pointer to \c TRUE (1) if the RAO has any
                            subattributes; otherwise pointer to \c FALSE (0).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
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
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoGetHasSubAttributes(RAO *pRAO, intBoolean *pHasSubAttributes);

/**
@brief      Get an RAO's vendor ID.
@details    This function retrieves the specified RAO's vendor ID. The RAO's
            basic type must be \c RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@param pRAO         Pointer to RAO.
@param pVendorID    On return, pointer to value representing the RAO's vendor
                    ID, as assigned by IANA; refer to the following Web page:
                    "http://www.iana.org/assignments/enterprise-numbers2".

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoGetVendorID(RAO *pRAO, ubyte4 *pVendorID);

/**
@brief      Get the specified subattribute from an RAO.
@details    This function extracts the specified RAO subattribute (by calling
            RADIUS_getSubAttributeByIndex), and returns it as a fully defined
            RAO (with basic type RADIUS_ATTRIBUTE_TYPE_SUB_ATTRIBUTE) through
            the \p ppSubRAO parameter.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@note       You should call this function only for RAOs of basic type
            RADIUS_ATTRIBUTE_TYPE_VENDOR_SPECIFIC, and only if you know that the
            RAO has subattributes.
@note       If an invalid \p index is specified, \c ERR_INDEX_OOB is returned.

@param pRAO         Pointer to RAO.
@param index        Zero-based index of desired subattribute.
@param ppSubRAO     On return, pointer to desired subattribute.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
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
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoGetSubAttributeByIndex(RAO *pRAO, sbyte4 index, RAO **ppSubRAO);

/**
@brief      Get a \c ubyte4 representation of an RAO data field.
@details    This function retrieves a \c ubyte4 representation of a specified
            RAO's data field. Regardless of the RAO's basic type, the retrieved
            data is returned through the \p pValue parameter in host order.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@note       The data field's size must be the same size as a \c ubyte4. If it is
            not, the function returns an \c ERR_RADIUS_COERCION_ERROR status.

@param pRAO     Pointer to RAO.
@param pValue   On return, pointer to \c ubyte4 representation of the RAO data
                field.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
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
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoUByte4FromRAO(RAO *pRAO, ubyte4 *pValue);

/**
@brief      Get an RAO data field's C&nbsp;string representation.
@details    This function retrieves a C&nbsp;string representation of an RAO
            data field for any RAO type except \c RADIUS_ATTRIBUTE_TYPE_UBYTE4.

@ingroup    radius_rao_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_RADIUS_CLIENT__

@inc_file radius_aobj.h

@note       To prevent a memory leak, call RADIUS_responseFreeString when you're
            done using the the returned \p ppStr.

@param pRAO     Pointer to RAO.
@param ppStr    On return, pointer to address of desired attribute's
                C&nbsp;string value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
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
@endcode

@funcdoc    radius_aobj.h
*/
MOC_EXTERN sbyte4 RADIUS_raoCStringFromRAO(RAO *pRAO, sbyte **ppStr);

#ifdef __cplusplus
}
#endif

#endif /* __RAD_ATTR_OBJ_HEADER__ */

