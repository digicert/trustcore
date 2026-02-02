/**
 * @file tap_base_serialize.h
 *
 * @brief The base definitions and functions needed for Trust Anchor Platform (TAP) serialization
 * @details This file contains the base definitions and functions needed for Trust Anchor Platform (TAP) serialization
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
#ifndef __TAP_BASE_SERIALIZE_H
#define __TAP_BASE_SERIALIZE_H

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"

#define TAP_SHADOW_MAX_FIELDS 30
#define TAP_OFFSETOF(type, field) ((unsigned long)&(((type *) 0)->field))
#define SIZEOF(type, field) (sizeof(((type *) 0)->field))

typedef enum {
    TAP_SD_IN,
    TAP_SD_OUT,
    TAP_SD_INVALID,
} TAP_SERIALIZE_DIRECTION;

typedef MSTATUS (*pSerializeFunc)(ubyte *, ubyte4, ubyte *, ubyte4, ubyte4 *,
                                  TAP_SERIALIZE_DIRECTION direction, byteBoolean freeMemory);

/***************************************************************
   Structure  Definitions
****************************************************************/

/* Forward declare tap_shadow_struct for pShadowHandler */
typedef struct tap_shadow_struct tap_shadow_struct;

typedef MSTATUS (*pShadowHandler)(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

typedef struct
{
    ubyte8 selectorOrOffset;
    const struct tap_shadow_struct *pField;
} TapFieldInfo;

struct tap_shadow_struct
{
    pShadowHandler handler;
    ubyte4 structSize;
    ubyte4 numFields;
    ubyte2 unionSelectorOffset;
    ubyte2 unionSelectorSize;
    pSerializeFunc pSerialize;
    TapFieldInfo pFieldList[];
};

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_none;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte_ptr_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte2;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte2_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte2_ptr_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte4;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte4_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte4_ptr_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte8;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte8_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_ubyte8_ptr_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_void_ptr;

MOC_EXTERN const tap_shadow_struct TAP_SHADOW_void_ptr_ptr;

/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @private
 * @internal
 * @ingroup tap_common_functions
 *
 * @brief Convert a ubyte2 to a ubyte array.
 * @details Convert a ubyte2 to a ubyte array.
 *
 * @param [in] in      ubyte2 to convert to array
 * @param [out] pOut   ubyte * containing converted ubyte2
 *
 * @return OK on success
 * @return ERR_NULL_POINTER on error
 */
MOC_EXTERN MSTATUS ubyte2ToArray(ubyte2 in, ubyte *pOut);

/**
 * @private
 * @internal
 * @ingroup tap_common_functions
 *
 * @brief Convert a ubyte4 to a ubyte array.
 * @details Convert a ubyte4 to a ubyte array.
 *
 * @param [in]  in    ubyte4 to convert to array
 * @param [out] pOut  ubyte * containing converted ubyte4
 *
 * @return OK on success
 * @return ERR_NULL_POINTER on error
 */
MOC_EXTERN MSTATUS ubyte4ToArray(ubyte4 in, ubyte *pOut);

/**
 * @private
 * @internal
 * @ingroup tap_common_functions
 *
 * @brief Convert a ubyte8 to a ubyte array.
 * @details Convert a ubyte8 to a ubyte array.
 *
 * @param [in]  in   ubyte8 to convert to array
 * @param [out] pOut ubyte * containing converted ubyte8
 *
 * @return OK on success
 * @return ERR_NULL_POINTER on error
 */
MSTATUS ubyte8ToArray(ubyte8 in, ubyte *pOut);


/**
 * @private
 * @internal
 * @ingroup tap_common_functions
 *
 * @brief Convert a ubyte array to a ubyte2
 * @details Convert a ubyte array to a ubyte2
 *
 * @param [in]  pIn  buffer containing 2 bytes to be converted to a ubyte2
 * @param [out] pOut converted ubyte2
 *
 * @return OK on success
 * @return ERR_NULL_POINTER on error
 */
MOC_EXTERN MSTATUS arrayToUbyte2(const ubyte *pIn, ubyte2 *pOut);

/**
 * @private
 * @internal
 * @ingroup tap_common_functions
 *
 * @brief Convert a ubyte array to a ubyte4
 * @details Convert a ubyte array to a ubyte4
 *
 * @param [in]  pIn  buffer containing 4 bytes to be converted to a ubyte4
 * @param [out] pOut converted ubyte4
 *
 * @return OK on success
 * @return ERR_NULL_POINTER on error
 */
MOC_EXTERN MSTATUS arrayToUbyte4(const ubyte *pIn, ubyte4 *pOut);

/**
 * @private
 * @internal
 * @ingroup tap_common_functions
 *
 * @brief Convert a ubyte array to a ubyte8
 * @details Convert a ubyte array to a ubyte8
 *
 * @param [in]  pIn  buffer containing 8 bytes to be converted to a ubyte8
 * @param [out] pOut converted ubyte8
 *
 * @return OK on success
 * @return ERR_NULL_POINTER on error
 */
MSTATUS arrayToUbyte8(const ubyte *pIn, ubyte8 *pOut);

MOC_EXTERN MSTATUS TAP_SERIALIZE_ValidateCommonHandlerParams(
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MSTATUS TAP_SERIALIZE_baseTypeHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_StructTypeHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_UnionTypeHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_PointerTypeHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_ArrayListTypeHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_ListPointerTypeHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_SizedBufferHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_FixedSizeArrayHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_serialize(
        const tap_shadow_struct *pRoot,
        TAP_SERIALIZE_DIRECTION direction,
        ubyte *pIn,
        ubyte4 InSize,
        ubyte *pOut,
        ubyte4 OutSize,
        ubyte4 *pOffset
);

MOC_EXTERN MSTATUS TAP_SERIALIZE_freeDeserializedStructure(
        const tap_shadow_struct *pRoot,
        ubyte *pIn,
        ubyte4 InSize
);

MOC_EXTERN const tap_shadow_struct *TAP_SERIALIZE_getUbyte2(
        void
);

#endif
