/**
 * @file base_serialize.c
 * 
 * @brief This file contains serialization functions for basic data types
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

#include <stdio.h>

#include "../common/moptions.h"

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "tap_base_serialize.h"


/***************************************************************
   Forward Definitions
****************************************************************/

static MSTATUS TAP_SERIALIZE_ubyte(ubyte *pUnserialized,
                                   ubyte4 maxUnserializedBuffSize, ubyte *pSerialized,
                                   ubyte4 maxSerializedBuffSize, ubyte4 *pSerializedOffset,
                                   TAP_SERIALIZE_DIRECTION direction,
                                   byteBoolean freeMemory);

static MSTATUS TAP_SERIALIZE_ubyte2(ubyte *pUnserialized,
                                    ubyte4 maxUnserializedBuffSize, ubyte *pSerialized,
                                    ubyte4 maxSerializedBuffSize, ubyte4 *pSerializedOffset,
                                    TAP_SERIALIZE_DIRECTION direction,
                                    byteBoolean freeMemory);

static MSTATUS TAP_SERIALIZE_ubyte4(ubyte *pUnserialized,
                                    ubyte4 maxUnserializedBuffSize, ubyte *pSerialized,
                                    ubyte4 maxSerializedBuffSize, ubyte4 *pSerializedOffset,
                                    TAP_SERIALIZE_DIRECTION direction,
                                    byteBoolean freeMemory);

static MSTATUS TAP_SERIALIZE_ubyte8(ubyte *pUnserialized,
                                    ubyte4 maxUnserializedBuffSize, ubyte *pSerialized,
                                    ubyte4 maxSerializedBuffSize, ubyte4 *pSerializedOffset,
                                    TAP_SERIALIZE_DIRECTION direction,
                                    byteBoolean freeMemory);

/* This is a special case function to handle unions where a particular
 * union selector requires no marshalling and unmarshalling.
 * An example of this would be for TPMS_EMPTY, used by TPM2.0.
 */
static MSTATUS TAP_SERIALIZE_none(ubyte *pUnserialized,
                                  ubyte4 maxUnserializedBuffSize, ubyte *pSerialized,
                                  ubyte4 maxSerializedBuffSize, ubyte4 *pSerializedOffset,
                                  TAP_SERIALIZE_DIRECTION direction,
                                  byteBoolean freeMemory);

/***************************************************************
   Shadow Structure Definitions
****************************************************************/

const tap_shadow_struct TAP_SHADOW_none = {
        .handler = TAP_SERIALIZE_baseTypeHandler,
        .structSize = sizeof(ubyte),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pSerialize = TAP_SERIALIZE_none
};

const tap_shadow_struct TAP_SHADOW_ubyte = {
        .handler = TAP_SERIALIZE_baseTypeHandler,
        .structSize = sizeof(ubyte),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pSerialize = TAP_SERIALIZE_ubyte
};

const tap_shadow_struct TAP_SHADOW_ubyte_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte,},}
};

const tap_shadow_struct TAP_SHADOW_ubyte_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte_ptr,},}
};

const tap_shadow_struct TAP_SHADOW_ubyte2 = {
        .handler = TAP_SERIALIZE_baseTypeHandler,
        .structSize = sizeof(ubyte2),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pSerialize = TAP_SERIALIZE_ubyte2
};

const tap_shadow_struct TAP_SHADOW_ubyte2_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2,},}
};

const tap_shadow_struct TAP_SHADOW_ubyte2_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2_ptr,},}
};

const tap_shadow_struct TAP_SHADOW_ubyte4 = {
        .handler = TAP_SERIALIZE_baseTypeHandler,
        .structSize = sizeof(ubyte4),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pSerialize = TAP_SERIALIZE_ubyte4,
};

const tap_shadow_struct TAP_SHADOW_ubyte4_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4,},}
};

const tap_shadow_struct TAP_SHADOW_ubyte4_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4_ptr,},}
};


const tap_shadow_struct TAP_SHADOW_ubyte8 = {
        .handler = TAP_SERIALIZE_baseTypeHandler,
        .structSize = sizeof(ubyte8),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pSerialize = TAP_SERIALIZE_ubyte8,
};

const tap_shadow_struct TAP_SHADOW_ubyte8_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte8,},}
};

const tap_shadow_struct TAP_SHADOW_ubyte8_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte8_ptr,},}
};

const tap_shadow_struct TAP_SHADOW_void_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte,},}
};

const tap_shadow_struct TAP_SHADOW_void_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_void_ptr,},}
};



/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @private
 * @internal
 *
 * @brief Function to convert a ubyte2 to a ubyte *
 */
MOC_EXTERN MSTATUS ubyte2ToArray(ubyte2 in, ubyte *pOut)
{
    if (NULL == pOut)
    {
        return ERR_NULL_POINTER;
    }

    pOut[0] = (ubyte) ((in >> 8) & 0xFF);
    pOut[1] = (ubyte) (in & 0xFF);

    return OK;
}

/**
 * @private
 * @internal
 *
 * @brief Function to convert a ubyte4 to a ubyte *
 */
MOC_EXTERN MSTATUS ubyte4ToArray(ubyte4 in, ubyte *pOut)
{
    if (NULL == pOut)
    {
        return ERR_NULL_POINTER;
    }

    pOut[0] = (ubyte) ((in >> 24) & 0xFF);
    pOut[1] = (ubyte) ((in >> 16) & 0xFF);
    pOut[2] = (ubyte) ((in >> 8) & 0xFF);
    pOut[3] = (ubyte) (in & 0xFF);

    return OK;
}

/**
 * @private
 * @internal
 *
 * @brief Function to convert a ubyte8 to a ubyte *
 */
MSTATUS ubyte8ToArray(ubyte8 in, ubyte *pOut)
{
    if (NULL == pOut)
    {
        return ERR_NULL_POINTER;
    }

    pOut[0] = (ubyte) ((in >> 56) & 0xFF);
    pOut[1] = (ubyte) ((in >> 48) & 0xFF);
    pOut[2] = (ubyte) ((in >> 40) & 0xFF);
    pOut[3] = (ubyte) ((in >> 32) & 0xFF);
    pOut[4] = (ubyte) ((in >> 24) & 0xFF);
    pOut[5] = (ubyte) ((in >> 16) & 0xFF);
    pOut[6] = (ubyte) ((in >> 8) & 0xFF);
    pOut[7] = (ubyte) (in & 0xFF);

    return OK;
}



/**
 * @private
 * @internal
 *
 * @brief Function to convert a ubyte * to a ubyte2
 */
MOC_EXTERN MSTATUS arrayToUbyte2(const ubyte *pIn, ubyte2 *pOut)
{
    if ((NULL == pOut) || (NULL == pIn))
    {
        return ERR_NULL_POINTER;
    }

    *pOut = ((pIn[0] & 0xFF) << 8) |
            (pIn[1] & 0xFF);

    return OK;
}

/**
 * @private
 * @internal
 *
 * @brief Function to convert a ubyte * to a ubyte4
 */
MSTATUS arrayToUbyte4(const ubyte *pIn, ubyte4 *pOut)
{
    if ((NULL == pOut) || (NULL == pIn))
    {
        return ERR_NULL_POINTER;
    }

    *pOut = ((pIn[0] & 0xFF) << 24)  |
            ((pIn[1] & 0xFF) << 16) |
            ((pIn[2] & 0xFF) << 8) |
            (pIn[3] & 0xFF);

    return OK;
}

/**
 * @private
 * @internal
 *
 * @brief Function to convert a ubyte * to a ubyte8
 */
MSTATUS arrayToUbyte8(const ubyte *pIn, ubyte8 *pOut)
{
    if ((NULL == pOut) || (NULL == pIn))
    {
        return ERR_NULL_POINTER;
    }

    *pOut = ((ubyte8)(pIn[0] & 0xFF) << 56) |
            ((ubyte8)(pIn[1] & 0xFF) << 48) |
            ((ubyte8)(pIn[2] & 0xFF) << 40) |
            ((ubyte8)(pIn[3] & 0xFF) << 32) |
            ((ubyte8)(pIn[4] & 0xFF) << 24) |
            ((ubyte8)(pIn[5] & 0xFF) << 16) |
            ((ubyte8)(pIn[6] & 0xFF) << 8)  |
            ((ubyte8)(pIn[7] & 0xFF));

    return OK;
}


static MSTATUS TAP_SERIALIZE_none(
        ubyte *pUnserialized,
        ubyte4 maxUnserializedBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
)
{
    return OK;
}


static MSTATUS TAP_SERIALIZE_ubyte(
        ubyte *pUnserialized,
        ubyte4 maxUnserializedBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
)
{
    MSTATUS status = ERR_GENERAL;

    if (freeMemory)
    {
        return OK;
    }

    if ((NULL == pUnserialized) || (NULL == pSerialized) ||
        (NULL == pSerializedOffset))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == maxSerializedBuffSize) ||
        ((*pSerializedOffset + sizeof(ubyte)) > maxSerializedBuffSize) ||
        (maxUnserializedBuffSize < sizeof(ubyte)))
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != (status =
                           DIGI_MEMCPY(&pSerialized[*pSerializedOffset], pUnserialized,
                                      sizeof(ubyte))))
            goto exit;
    }
    else
    {
        if (OK != (status =
                           DIGI_MEMCPY(pUnserialized, &pSerialized[*pSerializedOffset],
                                      sizeof(ubyte))))
            goto exit;
    }

    *pSerializedOffset = *pSerializedOffset + sizeof(ubyte);

    status = OK;

exit:
    return status;
}

static MSTATUS TAP_SERIALIZE_ubyte2(
        ubyte *pUnserialized,
        ubyte4 maxUnserializedBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
)
{
    MSTATUS status = ERR_GENERAL;

    if (freeMemory)
    {
        return OK;
    }

    if ((NULL == pUnserialized) || (NULL == pSerialized) ||
        (NULL == pSerializedOffset))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == maxSerializedBuffSize) ||
        ((*pSerializedOffset + sizeof(ubyte2)) > maxSerializedBuffSize) ||
        (maxUnserializedBuffSize < sizeof(ubyte2)))
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != (status = ubyte2ToArray(*((ubyte2 *)pUnserialized),
                                          &pSerialized[*pSerializedOffset])))
            goto exit;
    }
    else
    {
        if (OK != (status = arrayToUbyte2(&pSerialized[*pSerializedOffset],
                                          (ubyte2 *)pUnserialized)))
            goto exit;
    }

    *pSerializedOffset = *pSerializedOffset + sizeof(ubyte2);

    status = OK;

exit:
    return status;
}

static MSTATUS TAP_SERIALIZE_ubyte4(
        ubyte *pUnserialized,
        ubyte4 maxUnserializedBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
)
{
    MSTATUS status = ERR_GENERAL;

    if (freeMemory)
    {
        return OK;
    }

    if ((NULL == pUnserialized) || (NULL == pSerialized) ||
        (NULL == pSerializedOffset))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == maxSerializedBuffSize) ||
        ((*pSerializedOffset + sizeof(ubyte4)) > maxSerializedBuffSize) ||
        (maxUnserializedBuffSize < sizeof(ubyte4)))
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != (status = ubyte4ToArray(*((ubyte4 *)pUnserialized),
                                          &pSerialized[*pSerializedOffset])))
            goto exit;
    }
    else
    {
        if (OK != (status = arrayToUbyte4(&pSerialized[*pSerializedOffset],
                                          (ubyte4 *)pUnserialized)))
            goto exit;
    }

    *pSerializedOffset = *pSerializedOffset + sizeof(ubyte4);

    status = OK;

exit:
    return status;
}

static MSTATUS TAP_SERIALIZE_ubyte8(
        ubyte *pUnserialized,
        ubyte4 maxUnserializedBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
)
{
    MSTATUS status = ERR_GENERAL;

    if (freeMemory)
    {
        return OK;
    }

    if ((NULL == pUnserialized) || (NULL == pSerialized) ||
        (NULL == pSerializedOffset))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == maxSerializedBuffSize) ||
        ((*pSerializedOffset + sizeof(ubyte8)) > maxSerializedBuffSize) ||
        (maxUnserializedBuffSize < sizeof(ubyte8)))
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != (status = ubyte8ToArray(*((ubyte8 *)pUnserialized),
                                          &pSerialized[*pSerializedOffset])))
            goto exit;
    }
    else
    {
        if (OK != (status = arrayToUbyte8(&pSerialized[*pSerializedOffset],
                                          (ubyte8 *)pUnserialized)))
            goto exit;
    }

    *pSerializedOffset = *pSerializedOffset + sizeof(ubyte8);

    status = OK;

exit:
    return status;
}

static MSTATUS TAP_SERIALIZE_SerializeGetUnionSelector(
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxCurrentBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory,
        ubyte8 *unionSelector
)
{
    MSTATUS status = ERR_GENERAL;
    void *pNextUnserialized = NULL;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    /* List must have a field that gives the size of the array of
     * structures it identifies
     * We don't expect the union selector to be > 8 bytes at
     * this point.
     */
    if ((0 == pCurrent->unionSelectorSize) ||
        (pCurrent->unionSelectorSize > 8) ||
        (NULL == unionSelector))
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    pNextUnserialized = pCurrentBuffer + pCurrent->unionSelectorOffset;

    if (TAP_SD_IN == direction)
    {
        switch (pCurrent->unionSelectorSize)
        {
            case 1:
                if (!freeMemory)
                {
                    if (OK != (status =
                                       DIGI_MEMCPY(&pSerialized[*pSerializedOffset], pNextUnserialized,
                                                  sizeof(ubyte))))
                        goto exit;
                }
                *unionSelector = *((ubyte *)pNextUnserialized);
                break;

            case 2:
                if (!freeMemory)
                {
                    if (OK != (status = ubyte2ToArray(*((ubyte2 *)pNextUnserialized),
                                                      &pSerialized[*pSerializedOffset])))
                        goto exit;
                }
                *unionSelector = *((ubyte2 *)pNextUnserialized);
                break;

            case 4:
                if (!freeMemory)
                {
                    if (OK != (status = ubyte4ToArray(*((ubyte4 *)pNextUnserialized),
                                                      &pSerialized[*pSerializedOffset])))
                        goto exit;
                }
                *unionSelector = *((ubyte4 *)pNextUnserialized);
                break;

            default:
                status = ERR_INTERNAL_ERROR;
                goto exit;
                break;
        }
    }
    else
    {
        /*
         * freeMemory must never be TRUE when direction is TAP_SD_OUT
         */
        if (freeMemory)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        switch (pCurrent->unionSelectorSize)
        {
            case 1:
                if (OK != (status =
                                   DIGI_MEMCPY(pNextUnserialized, &pSerialized[*pSerializedOffset],
                                              sizeof(ubyte))))
                    goto exit;
                *unionSelector = *((ubyte *)pNextUnserialized);
                break;

            case 2:
                if (OK != (status = arrayToUbyte2(&pSerialized[*pSerializedOffset],
                                                  (ubyte2 *)pNextUnserialized)))
                    goto exit;
                *unionSelector = *((ubyte2 *)pNextUnserialized);
                break;

            case 4:
                if (OK != (status = arrayToUbyte4(&pSerialized[*pSerializedOffset],
                                                  (ubyte4 *)pNextUnserialized)))
                    goto exit;
                *unionSelector = *((ubyte4 *)pNextUnserialized);
                break;

            default:
                status = ERR_INTERNAL_ERROR;
                goto exit;
                break;
        }
    }

    if (!freeMemory)
        *pSerializedOffset = *pSerializedOffset + pCurrent->unionSelectorSize;

    status = OK;

exit:
    return status;
}

MOC_EXTERN MSTATUS TAP_SERIALIZE_ValidateCommonHandlerParams(
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
        byteBoolean freeMemory
)
{
    MSTATUS status = ERR_GENERAL;

    /* We dont check the parent pointer since it can be null for when this
     * function is called for the root node. parent node is only required
     * for unions.
     */

    if ((NULL == pCurrentBuffer) || (NULL == pCurrent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pCurrent->numFields < 1)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (!freeMemory)
    {
        if ((NULL == pSerialized) || (NULL == pSerializedOffset))
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if ((0 == maxSerializedBuffSize) || (*pSerializedOffset > maxSerializedBuffSize))
        {
            status = ERR_INDEX_OOB;
            goto exit;
        }
    }
    else
    {
        /*
         * Direction must be IN when attempting to free(so that pointers are looked
         * up appropriately to be freed. If freeMemory is requested, we dont perform
         * parameter validation. There should be no buffer copies, or use of serialized
         * offsets.
         */
        if (direction != TAP_SD_IN)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }
    status = OK;

exit:
    return status;
}

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
)
{
    MSTATUS status = ERR_GENERAL;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    if ((NULL == pCurrent->pSerialize) ||
        (pCurrent->numFields != 1))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = pCurrent->pSerialize(pCurrentBuffer,
                                  maxCurrentBuffSize, pSerialized, maxSerializedBuffSize,
                                  pSerializedOffset, direction, freeMemory);

exit:
    return status;
}

MSTATUS TAP_SERIALIZE_StructTypeHandler(
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
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 i = 0;
    void *pNextUnserialized = NULL;
    const tap_shadow_struct *pNextShadowStruct = NULL;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    for (i = 0; i < pCurrent->numFields; i++)
    {
        pNextShadowStruct = pCurrent->pFieldList[i].pField;
        pNextUnserialized = (void *)((ubyte *)pCurrentBuffer +
                                     pCurrent->pFieldList[i].selectorOrOffset);

        status = pNextShadowStruct->handler(pCurrent, pCurrentBuffer,
                                            pNextShadowStruct, pNextUnserialized, pNextShadowStruct->structSize,
                                            pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                            direction, freeMemory);

        if (OK != status)
            goto exit;
    }

    status = OK;

exit:
    return status;
}

MSTATUS TAP_SERIALIZE_UnionTypeHandler(
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
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 i = 0;
    ubyte8 unionSelector = 0;
    const tap_shadow_struct *pNextShadowStruct = NULL;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    /* Unions must have parents which are of types structs.
     * We dont expect the union selector to be > 8bytes at
     * this point.
     */
    if ((NULL == pParent) ||
        (pParent->handler != TAP_SERIALIZE_StructTypeHandler) ||
        (0 == pParent->unionSelectorSize) ||
        (pParent->unionSelectorSize > 8) || (NULL == pParentBuffer))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (OK != (status = DIGI_MEMCPY(&unionSelector,
                                   (pParentBuffer + pParent->unionSelectorOffset),
                                   pParent->unionSelectorSize)))
    {
        goto exit;
    }

    for (i = 0; i < pCurrent->numFields; i++)
    {
        if (pCurrent->pFieldList[i].selectorOrOffset
            == unionSelector)
        {
            pNextShadowStruct =
                    pCurrent->pFieldList[i].pField;
            break;
        }
    }

    if (NULL == pNextShadowStruct)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* Unexpected nested unions */
    if (TAP_SERIALIZE_UnionTypeHandler == pNextShadowStruct->handler)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status =  pNextShadowStruct->handler(NULL, NULL,
                                         pNextShadowStruct, pCurrentBuffer, pNextShadowStruct->structSize,
                                         pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                         direction, freeMemory);

exit:
    return status;
}

MSTATUS TAP_SERIALIZE_PointerTypeHandler(
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
)
{
    MSTATUS status = ERR_GENERAL;
    void *pNextUnserialized = NULL;
    const tap_shadow_struct *pNextShadowStruct = NULL;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    if (pCurrent->numFields != 1)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pNextShadowStruct = pCurrent->pFieldList[0].pField;

    /*
     * If structure pointed to is of type union, parent must be passed in.
     */
    if ((TAP_SERIALIZE_UnionTypeHandler == pNextShadowStruct->handler) &&
            ((NULL == pParent) || (NULL == pParentBuffer)))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        pNextUnserialized = (void *)(*(void **)pCurrentBuffer);
    }
    else
    {
        pNextUnserialized = NULL;

        if (0 < pNextShadowStruct->structSize)
        {
            if (OK != DIGI_MALLOC(&pNextUnserialized, pNextShadowStruct->structSize))
                goto exit;
        }
        *((void **)pCurrentBuffer) = pNextUnserialized;
    }

    /*
     * Serialize only if pointer is not NULL. If it is NULL, no error is returned,
     * nothing is serialized.
     */
    if (pNextUnserialized)
    {
        status = pNextShadowStruct->handler(pParent, pParentBuffer,
                pNextShadowStruct, pNextUnserialized, pNextShadowStruct->structSize,
                pSerialized, maxSerializedBuffSize, pSerializedOffset,
                direction, freeMemory);

        if (OK != status)
            goto exit;
    }

    if (freeMemory)
    {
        if (pNextUnserialized)
            DIGI_FREE(&pNextUnserialized);
    }
    status = OK;

exit:
    /*
     * Free memory allocated by this function on failure. This is the case
     * during deserialization. During serialization, the caller must allocate
     * memory.
     */
    if ((OK != status) && (TAP_SD_OUT == direction) &&
        (pNextUnserialized != NULL))
    {
        DIGI_FREE(&pNextUnserialized);
    }
    return status;
}

MSTATUS TAP_SERIALIZE_ListPointerTypeHandler(
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
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 i = 0;
    ubyte8 listLength = 0;
    const tap_shadow_struct *pNextShadowStruct = NULL;
    void *pNextUnserialized = NULL;
    void *pUnserializedList = NULL;
    const tap_shadow_struct *pListShadowStruct = NULL;
    ubyte4 listIndex = 0;

    status = TAP_SERIALIZE_SerializeGetUnionSelector(pCurrent, pCurrentBuffer,
                                                     maxCurrentBuffSize, pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                                     direction, freeMemory, &listLength);
    if (OK != status)
        goto exit;

    for (i = 0; i < pCurrent->numFields; i++)
    {
        pNextShadowStruct =
                pCurrent->pFieldList[i].pField;

        pNextUnserialized = (void *)((ubyte *)pCurrentBuffer +
                                     pCurrent->pFieldList[i].selectorOrOffset);

        if (NULL == pNextShadowStruct)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        if (pNextShadowStruct->handler != TAP_SERIALIZE_PointerTypeHandler)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (pNextShadowStruct->numFields != 1)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        pListShadowStruct = pNextShadowStruct->pFieldList[0].pField;

        if (TAP_SD_IN == direction)
        {
            pUnserializedList = (void *)(*(void **)pNextUnserialized);
        }
        else
        {
            pUnserializedList = NULL;
            if (0 < listLength)
            {
                if (OK != DIGI_MALLOC(&pUnserializedList,
                                     listLength * pListShadowStruct->structSize))
                    goto exit;
            }
            *((void **)pNextUnserialized)= pUnserializedList;
        }

        for (listIndex = 0; listIndex < listLength; listIndex++)
        {
            if (OK != (status = pListShadowStruct->handler(NULL, NULL,
                                                           pListShadowStruct, pUnserializedList, pListShadowStruct->structSize,
                                                           pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                                           direction, freeMemory)))
            {
                /*
                 * Free memory allocated by this function on failure. This is the case
                 * during deserialization. During serialization, the caller must allocate
                 * memory.
                 */
                if ((TAP_SD_OUT == direction) &&
                    (pUnserializedList != NULL))
                {
                    DIGI_FREE(&pUnserializedList);
                }
                goto exit;
            }
            pUnserializedList = (void *)((ubyte *)pUnserializedList +
                                         pListShadowStruct->structSize);
        }

        if (freeMemory)
        {
            if (pNextUnserialized)
                DIGI_FREE((void **)pNextUnserialized);
        }
    }

    status = OK;

exit:
    return status;
}

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
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 i = 0;
    ubyte8 listLength = 0;
    const tap_shadow_struct *pNextShadowStruct = NULL;
    void *pNextUnserialized = NULL;
    ubyte4 listIndex = 0;

    status = TAP_SERIALIZE_SerializeGetUnionSelector(pCurrent, pCurrentBuffer,
                                                     maxCurrentBuffSize, pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                                     direction, freeMemory, &listLength);
    if (OK != status)
        goto exit;

    for (i = 0; i < pCurrent->numFields; i++)
    {
        pNextShadowStruct =
                pCurrent->pFieldList[i].pField;

        pNextUnserialized = (void *)((ubyte *)pCurrentBuffer +
                                     pCurrent->pFieldList[i].selectorOrOffset);

        if (NULL == pNextShadowStruct)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        if (TAP_SERIALIZE_UnionTypeHandler == pNextShadowStruct->handler)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        for (listIndex = 0; listIndex < listLength; listIndex++)
        {
            if (OK != (status = pNextShadowStruct->handler(NULL, NULL,
                                                           pNextShadowStruct, pNextUnserialized, pNextShadowStruct->structSize,
                                                           pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                                           direction, freeMemory)))
            {
                goto exit;
            }
            pNextUnserialized = (void *)((ubyte *)pNextUnserialized +
                                         pNextShadowStruct->structSize);
        }
    }

    status = OK;

exit:
    return status;
}

MSTATUS TAP_SERIALIZE_FixedSizeArrayHandler(
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
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte8 bufferSize = 0;

    if (freeMemory)
        return OK;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    if (pCurrent->numFields != 1)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    bufferSize = pCurrent->structSize;

    if (((*pSerializedOffset) + bufferSize) >
        maxSerializedBuffSize)
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != DIGI_MEMCPY(&pSerialized[*pSerializedOffset],
                             pCurrentBuffer, bufferSize))
        {
            goto exit;
        }
    }
    else
    {
        if (OK != DIGI_MEMCPY(pCurrentBuffer, &pSerialized[*pSerializedOffset],
                             bufferSize))
        {
            goto exit;
        }
    }

    *pSerializedOffset = *pSerializedOffset + bufferSize;

    status = OK;

exit:
    return status;
}

/*
 * Main difference between ListPointerTypeHandler and this function:
 * the ListPointerTypeHandler cares about the type pointed to by
 * the pointer. Here, we simply do a memcpy. Serializing the data
 * structure recursively might save space in the serialized buffer
 * in the ListPointerTypeHandler but not in this case. Note here that
 * if the serializing and deserializing applications dont use the
 * same compiler/compiler padding for structures, there may be issues.
 * Typical use is for structures that contain a size and a ubyte buffer.
 */
MSTATUS TAP_SERIALIZE_SizedBufferHandler(
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
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte8 bufferSize = 0;
    void *pNextUnserialized = NULL;
    const tap_shadow_struct *pNextShadowStruct = NULL;
    ubyte4 i = 0;
    void *pUnserializedBuffer = NULL;

    status = TAP_SERIALIZE_SerializeGetUnionSelector(pCurrent, pCurrentBuffer,
                                                     maxCurrentBuffSize, pSerialized, maxSerializedBuffSize, pSerializedOffset,
                                                     direction, freeMemory, &bufferSize);
    if (OK != status)
        goto exit;

    for (i = 0; i < pCurrent->numFields; i++)
    {
        pNextShadowStruct =
                pCurrent->pFieldList[i].pField;
        pNextUnserialized = (void *)((ubyte *)pCurrentBuffer +
                                     pCurrent->pFieldList[i].selectorOrOffset);

        if (NULL == pNextShadowStruct)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        if (TAP_SERIALIZE_UnionTypeHandler == pNextShadowStruct->handler)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (!freeMemory)
        {
            if (((*pSerializedOffset) + (bufferSize)) >
                maxSerializedBuffSize)
            {
                status = ERR_INDEX_OOB;
                goto exit;
            }
        }

        if (TAP_SD_IN == direction)
        {
            pUnserializedBuffer = (void *)(*(void **)pNextUnserialized);

            if (!freeMemory)
            {
                if (OK != DIGI_MEMCPY(&pSerialized[*pSerializedOffset],
                                     pUnserializedBuffer, bufferSize))
                {
                    goto exit;
                }
            }
        }
        else
        {
            if (freeMemory)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }

            pUnserializedBuffer = NULL;
            if (0 < bufferSize)
            {
                if (OK != DIGI_MALLOC(&pUnserializedBuffer, bufferSize))
                    goto exit;
            }
            *((void **)pNextUnserialized) = pUnserializedBuffer;

            if (0 < bufferSize)
            {
                if (OK != DIGI_MEMCPY(pUnserializedBuffer,
                                     &pSerialized[*pSerializedOffset], bufferSize))
                {
                    /*
                     * Free memory allocated by this function on failure. This is the case
                     * during deserialization. During serialization, the caller must allocate
                     * memory.
                     */
                    if ((TAP_SD_OUT == direction) &&
                        (pUnserializedBuffer != NULL))
                    {
                        DIGI_FREE(&pUnserializedBuffer);
                    }
                    goto exit;
                }
            }
        }

        if (!freeMemory)
        {
            *pSerializedOffset = *pSerializedOffset + bufferSize;
        }
        else
        {
            DIGI_FREE((void **)pNextUnserialized);
        }
    }

    status = OK;

exit:
    return status;
}

MSTATUS TAP_SERIALIZE_serialize(
        const tap_shadow_struct *pRoot,
        TAP_SERIALIZE_DIRECTION direction,
        ubyte *pIn,
        ubyte4 InSize,
        ubyte *pOut,
        ubyte4 OutSize,
        ubyte4 *pOffset
)
{
    MSTATUS status = ERR_GENERAL;

    if (direction >= TAP_SD_INVALID)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if ((NULL == pIn) || (NULL == pOut) || (NULL == pOffset) ||
        (NULL == pRoot) || (NULL == pRoot->handler))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (0 == InSize)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (0 == OutSize)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if ((TAP_SD_IN == direction) && (*pOffset >= OutSize))
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    if ((TAP_SD_OUT == direction) && (*pOffset >= InSize))
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    /* The root structure that we traverse down cannot be of type
     * union since a union has no meaning without its selector,
     * which is always a part of a structure.
     */
    if (TAP_SERIALIZE_UnionTypeHandler == pRoot->handler)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        status = pRoot->handler(NULL, NULL, pRoot, pIn, InSize,
                                pOut, OutSize, pOffset, direction, FALSE);
    }
    else
    {
        status = pRoot->handler(NULL, NULL, pRoot, pOut, OutSize,
                                pIn, InSize, pOffset, direction, FALSE);
    }

exit:
    return status;
}

/*
 * This utility function can be used to free a structure that was deserialized
 * that may contain pointers/lists etc allocated by the deserialization code.
 * Since deserialization knows how to allocate memory, the shadow structures
 * contain enough information to free any such memory allocated.
 */
MSTATUS TAP_SERIALIZE_freeDeserializedStructure(
        const tap_shadow_struct *pRoot,
        ubyte *pIn,
        ubyte4 InSize
)
{
    MSTATUS status = ERR_GENERAL;

    if ((NULL == pIn) || (NULL == pRoot) || (NULL == pRoot->handler))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = pRoot->handler(NULL, NULL, pRoot, pIn, InSize,
                            NULL, 0, NULL, TAP_SD_IN, TRUE);

exit:
    return status;
}

MOC_EXTERN const tap_shadow_struct *TAP_SERIALIZE_getUbyte2(
        void
)
{
    return &TAP_SHADOW_ubyte2;
}