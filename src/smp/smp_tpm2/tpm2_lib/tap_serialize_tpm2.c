/**
 * @file tap_serialize_tpm2.h
 * @brief This file contains the shadow structures for all structures related
 * to TPM2.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#include "../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__))

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#define __ENABLE_DIGICERT_TPM2__
#endif

#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/mstdlib.h"
#include "../../../common/debug_console.h"
#include "tpm2_types.h"
#include "fapi2/fapi2_types.h"
#include "tap_serialize_tpm2.h"

static MSTATUS TPM2_SERIALIZETPM2BHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
        ubyte4 maxUnserializedBuffSize,
        ubyte *pSerialized,
        ubyte4 maxSerializedBuffSize,
        ubyte4 *pSerializedOffset,
        TAP_SERIALIZE_DIRECTION direction,
         byteBoolean freeMemory
);

static MSTATUS TPM2_SERIALIZETPM2BStructHandler(
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

static MSTATUS TPM2_SERIALIZETPM2BHandler(
        const tap_shadow_struct *pParent,
        ubyte *pParentBuffer,
        const tap_shadow_struct *pCurrent,
        ubyte *pCurrentBuffer,
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
        return OK;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    if (NULL == pParent)
        goto exit;

    TPM2B_DIGEST *pInTpm2b = (TPM2B_DIGEST *)pCurrentBuffer;

    if (pParent->structSize < sizeof(ubyte2))
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != (status = ubyte2ToArray(pInTpm2b->size,
                &pSerialized[*pSerializedOffset])))
            goto exit;

    }
    else
    {

        if (OK != (status = arrayToUbyte2(&pSerialized[*pSerializedOffset],
                &pInTpm2b->size)))
            goto exit;

    }

    *pSerializedOffset = *pSerializedOffset + sizeof(ubyte2);

    if (0 == pInTpm2b->size)
    {
        status = OK;
        goto exit;
    }

    if (pParent->structSize < (pInTpm2b->size + sizeof(ubyte2)))
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (TAP_SD_IN == direction)
    {
        if (OK != (status = DIGI_MEMCPY(&pSerialized[*pSerializedOffset],
                pInTpm2b->buffer, pInTpm2b->size)))
            goto exit;
    }
    else
    {
        if (OK != (status = DIGI_MEMCPY(pInTpm2b->buffer,
                &pSerialized[*pSerializedOffset], pInTpm2b->size)))
            goto exit;
    }

    *pSerializedOffset = *pSerializedOffset + pInTpm2b->size;

    status = OK;
exit:
    return status;
}

/*
 * The TPM2 specifications have 2 types of sized buffers, one with
 * a size and a BYTE buffer, another with a size followed by another
 * TPM structure. TPM2_SHADOW_TPM2B_GENERIC handles the BYTE
 * buffers, and this case handles the TPM2B_* data structure with
 * a size followed by a structure. The main difference between the
 * two TPM2B types is that with the BYTE buffer, the size indicates
 * how much data should be marshaled and un-marshaled.
 * With the second type, we must back fill the number of bytes of
 * the structure that was marshaled. The size to be un-marshaled
 * is implied by the type of the struct, but the TPM expects the
 * size field to ensure it un-marshaled the correct amount of data.
 * TPM2 Part2 10.4 (sized buffers).
 */
static MSTATUS TPM2_SERIALIZETPM2BStructHandler(
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
    const tpm2_shadow_struct *pNextShadowStruct = NULL;
    ubyte4 oldSerializedOffset = 0;
    ubyte2 bytesWritten = 0;
    void *pSizePtr = NULL;

    if (freeMemory)
        return OK;

    status = TAP_SERIALIZE_ValidateCommonHandlerParams(
            pCurrent, pCurrentBuffer, pSerialized, maxSerializedBuffSize,
            pSerializedOffset, direction, freeMemory);
    if (OK != status)
        goto exit;

    /*
     * TPM2B_STRUCTS should have no more than one field. The size
     * field is implied by the fact that the structure is a TPM2B_
     * STRUCT.
     */
    if (pCurrent->numFields != 1)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /*
     * Advance pointer to , unserialized buffer by 2 bytes, for the
     * size field. Do the same for the serialized buffer. The size will
     * be back filled after serializing the structure.
     */
    pNextUnserialized = pCurrentBuffer + pCurrent->pFieldList[0].selectorOrOffset;

    oldSerializedOffset = *pSerializedOffset;
    *pSerializedOffset = *pSerializedOffset + sizeof(ubyte2);

    pNextShadowStruct = pCurrent->pFieldList[0].pField;

    status = pNextShadowStruct->handler(pCurrent, pCurrentBuffer,
            pNextShadowStruct, pNextUnserialized, pNextShadowStruct->structSize,
            pSerialized, maxSerializedBuffSize, pSerializedOffset,
            direction, freeMemory);

    if (OK != status)
        goto exit;

    bytesWritten = *pSerializedOffset - oldSerializedOffset -sizeof(ubyte2);

    if (TAP_SD_IN == direction)
    {
        if (OK != (status = ubyte2ToArray(bytesWritten,
                &pSerialized[oldSerializedOffset])))
            goto exit;
    }
    else
    {
        pSizePtr = pCurrentBuffer + pCurrent->unionSelectorOffset;
        if (OK != (status = arrayToUbyte2(&pSerialized[oldSerializedOffset],
                (ubyte2 *)pSizePtr)))
            goto exit;

        if (bytesWritten != (*(ubyte2 *)(pSizePtr)))
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }
    }

    status = OK;
exit:
    return status;
}

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_GENERIC = {
        .handler = TPM2_SERIALIZETPM2BHandler,
        .structSize = 0, /* since this is generic, we will use parents struct size */
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pSerialize = NULL,
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_NAME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_NAME),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_PRIVATE_KEY_RSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_PRIVATE_KEY_RSA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_SYM_KEY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_SYM_KEY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_IV = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_IV),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_ECC_PARAMETER = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_ECC_PARAMETER),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_PRIVATE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_PRIVATE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_DIGEST = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_DIGEST),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_MAX_BUFFER = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_MAX_BUFFER),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_EVENT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_EVENT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_MAX_NV_BUFFER = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_MAX_NV_BUFFER),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_ENCRYPTED_SECRET),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_ID_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_ID_OBJECT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_NONCE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_NONCE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_DIGEST},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_AUTH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_AUTH),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_DIGEST},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_SENSITIVE_DATA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_SENSITIVE_DATA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_HANDLE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_HANDLE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_SE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_SE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_GENERATED = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_GENERATED),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMA_SESSION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMA_SESSION),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMA_NV = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMA_NV),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMA_LOCALITY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMA_LOCALITY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_ALG_ID = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ALG_ID),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_ECC_CURVE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ECC_CURVE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_NV_INDEX = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_NV_INDEX),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_CLEAR = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_CLEAR),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

/* TPMI_RH_CLEAR interface type is used with Lockout handle */
const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_DA_LOCK_RESET = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_CLEAR),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_DA_LOCK_PARAMETERS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_DA_LOCKOUT_PARAMETERS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
            { TAP_OFFSETOF(TPM2_DA_LOCKOUT_PARAMETERS, newMaxTries), &TAP_SHADOW_ubyte4 },
            { TAP_OFFSETOF(TPM2_DA_LOCKOUT_PARAMETERS, newRecoveryTime), &TAP_SHADOW_ubyte4 },
            { TAP_OFFSETOF(TPM2_DA_LOCKOUT_PARAMETERS, lockoutRecovery), &TAP_SHADOW_ubyte4 }
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_ENABLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_ENABLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_DH_PCR = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_DH_PCR),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_DH_PERSISTENT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_DH_PERSISTENT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_NV_AUTH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_NV_AUTH),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_SH_AUTH_SESSION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_SH_AUTH_SESSION),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_DH_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_DH_OBJECT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_DH_ENTITY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_DH_ENTITY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_DH_CONTEXT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_DH_CONTEXT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_HIERARCHY_AUTH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_HIERARCHY_AUTH),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_PROVISION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_PROVISION),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RH_HIERARCHY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_RH_HIERARCHY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_HANDLE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_RSA_DECRYPT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_RSA_DECRYPT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_HASH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_HASH),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_KDF = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_KDF),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_NV_PUBLIC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_NV_PUBLIC),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_NV_PUBLIC, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
                {TAP_OFFSETOF(TPMS_NV_PUBLIC, nameAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMS_NV_PUBLIC, attributes), &TPM2_SHADOW_TPMA_NV},
                {TAP_OFFSETOF(TPMS_NV_PUBLIC, authPolicy), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPMS_NV_PUBLIC, dataSize), &TAP_SHADOW_ubyte2},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_PUBLIC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_PUBLIC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMA_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMA_OBJECT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_KEYEDHASH_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_PUBLIC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_SIG_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_SIG_SCHEME),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_HASH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_HASH),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPMS_SCHEME_HASH, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_HMAC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_HMAC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_XOR = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_XOR),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_SCHEME_XOR, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMS_SCHEME_XOR, kdf), &TPM2_SHADOW_TPMI_ALG_KDF},
        },
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_EMPTY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_EMPTY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_none},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_SCHEME_KEYEDHASH = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_SCHEME_KEYEDHASH),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_HMAC, &TPM2_SHADOW_TPMS_SCHEME_HMAC},
                {TPM2_ALG_XOR, &TPM2_SHADOW_TPMS_SCHEME_XOR},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPMU_SENSITIVE_COMPOSITE = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_SENSITIVE_COMPOSITE),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_RSA, &TPM2_SHADOW_TPM2B_PRIVATE_KEY_RSA},
                {TPM2_ALG_ECC, &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TPM2_ALG_KEYEDHASH, &TPM2_SHADOW_TPM2B_SENSITIVE_DATA},
                {TPM2_ALG_SYMCIPHER, &TPM2_SHADOW_TPM2B_SYM_KEY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_KEYEDHASH_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_KEYEDHASH_SCHEME),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_KEYEDHASH_SCHEME, scheme),
        .unionSelectorSize = sizeof(TPMI_ALG_KEYEDHASH_SCHEME),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_KEYEDHASH_SCHEME, scheme), &TPM2_SHADOW_TPMI_ALG_KEYEDHASH_SCHEME},
                {TAP_OFFSETOF(TPMT_KEYEDHASH_SCHEME, details), &TPM2_SHADOW_TPMU_SCHEME_KEYEDHASH},
        },
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_KEYEDHASH_PARMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_KEYEDHASH_PARMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPMS_KEYEDHASH_PARMS, scheme), &TPM2_SHADOW_TPMT_KEYEDHASH_SCHEME},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_SYM = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_SYM),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_SYM_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_SYM_OBJECT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_KEY_BITS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_KEY_BITS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_SM4_KEY_BITS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_SM4_KEY_BITS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_KEY_BITS},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_CAMELLIA_KEY_BITS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_CAMELLIA_KEY_BITS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_KEY_BITS},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_AES_KEY_BITS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_AES_KEY_BITS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_KEY_BITS},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_SYM_KEY_BITS = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_SYM_KEY_BITS),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_AES, &TPM2_SHADOW_TPMI_AES_KEY_BITS},
                {TPM2_ALG_SM4, &TPM2_SHADOW_TPMI_SM4_KEY_BITS},
                {TPM2_ALG_CAMELLIA, &TPM2_SHADOW_TPMI_CAMELLIA_KEY_BITS},
                {TPM2_ALG_SYMCIPHER, &TPM2_SHADOW_TPM2_KEY_BITS},
                {TPM2_ALG_XOR, &TPM2_SHADOW_TPMI_ALG_HASH},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_SYM_MODE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_SYM_MODE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_SYM_MODE = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_SYM_MODE),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_AES, &TPM2_SHADOW_TPMI_ALG_SYM_MODE},
                {TPM2_ALG_SM4, &TPM2_SHADOW_TPMI_ALG_SYM_MODE},
                {TPM2_ALG_CAMELLIA, &TPM2_SHADOW_TPMI_ALG_SYM_MODE},
                {TPM2_ALG_SYMCIPHER, &TPM2_SHADOW_TPMI_ALG_SYM_MODE},
                {TPM2_ALG_XOR, &TPM2_SHADOW_TPMS_EMPTY},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_SYM_DEF_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_SYM_DEF_OBJECT),
        .numFields = 3,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_SYM_DEF_OBJECT, algorithm),
        .unionSelectorSize = sizeof(TPMI_ALG_SYM_OBJECT),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_SYM_DEF_OBJECT, algorithm), &TPM2_SHADOW_TPMI_ALG_SYM_OBJECT},
                {TAP_OFFSETOF(TPMT_SYM_DEF_OBJECT, keyBits), &TPM2_SHADOW_TPMU_SYM_KEY_BITS},
                {TAP_OFFSETOF(TPMT_SYM_DEF_OBJECT, mode), &TPM2_SHADOW_TPMU_SYM_MODE},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_SYM_DEF = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_SYM_DEF),
        .numFields = 3,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_SYM_DEF, algorithim),
        .unionSelectorSize = sizeof(TPMI_ALG_SYM),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_SYM_DEF, algorithim), &TPM2_SHADOW_TPMI_ALG_SYM},
                {TAP_OFFSETOF(TPMT_SYM_DEF, keyBits), &TPM2_SHADOW_TPMU_SYM_KEY_BITS},
                {TAP_OFFSETOF(TPMT_SYM_DEF, mode), &TPM2_SHADOW_TPMU_SYM_MODE}
        },
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SYMCIPHER_PARMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SYMCIPHER_PARMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPMS_SYMCIPHER_PARMS, sym), &TPM2_SHADOW_TPMT_SYM_DEF_OBJECT},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_KEY_SCHEME_ECDH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_KEY_SCHEME_ECDH),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_KEY_SCHEME_ECMQV = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_KEY_SCHEME_ECMQV),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIG_SCHEME_RSASSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIG_SCHEME_RSASSA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIG_SCHEME_RSAPSS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIG_SCHEME_RSAPSS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIG_SCHEME_ECDSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIG_SCHEME_ECDSA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_ECDAA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_ECDAA),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_SCHEME_ECDAA, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMS_SCHEME_ECDAA, count), &TAP_SHADOW_ubyte2}
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIG_SCHEME_ECDAA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIG_SCHEME_ECDAA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_ECDAA},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIG_SCHEME_SM2 = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIG_SCHEME_SM2),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIG_SCHEME_ECSCHNORR = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIG_SCHEME_ECSCHNORR),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ENC_SCHEME_RSAES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ENC_SCHEME_RSAES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_EMPTY},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ENC_SCHEME_OAEP = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ENC_SCHEME_OAEP),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_ASYM_SCHEME = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_ASYM_SCHEME),
        .numFields = 11,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_ECDH, &TPM2_SHADOW_TPMS_KEY_SCHEME_ECDH},
                {TPM2_ALG_ECMQV, &TPM2_SHADOW_TPMS_KEY_SCHEME_ECMQV},
                {TPM2_ALG_RSASSA, &TPM2_SHADOW_TPMS_SIG_SCHEME_RSASSA},
                {TPM2_ALG_RSAPSS, &TPM2_SHADOW_TPMS_SIG_SCHEME_RSAPSS},
                {TPM2_ALG_ECDSA, &TPM2_SHADOW_TPMS_SIG_SCHEME_ECDSA},
                {TPM2_ALG_ECDAA, &TPM2_SHADOW_TPMS_SIG_SCHEME_ECDAA},
                {TPM2_ALG_SM2, &TPM2_SHADOW_TPMS_SIG_SCHEME_SM2},
                {TPM2_ALG_ECSCHNORR, &TPM2_SHADOW_TPMS_SIG_SCHEME_ECSCHNORR},
                {TPM2_ALG_RSAES, &TPM2_SHADOW_TPMS_ENC_SCHEME_RSAES},
                {TPM2_ALG_OAEP, &TPM2_SHADOW_TPMS_ENC_SCHEME_OAEP},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_RSA_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_RSA_SCHEME),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ID_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ID_OBJECT),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_ID_OBJECT, integrityHMAC), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPMS_ID_OBJECT, encIdentity), &TPM2_SHADOW_TPM2B_DIGEST},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_RSA_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_RSA_SCHEME),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_RSA_SCHEME, scheme),
        .unionSelectorSize = sizeof(TPMI_ALG_RSA_SCHEME),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_RSA_SCHEME, scheme), &TPM2_SHADOW_TPMI_ALG_RSA_SCHEME},
                {TAP_OFFSETOF(TPMT_RSA_SCHEME, details), &TPM2_SHADOW_TPMU_ASYM_SCHEME},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_RSA_KEY_BITS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_SM4_KEY_BITS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_KEY_BITS},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_RSA_PARMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_RSA_PARMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_RSA_PARMS, symmetric), &TPM2_SHADOW_TPMT_SYM_DEF_OBJECT},
                {TAP_OFFSETOF(TPMS_RSA_PARMS, scheme), &TPM2_SHADOW_TPMT_RSA_SCHEME},
                {TAP_OFFSETOF(TPMS_RSA_PARMS, keyBits), &TPM2_SHADOW_TPMI_RSA_KEY_BITS},
                {TAP_OFFSETOF(TPMS_RSA_PARMS, exponent), &TAP_SHADOW_ubyte4},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ALG_ECC_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ALG_ECC_SCHEME),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ALG_ID},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_ECC_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_ECC_SCHEME),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_ECC_SCHEME, scheme),
        .unionSelectorSize = sizeof(TPMI_ALG_ECC_SCHEME),

        .pFieldList = {
                {TAP_OFFSETOF(TPMT_ECC_SCHEME, scheme), &TPM2_SHADOW_TPMI_ALG_ECC_SCHEME},
                {TAP_OFFSETOF(TPMT_ECC_SCHEME, details),&TPM2_SHADOW_TPMU_ASYM_SCHEME},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ECC_CURVE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ECC_CURVE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ECC_CURVE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_MGF1 = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_MGF1),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_KDF1_SP800_56A = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_KDF1_SP800_56A),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_KDF2 = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_KDF2),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SCHEME_KDF1_SP800_108 = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SCHEME_KDF1_SP800_108),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SCHEME_HASH},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_KDF_SCHEME = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_KDF_SCHEME),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_MGF1, &TPM2_SHADOW_TPMS_SCHEME_MGF1},
                {TPM2_ALG_KDF1_SP800_56A, &TPM2_SHADOW_TPMS_SCHEME_KDF1_SP800_56A},
                {TPM2_ALG_KDF2, &TPM2_SHADOW_TPMS_SCHEME_KDF2},
                {TPM2_ALG_KDF1_SP800_108, &TPM2_SHADOW_TPMS_SCHEME_KDF1_SP800_108},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_KDF_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_KDF_SCHEME),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_KDF_SCHEME, scheme),
        .unionSelectorSize = sizeof(TPMI_ALG_KDF),

        .pFieldList = {
                {TAP_OFFSETOF(TPMT_KDF_SCHEME, scheme), &TPM2_SHADOW_TPMI_ALG_KDF},
                {TAP_OFFSETOF(TPMT_KDF_SCHEME, details), &TPM2_SHADOW_TPMU_KDF_SCHEME},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ECC_PARMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ECC_PARMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_ECC_PARMS, symmetric), &TPM2_SHADOW_TPMT_SYM_DEF_OBJECT},
                {TAP_OFFSETOF(TPMS_ECC_PARMS, scheme), &TPM2_SHADOW_TPMT_ECC_SCHEME},
                {TAP_OFFSETOF(TPMS_ECC_PARMS, curveID), &TPM2_SHADOW_TPMI_ECC_CURVE},
                {TAP_OFFSETOF(TPMS_ECC_PARMS, kdf), &TPM2_SHADOW_TPMT_KDF_SCHEME},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_PUBLIC_PARMS = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_PUBLIC_PARMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_KEYEDHASH, &TPM2_SHADOW_TPMS_KEYEDHASH_PARMS},
                {TPM2_ALG_SYMCIPHER, &TPM2_SHADOW_TPMS_SYMCIPHER_PARMS},
                {TPM2_ALG_RSA, &TPM2_SHADOW_TPMS_RSA_PARMS},
                {TPM2_ALG_ECC, &TPM2_SHADOW_TPMS_ECC_PARMS},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_PUBLIC_KEY_RSA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ECC_POINT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ECC_POINT),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_ECC_POINT, x), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ECC_POINT, y), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_DATA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_DATA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_ATTEST = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2B_ATTEST),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_PUBLIC_ID = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_PUBLIC_ID),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_KEYEDHASH, &TPM2_SHADOW_TPM2B_DIGEST},
                {TPM2_ALG_SYMCIPHER, &TPM2_SHADOW_TPM2B_DIGEST},
                {TPM2_ALG_RSA, &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TPM2_ALG_ECC, &TPM2_SHADOW_TPMS_ECC_POINT},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_PUBLIC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_PUBLIC),
        .numFields = 6,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_PUBLIC, type),
        .unionSelectorSize = sizeof(TPMI_ALG_PUBLIC),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_PUBLIC, type), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
                {TAP_OFFSETOF(TPMT_PUBLIC, nameAlg),&TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMT_PUBLIC, objectAttributes),&TPM2_SHADOW_TPMA_OBJECT},
                {TAP_OFFSETOF(TPMT_PUBLIC, authPolicy),&TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPMT_PUBLIC, parameters),&TPM2_SHADOW_TPMU_PUBLIC_PARMS},
                {TAP_OFFSETOF(TPMT_PUBLIC, unique),&TPM2_SHADOW_TPMU_PUBLIC_ID},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_ST = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ST),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ST_ATTEST = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ST_ATTEST),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ST},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_CC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_CC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_RC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_RC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_ST_COMMAND_TAG = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_ST_COMMAND_TAG),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_ST},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_COMMAND_HEADER = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_COMMAND_HEADER),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_COMMAND_HEADER, tag), &TPM2_SHADOW_TPMI_ST_COMMAND_TAG},
                {TAP_OFFSETOF(TPM2_COMMAND_HEADER, commandSize), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPM2_COMMAND_HEADER, commandCode), &TPM2_SHADOW_TPM2_CC},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_RESPONSE_HEADER = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_RESPONSE_HEADER),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_RESPONSE_HEADER, tag), &TPM2_SHADOW_TPM2_ST},
                {TAP_OFFSETOF(TPM2_RESPONSE_HEADER, responseSize), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPM2_RESPONSE_HEADER, responseCode), &TPM2_SHADOW_TPM2_RC}
        },
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_AUTH_COMMAND = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_AUTH_COMMAND),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_AUTH_COMMAND, sessionHandle), &TPM2_SHADOW_TPMI_SH_AUTH_SESSION},
                {TAP_OFFSETOF(TPMS_AUTH_COMMAND, nonce), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPMS_AUTH_COMMAND, sessionAttributes), &TPM2_SHADOW_TPMA_SESSION},
                {TAP_OFFSETOF(TPMS_AUTH_COMMAND, hmac), &TPM2_SHADOW_TPM2B_AUTH}
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_AUTH_RESPONSE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_AUTH_RESPONSE),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_AUTH_RESPONSE, nonce), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPMS_AUTH_RESPONSE, sessionAttributes), &TPM2_SHADOW_TPMA_SESSION},
                {TAP_OFFSETOF(TPMS_AUTH_RESPONSE, hmac), &TPM2_SHADOW_TPM2B_AUTH},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_START_AUTH_SESSION_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_START_AUTH_SESSION_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_HANDLES, tpmKey), &TPM2_SHADOW_TPMI_DH_OBJECT},
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_HANDLES, bind), &TPM2_SHADOW_TPMI_DH_ENTITY}
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_CAP = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_CAP),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_GET_CAPABILITY_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_GET_CAPABILITY_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_GET_CAPABILITY_CMD_PARAMS, capability), &TPM2_SHADOW_TPM2_CAP},
                {TAP_OFFSETOF(TPM2_GET_CAPABILITY_CMD_PARAMS, property), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPM2_GET_CAPABILITY_CMD_PARAMS, propertyCount), &TAP_SHADOW_ubyte4},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMA_ALGORITHM = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMA_ALGORITHM),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ALG_PROPERTY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ALG_PROPERTY),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_ALG_PROPERTY, alg), &TPM2_SHADOW_TPM2_ALG_ID},
                {TAP_OFFSETOF(TPMS_ALG_PROPERTY, algProperties), &TPM2_SHADOW_TPMA_ALGORITHM}
        }
};

const tap_shadow_struct TPM2_SHADOW_SHA_BUFFER = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = TPM2_SHA_DIGEST_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tap_shadow_struct TPM2_SHADOW_SHA1_BUFFER = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = TPM2_SHA1_DIGEST_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tap_shadow_struct TPM2_SHADOW_SHA256_BUFFER = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = TPM2_SHA256_DIGEST_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tap_shadow_struct TPM2_SHADOW_SHA384_BUFFER = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = TPM2_SHA384_DIGEST_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tap_shadow_struct TPM2_SHADOW_SHA512_BUFFER = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = TPM2_SHA512_DIGEST_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tap_shadow_struct TPM2_SHADOW_SM3_256_BUFFER = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = TPM2_SM3_256_DIGEST_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_HA = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_HA),
        .numFields = 7,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_SHA, &TPM2_SHADOW_SHA_BUFFER},
                {TPM2_ALG_SHA1, &TPM2_SHADOW_SHA1_BUFFER},
                {TPM2_ALG_SHA256, &TPM2_SHADOW_SHA256_BUFFER},
                {TPM2_ALG_SHA384, &TPM2_SHADOW_SHA384_BUFFER},
                {TPM2_ALG_SHA512, &TPM2_SHADOW_SHA512_BUFFER},
                {TPM2_ALG_SM3_256, &TPM2_SHADOW_SM3_256_BUFFER},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},

        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_HA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_HA),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_HA, hashAlg),
        .unionSelectorSize = sizeof(TPMI_ALG_HASH),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_HA, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMT_HA, digest), &TPM2_SHADOW_TPMU_HA},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_ALG_PROPERTY = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_ALG_PROPERTY),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_ALG_PROPERTY, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_ALG_PROPERTY, algProperties[0]), &TPM2_SHADOW_TPMS_ALG_PROPERTY}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_DIGEST = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_DIGEST),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_DIGEST, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_DIGEST, digests[0]), &TPM2_SHADOW_TPM2B_DIGEST}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_DIGEST_VALUES = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_DIGEST_VALUES),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_DIGEST_VALUES, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_DIGEST_VALUES, digests), &TPM2_SHADOW_TPMT_HA}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_HANDLE = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_HANDLE),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_HANDLE, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_HANDLE, handle[0]), &TPM2_SHADOW_TPM2_HANDLE}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMA_CC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMA_CC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPML_CCA = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_CCA),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_CCA, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_CCA, commandAttributes[0]), &TPM2_SHADOW_TPMA_CC}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_CC = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_CC),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_CC, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_CC, commandCodes[0]), &TPM2_SHADOW_TPM2_CC}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_PCR_SELECT = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPMS_PCR_SELECT),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPMS_PCR_SELECT, sizeofSelect),
        .unionSelectorSize = sizeof(ubyte),
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_PCR_SELECT, pcrSelect[0]), &TAP_SHADOW_ubyte}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_PCR_SELECTION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_PCR_SELECTION),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_PCR_SELECTION, hash), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMS_PCR_SELECTION, sizeofSelect), &TPM2_SHADOW_TPML_PCR_SELECT}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_PCR_SELECTION = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_PCR_SELECTION),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_PCR_SELECTION, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_PCR_SELECTION, pcrSelections[0]), &TPM2_SHADOW_TPMS_PCR_SELECTION}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_PT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_PT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_TAGGED_PROPERTY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_TAGGED_PROPERTY),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_TAGGED_PROPERTY, property), &TPM2_SHADOW_TPM2_PT},
                {TAP_OFFSETOF(TPMS_TAGGED_PROPERTY, value), &TAP_SHADOW_ubyte4}
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPML_TAGGED_TPM_PROPERTY = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_TAGGED_TPM_PROPERTY),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_TAGGED_TPM_PROPERTY, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_TAGGED_TPM_PROPERTY, tpmProperty[0]), &TPM2_SHADOW_TPMS_TAGGED_PROPERTY}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_TAGGED_PCR_SELECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_TAGGED_PCR_SELECT),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_TAGGED_PCR_SELECT, tag), &TPM2_SHADOW_TPM2_PT},
                {TAP_OFFSETOF(TPMS_TAGGED_PCR_SELECT, sizeOfSelect), &TPM2_SHADOW_TPML_PCR_SELECT}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_TAGGED_PCR_PROPERTY = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_TAGGED_PCR_PROPERTY),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_TAGGED_PCR_PROPERTY, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_TAGGED_PCR_PROPERTY, pcrProperty[0]), &TPM2_SHADOW_TPMS_TAGGED_PCR_SELECT}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPML_ECC_CURVE = {
        .handler = TAP_SERIALIZE_ArrayListTypeHandler,
        .structSize = sizeof(TPML_ECC_CURVE),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPML_ECC_CURVE, count),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {
                {TAP_OFFSETOF(TPML_ECC_CURVE, eccCurves[0]), &TPM2_SHADOW_TPM2_ECC_CURVE}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_CAPABILITY_DATA = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_CAPABILITIES),
        .numFields = 9,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_CAP_ALGS, &TPM2_SHADOW_TPML_ALG_PROPERTY},
                {TPM2_CAP_HANDLES, &TPM2_SHADOW_TPML_HANDLE},
                {TPM2_CAP_COMMANDS, &TPM2_SHADOW_TPML_CCA},
                {TPM2_CAP_PP_COMMANDS, &TPM2_SHADOW_TPML_CC},
                {TPM2_CAP_AUDIT_COMMANDS, &TPM2_SHADOW_TPML_CC},
                {TPM2_CAP_PCRS, &TPM2_SHADOW_TPML_PCR_SELECTION},
                {TPM2_CAP_TPM_PROPERTIES, &TPM2_SHADOW_TPML_TAGGED_TPM_PROPERTY},
                {TPM2_CAP_PCR_PROPERTIES, &TPM2_SHADOW_TPML_TAGGED_PCR_PROPERTY},
                {TPM2_CAP_ECC_CURVES, &TPM2_SHADOW_TPML_ECC_CURVE}

        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_CAPABILITY_DATA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_CAPABILITY_DATA),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMS_CAPABILITY_DATA, capability),
        .unionSelectorSize = sizeof(TPM2_CAP),

        .pFieldList = {
                {TAP_OFFSETOF(TPMS_CAPABILITY_DATA, capability), &TPM2_SHADOW_TPM2_CAP},
                {TAP_OFFSETOF(TPMS_CAPABILITY_DATA, data), &TPM2_SHADOW_TPMU_CAPABILITY_DATA}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMI_YES_NO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMI_YES_NO),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_GET_CAPABILITY_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_GET_CAPABILITY_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_GET_CAPABILITY_RSP_PARAMS, moreData), &TPM2_SHADOW_TPMI_YES_NO},
                {TAP_OFFSETOF(TPM2_GET_CAPABILITY_RSP_PARAMS, capabilityData), &TPM2_SHADOW_TPMS_CAPABILITY_DATA}
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SENSITIVE_CREATE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SENSITIVE_CREATE),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_SENSITIVE_CREATE, userAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(TPMS_SENSITIVE_CREATE, data), &TPM2_SHADOW_TPM2B_SENSITIVE_DATA}
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_SENSITIVE_CREATE = {
        .handler = TPM2_SERIALIZETPM2BStructHandler,
        .structSize = sizeof(TPM2B_SENSITIVE_CREATE),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPM2B_SENSITIVE_CREATE, size),
        .unionSelectorSize = SIZEOF(TPM2B_SENSITIVE_CREATE, size),
        .pFieldList = {{TAP_OFFSETOF(TPM2B_SENSITIVE_CREATE, sensitive), &TPM2_SHADOW_TPMS_SENSITIVE_CREATE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_PUBLIC = {
        .handler = TPM2_SERIALIZETPM2BStructHandler,
        .structSize = sizeof(TPM2B_PUBLIC),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPM2B_PUBLIC, size),
        .unionSelectorSize = SIZEOF(TPM2B_PUBLIC, size),
        .pFieldList = {{TAP_OFFSETOF(TPM2B_PUBLIC, publicArea), &TPM2_SHADOW_TPMT_PUBLIC},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_NV_PUBLIC = {
        .handler = TPM2_SERIALIZETPM2BStructHandler,
        .structSize = sizeof(TPM2B_NV_PUBLIC),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPM2B_NV_PUBLIC, size),
        .unionSelectorSize = SIZEOF(TPM2B_NV_PUBLIC, size),
        .pFieldList = {{TAP_OFFSETOF(TPM2B_NV_PUBLIC, nvPublic), &TPM2_SHADOW_TPMS_NV_PUBLIC},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_START_AUTH_SESSION_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_START_AUTH_SESSION_CMD_PARAMS),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_PARAMS, nonceCaller), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_PARAMS, encryptedSalt), &TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET},
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_PARAMS, sessionType), &TPM2_SHADOW_TPM2_SE},
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_PARAMS, symmetric), &TPM2_SHADOW_TPMT_SYM_DEF},
                {TAP_OFFSETOF(TPM2_START_AUTH_SESSION_CMD_PARAMS, authHash), &TPM2_SHADOW_TPMI_ALG_HASH},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_START_AUTH_SESSION_RSP_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_START_AUTH_SESSION_RSP_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPM2_START_AUTH_SESSION_RSP_HANDLES, sessionHandle), &TPM2_SHADOW_TPMI_SH_AUTH_SESSION},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_START_AUTH_SESSION_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_START_AUTH_SESSION_RSP_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPM2_START_AUTH_SESSION_RSP_PARAMS, nonceTPM), &TPM2_SHADOW_TPM2B_NONCE},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_CREATION_DATA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_CREATION_DATA),
        .numFields = 7,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_CREATION_DATA, pcrSelect), &TPM2_SHADOW_TPML_PCR_SELECTION},
                {TAP_OFFSETOF(TPMS_CREATION_DATA, pcrDigest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPMS_CREATION_DATA, locality), &TPM2_SHADOW_TPMA_LOCALITY},
                {TAP_OFFSETOF(TPMS_CREATION_DATA, parentNameAlg), &TPM2_SHADOW_TPM2_ALG_ID},
                {TAP_OFFSETOF(TPMS_CREATION_DATA, parentName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPMS_CREATION_DATA, parentQualifiedName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPMS_CREATION_DATA, outsideInfo), &TPM2_SHADOW_TPM2B_DATA},
        },
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_CREATION_DATA = {
        .handler = TPM2_SERIALIZETPM2BStructHandler,
        .structSize = sizeof(TPM2B_CREATION_DATA),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPM2B_CREATION_DATA, size),
        .unionSelectorSize = SIZEOF(TPM2B_CREATION_DATA, size),
        .pFieldList = {{TAP_OFFSETOF(TPM2B_CREATION_DATA, creationData), &TPM2_SHADOW_TPMS_CREATION_DATA},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_TK_CREATION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_TK_CREATION),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_TK_CREATION, tag), &TPM2_SHADOW_TPM2_ST},
                {TAP_OFFSETOF(TPMT_TK_CREATION, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
                {TAP_OFFSETOF(TPMT_TK_CREATION, digest), &TPM2_SHADOW_TPM2B_DIGEST},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_TK_AUTH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_TK_AUTH),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_TK_AUTH, tag), &TPM2_SHADOW_TPM2_ST},
                {TAP_OFFSETOF(TPMT_TK_AUTH, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
                {TAP_OFFSETOF(TPMT_TK_AUTH, digest), &TPM2_SHADOW_TPM2B_DIGEST},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ALGORITHM_DETAIL_ECC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ALGORITHM_DETAIL_ECC),
        .numFields = 11,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, curveID), &TPM2_SHADOW_TPM2_ECC_CURVE},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, keySize), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, kdf), &TPM2_SHADOW_TPMT_KDF_SCHEME},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, sign), &TPM2_SHADOW_TPMT_ECC_SCHEME},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, p), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, a), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, b), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, gX), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, gY), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, n), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_ALGORITHM_DETAIL_ECC, h), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_RSA_DECRYPT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_RSA_DECRYPT),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_RSA_DECRYPT, scheme),
        .unionSelectorSize = sizeof(TPMI_ALG_RSA_DECRYPT),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_RSA_DECRYPT, scheme), &TPM2_SHADOW_TPMI_ALG_RSA_DECRYPT},
                {TAP_OFFSETOF(TPMT_RSA_DECRYPT, details), &TPM2_SHADOW_TPMU_ASYM_SCHEME},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_SENSITIVE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_SENSITIVE),
        .numFields = 4,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_SENSITIVE, sensitiveType),
        .unionSelectorSize = sizeof(TPMI_ALG_PUBLIC),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_SENSITIVE, sensitiveType), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
                {TAP_OFFSETOF(TPMT_SENSITIVE, authValue), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(TPMT_SENSITIVE, seedValue), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPMT_SENSITIVE, sensitive), &TPM2_SHADOW_TPMU_SENSITIVE_COMPOSITE},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2B_SENSITIVE = {
        .handler = TPM2_SERIALIZETPM2BStructHandler,
        .structSize = sizeof(TPM2B_SENSITIVE),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TPM2B_SENSITIVE, size),
        .unionSelectorSize = SIZEOF(TPM2B_SENSITIVE, size),
        .pFieldList = {{TAP_OFFSETOF(TPM2B_SENSITIVE, sensitiveArea), &TPM2_SHADOW_TPMT_SENSITIVE},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_RSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_RSA),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_SIGNATURE_RSA, hash), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMS_SIGNATURE_RSA, sig), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_RSASSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_RSASSA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SIGNATURE_RSA,},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_RSAPSS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_RSAPSS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SIGNATURE_RSA,},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_ECC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_ECC),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_SIGNATURE_ECC, hash), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(TPMS_SIGNATURE_ECC, signatureR), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(TPMS_SIGNATURE_ECC, signatureS), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
            },

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_ECDSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_ECDSA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SIGNATURE_ECC,},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_ECDAA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_ECDAA),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SIGNATURE_ECC,},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_SM2 = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_SM2),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SIGNATURE_ECC,},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SIGNATURE_ECSCHNORR = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SIGNATURE_ECSCHNORR),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPMS_SIGNATURE_ECC,},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_SIGNATURE = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_SIGNATURE),
        .numFields = 8,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_RSASSA, &TPM2_SHADOW_TPMS_SIGNATURE_RSASSA},
                {TPM2_ALG_RSAPSS, &TPM2_SHADOW_TPMS_SIGNATURE_RSAPSS},
                {TPM2_ALG_ECDSA, &TPM2_SHADOW_TPMS_SIGNATURE_ECDSA},
                {TPM2_ALG_ECDAA, &TPM2_SHADOW_TPMS_SIGNATURE_ECDAA},
                {TPM2_ALG_SM2, &TPM2_SHADOW_TPMS_SIGNATURE_SM2},
                {TPM2_ALG_ECSCHNORR, &TPM2_SHADOW_TPMS_SIGNATURE_ECSCHNORR},
                {TPM2_ALG_HMAC, &TPM2_SHADOW_TPMT_HA},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_SIGNATURE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_SIGNATURE),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_SIGNATURE, sigAlg),
        .unionSelectorSize = sizeof(TPMI_ALG_SIG_SCHEME),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_SIGNATURE, sigAlg), &TPM2_SHADOW_TPMI_ALG_SIG_SCHEME},
                {TAP_OFFSETOF(TPMT_SIGNATURE, signature), &TPM2_SHADOW_TPMU_SIGNATURE},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_SIG_SCHEME = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_SIG_SCHEME),
        .numFields = 8,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_RSASSA, &TPM2_SHADOW_TPMS_SIG_SCHEME_RSASSA},
                {TPM2_ALG_RSAPSS, &TPM2_SHADOW_TPMS_SIG_SCHEME_RSAPSS},
                {TPM2_ALG_ECDSA, &TPM2_SHADOW_TPMS_SIG_SCHEME_ECDSA},
                {TPM2_ALG_ECDAA, &TPM2_SHADOW_TPMS_SIG_SCHEME_ECDAA},
                {TPM2_ALG_SM2, &TPM2_SHADOW_TPMS_SIG_SCHEME_SM2},
                {TPM2_ALG_ECSCHNORR, &TPM2_SHADOW_TPMS_SIG_SCHEME_ECSCHNORR},
                {TPM2_ALG_HMAC, &TPM2_SHADOW_TPMS_SCHEME_HMAC},
                {TPM2_ALG_NULL, &TPM2_SHADOW_TPMS_EMPTY},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_SIG_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_SIG_SCHEME),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TPMT_SIG_SCHEME, scheme),
        .unionSelectorSize = sizeof(TPMI_ALG_SIG_SCHEME),
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_SIG_SCHEME, scheme), &TPM2_SHADOW_TPMI_ALG_SIG_SCHEME},
                {TAP_OFFSETOF(TPMT_SIG_SCHEME, details), &TPM2_SHADOW_TPMU_SIG_SCHEME},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_TK_HASHCHECK = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_TK_HASHCHECK),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_TK_HASHCHECK, tag), &TPM2_SHADOW_TPM2_ST},
                {TAP_OFFSETOF(TPMT_TK_HASHCHECK, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
                {TAP_OFFSETOF(TPMT_TK_HASHCHECK, digest), &TPM2_SHADOW_TPM2B_DIGEST},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPMT_TK_VERIFIED = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMT_TK_VERIFIED),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMT_TK_VERIFIED, tag), &TPM2_SHADOW_TPM2_ST},
                {TAP_OFFSETOF(TPMT_TK_VERIFIED, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
                {TAP_OFFSETOF(TPMT_TK_VERIFIED, digest), &TPM2_SHADOW_TPM2B_DIGEST},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_CREATE_PRIMARY_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_CREATE_PRIMARY_CMD_PARAMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_CMD_PARAMS, inSensitive), &TPM2_SHADOW_TPM2B_SENSITIVE_CREATE},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_CMD_PARAMS, inPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_CMD_PARAMS, outsideInfo), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_CMD_PARAMS, creationPCR), &TPM2_SHADOW_TPML_PCR_SELECTION},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_CREATE_PRIMARY_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_CREATE_PRIMARY_RSP_PARAMS),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_RSP_PARAMS, outPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_RSP_PARAMS, creationData), &TPM2_SHADOW_TPM2B_CREATION_DATA},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_RSP_PARAMS, creationHash), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_RSP_PARAMS, creationTicket), &TPM2_SHADOW_TPMT_TK_CREATION},
                {TAP_OFFSETOF(TPM2_CREATE_PRIMARY_RSP_PARAMS, name), &TPM2_SHADOW_TPM2B_NAME},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_CREATE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_CREATE_CMD_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_CREATE_PRIMARY_CMD_PARAMS},},

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_CREATE_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_CREATE_RSP_PARAMS),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_CREATE_RSP_PARAMS, outPrivate), &TPM2_SHADOW_TPM2B_PRIVATE},
                {TAP_OFFSETOF(TPM2_CREATE_RSP_PARAMS, outPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_CREATE_RSP_PARAMS, creationData), &TPM2_SHADOW_TPM2B_CREATION_DATA},
                {TAP_OFFSETOF(TPM2_CREATE_RSP_PARAMS, creationHash), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_CREATE_RSP_PARAMS, creationTicket), &TPM2_SHADOW_TPMT_TK_CREATION},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_DUPLICATE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_DUPLICATE_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_DUPLICATE_CMD_PARAMS, encryptKeyIn), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(TPM2_DUPLICATE_CMD_PARAMS, symmetricAlg), &TPM2_SHADOW_TPMT_SYM_DEF_OBJECT},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_DUPLICATE_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_DUPLICATE_RSP_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_DUPLICATE_RSP_PARAMS, encryptionKeyOut), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(TPM2_DUPLICATE_RSP_PARAMS, duplicate), &TPM2_SHADOW_TPM2B_PRIVATE},
                {TAP_OFFSETOF(TPM2_DUPLICATE_RSP_PARAMS, outSymSeed), &TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_DuplicateOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_DuplicateOut),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(FAPI2_DuplicateOut, encryptionKeyOut), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(FAPI2_DuplicateOut, duplicate), &TPM2_SHADOW_TPM2B_PRIVATE},
                {TAP_OFFSETOF(FAPI2_DuplicateOut, outSymSeed), &TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET},
                {TAP_OFFSETOF(FAPI2_DuplicateOut, symmetricAlg), &TPM2_SHADOW_TPMT_SYM_DEF_OBJECT},
                {TAP_OFFSETOF(FAPI2_DuplicateOut, objectPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_DUPLICATE_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_DUPLICATE_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_DUPLICATE_CMD_HANDLES, objectHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
                {TAP_OFFSETOF(TPM2_DUPLICATE_CMD_HANDLES, newParentHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_IMPORT_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_IMPORT_CMD_PARAMS),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_IMPORT_CMD_PARAMS, encryptionKey), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(TPM2_IMPORT_CMD_PARAMS, objectPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_IMPORT_CMD_PARAMS, duplicate), &TPM2_SHADOW_TPM2B_PRIVATE},
                {TAP_OFFSETOF(TPM2_IMPORT_CMD_PARAMS, inSymSeed), &TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET},
                {TAP_OFFSETOF(TPM2_IMPORT_CMD_PARAMS, symmetricAlg), &TPM2_SHADOW_TPMT_SYM_DEF_OBJECT},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_IMPORT_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_IMPORT_RSP_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_IMPORT_RSP_PARAMS, outPrivate), &TPM2_SHADOW_TPM2B_PRIVATE},
        },

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_LOAD_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_LOAD_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_LOAD_CMD_PARAMS, inPrivate), &TPM2_SHADOW_TPM2B_PRIVATE},
                {TAP_OFFSETOF(TPM2_LOAD_CMD_PARAMS, inPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
        },
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_LOAD_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_LOAD_RSP_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPM2_LOAD_RSP_PARAMS, name), &TPM2_SHADOW_TPM2B_NAME,},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_FLUSH_CONTEXT_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_FLUSH_CONTEXT_CMD_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPM2_FLUSH_CONTEXT_CMD_PARAMS, flushHandle), &TPM2_SHADOW_TPMI_DH_CONTEXT},},
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_NV_DEFINE_SPACE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_DEFINE_SPACE_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_NV_DEFINE_SPACE_CMD_PARAMS, auth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(TPM2_NV_DEFINE_SPACE_CMD_PARAMS, publicInfo), &TPM2_SHADOW_TPM2B_NV_PUBLIC},
        },

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES, authHandle), &TPM2_SHADOW_TPMI_RH_PROVISION},
                {TAP_OFFSETOF(TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
        },

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_WRITE_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_NV_WRITE_CMD_HANDLES, authHandle), &TPM2_SHADOW_TPMI_RH_NV_AUTH},
                {TAP_OFFSETOF(TPM2_NV_WRITE_CMD_HANDLES, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
        },

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_WRITE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_WRITE_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_NV_WRITE_CMD_PARAMS, data), &TPM2_SHADOW_TPM2B_MAX_NV_BUFFER},
                {TAP_OFFSETOF(TPM2_NV_WRITE_CMD_PARAMS, offset), &TAP_SHADOW_ubyte2},
        },

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_READ_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_READ_CMD_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES},},

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_READ_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_READ_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_NV_READ_CMD_PARAMS, size), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TPM2_NV_READ_CMD_PARAMS, offset), &TAP_SHADOW_ubyte2},
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_READ_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_READ_RSP_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(TPM2_NV_READ_RSP_PARAMS, data), &TPM2_SHADOW_TPM2B_MAX_NV_BUFFER,},},

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_READ_PUBLIC_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_READ_PUBLIC_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_NV_READ_PUBLIC_RSP_PARAMS, nvPublic), &TPM2_SHADOW_TPM2B_NV_PUBLIC},
                {TAP_OFFSETOF(TPM2_NV_READ_PUBLIC_RSP_PARAMS, nvName), &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_PCR_READ_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_PCR_READ_RSP_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_PCR_READ_RSP_PARAMS, pcrUpdateCounter), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPM2_PCR_READ_RSP_PARAMS, pcrSelectionOut), &TPM2_SHADOW_TPML_PCR_SELECTION},
                {TAP_OFFSETOF(TPM2_PCR_READ_RSP_PARAMS, pcrValues), &TPM2_SHADOW_TPML_DIGEST},
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_GET_TEST_RESULT_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_GET_TEST_RESULT_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_GET_TEST_RESULT_RSP_PARAMS, outData), &TPM2_SHADOW_TPM2B_MAX_BUFFER},
                {TAP_OFFSETOF(TPM2_GET_TEST_RESULT_RSP_PARAMS, testResult), &TPM2_SHADOW_TPM2_RC},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_READ_PUBLIC_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_READ_PUBLIC_RSP_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_READ_PUBLIC_RSP_PARAMS, outPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_READ_PUBLIC_RSP_PARAMS, name),&TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPM2_READ_PUBLIC_RSP_PARAMS, qualifiedName),&TPM2_SHADOW_TPM2B_NAME},
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_RSA_ENCRYPT_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_RSA_ENCRYPT_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_RSA_ENCRYPT_CMD_PARAMS, message), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TAP_OFFSETOF(TPM2_RSA_ENCRYPT_CMD_PARAMS, scheme), &TPM2_SHADOW_TPMT_RSA_DECRYPT},
                {TAP_OFFSETOF(TPM2_RSA_ENCRYPT_CMD_PARAMS, label), &TPM2_SHADOW_TPM2B_DATA},
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_RSA_DECRYPT_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_RSA_DECRYPT_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_RSA_DECRYPT_CMD_PARAMS, cipherText), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TAP_OFFSETOF(TPM2_RSA_DECRYPT_CMD_PARAMS, scheme), &TPM2_SHADOW_TPMT_RSA_DECRYPT},
                {TAP_OFFSETOF(TPM2_RSA_DECRYPT_CMD_PARAMS, label), &TPM2_SHADOW_TPM2B_DATA}
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_SIGN_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_SIGN_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_SIGN_CMD_PARAMS, digest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_SIGN_CMD_PARAMS, inScheme), &TPM2_SHADOW_TPMT_SIG_SCHEME},
                {TAP_OFFSETOF(TPM2_SIGN_CMD_PARAMS, validation), &TPM2_SHADOW_TPMT_TK_HASHCHECK}
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_VERIFY_SIGNATURE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_VERIFY_SIGNATURE_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_VERIFY_SIGNATURE_CMD_PARAMS, digest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_VERIFY_SIGNATURE_CMD_PARAMS, signature),&TPM2_SHADOW_TPMT_SIGNATURE},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_ENCRYPT_DECRYPT_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ENCRYPT_DECRYPT_CMD_PARAMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT_CMD_PARAMS, decrypt), &TPM2_SHADOW_TPMI_YES_NO},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT_CMD_PARAMS, mode), &TPM2_SHADOW_TPMI_ALG_SYM_MODE},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT_CMD_PARAMS, ivIn), &TPM2_SHADOW_TPM2B_IV},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT_CMD_PARAMS, inData), &TPM2_SHADOW_TPM2B_MAX_BUFFER},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS, inData), &TPM2_SHADOW_TPM2B_MAX_BUFFER},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS, decrypt), &TPM2_SHADOW_TPMI_YES_NO},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS, mode), &TPM2_SHADOW_TPMI_ALG_SYM_MODE},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS, ivIn), &TPM2_SHADOW_TPM2B_IV},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_ENCRYPT_DECRYPT_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ENCRYPT_DECRYPT_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT_RSP_PARAMS, outData), &TPM2_SHADOW_TPM2B_MAX_BUFFER},
                {TAP_OFFSETOF(TPM2_ENCRYPT_DECRYPT_RSP_PARAMS, ivOut), &TPM2_SHADOW_TPM2B_IV},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_HIERARCHY_CONTROL_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_HIERARCHY_CONTROL_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_HIERARCHY_CONTROL_CMD_PARAMS, enable), &TPM2_SHADOW_TPMI_RH_ENABLES},
                {TAP_OFFSETOF(TPM2_HIERARCHY_CONTROL_CMD_PARAMS, state), &TPM2_SHADOW_TPMI_YES_NO},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_EVICT_CONTROL_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_EVICT_CONTROL_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_EVICT_CONTROL_CMD_HANDLES, authHandle), &TPM2_SHADOW_TPMI_RH_PROVISION},
                {TAP_OFFSETOF(TPM2_EVICT_CONTROL_CMD_HANDLES, objectHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
        }

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_INCREMENT_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_INCREMENT_CMD_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES,},},
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_EXTEND_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_EXTEND_CMD_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES,},},
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_SET_BITS_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_SET_BITS_CMD_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES,},},
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_WRITE_LOCK_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_WRITE_LOCK_CMD_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES,},},
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_NV_READ_LOCK_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_NV_READ_LOCK_CMD_HANDLES),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2_NV_WRITE_CMD_HANDLES,},},
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_LOAD_EXTERNAL_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_LOAD_EXTERNAL_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_LOAD_EXTERNAL_CMD_PARAMS, inSensitive), &TPM2_SHADOW_TPM2B_SENSITIVE},
                {TAP_OFFSETOF(TPM2_LOAD_EXTERNAL_CMD_PARAMS, inPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_LOAD_EXTERNAL_CMD_PARAMS, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_LOAD_EXTERNAL_CMD_PARAMS2 = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_LOAD_EXTERNAL_CMD_PARAMS2),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_LOAD_EXTERNAL_CMD_PARAMS2, size0), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TPM2_LOAD_EXTERNAL_CMD_PARAMS2, inPublic), &TPM2_SHADOW_TPM2B_PUBLIC},
                {TAP_OFFSETOF(TPM2_LOAD_EXTERNAL_CMD_PARAMS2, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES, objectHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
                {TAP_OFFSETOF(TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES, parentHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_HASH_SEQUENCE_START_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_HASH_SEQUENCE_START_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_HASH_SEQUENCE_START_CMD_PARAMS, auth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(TPM2_HASH_SEQUENCE_START_CMD_PARAMS, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_SEQUENCE_COMPLETE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_SEQUENCE_COMPLETE_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_SEQUENCE_COMPLETE_CMD_PARAMS, buffer), &TPM2_SHADOW_TPM2B_MAX_BUFFER},
                {TAP_OFFSETOF(TPM2_SEQUENCE_COMPLETE_CMD_PARAMS, hierarchy), &TPM2_SHADOW_TPMI_RH_HIERARCHY},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_SEQUENCE_COMPLETE_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_SEQUENCE_COMPLETE_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_SEQUENCE_COMPLETE_RSP_PARAMS, digest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_SEQUENCE_COMPLETE_RSP_PARAMS, validation), &TPM2_SHADOW_TPMT_TK_HASHCHECK},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_MAKE_CREDENTIAL_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_MAKE_CREDENTIAL_CMD_PARAMS, credential), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_MAKE_CREDENTIAL_CMD_PARAMS, name), &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_MAKE_CREDENTIAL_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_MAKE_CREDENTIAL_RSP_PARAMS, credentialBlob), &TPM2_SHADOW_TPM2B_ID_OBJECT},
                {TAP_OFFSETOF(TPM2_MAKE_CREDENTIAL_RSP_PARAMS, secret), &TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES, activateHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
                {TAP_OFFSETOF(TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES, keyHandle), &TPM2_SHADOW_TPMI_DH_OBJECT},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_QUOTE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_QUOTE_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_QUOTE_CMD_PARAMS, qualifyingData), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(TPM2_QUOTE_CMD_PARAMS, inScheme), &TPM2_SHADOW_TPMT_SIG_SCHEME},
                {TAP_OFFSETOF(TPM2_QUOTE_CMD_PARAMS, PCRSelect), &TPM2_SHADOW_TPML_PCR_SELECTION},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_QUOTE_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_QUOTE_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_QUOTE_RSP_PARAMS, quoted), &TPM2_SHADOW_TPM2B_ATTEST},
                {TAP_OFFSETOF(TPM2_QUOTE_RSP_PARAMS, signature), &TPM2_SHADOW_TPMT_SIGNATURE},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_CLOCK_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_CLOCK_INFO),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_CLOCK_INFO, clock), &TAP_SHADOW_ubyte8},
                {TAP_OFFSETOF(TPMS_CLOCK_INFO, resetCount), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPMS_CLOCK_INFO, restartCount), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPMS_CLOCK_INFO, safe), &TPM2_SHADOW_TPMI_YES_NO},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_CERTIFY_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_CERTIFY_INFO),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_CERTIFY_INFO, name), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPMS_CERTIFY_INFO, qualifiedName), &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_CREATION_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_CREATION_INFO),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_CREATION_INFO, objectName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPMS_CREATION_INFO, creationHash), &TPM2_SHADOW_TPM2B_DIGEST},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_QUOTE_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_QUOTE_INFO),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_QUOTE_INFO, pcrSelect), &TPM2_SHADOW_TPML_PCR_SELECTION},
                {TAP_OFFSETOF(TPMS_QUOTE_INFO, pcrDigest), &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_COMMAND_AUDIT_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_COMMAND_AUDIT_INFO),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_COMMAND_AUDIT_INFO, auditCounter), &TAP_SHADOW_ubyte8},
                {TAP_OFFSETOF(TPMS_COMMAND_AUDIT_INFO, digestAlg), &TPM2_SHADOW_TPM2_ALG_ID},
                {TAP_OFFSETOF(TPMS_COMMAND_AUDIT_INFO, auditDigest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPMS_COMMAND_AUDIT_INFO, commandDigest), &TPM2_SHADOW_TPM2B_DIGEST},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_SESSION_AUDIT_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_SESSION_AUDIT_INFO),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_SESSION_AUDIT_INFO, exclusiveSession), &TPM2_SHADOW_TPM2_ALG_ID},
                {TAP_OFFSETOF(TPMS_SESSION_AUDIT_INFO, sessionDigest), &TPM2_SHADOW_TPM2_ALG_ID},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_TIME_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_TIME_INFO),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_TIME_INFO, time), &TAP_SHADOW_ubyte8},
                {TAP_OFFSETOF(TPMS_TIME_INFO, clockinfo), &TPM2_SHADOW_TPMS_CLOCK_INFO},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_TIME_ATTEST_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_TIME_ATTEST_INFO),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_TIME_ATTEST_INFO, time), &TPM2_SHADOW_TPMS_TIME_INFO},
                {TAP_OFFSETOF(TPMS_TIME_ATTEST_INFO, firmwareVersion), &TAP_SHADOW_ubyte8},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_NV_CERTIFY_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_NV_CERTIFY_INFO),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_NV_CERTIFY_INFO, indexName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPMS_NV_CERTIFY_INFO, offset), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TPMS_NV_CERTIFY_INFO, nvContents), &TPM2_SHADOW_TPM2B_MAX_NV_BUFFER},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMU_ATTEST = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TPMU_ATTEST),
        .numFields = 7,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ST_ATTEST_CERTIFY, &TPM2_SHADOW_TPMS_CERTIFY_INFO},
                {TPM2_ST_ATTEST_CREATION, &TPM2_SHADOW_TPMS_CREATION_INFO},
                {TPM2_ST_ATTEST_QUOTE, &TPM2_SHADOW_TPMS_QUOTE_INFO},
                {TPM2_ST_ATTEST_COMMAND_AUDIT, &TPM2_SHADOW_TPMS_COMMAND_AUDIT_INFO},
                {TPM2_ST_ATTEST_SESSION_AUDIT, &TPM2_SHADOW_TPMS_SESSION_AUDIT_INFO},
                {TPM2_ST_ATTEST_TIME, &TPM2_SHADOW_TPMS_TIME_ATTEST_INFO},
                {TPM2_ST_ATTEST_NV, &TPM2_SHADOW_TPMS_NV_CERTIFY_INFO},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPMS_ATTEST = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPMS_ATTEST),
        .numFields = 7,
        .unionSelectorOffset = TAP_OFFSETOF(TPMS_ATTEST, type),
        .unionSelectorSize = SIZEOF(TPMS_ATTEST, type),
        .pFieldList = {
                {TAP_OFFSETOF(TPMS_ATTEST, magic), &TPM2_SHADOW_TPM2_GENERATED},
                {TAP_OFFSETOF(TPMS_ATTEST, type), &TPM2_SHADOW_TPMI_ST_ATTEST},
                {TAP_OFFSETOF(TPMS_ATTEST, qualifiedSigner), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPMS_ATTEST, extraData), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(TPMS_ATTEST, clockInfo), &TPM2_SHADOW_TPMS_CLOCK_INFO},
                {TAP_OFFSETOF(TPMS_ATTEST, firmwareVersion), &TAP_SHADOW_ubyte8},
                {TAP_OFFSETOF(TPMS_ATTEST, attested), &TPM2_SHADOW_TPMU_ATTEST},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_AK_CSR_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_AK_CSR_INFO),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_AK_CSR_INFO, ekObjectAttributes), &TPM2_SHADOW_TPMA_OBJECT},
                {TAP_OFFSETOF(TPM2_AK_CSR_INFO, ekNameAlg), &TPM2_SHADOW_TPM2_ALG_ID},
                {TAP_OFFSETOF(TPM2_AK_CSR_INFO, akPublicArea), &TPM2_SHADOW_TPMT_PUBLIC},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_POLICY_AUTHORIZE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_AUTHORIZE_CMD_PARAMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_CMD_PARAMS, approvedPolicy), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_CMD_PARAMS, policyRef), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_CMD_PARAMS, keySign), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_CMD_PARAMS, checkTicket), &TPM2_SHADOW_TPMT_TK_VERIFIED},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_PCR_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_PCR_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_PCR_CMD_PARAMS, pcrDigest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_POLICY_PCR_CMD_PARAMS, pcrs), &TPM2_SHADOW_TPML_PCR_SELECTION},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES, authHandle), &TPM2_SHADOW_TPMI_RH_NV_AUTH},
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
                {TAP_OFFSETOF(TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES, policySession), &TPM2_SHADOW_TPM2_HANDLE},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_SECRET_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_SECRET_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_CMD_HANDLES, authHandle), &TPM2_SHADOW_TPMI_DH_ENTITY},
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_CMD_HANDLES, policySession), &TPM2_SHADOW_TPM2_HANDLE},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_SECRET_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_SECRET_CMD_PARAMS),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_CMD_PARAMS, nonceTPM), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_CMD_PARAMS, cpHashA), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_CMD_PARAMS, policyRef), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_CMD_PARAMS, expiration), &TAP_SHADOW_ubyte4},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_SECRET_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_SECRET_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_RSP_PARAMS, timeout), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_POLICY_SECRET_RSP_PARAMS, policyTicket), &TPM2_SHADOW_TPMT_TK_AUTH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_SIGNED_CMD_HANDLES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_SIGNED_CMD_HANDLES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_HANDLES, authObject), &TPM2_SHADOW_TPMI_DH_OBJECT},
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_HANDLES, policySession), &TPM2_SHADOW_TPM2_HANDLE},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_SIGNED_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_SIGNED_CMD_PARAMS),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_PARAMS, nonceTPM), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_PARAMS, cpHashA), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_PARAMS, policyRef), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_PARAMS, expiration), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_CMD_PARAMS, auth), &TPM2_SHADOW_TPMT_SIGNATURE},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_TPM2_POLICY_SIGNED_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_SIGNED_RSP_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_RSP_PARAMS, timeout), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(TPM2_POLICY_SIGNED_RSP_PARAMS, policyTicket), &TPM2_SHADOW_TPMT_TK_AUTH},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS, objectName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS, newParentName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS, includeObject), &TAP_SHADOW_ubyte},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_POLICY_COMMANDCODE_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_POLICY_COMMANDCODE_CMD_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_POLICY_COMMANDCODE_CMD_PARAMS, code), &TAP_SHADOW_ubyte4},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2B_OBJECT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2B_OBJECT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TPM2_SHADOW_TPM2B_GENERIC,},},

};

const tpm2_shadow_struct TPM2_SHADOW_AUTH_ENTITY_UNION = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(AuthEntityUnion),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {1, &TPM2_SHADOW_TPMI_RH_HIERARCHY},
                {2, &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_OBJECT_SECRET = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(PolicyObjectSecret),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(PolicyObjectSecret, authEntitySelector),
        .unionSelectorSize = SIZEOF(PolicyObjectSecret, authEntitySelector),
        .pFieldList = {
                {TAP_OFFSETOF(PolicyObjectSecret, policyRef), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(PolicyObjectSecret, authEntitySelector), &TAP_SHADOW_ubyte},
                {TAP_OFFSETOF(PolicyObjectSecret, authEntity), &TPM2_SHADOW_AUTH_ENTITY_UNION},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_SIGNED_AUTH = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(PolicySignedAuth),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(PolicySignedAuth, policyRef), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(PolicySignedAuth, authorizingKey), &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_PCR = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(PolicyPcr),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(PolicyPcr, pcrDigest), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(PolicyPcr, pcrBitmask), &TAP_SHADOW_ubyte4},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_DYNAMIC_POLICY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(PolicyDynamicPolicy),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(PolicyDynamicPolicy, policyRef), &TPM2_SHADOW_TPM2B_NONCE},
                {TAP_OFFSETOF(PolicyDynamicPolicy, authorizingKey), &TPM2_SHADOW_TPM2B_NAME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_DYNAMIC_POLICY_NV = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(PolicyDynamicPolicyNV),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(PolicyDynamicPolicyNV, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_INFO_UNION = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(PolicyInfoUnion),
        .numFields = 8,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {FAPI2_POLICY_AUTH_VALUE, &TPM2_SHADOW_TPMS_EMPTY},
                {FAPI2_POLICY_OBJECT_SECRET, &TPM2_SHADOW_POLICY_OBJECT_SECRET},
                {FAPI2_POLICY_SIGNED_AUTH, &TPM2_SHADOW_POLICY_SIGNED_AUTH},
                {FAPI2_POLICY_PCR, &TPM2_SHADOW_POLICY_PCR},
                {FAPI2_POLICY_DYNAMIC_POLICY, &TPM2_SHADOW_POLICY_DYNAMIC_POLICY},
                {FAPI2_POLICY_DYNAMIC_POLICY_NV, &TPM2_SHADOW_POLICY_DYNAMIC_POLICY_NV},
                {FAPI2_POLICY_COMMAND_CODE, &TPM2_SHADOW_TPM2_POLICY_COMMANDCODE_CMD_PARAMS},
                {FAPI2_POLICY_NO_DEFAULT, &TPM2_SHADOW_TPMS_EMPTY},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_POLICY_AUTH_NODE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(PolicyAuthNode),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(PolicyAuthNode, policyType),
        .unionSelectorSize = SIZEOF(PolicyAuthNode, policyType),
        .pFieldList = {
                {TAP_OFFSETOF(PolicyAuthNode, policyType), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(PolicyAuthNode, policyInfo), &TPM2_SHADOW_POLICY_INFO_UNION},

        }
};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_ASYM_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_ASYM_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte,},},

};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_RSA_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_RSA_INFO),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(FAPI2_RSA_INFO, keyType), &TPM2_SHADOW_FAPI2_ASYM_TYPE},
                {TAP_OFFSETOF(FAPI2_RSA_INFO, keySize), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(FAPI2_RSA_INFO, exponent), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(FAPI2_RSA_INFO, scheme), &TPM2_SHADOW_TPMI_ALG_RSA_SCHEME},
                {TAP_OFFSETOF(FAPI2_RSA_INFO, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_ECC_INFO = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_ECC_INFO),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(FAPI2_ECC_INFO, keyType), &TPM2_SHADOW_FAPI2_ASYM_TYPE},
                {TAP_OFFSETOF(FAPI2_ECC_INFO, curveID), &TPM2_SHADOW_TPMI_ECC_CURVE},
                {TAP_OFFSETOF(FAPI2_ECC_INFO, scheme), &TPM2_SHADOW_TPMI_ALG_ECC_SCHEME},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_KEY_INFO_UNION = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(FAPI2_KEY_INFO_UNION),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_RSA, &TPM2_SHADOW_FAPI2_RSA_INFO},
                {TPM2_ALG_ECC, &TPM2_SHADOW_FAPI2_ECC_INFO},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_PUBLIC_KEY_UNION = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(FAPI2_PUBLIC_KEY_UNION),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_RSA, &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TPM2_ALG_ECC, &TPM2_SHADOW_TPMS_ECC_POINT},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_AsymCreateKeyIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymCreateKeyIn),
        .numFields = 3,
        .unionSelectorOffset = TAP_OFFSETOF(AsymCreateKeyIn, keyAlg),
        .unionSelectorSize = SIZEOF(AsymCreateKeyIn, keyAlg),
        .pFieldList = {
                {TAP_OFFSETOF(AsymCreateKeyIn, keyAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(AsymCreateKeyIn, keyAlg),&TPM2_SHADOW_TPMI_ALG_PUBLIC},
                {TAP_OFFSETOF(AsymCreateKeyIn, keyInfo),&TPM2_SHADOW_FAPI2_KEY_INFO_UNION},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AsymCreateKeyOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymCreateKeyOut),
        .numFields = 4,
        .unionSelectorOffset = TAP_OFFSETOF(AsymCreateKeyOut, keyAlg),
        .unionSelectorSize = SIZEOF(AsymCreateKeyOut, keyAlg),
        .pFieldList = {
                {TAP_OFFSETOF(AsymCreateKeyOut, key), &TPM2_SHADOW_FAPI2B_OBJECT},
                {TAP_OFFSETOF(AsymCreateKeyOut, keyName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(AsymCreateKeyOut, keyAlg), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
                {TAP_OFFSETOF(AsymCreateKeyOut, publicKey), &TPM2_SHADOW_FAPI2_PUBLIC_KEY_UNION},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AsymSignIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymSignIn),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(AsymSignIn, keyName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(AsymSignIn, signDigest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(AsymSignIn, sigScheme), &TPM2_SHADOW_TPMI_ALG_SIG_SCHEME},
                {TAP_OFFSETOF(AsymSignIn, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_ECC_SIGNATURE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_ECC_SIGNATURE),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(FAPI2_ECC_SIGNATURE, signatureR), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
                {TAP_OFFSETOF(FAPI2_ECC_SIGNATURE, signatureS), &TPM2_SHADOW_TPM2B_ECC_PARAMETER},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_SIGNATURE_UNION = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(FAPI2_SIGNATURE_UNION),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TPM2_ALG_RSA, &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TPM2_ALG_RSAPSS, &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TPM2_ALG_RSASSA, &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},
                {TPM2_ALG_ECC, &TPM2_SHADOW_FAPI2_ECC_SIGNATURE},
                {TPM2_ALG_ECDSA, &TPM2_SHADOW_FAPI2_ECC_SIGNATURE},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_AsymSignOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymSignOut),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(AsymSignOut, keyAlg),
        .unionSelectorSize = SIZEOF(AsymSignOut, keyAlg),
        .pFieldList = {
                {TAP_OFFSETOF(AsymSignOut, keyAlg), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
                {TAP_OFFSETOF(AsymSignOut, signature), &TPM2_SHADOW_FAPI2_SIGNATURE_UNION},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AsymVerifySigIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymVerifySigIn),
        .numFields = 5,
        .unionSelectorOffset = TAP_OFFSETOF(AsymVerifySigIn, sigScheme),
        .unionSelectorSize = SIZEOF(AsymVerifySigIn, sigScheme),
        .pFieldList = {
                {TAP_OFFSETOF(AsymVerifySigIn, keyName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(AsymVerifySigIn, digest), &TPM2_SHADOW_TPM2B_DIGEST},
                {TAP_OFFSETOF(AsymVerifySigIn, sigScheme), &TPM2_SHADOW_TPMI_ALG_SIG_SCHEME},
                {TAP_OFFSETOF(AsymVerifySigIn, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(AsymVerifySigIn, signature), &TPM2_SHADOW_FAPI2_SIGNATURE_UNION}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AsymVerifySigOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymVerifySigOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(AsymVerifySigOut, sigValid), &TAP_SHADOW_ubyte},},
};

const tpm2_shadow_struct TPM2_SHADOW_AsymRsaEncryptIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymRsaEncryptIn),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(AsymRsaEncryptIn, keyName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(AsymRsaEncryptIn, scheme), &TPM2_SHADOW_TPMI_ALG_RSA_DECRYPT},
                {TAP_OFFSETOF(AsymRsaEncryptIn, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(AsymRsaEncryptIn, label), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(AsymRsaEncryptIn, message), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AsymRsaEncryptOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymRsaEncryptOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(AsymRsaEncryptOut, encryptedData), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},},
};

const tpm2_shadow_struct TPM2_SHADOW_AsymRsaDecryptIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymRsaDecryptIn),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(AsymRsaDecryptIn, keyName), &TPM2_SHADOW_TPM2B_NAME},
                {TAP_OFFSETOF(AsymRsaDecryptIn, scheme), &TPM2_SHADOW_TPMI_ALG_RSA_DECRYPT},
                {TAP_OFFSETOF(AsymRsaDecryptIn, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
                {TAP_OFFSETOF(AsymRsaDecryptIn, label), &TPM2_SHADOW_TPM2B_DATA},
                {TAP_OFFSETOF(AsymRsaDecryptIn, cipherText), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AsymRsaDecryptOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AsymRsaDecryptOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(AsymRsaDecryptOut, plainText), &TPM2_SHADOW_TPM2B_PUBLIC_KEY_RSA},},
};

const tpm2_shadow_struct TPM2_SHADOW_AdminTakeOwnershipIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AdminTakeOwnershipIn),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(AdminTakeOwnershipIn, newLockOutAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(AdminTakeOwnershipIn, newOwnerAuth),&TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(AdminTakeOwnershipIn, newEndorsementAuth),&TPM2_SHADOW_TPM2B_AUTH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AdminCreateEKIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AdminCreateEKIn),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(AdminCreateEKIn, isPrivacySensitive), &TAP_SHADOW_ubyte},
                {TAP_OFFSETOF(AdminCreateEKIn, EKAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(AdminCreateEKIn, keyAlg), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_AdminCreateSRKIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AdminCreateSRKIn),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(AdminCreateSRKIn, SRKAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(AdminCreateSRKIn, keyAlg), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_AdminCreateAKIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(AdminCreateAKIn),
        .numFields = 4,
        .unionSelectorOffset = TAP_OFFSETOF(AdminCreateAKIn, keyAlg),
        .unionSelectorSize = SIZEOF(AdminCreateAKIn, keyAlg),
        .pFieldList = {
                {TAP_OFFSETOF(AdminCreateAKIn, AKAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(AdminCreateAKIn, keyAlg), &TPM2_SHADOW_TPMI_ALG_PUBLIC},
                {TAP_OFFSETOF(AdminCreateAKIn, keyInfo), &TPM2_SHADOW_FAPI2_KEY_INFO_UNION},
                {TAP_OFFSETOF(AdminCreateAKIn, persistentHandle), &TPM2_SHADOW_TPMI_DH_PERSISTENT}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_ContextSetHierarchyAuthIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextSetHierarchyAuthIn),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(ContextSetHierarchyAuthIn, ownerAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(ContextSetHierarchyAuthIn, endorsementAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(ContextSetHierarchyAuthIn, lockoutAuth), &TPM2_SHADOW_TPM2B_AUTH},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_ContextSetPrimaryKeyAuthIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextSetPrimaryKeyAuthIn),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(ContextSetPrimaryKeyAuthIn, EKAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(ContextSetPrimaryKeyAuthIn, SRKAuth), &TPM2_SHADOW_TPM2B_AUTH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_ContextGetAuthValueLengthOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextGetAuthValueLengthOut),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(ContextGetAuthValueLengthOut, objectAuthValueLen), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(ContextGetAuthValueLengthOut, hierarchyAuthValueLen), &TAP_SHADOW_ubyte2},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_ContextFlushObjectIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextFlushObjectIn),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(ContextFlushObjectIn, objName), &TPM2_SHADOW_TPM2B_NAME},},
};

const tpm2_shadow_struct TPM2_SHADOW_ContextLoadObjectIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextLoadObjectIn),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(ContextLoadObjectIn, obj), &TPM2_SHADOW_FAPI2B_OBJECT},
                {TAP_OFFSETOF(ContextLoadObjectIn, objAuth), &TPM2_SHADOW_TPM2B_AUTH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_ContextLoadObjectOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextLoadObjectOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(ContextLoadObjectOut, objName), &TPM2_SHADOW_TPM2B_NAME},},
};

const tpm2_shadow_struct TPM2_SHADOW_DataSealIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(DataSealIn),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(DataSealIn, authValue), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(DataSealIn, dataToSeal), &TPM2_SHADOW_TPM2B_SENSITIVE_DATA},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_DataSealOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(DataSealOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(DataSealOut,sealedObject), &TPM2_SHADOW_FAPI2B_OBJECT,},},
};

const tpm2_shadow_struct TPM2_SHADOW_DataUnsealIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(DataUnsealIn),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(DataUnsealIn, sealedObject), &TPM2_SHADOW_FAPI2B_OBJECT},
                {TAP_OFFSETOF(DataUnsealIn, authValue), &TPM2_SHADOW_TPM2B_AUTH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_DataUnsealOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(DataUnsealOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(DataUnsealOut, unsealedData),&TPM2_SHADOW_TPM2B_SENSITIVE_DATA,},},
};

const tpm2_shadow_struct TPM2_SHADOW_MgmtGetPcrSelectionIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(MgmtGetPcrSelectionIn),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(MgmtGetPcrSelectionIn, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH,},},
};

const tpm2_shadow_struct TPM2_SHADOW_MgmtGetPcrSelectionOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(MgmtGetPcrSelectionOut),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(MgmtGetPcrSelectionOut, pcrSelection), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(MgmtGetPcrSelectionOut, numBytesPcrSelection), &TAP_SHADOW_ubyte},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_MgmtCapabilityIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(MgmtCapabilityIn),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(MgmtCapabilityIn, capability), &TPM2_SHADOW_TPM2_CAP},
                {TAP_OFFSETOF(MgmtCapabilityIn, property), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(MgmtCapabilityIn, propertyCount), &TAP_SHADOW_ubyte4},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_MgmtCapabilityOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(MgmtCapabilityOut),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {\
                {TAP_OFFSETOF(MgmtCapabilityOut, moreData), &TPM2_SHADOW_TPMI_YES_NO},
                {TAP_OFFSETOF(MgmtCapabilityOut, capabilityData), &TPM2_SHADOW_TPMS_CAPABILITY_DATA},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_NVDefineIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(NVDefineIn),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(NVDefineIn, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
                {TAP_OFFSETOF(NVDefineIn, nvIndexType), &TAP_SHADOW_ubyte},
                {TAP_OFFSETOF(NVDefineIn, dataSize), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(NVDefineIn, nvAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(NVDefineIn, disableDA), &TAP_SHADOW_ubyte},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_NVUndefineIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(NVUndefineIn),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(NVUndefineIn, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX,},},
};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_NV_WRITE_OP = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_NV_WRITE_OP),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte,},},

};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_NV_WRITE_UNION = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(FAPI2_NV_WRITE_UNION),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {FAPI2_NV_WRITE_OP_WRITE, &TPM2_SHADOW_TPM2B_MAX_NV_BUFFER},
                {FAPI2_NV_WRITE_OP_EXTEND, &TPM2_SHADOW_TPM2B_MAX_NV_BUFFER},
                {FAPI2_NV_WRITE_OP_SET_BITS, &TAP_SHADOW_ubyte8},
                {FAPI2_NV_WRITE_OP_INCREMENT, &TAP_SHADOW_ubyte},
                {FAPI2_NV_WRITE_OP_WRITE_LOCK, &TAP_SHADOW_ubyte},
        }

};

const tpm2_shadow_struct TPM2_SHADOW_NVWriteOpIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(NVWriteOpIn),
        .numFields = 4,
        .unionSelectorOffset = TAP_OFFSETOF(NVWriteOpIn, writeOp),
        .unionSelectorSize = SIZEOF(NVWriteOpIn, writeOp),
        .pFieldList = {
                {TAP_OFFSETOF(NVWriteOpIn, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
                {TAP_OFFSETOF(NVWriteOpIn, nvAuth), &TPM2_SHADOW_TPM2B_AUTH},
                {TAP_OFFSETOF(NVWriteOpIn, writeOp), &TPM2_SHADOW_FAPI2_NV_WRITE_OP},
                {TAP_OFFSETOF(NVWriteOpIn, write), &TPM2_SHADOW_FAPI2_NV_WRITE_UNION}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_NVReadOpIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(NVReadOpIn),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(NVReadOpIn, nvIndex), &TPM2_SHADOW_TPMI_RH_NV_INDEX},
                {TAP_OFFSETOF(NVReadOpIn, nvAuth), &TPM2_SHADOW_TPM2B_AUTH},
        }
};

const tpm2_shadow_struct TPM2_SHADOW_NVReadOpOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(NVReadOpOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(NVReadOpOut, readData), &TPM2_SHADOW_TPM2B_MAX_NV_BUFFER}
        }
};

const tpm2_shadow_struct TPM2_SHADOW_RngGetRandomDataIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(RngGetRandomDataIn),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(RngGetRandomDataIn, bytesRequested), &TAP_SHADOW_ubyte2},},

};

const tpm2_shadow_struct TPM2_SHADOW_RngGetRandomDataOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(RngGetRandomDataOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(RngGetRandomDataOut, randomBytes), &TPM2_SHADOW_TPM2B_DIGEST},},
};

const tpm2_shadow_struct TPM2_SHADOW_RngStirRNGIn = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(RngStirRNGIn),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(RngStirRNGIn, additionalData), &TPM2_SHADOW_TPM2B_SENSITIVE_DATA},},
};

const tpm2_shadow_struct TPM2_SHADOW_ContextGetLastTpmErrorOut = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(ContextGetLastTpmErrorOut),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{TAP_OFFSETOF(ContextGetLastTpmErrorOut, tpmError), &TPM2_SHADOW_TPM2_RC},},
};

const tpm2_shadow_struct TPM2_SHADOW_FAPI2_CC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(FAPI2_CC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_HMAC_CMD_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_HMAC_CMD_PARAMS),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_HMAC_CMD_PARAMS, buffer), &TPM2_SHADOW_TPM2B_MAX_BUFFER},
                {TAP_OFFSETOF(TPM2_HMAC_CMD_PARAMS, hashAlg), &TPM2_SHADOW_TPMI_ALG_HASH},
        }
};

const tpm2_shadow_struct  TPM2_SHADOW_TPM2_HMAC_RSP_PARAMS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_HMAC_RSP_PARAMS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TPM2_HMAC_RSP_PARAMS, outHMAC), &TPM2_SHADOW_TPM2B_DIGEST},
        }
};


/*
const tpm2_shadow_struct TPM2_SHADOW_LockoutParameters = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TPM2_DA_LOCKOUT_PARAMETERS),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
            { TAP_OFFSETOF(TPM2_DA_LOCKOUT_PARAMETERS, newMaxTries), &TAP_SHADOW_ubyte4 },
            { TAP_OFFSETOF(TPM2_DA_LOCKOUT_PARAMETERS, newRecoveryTime), &TAP_SHADOW_ubyte4 },
            { TAP_OFFSETOF(TPM2_DA_LOCKOUT_PARAMETERS, lockoutRecovery), &TAP_SHADOW_ubyte4 }
        }
};
*/

MOC_EXTERN const tpm2_shadow_struct *TAP_SERIALIZE_TPM2_getTpm2BIdObject(void)
{
        return &TPM2_SHADOW_TPM2B_ID_OBJECT;
}
MOC_EXTERN const tpm2_shadow_struct *TAP_SERIALIZE_TPM2_getTpm2BEncryptedSecret(void)
{
        return &TPM2_SHADOW_TPM2B_ENCRYPTED_SECRET;
}
MOC_EXTERN const tpm2_shadow_struct *TAP_SERIALIZE_TPM2_getTpm2BPrivate(void)
{
        return &TPM2_SHADOW_TPM2B_PRIVATE;
}
MOC_EXTERN const tpm2_shadow_struct *TAP_SERIALIZE_TPM2_getTpm2BPublic(void)
{
        return &TPM2_SHADOW_TPM2B_PUBLIC;
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
