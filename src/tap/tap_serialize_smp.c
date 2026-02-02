/**
 * @file tap_serialize.c
 * @brief  Trust Anchor Platform (TAP) serialization code for structures defined in tap.h
 * @details This file contains definitions for Trust Anchor Platform (TAP) serialization of structures defined in tap.h.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *  + \c \__ENABLE_DIGICERT_TAP__
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

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TAP__))
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/vlong.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "tap_smp.h"
#include "tap_base_serialize.h"
#include "tap_serialize.h"
#include "smp_serialize_interface.h"
#include "../smp/smp_cc.h"

/* Even though this is in smp_cc, we need the shadow structure here */
const tap_shadow_struct TAP_SHADOW_SMP_CC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_CC),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},
};

const tap_shadow_struct TAP_SHADOW_TAP_HANDLE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_HANDLE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte8},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ID = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ID),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte8},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SHA256Buffer = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = SHA256_RESULT_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RequestContext = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_RequestContext),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_void_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TestContext = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TestContext),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_void_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TestContext_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {{0, &TAP_SHADOW_TAP_TestContext},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ErrorContext = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ErrorContext),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_void_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PROVIDER = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_PROVIDER),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KEY_ALGORITHM = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KEY_ALGORITHM),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KEY_SIZE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KEY_SIZE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RAW_KEY_SIZE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_RAW_KEY_SIZE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SYM_KEY_MODE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SYM_KEY_MODE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_HASH_ALG = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_HASH_ALG),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};


const tap_shadow_struct TAP_SHADOW_TAP_KEY_USAGE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KEY_USAGE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KEY_CMK = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KEY_CMK),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KEY_WRAP_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KEY_WRAP_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CREDENTIAL_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CREDENTIAL_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CREDENTIAL_FORMAT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CREDENTIAL_FORMAT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_MODULE_PROVISION_STATE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_MODULE_PROVISION_STATE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_BLOB_FORMAT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_BLOB_FORMAT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_BLOB_ENCODING = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_BLOB_ENCODING),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CREDENTIAL_CONTEXT = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CREDENTIAL_CONTEXT),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_OP_EXEC_FLAG = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_OP_EXEC_FLAG),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RNG_PROPERTY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_RNG_PROPERTY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_WRITE_OP_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_WRITE_OP_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TRUSTED_DATA_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TRUSTED_DATA_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TRUSTED_DATA_SUBTYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TRUSTED_DATA_SUBTYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ROOT_OF_TRUST_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ROOT_OF_TRUST_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TRUSTED_DATA_OPERATION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TRUSTED_DATA_OPERATION),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ATTR_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ATTR_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ENTITY_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ENTITY_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TOKEN_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TOKEN_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TEST_MODE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TEST_MODE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TEST_STATUS = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TEST_STATUS),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PERMISSION_BITMASK = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_PERMISSION_BITMASK),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte4},},
};


const tap_shadow_struct TAP_SHADOW_TAP_CAPABILITY_CATEGORY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CAPABILITY_CATEGORY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CAPABILITY_FUNCTIONALITY = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CAPABILITY_FUNCTIONALITY),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte2},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Buffer = {
        .handler = TAP_SERIALIZE_SizedBufferHandler,
        .structSize = sizeof(TAP_Buffer),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_Buffer, bufferLen),
        .unionSelectorSize = SIZEOF(TAP_Buffer, bufferLen),
        .pFieldList = {{TAP_OFFSETOF(TAP_Buffer, pBuffer), &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Buffer_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Buffer},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Buffer_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Buffer_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_BufferList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_BufferList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_BufferList, count),
        .unionSelectorSize = SIZEOF(TAP_BufferList, count),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_BufferList, pBufferList),&TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ConfigInfo),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ConfigInfo, provider), &TAP_SHADOW_TAP_PROVIDER},
                {TAP_OFFSETOF(TAP_ConfigInfo, configInfo), &TAP_SHADOW_TAP_Buffer}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfo_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ConfigInfo},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfo_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ConfigInfo_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfoList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_ConfigInfoList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_ConfigInfoList, count),
        .unionSelectorSize = SIZEOF(TAP_ConfigInfoList, count),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ConfigInfoList, pConfig),&TAP_SHADOW_TAP_ConfigInfo_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfoList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ConfigInfoList},},
};


const tap_shadow_struct TAP_SHADOW_TAP_Blob = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Blob),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Blob, format), &TAP_SHADOW_TAP_BLOB_FORMAT},
                {TAP_OFFSETOF(TAP_Blob, encoding), &TAP_SHADOW_TAP_BLOB_ENCODING},
                {TAP_OFFSETOF(TAP_Blob, blob), &TAP_SHADOW_TAP_Buffer}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Blob_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_Blob},
        },
};

/*
 * TAP_Attribute shadow structure
 */
const tap_shadow_struct TAP_SHADOW_TAP_Attribute = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Attribute),
        .numFields = 3,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_Attribute, type),
        .unionSelectorSize = SIZEOF(TAP_Attribute, type),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Attribute, type), &TAP_SHADOW_TAP_ATTR_TYPE},
                {TAP_OFFSETOF(TAP_Attribute, length), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_Attribute, pStructOfType), &TAP_SHADOW_TAP_AttributeStructUnion_ptr}
        },
};

/*
 * TAP_AttributeList shadow
 */
const tap_shadow_struct TAP_SHADOW_TAP_Attribute_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_Attribute},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Attribute_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Attribute_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_AttributeList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_AttributeList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_AttributeList, listLen),
        .unionSelectorSize = SIZEOF(TAP_AttributeList, listLen),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_AttributeList, pAttributeList), &TAP_SHADOW_TAP_Attribute_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_AttributeList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapabilityAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ModuleCapabilityAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapabilityAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ModuleCapabilityAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleProvisionAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ModuleProvisionAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleProvisionAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ModuleProvisionAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ErrorAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ErrorAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ErrorAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ErrorAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RngAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_RngAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RngAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_RngAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ObjectAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ObjectAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TokenCapabilityAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TokenCapabilityAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TokenCapabilityAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_TokenCapabilityAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TokenProvisionAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TokenProvisionAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TokenProvisionAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_TokenProvisionAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectCapabilityAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ObjectCapabilityAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ObjectCapabilityAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_MechanismAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_MechanismAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_MechanismAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_MechanismAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SignAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SignAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SignAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_SignAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SealAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SealAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SealAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_SealAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PolicyStorageAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_PolicyStorageAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PolicyStorageAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_PolicyStorageAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KeyAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KeyAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_KeyAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_OperationAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_OperationAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_OperationAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_OperationAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TestRequestAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TestRequestAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TestRequestAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_TestRequestAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TestResponseAttributes = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TestResponseAttributes),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_AttributeList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TestResponseAttributes_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_TestResponseAttributes},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PROVIDER_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_PROVIDER},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PROVIDER_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_PROVIDER_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CmdCodeList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_CmdCodeList),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_CmdCodeList, listLen),
        .unionSelectorSize = SIZEOF(TAP_CmdCodeList, listLen),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_CmdCodeList, pCmdList), &TAP_SHADOW_SMP_CC},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ProviderCmdList = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ProviderCmdList),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ProviderCmdList, provider), &TAP_SHADOW_TAP_PROVIDER},
                {TAP_OFFSETOF(TAP_ProviderCmdList, cmdList), &TAP_SHADOW_TAP_CmdCodeList}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ProviderCmdList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_ProviderCmdList},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ProviderList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_ProviderList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_ProviderList, listLen),
        .unionSelectorSize = SIZEOF(TAP_ProviderList, listLen),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ProviderList, pProviderCmdList),&TAP_SHADOW_TAP_ProviderCmdList_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ProviderList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_ProviderList},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Version = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Version),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Version, major), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_Version, minor), &TAP_SHADOW_ubyte4}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_FirmwareVersion = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_FirmwareVersion),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Version},},
};

const tap_shadow_struct TAP_SHADOW_TAP_HardwareVersion = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_HardwareVersion),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Version},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SMPVersion = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SMPVersion),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Version},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Error = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Error),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Error, tapError), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_Error, tapErrorString), &TAP_SHADOW_TAP_Buffer},
                {TAP_OFFSETOF(TAP_Error, pErrorAttributes), &TAP_SHADOW_TAP_ErrorAttributes_ptr}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_TrustData = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TrustData),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Buffer},},
};

const tap_shadow_struct TAP_SHADOW_TAP_AuthData = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_AuthData),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Buffer},},
};

const tap_shadow_struct TAP_SHADOW_TAP_KeyHandle  = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyHandle),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_HANDLE},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleHandle  = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ModuleHandle),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_HANDLE},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectHandle  = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ObjectHandle),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_HANDLE},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TokenHandle  = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TokenHandle),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_HANDLE},},
};

const tap_shadow_struct TAP_SHADOW_TAP_OperationHandle  = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_OperationHandle),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_HANDLE},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleId = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ModuleId),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ID},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectId = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ObjectId),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ID},},
};

const tap_shadow_struct TAP_SHADOW_TAP_TokenId = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TokenId),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ID},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SlotId = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SlotId),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ID},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityId = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_EntityId),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ID},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleSlotInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ModuleSlotInfo),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ModuleSlotInfo, numSlots), &TAP_SHADOW_ubyte4},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_SlotId_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_SlotId},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SlotId_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_SlotId_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleSlotList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_ModuleSlotList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_ModuleSlotList, numSlots),
        .unionSelectorSize = SIZEOF(TAP_ModuleSlotList, numSlots),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ModuleSlotList, pSlotIdList),&TAP_SHADOW_TAP_SlotId_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Credential = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Credential),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Credential, credentialType), &TAP_SHADOW_TAP_CREDENTIAL_TYPE},
                {TAP_OFFSETOF(TAP_Credential, credentialFormat), &TAP_SHADOW_TAP_CREDENTIAL_FORMAT},
                {TAP_OFFSETOF(TAP_Credential, credentialContext), &TAP_SHADOW_TAP_CREDENTIAL_CONTEXT},
                {TAP_OFFSETOF(TAP_Credential, credentialData), &TAP_SHADOW_TAP_AuthData}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Credential_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Credential},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Credential_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Credential_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CredentialList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_CredentialList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_CredentialList, numCredentials),
        .unionSelectorSize = SIZEOF(TAP_CredentialList, numCredentials),
        .pFieldList = {{TAP_OFFSETOF(TAP_CredentialList, pCredentialList), &TAP_SHADOW_TAP_Credential_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_CredentialList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_CredentialList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityId_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_EntityId},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityId_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_EntityId_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityIdList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_EntityList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_EntityIdList, numEntities),
        .unionSelectorSize = sizeof(ubyte4),
        .pFieldList = {{TAP_OFFSETOF(TAP_EntityIdList, pEntityIdList), &TAP_SHADOW_TAP_EntityId_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityList = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_EntityList),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_EntityList, entityType), &TAP_SHADOW_TAP_ENTITY_TYPE},
                {TAP_OFFSETOF(TAP_EntityList, entityIdList), &TAP_SHADOW_TAP_EntityIdList},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_EntityList},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityCredential = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_EntityCredential),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_EntityCredential, parentType), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_EntityCredential, parentId), &TAP_SHADOW_ubyte8},
                {TAP_OFFSETOF(TAP_EntityCredential, entityType), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_EntityCredential, entityId), &TAP_SHADOW_ubyte8},
                {TAP_OFFSETOF(TAP_EntityCredential, credentialList), &TAP_SHADOW_TAP_CredentialList},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityCredential_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_EntityCredential},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityCredential_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_EntityCredential_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityCredentialList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_EntityCredentialList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_EntityCredentialList, numCredentials),
        .unionSelectorSize = SIZEOF(TAP_EntityCredentialList, numCredentials),
        .pFieldList = {{TAP_OFFSETOF(TAP_EntityCredentialList, pEntityCredentials), &TAP_SHADOW_TAP_EntityCredential_ptr},},
};

/* TODO: should this be a buffer, with policyInfoLen being the number of bytes? */
const tap_shadow_struct TAP_SHADOW_TAP_PolicyInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_PolicyInfo),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_PolicyInfo, policyInfoLen), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_PolicyInfo, pPolicyInfo), &TAP_SHADOW_void_ptr}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_TrustedDataInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_TrustedDataInfo),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_TrustedDataInfo, subType), &TAP_SHADOW_TAP_TRUSTED_DATA_SUBTYPE},
                {TAP_OFFSETOF(TAP_TrustedDataInfo, attributes), &TAP_SHADOW_TAP_AttributeList}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_TrustedDataInfo_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_TrustedDataInfo},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RSASignature = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_RSASignature),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_RSASignature, signatureLen), &TAP_SHADOW_TAP_BufferPacked}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_MLDSASignature = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_MLDSASignature),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_MLDSASignature, signatureLen), &TAP_SHADOW_TAP_BufferPacked}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ECCSignature = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ECCSignature),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ECCSignature, rDataLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_ECCSignature, sDataLen), &TAP_SHADOW_TAP_BufferPacked}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_DSASignature = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_DSASignature),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_DSASignature, rDataLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_DSASignature, sDataLen), &TAP_SHADOW_TAP_BufferPacked}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_SymSignature = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SymSignature),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_SymSignature, signatureLen), &TAP_SHADOW_TAP_BufferPacked}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Signature_Union = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TAP_Signature_Union),
        .numFields = 7,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_KEY_ALGORITHM_UNDEFINED, &TAP_SHADOW_ubyte},
                {TAP_KEY_ALGORITHM_RSA, &TAP_SHADOW_TAP_RSASignature},
                {TAP_KEY_ALGORITHM_ECC, &TAP_SHADOW_TAP_ECCSignature},
                {TAP_KEY_ALGORITHM_DSA, &TAP_SHADOW_TAP_DSASignature},
                {TAP_KEY_ALGORITHM_AES, &TAP_SHADOW_TAP_SymSignature},
                {TAP_KEY_ALGORITHM_HMAC, &TAP_SHADOW_TAP_SymSignature},
                {TAP_KEY_ALGORITHM_MLDSA, &TAP_SHADOW_TAP_MLDSASignature}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Signature = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Signature),
        .numFields = 4,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_Signature, keyAlgorithm),
        .unionSelectorSize = SIZEOF(TAP_Signature, keyAlgorithm),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Signature, isDEREncoded), &TAP_SHADOW_ubyte},
                {TAP_OFFSETOF(TAP_Signature, keyAlgorithm), &TAP_SHADOW_TAP_KEY_ALGORITHM},
                {TAP_OFFSETOF(TAP_Signature, signature), &TAP_SHADOW_TAP_Signature_Union},
                {TAP_OFFSETOF(TAP_Signature, derEncSignature), &TAP_SHADOW_TAP_Buffer},
        }
};

const tap_shadow_struct TAP_SHADOW_TAP_Signature_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Signature},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Signature_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Signature_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ENC_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ENC_SCHEME),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_SIG_SCHEME = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SIG_SCHEME),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ECC_CURVE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ECC_CURVE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_RSAPublicKey = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_RSAPublicKey),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_RSAPublicKey, modulusLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_RSAPublicKey, exponentLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_RSAPublicKey, encScheme), &TAP_SHADOW_TAP_ENC_SCHEME},
                {TAP_OFFSETOF(TAP_RSAPublicKey, sigScheme), &TAP_SHADOW_TAP_SIG_SCHEME}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_MLDSAPublicKey = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_MLDSAPublicKey),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_MLDSAPublicKey, publicKeyLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_MLDSAPublicKey, qsAlg), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_MLDSAPublicKey, sigScheme), &TAP_SHADOW_TAP_SIG_SCHEME},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ECCPublicKey = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ECCPublicKey),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ECCPublicKey, curveId),&TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_ECCPublicKey, pubXLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_ECCPublicKey, pubYLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_ECCPublicKey, encScheme),&TAP_SHADOW_TAP_ENC_SCHEME},
                {TAP_OFFSETOF(TAP_ECCPublicKey, sigScheme),&TAP_SHADOW_TAP_SIG_SCHEME},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_DSAPublicKey = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_DSAPublicKey),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_DSAPublicKey, primeLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_DSAPublicKey, subprimeLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_DSAPublicKey, baseLen), &TAP_SHADOW_TAP_BufferPacked},
                {TAP_OFFSETOF(TAP_DSAPublicKey, pubValLen), &TAP_SHADOW_TAP_BufferPacked}
            },
};

const tap_shadow_struct TAP_SHADOW_TAP_PublicKey_Union = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TAP_PublicKey_Union),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_KEY_ALGORITHM_UNDEFINED, &TAP_SHADOW_none},
                {TAP_KEY_ALGORITHM_RSA, &TAP_SHADOW_TAP_RSAPublicKey},
                {TAP_KEY_ALGORITHM_ECC, &TAP_SHADOW_TAP_ECCPublicKey},
                {TAP_KEY_ALGORITHM_DSA, &TAP_SHADOW_TAP_DSAPublicKey},
                {TAP_KEY_ALGORITHM_MLDSA, &TAP_SHADOW_TAP_MLDSAPublicKey},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_PublicKey = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_PublicKey),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_PublicKey, keyAlgorithm),
        .unionSelectorSize = SIZEOF(TAP_PublicKey, keyAlgorithm),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_PublicKey, keyAlgorithm), &TAP_SHADOW_TAP_KEY_ALGORITHM},
                {TAP_OFFSETOF(TAP_PublicKey, publicKey), &TAP_SHADOW_TAP_PublicKey_Union},
        }
};

const tap_shadow_struct TAP_SHADOW_TAP_PublicKey_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_PublicKey},},
};

const tap_shadow_struct TAP_SHADOW_TAP_PublicKey_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_PublicKey_ptr},},
};

/*
 * Shadow structures for TAP_getModuleCapability
*/

const tap_shadow_struct TAP_SHADOW_TAP_MODULE_CAP_CAP_T = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(TAP_MODULE_CAP_CAP_T),
    .numFields = 1,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {{ 0, &TAP_SHADOW_ubyte4 },},
};

const tap_shadow_struct TAP_SHADOW_TAP_MODULE_CAP_PROPERTY_TAG = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(TAP_MODULE_CAP_PROPERTY_TAG),
    .numFields = 1,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {{ 0, &TAP_SHADOW_ubyte4 },},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapPropertyAttributes = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(TAP_ModuleCapPropertyAttributes),
    .numFields = 1,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {{ 0, &TAP_SHADOW_TAP_AttributeList },},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapPropertyAttributes_ptr = {
    .handler = TAP_SERIALIZE_PointerTypeHandler,
    .structSize = sizeof(void *),
    .numFields = 1,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {{ 0, &TAP_SHADOW_TAP_ModuleCapPropertyAttributes },},
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapProperty = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(TAP_ModuleCapProperty),
    .numFields = 3,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {
        { TAP_OFFSETOF(TAP_ModuleCapProperty, propertyId), &TAP_SHADOW_TAP_MODULE_CAP_PROPERTY_TAG },
        { TAP_OFFSETOF(TAP_ModuleCapProperty, propertyValue), &TAP_SHADOW_TAP_Buffer },
        { TAP_OFFSETOF(TAP_ModuleCapProperty, propertyDescription), &TAP_SHADOW_TAP_Buffer }
    },
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapProperty_Ptr = {
    .handler = TAP_SERIALIZE_PointerTypeHandler,
    .structSize = sizeof(void *),
    .numFields = 1,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,
    .pFieldList = {
        { 0, &TAP_SHADOW_TAP_ModuleCapProperty },
    },
};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapPropertyList = {
    .handler = TAP_SERIALIZE_ListPointerTypeHandler,
    .structSize = sizeof(TAP_ModuleCapPropertyList),
    .numFields = 1,
    .unionSelectorOffset = TAP_OFFSETOF(TAP_ModuleCapPropertyList, numProperties),
    .unionSelectorSize = SIZEOF(TAP_ModuleCapPropertyList, numProperties),
    .pFieldList = {
        { TAP_OFFSETOF(TAP_ModuleCapPropertyList, pPropertyList), &TAP_SHADOW_TAP_ModuleCapProperty_Ptr },
    },
};

/***************************************************************
Function Definitions
****************************************************************/

const tap_shadow_struct *
TAP_SERALIZE_SMP_getPublicKeyShadowStruct(void)
{
    return &TAP_SHADOW_TAP_PublicKey;
}


#endif /* if defined(__ENABLE_DIGICERT_TAP__) */
