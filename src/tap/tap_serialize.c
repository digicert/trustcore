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
#include "tap_common.h"
#include "tap_serialize.h"
#include "tap_serialize_smp.h"



const tap_shadow_struct TAP_SHADOW_MOC_UUID_NODE = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = 6,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_MOC_UUID = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(MOC_UUID),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(MOC_UUID, timeLow), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(MOC_UUID, timeMid), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(MOC_UUID, timeHigh), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(MOC_UUID, clockSeqHigh), &TAP_SHADOW_ubyte},
                {TAP_OFFSETOF(MOC_UUID, clockSeqLow), &TAP_SHADOW_ubyte},
                {TAP_OFFSETOF(MOC_UUID, node), &TAP_SHADOW_MOC_UUID_NODE},
        },

};


/* TCP_SOCKET defined in mtcp.h.  Possible values are:
      int
      unsigned int
      void *
      uitronSocketDescrPtr
      char

   How should we handle this in a shadow structure?
 */

const tap_shadow_struct TAP_SHADOW_TAP_DATA_SOURCE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_DATA_SOURCE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};


const tap_shadow_struct TAP_SHADOW_TAP_OBJECT_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_OBJECT_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_BufferPacked = {
        .handler = TAP_SERIALIZE_SizedBufferHandler,
        .structSize = sizeof(TAP_BufferPacked),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_BufferPacked, bufferLen),
        .unionSelectorSize = SIZEOF(TAP_BufferPacked, bufferLen),
        .pFieldList = {{TAP_OFFSETOF(TAP_BufferPacked, pBuffer), &TAP_SHADOW_ubyte},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ServerName = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ServerName),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Buffer},},
};


const tap_shadow_struct TAP_SHADOW_TAP_FileInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_FileInfo),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Buffer},},

};

const tap_shadow_struct TAP_SHADOW_TAP_ConnectionInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ConnectionInfo),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ConnectionInfo, serverName), &TAP_SHADOW_TAP_ServerName},
                {TAP_OFFSETOF(TAP_ConnectionInfo, serverPort), &TAP_SHADOW_ubyte2}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_NULL = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = 0,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};


const tap_shadow_struct TAP_SHADOW_TAP_SHA1_DIGEST = {
        .handler = TAP_SERIALIZE_FixedSizeArrayHandler,
        .structSize = SHA1_RESULT_SIZE,
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_ubyte},},

};

const tap_shadow_struct TAP_SHADOW_TAP_Module = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Module),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_Module, providerType), &TAP_SHADOW_TAP_PROVIDER},
                {TAP_OFFSETOF(TAP_Module, moduleId), &TAP_SHADOW_TAP_ModuleId},
                {TAP_OFFSETOF(TAP_Module, hostInfo), &TAP_SHADOW_TAP_ConnectionInfo}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Module_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Module},},
};

const tap_shadow_struct TAP_SHADOW_TAP_Module_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Module_ptr},},

};

const tap_shadow_struct TAP_SHADOW_TAP_ModuleList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_ModuleList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_ModuleList, numModules),
        .unionSelectorSize = SIZEOF(TAP_ModuleList, numModules),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ModuleList, pModuleList),&TAP_SHADOW_TAP_Module_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_HostDeviceInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_HostDeviceInfo),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_HostDeviceInfo, hostConnInfo), &TAP_SHADOW_TAP_ConnectionInfo},
                {TAP_OFFSETOF(TAP_HostDeviceInfo, moduleList), &TAP_SHADOW_TAP_ModuleList},
        },

};


/* TCP_SOCKET defined in mtcp.h.  Possible values are:
      int
      unsigned int
      void *
      uitronSocketDescrPtr
      char

   How should we handle this in a shadow structure?
 */
const tap_shadow_struct TAP_SHADOW_TAP_SessionInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_SessionInfo),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
/*                {TAP_OFFSETOF(TAP_SessionInfo, sockfd), &TAP_SHADOW_TCP_SOCKET}, */
                {TAP_OFFSETOF(TAP_SessionInfo, sockfd), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_SessionInfo, sslSessionId), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_SessionInfo, sessionInit), &TAP_SHADOW_ubyte},
        },

};


const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_RSA = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_RSA),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo_RSA, keySize), &TAP_SHADOW_TAP_KEY_SIZE},
                {TAP_OFFSETOF(TAP_KeyInfo_RSA, exponent), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_KeyInfo_RSA, encScheme), &TAP_SHADOW_TAP_ENC_SCHEME},
                {TAP_OFFSETOF(TAP_KeyInfo_RSA, sigScheme), &TAP_SHADOW_TAP_SIG_SCHEME}
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_ECC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_ECC),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo_ECC, curveId), &TAP_SHADOW_TAP_ECC_CURVE},
                {TAP_OFFSETOF(TAP_KeyInfo_ECC, sigScheme), &TAP_SHADOW_TAP_SIG_SCHEME}
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_AES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_AES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo_AES, keySize), &TAP_SHADOW_TAP_KEY_SIZE},
                {TAP_OFFSETOF(TAP_KeyInfo_AES, symMode), &TAP_SHADOW_TAP_SYM_KEY_MODE},
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_DES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_DES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo_DES, keySize), &TAP_SHADOW_TAP_KEY_SIZE},
                {TAP_OFFSETOF(TAP_KeyInfo_DES, symMode), &TAP_SHADOW_TAP_SYM_KEY_MODE},
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_TDES = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_TDES),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo_TDES, keySize), &TAP_SHADOW_TAP_KEY_SIZE},
                {TAP_OFFSETOF(TAP_KeyInfo_TDES, symMode), &TAP_SHADOW_TAP_SYM_KEY_MODE},
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_HMAC = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_HMAC),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo_HMAC, keyLen), &TAP_SHADOW_TAP_RAW_KEY_SIZE},
                {TAP_OFFSETOF(TAP_KeyInfo_HMAC, hashAlg), &TAP_SHADOW_TAP_HASH_ALG},
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_Union = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TAP_KeyInfo_Union),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_KEY_ALGORITHM_RSA, &TAP_SHADOW_TAP_KeyInfo_RSA},
                {TAP_KEY_ALGORITHM_ECC, &TAP_SHADOW_TAP_KeyInfo_ECC},
                {TAP_KEY_ALGORITHM_AES, &TAP_SHADOW_TAP_KeyInfo_AES},
                {TAP_KEY_ALGORITHM_DES, &TAP_SHADOW_TAP_KeyInfo_DES},
                {TAP_KEY_ALGORITHM_TDES, &TAP_SHADOW_TAP_KeyInfo_TDES},
                {TAP_KEY_ALGORITHM_HMAC, &TAP_SHADOW_TAP_KeyInfo_HMAC},
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyInfo),
        .numFields = 5,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_KeyInfo, keyAlgorithm),
        .unionSelectorSize = SIZEOF(TAP_KeyInfo, keyAlgorithm),

        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyInfo, keyAlgorithm), &TAP_SHADOW_TAP_KEY_ALGORITHM},
                {TAP_OFFSETOF(TAP_KeyInfo, keyUsage), &TAP_SHADOW_TAP_KEY_USAGE},
                {TAP_OFFSETOF(TAP_KeyInfo, tokenId), &TAP_SHADOW_TAP_TokenId},
                {TAP_OFFSETOF(TAP_KeyInfo, objectId), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(TAP_KeyInfo, algKeyInfo), &TAP_SHADOW_TAP_KeyInfo_Union},
        }
};


const tap_shadow_struct TAP_SHADOW_TAP_ObjectInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ObjectInfo),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ObjectInfo, providerType), &TAP_SHADOW_TAP_PROVIDER},
                {TAP_OFFSETOF(TAP_ObjectInfo, moduleId), &TAP_SHADOW_TAP_ModuleId},
                {TAP_OFFSETOF(TAP_ObjectInfo, tokenId), &TAP_SHADOW_TAP_EntityId},
                {TAP_OFFSETOF(TAP_ObjectInfo, objectId), &TAP_SHADOW_TAP_EntityId},
                {TAP_OFFSETOF(TAP_ObjectInfo, objectAttributes), &TAP_SHADOW_TAP_ObjectAttributes},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectInfo_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_ObjectInfo},},
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectInfoList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_ObjectInfoList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_ObjectInfoList, count),
        .unionSelectorSize = SIZEOF(TAP_ObjectInfoList, count),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ObjectInfoList, pInfo),&TAP_SHADOW_TAP_ObjectInfo_ptr},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_ObjectData = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_ObjectData),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_ObjectData, objectInfo), &TAP_SHADOW_TAP_ObjectInfo},
                {TAP_OFFSETOF(TAP_ObjectData, objectBlob), &TAP_SHADOW_TAP_Blob}
        },

};

const tap_shadow_struct TAP_SHADOW_TAP_KeyData = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_KeyData),
        .numFields = 4,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_KeyData, keyAlgorithm),
        .unionSelectorSize = SIZEOF(TAP_KeyData, keyAlgorithm),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_KeyData, keyAlgorithm), &TAP_SHADOW_TAP_KEY_ALGORITHM},
                {TAP_OFFSETOF(TAP_KeyData, keyUsage), &TAP_SHADOW_TAP_KEY_USAGE},
                {TAP_OFFSETOF(TAP_KeyData, algKeyInfo), &TAP_SHADOW_TAP_KeyInfo_Union},
                {TAP_OFFSETOF(TAP_KeyData, publicKey), &TAP_SHADOW_TAP_PublicKey},
        },

};

MOC_EXTERN_DATA_DEF const tap_shadow_struct TAP_SHADOW_TAP_Key = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Key),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(TAP_Key, providerObjectData), &TAP_SHADOW_TAP_ObjectData},
                {TAP_OFFSETOF(TAP_Key, keyData), &TAP_SHADOW_TAP_KeyData},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_Key_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_Key},},
};

MOC_EXTERN_DATA_DEF const tap_shadow_struct TAP_SHADOW_TAP_Object = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_Object),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(TAP_Object, providerObjectData), &TAP_SHADOW_TAP_ObjectData},
        },
};



const tap_shadow_struct TAP_SHADOW_TAP_StorageInfo = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_StorageInfo),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(TAP_StorageInfo, index), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_StorageInfo, size), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_StorageInfo, storageType), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_StorageInfo, ownerPermission), &TAP_SHADOW_TAP_PERMISSION_BITMASK},
                {TAP_OFFSETOF(TAP_StorageInfo, publicPermission), &TAP_SHADOW_TAP_PERMISSION_BITMASK},
                {TAP_OFFSETOF(TAP_StorageInfo, pAttributes), &TAP_SHADOW_TAP_PolicyStorageAttributes_ptr},
        },
};


const tap_shadow_struct TAP_SHADOW_TAP_StorageInfo_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_StorageInfo},},
};

const tap_shadow_struct TAP_SHADOW_TAP_StorageInfo_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_StorageInfo_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_StorageInfoList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_StorageInfoList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_StorageInfoList, count),
        .unionSelectorSize = SIZEOF(TAP_StorageInfoList, count),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_StorageInfoList, pInfo),&TAP_SHADOW_TAP_StorageInfo_ptr},
        },
};


const tap_shadow_struct TAP_SHADOW_TAP_StorageObject = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_StorageObject),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(TAP_StorageObject, providerObjectInfo), &TAP_SHADOW_TAP_ObjectInfo},
                {TAP_OFFSETOF(TAP_StorageObject, storageInfo), &TAP_SHADOW_TAP_StorageInfo}
        },
};


const tap_shadow_struct TAP_SHADOW_TAP_StorageObject_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_StorageObject},},
};

const tap_shadow_struct TAP_SHADOW_TAP_StorageObject_ptr_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {{0, &TAP_SHADOW_TAP_StorageObject_ptr},},
};

const tap_shadow_struct TAP_SHADOW_TAP_StorageObjectList = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_StorageObjectList),
        .numFields = 1,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_StorageObjectList, count),
        .unionSelectorSize = SIZEOF(TAP_StorageObjectList, count),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_StorageObjectList, pObjects),&TAP_SHADOW_TAP_StorageObject_ptr},
        },
};



/*
 * Dummy union, that the void * in TAP_Attribute points to. This list will expand
 * with every attribute structure that is added. NOTE: If adding a new attribute
 * that uses a TAP_Buffer, the list in TAP_UTILS_getAttributeListLen must be updated
 * as well.
 */
const tap_shadow_struct TAP_SHADOW_TAP_AttributeStructUnion = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TAP_AttributeStructUnion),
        .numFields = 72,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_ATTR_NONE, &TAP_SHADOW_none},
                {TAP_ATTR_FIRMWARE_VERSION, &TAP_SHADOW_TAP_Version},
                {TAP_ATTR_TAP_PROVIDER, &TAP_SHADOW_TAP_PROVIDER},
                {TAP_ATTR_KEY_ALGORITHM, &TAP_SHADOW_TAP_KEY_ALGORITHM},
                {TAP_ATTR_KEY_USAGE, &TAP_SHADOW_TAP_KEY_USAGE},
                {TAP_ATTR_KEY_SIZE, &TAP_SHADOW_TAP_KEY_SIZE},
                {TAP_ATTR_CURVE, &TAP_SHADOW_TAP_ECC_CURVE},
                {TAP_ATTR_ENC_SCHEME, &TAP_SHADOW_TAP_ENC_SCHEME},
                {TAP_ATTR_SIG_SCHEME, &TAP_SHADOW_TAP_SIG_SCHEME},
                {TAP_ATTR_CREDENTIAL, &TAP_SHADOW_TAP_Credential},
                {TAP_ATTR_SYM_KEY_MODE, &TAP_SHADOW_TAP_SYM_KEY_MODE},
                {TAP_ATTR_HASH_ALG, &TAP_SHADOW_TAP_HASH_ALG},
                {TAP_ATTR_KEY_HANDLE, &TAP_SHADOW_TAP_KeyHandle},
                {TAP_ATTR_MODULE_KEY, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_PUBLIC_KEY, &TAP_SHADOW_TAP_PublicKey},
                {TAP_ATTR_RNG_PROPERTY, &TAP_SHADOW_TAP_RNG_PROPERTY},
                {TAP_ATTR_RNG_SEED, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_RND_STIR, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_PRELOAD_KEY, &TAP_SHADOW_ubyte},
                {TAP_ATTR_STORAGE_TYPE, &TAP_SHADOW_ubyte},
                {TAP_ATTR_STORAGE_SIZE, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_STORAGE_OFFSET, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_READ_OP, &TAP_SHADOW_ubyte},
                {TAP_ATTR_WRITE_OP, &TAP_SHADOW_TAP_WRITE_OP_TYPE},
                {TAP_ATTR_ENC_LABEL, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_BUFFER, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_CAPABILITY_CATEGORY, &TAP_SHADOW_TAP_CAPABILITY_CATEGORY},
                {TAP_ATTR_CAPABILITY_FUNCTIONALITY, &TAP_SHADOW_TAP_CAPABILITY_FUNCTIONALITY},
                {TAP_ATTR_MODULE_PROVISION_TYPE, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_ENTITY_CREDENTIAL, &TAP_SHADOW_TAP_EntityCredential},
                {TAP_ATTR_TRUSTED_DATA_KEY, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_TRUSTED_DATA_VALUE, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_TRUSTED_DATA_TYPE, &TAP_SHADOW_ubyte},
                {TAP_ATTR_TRUSTED_DATA_INFO, &TAP_SHADOW_TAP_TrustedDataInfo},
                {TAP_ATTR_OBJECT_HANDLE, &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_ATTR_TOKEN_TYPE, &TAP_SHADOW_TAP_TOKEN_TYPE},
                {TAP_ATTR_SLOT_ID, &TAP_SHADOW_TAP_SlotId},
                {TAP_ATTR_OBJECT_PROPERTY, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_PERMISSION, &TAP_SHADOW_TAP_PERMISSION_BITMASK},
                {TAP_ATTR_VENDOR_INFO, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_OP_EXEC_FLAG, &TAP_SHADOW_TAP_OP_EXEC_FLAG},
                {TAP_ATTR_STORAGE_INDEX, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_TEST_MODE, &TAP_SHADOW_TAP_TEST_MODE},
                {TAP_ATTR_TEST_STATUS, &TAP_SHADOW_TAP_TEST_STATUS},
                {TAP_ATTR_TEST_CONTEXT, &TAP_SHADOW_TAP_OperationHandle},
                {TAP_ATTR_TEST_REPORT, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_TEST_REQUEST_DATA, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_CREDENTIAL_SET, &TAP_SHADOW_TAP_CredentialList},
                {TAP_ATTR_CREDENTIAL_USAGE, &TAP_SHADOW_TAP_EntityCredentialList},
                {TAP_ATTR_MODULE_PROVISION_STATE, &TAP_SHADOW_TAP_MODULE_PROVISION_STATE},
                {TAP_ATTR_PERMISSION_OWNER, &TAP_SHADOW_TAP_PERMISSION_BITMASK},
                {TAP_ATTR_MODULE_ID_STRING, &TAP_SHADOW_ubyte_ptr},
                {TAP_ATTR_GET_MODULE_CREDENTIALS, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_KEY_CMK, &TAP_SHADOW_TAP_KEY_CMK},
                {TAP_ATTR_GET_CAP_CAPABILITY, &TAP_SHADOW_TAP_MODULE_CAP_CAP_T},
                {TAP_ATTR_GET_CAP_PROPERTY, &TAP_SHADOW_TAP_MODULE_CAP_PROPERTY_TAG},
                {TAP_ATTR_GET_CAP_PROPERTY_COUNT, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_IS_DATA_NOT_DIGEST, &TAP_SHADOW_ubyte},
                {TAP_ATTR_SALT_LEN, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_ADDITIONAL_AUTH_DATA, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_TAG_LEN_BITS, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_TOKEN_OBJECT, &TAP_SHADOW_ubyte4},
                {TAP_ATTR_OBJECT_VALUE, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_RAW_KEY_SIZE, &TAP_SHADOW_TAP_RAW_KEY_SIZE},
                {TAP_ATTR_OBJECT_ID_BYTESTRING, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_SERIALIZED_OBJECT_BLOB, &TAP_SHADOW_TAP_Blob},
                {TAP_ATTR_KEY_WRAP_TYPE, &TAP_SHADOW_TAP_KEY_WRAP_TYPE},
                {TAP_ATTR_KEY_TO_BE_WRAPPED_ID, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_WRAPPING_KEY_ID, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_CREATE_KEY_ENTROPY, &TAP_SHADOW_TAP_Buffer},
                {TAP_ATTR_CREATE_KEY_TYPE, &TAP_SHADOW_ubyte},
                {TAP_ATTR_AUTH_CONTEXT, &TAP_SHADOW_TAP_ID},

        },
};


const tap_shadow_struct TAP_SHADOW_TAP_AttributeStructUnion_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_AttributeStructUnion},
        },
};




#endif /* if defined(__ENABLE_DIGICERT_TAP__) */
