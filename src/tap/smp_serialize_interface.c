/**
 * @file smp_serialize_interface.c
 * @details This file contains shadow structure definitions and functions needed for
 *          Mocana SMP interface.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *  + \c \__ENABLE_DIGICERT_SMP__
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

#if (defined(__ENABLE_DIGICERT_SMP__))

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/vlong.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "tap_serialize_smp.h"
#include "smp_serialize_interface.h"
#include "../smp/smp_cc.h"
#include "../smp/smp_interface.h"


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleListCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getModuleListCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(SMP_getModuleListCmdParams, pModuleAttributes), &TAP_SHADOW_TAP_ModuleCapabilityAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleListRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getModuleListRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(SMP_getModuleListRspParams, moduleList), &TAP_SHADOW_TAP_EntityList},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_freeModuleListCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_freeModuleListCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(SMP_freeModuleListCmdParams, pModuleList), &TAP_SHADOW_TAP_EntityList_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleInfoCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getModuleInfoCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(SMP_getModuleInfoCmdParams, moduleId), &TAP_SHADOW_TAP_ModuleId},
                {TAP_OFFSETOF(SMP_getModuleInfoCmdParams, pCapabilitySelectCriterion), &TAP_SHADOW_TAP_ModuleCapabilityAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleInfoRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getModuleInfoRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(SMP_getModuleInfoRspParams, moduleCapabilties), &TAP_SHADOW_TAP_ModuleCapabilityAttributes},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleSlotsCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getModuleSlotsCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getModuleSlotsCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleSlotsRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getModuleSlotsRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getModuleSlotsRspParams, moduleSlotList), &TAP_SHADOW_TAP_ModuleSlotList},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getTokenListCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTokenListCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getTokenListCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getTokenListCmdParams, tokenType), &TAP_SHADOW_TAP_TOKEN_TYPE},
                {TAP_OFFSETOF(SMP_getTokenListCmdParams, pTokenAttributes), &TAP_SHADOW_TAP_TokenCapabilityAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getTokenListRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTokenListRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getTokenListRspParams, tokenIdList), &TAP_SHADOW_TAP_EntityList},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getTokenInfoCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTokenInfoCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getTokenInfoCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getTokenInfoCmdParams, tokenType), &TAP_SHADOW_TAP_TOKEN_TYPE},
                {TAP_OFFSETOF(SMP_getTokenInfoCmdParams, tokenId), &TAP_SHADOW_TAP_TokenId},
                {TAP_OFFSETOF(SMP_getTokenInfoCmdParams, pCapabilitySelectAttributes), &TAP_SHADOW_TAP_TokenCapabilityAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getTokenInfoRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTokenInfoRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getTokenInfoRspParams, tokenAttributes), &TAP_SHADOW_TAP_TokenCapabilityAttributes}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getObjectListCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getObjectListCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getObjectListCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getObjectListCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getObjectListCmdParams, pObjectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getObjectListRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getObjectListRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getObjectListRspParams, objectIdList), &TAP_SHADOW_TAP_EntityList}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getObjectInfoCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getObjectInfoCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getObjectInfoCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getObjectInfoCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getObjectInfoCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_getObjectInfoCmdParams, objectId), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_getObjectInfoCmdParams, pCapabilitySelectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getObjectInfoRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getObjectInfoRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getObjectInfoRspParams, objectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_provisionModuleCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_provisionModuleCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_provisionModuleCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_provisionModuleCmdParams, pModuleProvisionAttributes), &TAP_SHADOW_TAP_ModuleProvisionAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_resetModuleCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_resetModuleCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_resetModuleCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_resetModuleCmdParams, pModuleProvisionAttributes), &TAP_SHADOW_TAP_ModuleProvisionAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_provisionTokensCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_provisionTokensCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_provisionTokensCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_provisionTokensCmdParams, pTokenProvisionAttributes), &TAP_SHADOW_TAP_TokenProvisionAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_provisionTokensRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_provisionTokensRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_provisionTokensRspParams, tokenIdList), &TAP_SHADOW_TAP_EntityList},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_resetTokenCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_resetTokenCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_resetTokenCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_resetTokenCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_resetTokenCmdParams, pTokenProvisionAttributes), &TAP_SHADOW_TAP_TokenProvisionAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_deleteTokenCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_deleteTokenCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_deleteTokenCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_deleteTokenCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_deleteTokenCmdParams, pTokenProvisionAttributes), &TAP_SHADOW_TAP_TokenProvisionAttributes_ptr}
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_CredentialPtr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_Credential},
        },
};

const tap_shadow_struct TAP_SHADOW_TAP_EntityCredentialList_ptr = {
        .handler = TAP_SERIALIZE_PointerTypeHandler,
        .structSize = sizeof(void *),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &TAP_SHADOW_TAP_EntityCredentialList},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_initModuleCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_initModuleCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_initModuleCmdParams, moduleId), &TAP_SHADOW_TAP_ModuleId},
                {TAP_OFFSETOF(SMP_initModuleCmdParams, pModuleAttributes), &TAP_SHADOW_TAP_ModuleCapabilityAttributes_ptr},
                {TAP_OFFSETOF(SMP_initModuleCmdParams, pCredentialList), &TAP_SHADOW_TAP_CredentialList_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_initModuleRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_initModuleRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_initModuleRspParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_uninitModuleCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_uninitModuleCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_uninitModuleCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_associateModuleCredentialsCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_associateModuleCredentialsCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_associateModuleCredentialsCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_associateModuleCredentialsCmdParams, pEntityCredentialList), &TAP_SHADOW_TAP_EntityCredentialList_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_initTokenCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_initTokenCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_initTokenCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_initTokenCmdParams, pTokenAttributes), &TAP_SHADOW_TAP_TokenCapabilityAttributes_ptr},
                {TAP_OFFSETOF(SMP_initTokenCmdParams, tokenId), &TAP_SHADOW_TAP_TokenId},
                {TAP_OFFSETOF(SMP_initTokenCmdParams, pCredentialList), &TAP_SHADOW_TAP_EntityCredentialList_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_initTokenRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_initTokenRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_initTokenRspParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_uninitTokenCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_uninitTokenCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_uninitTokenCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_uninitTokenCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_associateTokenCredentialsCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_associateTokenCredentialsCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_associateTokenCredentialsCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_associateTokenCredentialsCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_associateTokenCredentialsCmdParams, pCredentialList), &TAP_SHADOW_TAP_EntityCredentialList_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_initObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_initObjectCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_initObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_initObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_initObjectCmdParams, objectIdIn), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_initObjectCmdParams, pObjectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr},
                {TAP_OFFSETOF(SMP_initObjectCmdParams, pCredentialList), &TAP_SHADOW_TAP_EntityCredentialList_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_initObjectRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_initObjectRspParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_initObjectRspParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_initObjectRspParams, objectIdOut), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_initObjectRspParams, objectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_importObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_importObjectCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_importObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_importObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_importObjectCmdParams, pBlob), &TAP_SHADOW_TAP_Blob_ptr},
                {TAP_OFFSETOF(SMP_importObjectCmdParams, pObjectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr},
                {TAP_OFFSETOF(SMP_importObjectCmdParams, pCredentialList), &TAP_SHADOW_TAP_EntityCredentialList_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_importObjectRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_importObjectRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_importObjectRspParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_uninitObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_uninitObjectCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_uninitObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_uninitObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_uninitObjectCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_associateObjectCredentialsCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_associateObjectCredentialsCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_associateObjectCredentialsCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_associateObjectCredentialsCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_associateObjectCredentialsCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_associateObjectCredentialsCmdParams, pCredentialsList), &TAP_SHADOW_TAP_EntityCredentialList_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyCmdParams),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_verifyCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_verifyCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_verifyCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
                {TAP_OFFSETOF(SMP_verifyCmdParams, pDigest), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_verifyCmdParams, pSignature), &TAP_SHADOW_TAP_Signature_ptr}
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyRspParams, signatureValid), &TAP_SHADOW_ubyte},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyInitCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyInitCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyInitCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_verifyInitCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_verifyInitCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_verifyInitCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyInitRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyInitRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyInitRspParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyUpdateCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyUpdateCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyUpdateCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_verifyUpdateCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_verifyUpdateCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_verifyUpdateCmdParams, pBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_verifyUpdateCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyFinalCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyFinalCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyFinalCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_verifyFinalCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_verifyFinalCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_verifyFinalCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_verifyFinalRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_verifyFinalRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_verifyFinalRspParams, signatureValid), &TAP_SHADOW_ubyte},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signDigestCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signDigestCmdParams),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signDigestCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_signDigestCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_signDigestCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_signDigestCmdParams, pDigest), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_signDigestCmdParams, type), &TAP_SHADOW_TAP_SIG_SCHEME},
                {TAP_OFFSETOF(SMP_signDigestCmdParams, pSignatureAttributes), &TAP_SHADOW_TAP_SignAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signDigestRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signDigestRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signDigestRspParams, pSignature), &TAP_SHADOW_TAP_Signature_ptr},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signBufferCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signBufferCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &SMP_INTERFACE_SHADOW_SMP_signDigestCmdParams},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signBufferRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signBufferRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {0, &SMP_INTERFACE_SHADOW_SMP_signDigestRspParams},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signInitCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signInitCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signInitCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_signInitCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_signInitCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_signInitCmdParams, type), &TAP_SHADOW_TAP_SIG_SCHEME},
                {TAP_OFFSETOF(SMP_signInitCmdParams, pSignatureAttributes), &TAP_SHADOW_TAP_SignAttributes_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signInitRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signInitRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signInitRspParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signUpdateCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signUpdateCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signUpdateCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_signUpdateCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_signUpdateCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_signUpdateCmdParams, pBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_signUpdateCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signFinalCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signFinalCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signFinalCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_signFinalCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_signFinalCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_signFinalCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_signFinalRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_signFinalRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_signFinalRspParams, pSignature), &TAP_SHADOW_TAP_Signature_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_freeSignatureBufferCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_freeSignatureBufferCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_freeSignatureBufferCmdParams, ppSignature), &TAP_SHADOW_TAP_Signature_ptr_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_encryptCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_encryptCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_encryptCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
                {TAP_OFFSETOF(SMP_encryptCmdParams, pBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptRspParams, cipherBuffer), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptInitCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptInitCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptInitCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_encryptInitCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_encryptInitCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_encryptInitCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptInitRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptInitRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptInitRspParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptUpdateCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptUpdateCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptUpdateCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_encryptUpdateCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_encryptUpdateCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_encryptUpdateCmdParams, pBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_encryptUpdateCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptUpdateRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptUpdateRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptUpdateRspParams, cipherBuffer), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptFinalCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptFinalCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptFinalCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_encryptFinalCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_encryptFinalCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_encryptFinalCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_encryptFinalRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_encryptFinalRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_encryptFinalRspParams, cipherBuffer), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_decryptCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_decryptCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_decryptCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
                {TAP_OFFSETOF(SMP_decryptCmdParams, pCipherBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptRspParams, buffer), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptInitCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptInitCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptInitCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_decryptInitCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_decryptInitCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_decryptInitCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptInitRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptInitRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptInitRspParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptUpdateCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptUpdateCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptUpdateCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_decryptUpdateCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_decryptUpdateCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_decryptUpdateCmdParams, pCipherBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_decryptUpdateCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptUpdateRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptUpdateRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptUpdateRspParams, buffer), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptFinalCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptFinalCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptFinalCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_decryptFinalCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_decryptFinalCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_decryptFinalCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_decryptFinalRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_decryptFinalRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_decryptFinalRspParams, buffer), &TAP_SHADOW_TAP_Buffer},
        },
};




const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_digestCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_digestCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
                {TAP_OFFSETOF(SMP_digestCmdParams, pInputBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestRspParams, buffer), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestInitCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestInitCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestInitCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_digestInitCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_digestInitCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestInitRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestInitRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestInitRspParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestUpdateCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestUpdateCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestUpdateCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_digestUpdateCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_digestUpdateCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
                {TAP_OFFSETOF(SMP_digestUpdateCmdParams, pBuffer), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestFinalCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestFinalCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestFinalCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_digestFinalCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_digestFinalCmdParams, opContext), &TAP_SHADOW_TAP_OperationHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_digestFinalRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_digestFinalRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_digestFinalRspParams, buffer), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_ecdhGenerateSharedSecretCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_ECDHgenerateSharedSecretCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_ECDHgenerateSharedSecretCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_ECDHgenerateSharedSecretCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_ECDHgenerateSharedSecretCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_ECDHgenerateSharedSecretCmdParams, pOpAttributes), &TAP_SHADOW_TAP_OperationAttributes_ptr},
                {TAP_OFFSETOF(SMP_ECDHgenerateSharedSecretCmdParams, pPublicKey), &TAP_SHADOW_TAP_PublicKey_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_ecdhGenerateSharedSecretRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_ECDHgenerateSharedSecretRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_ECDHgenerateSharedSecretRspParams, secret), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getRandomCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getRandomCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getRandomCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getRandomCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getRandomCmdParams, pRngRequest), &TAP_SHADOW_TAP_RngAttributes_ptr},
                {TAP_OFFSETOF(SMP_getRandomCmdParams, bytesRequested), &TAP_SHADOW_ubyte4},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getRandomRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getRandomRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getRandomRspParams, random), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_stirRandomCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_stirRandomCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_stirRandomCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_stirRandomCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_stirRandomCmdParams, pRngRequest), &TAP_SHADOW_TAP_RngAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getTrustedDataCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTrustedDataCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getTrustedDataCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getTrustedDataCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getTrustedDataCmdParams, trustedDataType), &TAP_SHADOW_TAP_TRUSTED_DATA_TYPE},
                {TAP_OFFSETOF(SMP_getTrustedDataCmdParams, pTrustedDataInfo), &TAP_SHADOW_TAP_TrustedDataInfo_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getTrustedDataRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTrustedDataRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getTrustedDataRspParams, dataValue), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_updateTrustedDataCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_updateTrustedDataCmdParams),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_updateTrustedDataCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_updateTrustedDataCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_updateTrustedDataCmdParams, trustedDataType), &TAP_SHADOW_TAP_TRUSTED_DATA_TYPE},
                {TAP_OFFSETOF(SMP_updateTrustedDataCmdParams, pTrustedDataInfo), &TAP_SHADOW_TAP_TrustedDataInfo_ptr},
                {TAP_OFFSETOF(SMP_updateTrustedDataCmdParams, trustedDataOp), &TAP_SHADOW_TAP_TRUSTED_DATA_OPERATION},
                {TAP_OFFSETOF(SMP_updateTrustedDataCmdParams, pDataValue), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_updateTrustedDataRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getTrustedDataRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_updateTrustedDataRspParams, updatedDataValue), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_sealWithTrustedDataCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_sealWithTrustedDataCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_sealWithTrustedDataCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_sealWithTrustedDataCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_sealWithTrustedDataCmdParams, pRequestTemplate), &TAP_SHADOW_TAP_SealAttributes_ptr},
                {TAP_OFFSETOF(SMP_sealWithTrustedDataCmdParams, pDataToSeal), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_sealWithTrustedDataRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_sealWithTrustedDataRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_sealWithTrustedDataRspParams, dataOut), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_unsealWithTrustedDataCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_unsealWithTrustedDataCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_unsealWithTrustedDataCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_unsealWithTrustedDataCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_unsealWithTrustedDataCmdParams, pRequestTemplate), &TAP_SHADOW_TAP_SealAttributes_ptr},
                {TAP_OFFSETOF(SMP_unsealWithTrustedDataCmdParams, pDataToUnseal), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_unsealWithTrustedDataRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_unsealWithTrustedDataRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_unsealWithTrustedDataRspParams, dataOut), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_setPolicyStorageCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_setPolicyStorageCmdParams),
        .numFields = 6,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_setPolicyStorageCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_setPolicyStorageCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_setPolicyStorageCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_setPolicyStorageCmdParams, pPolicyAttributes), &TAP_SHADOW_TAP_PolicyStorageAttributes_ptr},
                {TAP_OFFSETOF(SMP_setPolicyStorageCmdParams, pOpAttributes), &TAP_SHADOW_TAP_OperationAttributes_ptr},
                {TAP_OFFSETOF(SMP_setPolicyStorageCmdParams, pData), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getPolicyStorageCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getPolicyStorageCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getPolicyStorageCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getPolicyStorageCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getPolicyStorageCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_getPolicyStorageCmdParams, pOpAttributes), &TAP_SHADOW_TAP_OperationAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getPolicyStorageRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getPolicyStorageRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getPolicyStorageRspParams, data), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_setPolicyStorageRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_setPolicyStorageRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_setPolicyStorageRspParams, data), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getCertificateRequestValidationAttrsCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getCertificateRequestValidationAttrsCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getCertificateRequestValidationAttrsCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getCertificateRequestValidationAttrsCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getCertificateRequestValidationAttrsCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getCertificateRequestValidationAttrsRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getCertificateRequestValidationAttrsRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getCertificateRequestValidationAttrsRspParams, blob), &TAP_SHADOW_TAP_Blob},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_unWrapKeyValidatedSecretCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_unWrapKeyValidatedSecretCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_unWrapKeyValidatedSecretCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_unWrapKeyValidatedSecretCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_unWrapKeyValidatedSecretCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_unWrapKeyValidatedSecretCmdParams, rtKeyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_unWrapKeyValidatedSecretCmdParams, pBlob), &TAP_SHADOW_TAP_Blob_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_unWrapKeyValidatedSecretRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_unWrapKeyValidatedSecretRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_unWrapKeyValidatedSecretRspParams, secret), &TAP_SHADOW_TAP_Buffer},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getQuoteCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getQuoteCmdParams),
        .numFields = 7,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, type), &TAP_SHADOW_TAP_TRUSTED_DATA_TYPE},
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, pInfo), &TAP_SHADOW_TAP_TrustedDataInfo_ptr},
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, pNonce), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_getQuoteCmdParams, pReserved), &TAP_SHADOW_TAP_AttributeList_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getQuoteRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getQuoteRspParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getQuoteRspParams, quoteData), &TAP_SHADOW_TAP_Blob},
                {TAP_OFFSETOF(SMP_getQuoteRspParams, pQuoteSignature), &TAP_SHADOW_TAP_Signature_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_createAsymmetricKeyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_createAsymmetricKeyCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_createAsymmetricKeyCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_createAsymmetricKeyCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_createAsymmetricKeyCmdParams, objectId), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_createAsymmetricKeyCmdParams, pKeyAttributes), &TAP_SHADOW_TAP_KeyAttributes_ptr},
                {TAP_OFFSETOF(SMP_createAsymmetricKeyCmdParams, initFlag), &TAP_SHADOW_ubyte},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_createAsymmetricKeyRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_createAsymmetricKeyRspParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_createAsymmetricKeyRspParams, objectIdOut), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_createAsymmetricKeyRspParams, objectAttributes), &TAP_SHADOW_TAP_ObjectAttributes},
                {TAP_OFFSETOF(SMP_createAsymmetricKeyRspParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getPublicKeyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getPublicKeyCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getPublicKeyCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getPublicKeyCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getPublicKeyCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getPublicKeyRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getPublicKeyRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getPublicKeyRspParams, pPublicKey), &TAP_SHADOW_TAP_PublicKey_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_freePublicKeyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_freePublicKeyCmdParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_freePublicKeyCmdParams, ppPublicKey), &TAP_SHADOW_TAP_PublicKey_ptr_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getPublicKeyBlobCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getPublicKeyBlobCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getPublicKeyBlobCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getPublicKeyBlobCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getPublicKeyBlobCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getPublicKeyBlobRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getPublicKeyBlobRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getPublicKeyBlobRspParams, pubkeyBlob), &TAP_SHADOW_TAP_Blob},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_duplicateKeyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_duplicateKeyCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
 
        .pFieldList = {
                {TAP_OFFSETOF(SMP_duplicateKeyCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_duplicateKeyCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_duplicateKeyCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_duplicateKeyCmdParams, pNewPubkey), &TAP_SHADOW_TAP_Blob_ptr},
                {TAP_OFFSETOF(SMP_duplicateKeyCmdParams, pMechanism), &TAP_SHADOW_TAP_MechanismAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_duplicateKeyRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_duplicateKeyRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_duplicateKeyRspParams, duplicateBuf), &TAP_SHADOW_TAP_Buffer},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_importDuplicateKeyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_ImportDuplicateKeyCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_ImportDuplicateKeyCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_ImportDuplicateKeyCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_ImportDuplicateKeyCmdParams, pKeyAttributes), &TAP_SHADOW_TAP_KeyAttributes_ptr},
                {TAP_OFFSETOF(SMP_ImportDuplicateKeyCmdParams, pDuplicateBuf), &TAP_SHADOW_TAP_Buffer_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_importDuplicateKeyRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_ImportDuplicateKeyRspParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_ImportDuplicateKeyRspParams, objectAttributes), &TAP_SHADOW_TAP_ObjectAttributes},
                {TAP_OFFSETOF(SMP_ImportDuplicateKeyRspParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_createSymmetricKeyCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_createSymmetricKeyCmdParams),
        .numFields = 5,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_createSymmetricKeyCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_createSymmetricKeyCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_createSymmetricKeyCmdParams, objectId), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_createSymmetricKeyCmdParams, pAttributeKey), &TAP_SHADOW_TAP_KeyAttributes_ptr},
                {TAP_OFFSETOF(SMP_createSymmetricKeyCmdParams, initFlag), &TAP_SHADOW_ubyte},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_createSymmetricKeyRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_createSymmetricKeyRspParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_createSymmetricKeyRspParams, objectIdOut), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_createSymmetricKeyRspParams, objectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes},
                {TAP_OFFSETOF(SMP_createSymmetricKeyRspParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_exportObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_exportObjectCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_exportObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_exportObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_exportObjectCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_exportObjectRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_exportObjectRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_exportObjectRspParams, exportedObject), &TAP_SHADOW_TAP_Blob},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_serializeObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_serializeObjectCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_serializeObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_serializeObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_serializeObjectCmdParams, objectId), &TAP_SHADOW_TAP_ObjectId},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_serializeObjectRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_serializeObjectRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_serializeObjectRspParams, serializedObject), &TAP_SHADOW_TAP_Buffer},
        },
};



const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_createObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_createObjectCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_createObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_createObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_createObjectCmdParams, objectIdIn), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_createObjectCmdParams, pObjectAttributes), &TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_createObjectRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_createObjectRspParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_createObjectRspParams, objectAttributesOut), &TAP_SHADOW_TAP_ObjectCapabilityAttributes},
                {TAP_OFFSETOF(SMP_createObjectRspParams, objectIdOut), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_createObjectRspParams, handle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_deleteObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_deleteObjectCmdParams),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_deleteObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_deleteObjectCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_deleteObjectCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_deleteObjectCmdParams, authContext), &TAP_SHADOW_TAP_ID},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_evictObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_evictObjectCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_evictObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_evictObjectCmdParams, pObjectId), &TAP_SHADOW_TAP_Buffer_ptr},
                {TAP_OFFSETOF(SMP_evictObjectCmdParams, pAttributes), &TAP_SHADOW_TAP_AttributeList_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_persistObjectCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_persistObjectCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_persistObjectCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_persistObjectCmdParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
                {TAP_OFFSETOF(SMP_persistObjectCmdParams, pObjectId), &TAP_SHADOW_TAP_Buffer_ptr}
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getRootOfTrustCertificateCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getRootOfTrustCertificateCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getRootOfTrustCertificateCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getRootOfTrustCertificateCmdParams, objectId), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_getRootOfTrustCertificateCmdParams, type), &TAP_SHADOW_TAP_ROOT_OF_TRUST_TYPE},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getRootOfTrustCertificateRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getRootOfTrustCertificateRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getRootOfTrustCertificateRspParams, certificate), &TAP_SHADOW_TAP_Blob},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getRootOfTrustKeyHandleCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getRootOfTrustKeyHandleCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getRootOfTrustKeyHandleCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getRootOfTrustKeyHandleCmdParams, objectId), &TAP_SHADOW_TAP_ObjectId},
                {TAP_OFFSETOF(SMP_getRootOfTrustKeyHandleCmdParams, type), &TAP_SHADOW_TAP_ROOT_OF_TRUST_TYPE},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getRootOfTrustKeyHandleRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getRootOfTrustKeyHandleRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getRootOfTrustKeyHandleRspParams, keyHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};



const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getLastErrorCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getLastErrorCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getLastErrorCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_getLastErrorCmdParams, tokenHandle), &TAP_SHADOW_TAP_TokenHandle},
                {TAP_OFFSETOF(SMP_getLastErrorCmdParams, objectHandle), &TAP_SHADOW_TAP_ObjectHandle},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getLastErrorRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_getLastErrorRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_getLastErrorRspParams, errorAttributes), &TAP_SHADOW_TAP_ErrorAttributes},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_selfTestCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_selfTestCmdParams),
        .numFields = 2,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_selfTestCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_selfTestCmdParams, pTestRequest), &TAP_SHADOW_TAP_TestRequestAttributes_ptr},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_selfTestRspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_selfTestRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_selfTestRspParams, testResponse), &TAP_SHADOW_TAP_TestResponseAttributes},
        },
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_selfTestPollCmdParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_selfTestPollCmdParams),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_OFFSETOF(SMP_selfTestPollCmdParams, moduleHandle), &TAP_SHADOW_TAP_ModuleHandle},
                {TAP_OFFSETOF(SMP_selfTestPollCmdParams, pTestRequest), &TAP_SHADOW_TAP_TestRequestAttributes_ptr},
                {TAP_OFFSETOF(SMP_selfTestPollCmdParams, testContext), &TAP_SHADOW_TAP_TestContext},
        },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleCapRspParams = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(SMP_getModuleCapabilityRspParams),
    .numFields = 1,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,

    .pFieldList = {
        { TAP_OFFSETOF(SMP_getModuleCapabilityRspParams, moduleCapabilities), &TAP_SHADOW_TAP_ModuleCapPropertyList },
    },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_getModuleCapCmdParams = {
    .handler = TAP_SERIALIZE_StructTypeHandler,
    .structSize = sizeof(SMP_getModuleCapabilityCmdParams),
    .numFields = 2,
    .unionSelectorOffset = 0,
    .unionSelectorSize = 0,

    .pFieldList = {
        { TAP_OFFSETOF(SMP_getModuleCapabilityCmdParams, moduleId), &TAP_SHADOW_TAP_ModuleId},
        { TAP_OFFSETOF(SMP_getModuleCapabilityCmdParams, pCapabilitySelectRange), &TAP_SHADOW_TAP_ModuleCapPropertyAttributes_ptr },
    },
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_CmdReqParams = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(SMP_CmdReqParams),
        .numFields = 78,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {SMP_CC_GET_MODULE_LIST, &SMP_INTERFACE_SHADOW_SMP_getModuleListCmdParams},
                {SMP_CC_FREE_MODULE_LIST, &SMP_INTERFACE_SHADOW_SMP_freeModuleListCmdParams},
                {SMP_CC_GET_MODULE_INFO, &SMP_INTERFACE_SHADOW_SMP_getModuleInfoCmdParams},
                {SMP_CC_GET_MODULE_SLOTS, &SMP_INTERFACE_SHADOW_SMP_getModuleSlotsCmdParams},
                {SMP_CC_GET_TOKEN_LIST, &SMP_INTERFACE_SHADOW_SMP_getTokenListCmdParams},
                {SMP_CC_GET_TOKEN_INFO, &SMP_INTERFACE_SHADOW_SMP_getTokenInfoCmdParams},
                {SMP_CC_GET_OBJECT_LIST, &SMP_INTERFACE_SHADOW_SMP_getObjectListCmdParams},
                {SMP_CC_GET_OBJECT_INFO, &SMP_INTERFACE_SHADOW_SMP_getObjectInfoCmdParams},
                {SMP_CC_PROVISION_MODULE, &SMP_INTERFACE_SHADOW_SMP_provisionModuleCmdParams},
                {SMP_CC_RESET_MODULE, &SMP_INTERFACE_SHADOW_SMP_resetModuleCmdParams},
                {SMP_CC_PROVISION_TOKEN, &SMP_INTERFACE_SHADOW_SMP_provisionTokensCmdParams},
                {SMP_CC_RESET_TOKEN, &SMP_INTERFACE_SHADOW_SMP_resetTokenCmdParams},
                {SMP_CC_DELETE_TOKEN, &SMP_INTERFACE_SHADOW_SMP_deleteTokenCmdParams},
                {SMP_CC_INIT_MODULE, &SMP_INTERFACE_SHADOW_SMP_initModuleCmdParams},
                {SMP_CC_UNINIT_MODULE, &SMP_INTERFACE_SHADOW_SMP_uninitModuleCmdParams},
                {SMP_CC_ASSOCIATE_MODULE_CREDENTIALS, &SMP_INTERFACE_SHADOW_SMP_associateModuleCredentialsCmdParams},
                {SMP_CC_INIT_TOKEN, &SMP_INTERFACE_SHADOW_SMP_initTokenCmdParams},
                {SMP_CC_UNINIT_TOKEN, &SMP_INTERFACE_SHADOW_SMP_uninitTokenCmdParams},
                {SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS, &SMP_INTERFACE_SHADOW_SMP_associateTokenCredentialsCmdParams},
                {SMP_CC_INIT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_initObjectCmdParams},
                {SMP_CC_IMPORT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_importObjectCmdParams},
                {SMP_CC_UNINIT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_uninitObjectCmdParams},
                {SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS, &SMP_INTERFACE_SHADOW_SMP_associateObjectCredentialsCmdParams},
                {SMP_CC_VERIFY, &SMP_INTERFACE_SHADOW_SMP_verifyCmdParams},
                {SMP_CC_VERIFY_INIT, &SMP_INTERFACE_SHADOW_SMP_verifyInitCmdParams},
                {SMP_CC_VERIFY_UPDATE, &SMP_INTERFACE_SHADOW_SMP_verifyUpdateCmdParams},
                {SMP_CC_VERIFY_FINAL, &SMP_INTERFACE_SHADOW_SMP_verifyFinalCmdParams},
                {SMP_CC_SIGN_DIGEST, &SMP_INTERFACE_SHADOW_SMP_signDigestCmdParams},
                {SMP_CC_SIGN_BUFFER, &SMP_INTERFACE_SHADOW_SMP_signBufferCmdParams},
                {SMP_CC_SIGN_INIT, &SMP_INTERFACE_SHADOW_SMP_signInitCmdParams},
                {SMP_CC_SIGN_UPDATE, &SMP_INTERFACE_SHADOW_SMP_signUpdateCmdParams},
                {SMP_CC_SIGN_FINAL, &SMP_INTERFACE_SHADOW_SMP_signFinalCmdParams},
                {SMP_CC_FREE_SIGNATURE_BUFFER, &SMP_INTERFACE_SHADOW_SMP_freeSignatureBufferCmdParams},
                {SMP_CC_ENCRYPT, &SMP_INTERFACE_SHADOW_SMP_encryptCmdParams},
                {SMP_CC_ENCRYPT_INIT, &SMP_INTERFACE_SHADOW_SMP_encryptInitCmdParams},
                {SMP_CC_ENCRYPT_UPDATE, &SMP_INTERFACE_SHADOW_SMP_encryptUpdateCmdParams},
                {SMP_CC_ENCRYPT_FINAL, &SMP_INTERFACE_SHADOW_SMP_encryptFinalCmdParams},
                {SMP_CC_DECRYPT, &SMP_INTERFACE_SHADOW_SMP_decryptCmdParams},
                {SMP_CC_DECRYPT_INIT, &SMP_INTERFACE_SHADOW_SMP_decryptInitCmdParams},
                {SMP_CC_DECRYPT_UPDATE, &SMP_INTERFACE_SHADOW_SMP_decryptUpdateCmdParams},
                {SMP_CC_DECRYPT_FINAL, &SMP_INTERFACE_SHADOW_SMP_decryptFinalCmdParams},
                {SMP_CC_DIGEST, &SMP_INTERFACE_SHADOW_SMP_digestCmdParams},
                {SMP_CC_DIGEST_INIT, &SMP_INTERFACE_SHADOW_SMP_digestInitCmdParams},
                {SMP_CC_DIGEST_UPDATE, &SMP_INTERFACE_SHADOW_SMP_digestUpdateCmdParams},
                {SMP_CC_DIGEST_FINAL, &SMP_INTERFACE_SHADOW_SMP_digestFinalCmdParams},
                {SMP_CC_GET_RANDOM, &SMP_INTERFACE_SHADOW_SMP_getRandomCmdParams},
                {SMP_CC_STIR_RANDOM, &SMP_INTERFACE_SHADOW_SMP_stirRandomCmdParams},
                {SMP_CC_GET_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_getTrustedDataCmdParams},
                {SMP_CC_UPDATE_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_updateTrustedDataCmdParams},
                {SMP_CC_SEAL_WITH_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_sealWithTrustedDataCmdParams},
                {SMP_CC_UNSEAL_WITH_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_unsealWithTrustedDataCmdParams},
                {SMP_CC_SET_POLICY_STORAGE, &SMP_INTERFACE_SHADOW_SMP_setPolicyStorageCmdParams},
                {SMP_CC_GET_POLICY_STORAGE, &SMP_INTERFACE_SHADOW_SMP_getPolicyStorageCmdParams},
                {SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS, &SMP_INTERFACE_SHADOW_SMP_getCertificateRequestValidationAttrsCmdParams},
                {SMP_CC_UNWRAP_KEY_VALIDATED_SECRET, &SMP_INTERFACE_SHADOW_SMP_unWrapKeyValidatedSecretCmdParams},
                {SMP_CC_SMP_GET_QUOTE, &SMP_INTERFACE_SHADOW_SMP_getQuoteCmdParams},
                {SMP_CC_CREATE_ASYMMETRIC_KEY, &SMP_INTERFACE_SHADOW_SMP_createAsymmetricKeyCmdParams},
                {SMP_CC_GET_PUBLIC_KEY, &SMP_INTERFACE_SHADOW_SMP_getPublicKeyCmdParams},
                {SMP_CC_FREE_PUBLIC_KEY, &SMP_INTERFACE_SHADOW_SMP_freePublicKeyCmdParams},
                {SMP_CC_CREATE_SYMMETRIC_KEY, &SMP_INTERFACE_SHADOW_SMP_createSymmetricKeyCmdParams},
                {SMP_CC_EXPORT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_exportObjectCmdParams},
                {SMP_CC_SERIALIZE_OBJECT, &SMP_INTERFACE_SHADOW_SMP_serializeObjectCmdParams},
                {SMP_CC_CREATE_OBJECT, &SMP_INTERFACE_SHADOW_SMP_createObjectCmdParams},
                {SMP_CC_DELETE_OBJECT, &SMP_INTERFACE_SHADOW_SMP_deleteObjectCmdParams},
                {SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE, &SMP_INTERFACE_SHADOW_SMP_getRootOfTrustCertificateCmdParams},
                {SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE, &SMP_INTERFACE_SHADOW_SMP_getRootOfTrustKeyHandleCmdParams},
                {SMP_CC_GET_LAST_ERROR, &SMP_INTERFACE_SHADOW_SMP_getLastErrorCmdParams},
                {SMP_CC_SELF_TEST, &SMP_INTERFACE_SHADOW_SMP_selfTestCmdParams},
                {SMP_CC_SELF_TEST_POLL, &SMP_INTERFACE_SHADOW_SMP_selfTestPollCmdParams},
                {SMP_CC_GET_PUBLIC_KEY_BLOB, &SMP_INTERFACE_SHADOW_SMP_getPublicKeyBlobCmdParams},
                {SMP_CC_DUPLICATEKEY, &SMP_INTERFACE_SHADOW_SMP_duplicateKeyCmdParams},
                {SMP_CC_IMPORTDUPLICATEKEY, &SMP_INTERFACE_SHADOW_SMP_importDuplicateKeyCmdParams},
                {SMP_CC_GET_MODULE_CAPABILITY, &SMP_INTERFACE_SHADOW_SMP_getModuleCapCmdParams},
                {SMP_CC_ECDH_GENERATE_SHARED_SECRET, &SMP_INTERFACE_SHADOW_SMP_ecdhGenerateSharedSecretCmdParams},
                {SMP_CC_PURGE_OBJECT, &SMP_INTERFACE_SHADOW_SMP_deleteObjectCmdParams},
                {SMP_CC_IMPORT_EXTERNAL_KEY, &SMP_INTERFACE_SHADOW_SMP_createObjectCmdParams},
                {SMP_CC_EVICT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_evictObjectCmdParams},
                {SMP_CC_PERSIST_OBJECT, &SMP_INTERFACE_SHADOW_SMP_persistObjectCmdParams},
        }
};

const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_CmdRspParams = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(SMP_CmdRspParams),
        .numFields = 57,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {SMP_CC_GET_MODULE_LIST, &SMP_INTERFACE_SHADOW_SMP_getModuleListRspParams},
                /* {SMP_CC_FREE_MODULE_LIST, 0}, */
                {SMP_CC_GET_MODULE_INFO, &SMP_INTERFACE_SHADOW_SMP_getModuleInfoRspParams},
                {SMP_CC_GET_MODULE_SLOTS, &SMP_INTERFACE_SHADOW_SMP_getModuleSlotsRspParams},
                {SMP_CC_GET_TOKEN_LIST, &SMP_INTERFACE_SHADOW_SMP_getTokenListRspParams},
                {SMP_CC_GET_TOKEN_INFO, &SMP_INTERFACE_SHADOW_SMP_getTokenInfoRspParams},
                {SMP_CC_GET_OBJECT_LIST, &SMP_INTERFACE_SHADOW_SMP_getObjectListRspParams},
                {SMP_CC_GET_OBJECT_INFO, &SMP_INTERFACE_SHADOW_SMP_getObjectInfoRspParams},
                /* {SMP_CC_PROVISION_MODULE, 0}, */
                /* {SMP_CC_RESET_MODULE, 0}, */
                {SMP_CC_PROVISION_TOKEN, &SMP_INTERFACE_SHADOW_SMP_provisionTokensRspParams},
                /* {SMP_CC_RESET_TOKEN, 0}, */
                /* {SMP_CC_DELETE_TOKEN, 0}, */
                {SMP_CC_INIT_MODULE, &SMP_INTERFACE_SHADOW_SMP_initModuleRspParams},
                /* {SMP_CC_UNINIT_MODULE, 0}, */
                /* {SMP_CC_ASSOCIATE_MODULE_CREDENTIALS, 0}, */
                {SMP_CC_INIT_TOKEN, &SMP_INTERFACE_SHADOW_SMP_initTokenRspParams},
                /* {SMP_CC_UNINIT_TOKEN, 0}, */
                /* {SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS, 0}, */
                {SMP_CC_INIT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_initObjectRspParams},
                {SMP_CC_IMPORT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_importObjectRspParams},
                /* {SMP_CC_UNINIT_OBJECT, 0}, */
                /* {SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS, 0}, */
                {SMP_CC_VERIFY, &SMP_INTERFACE_SHADOW_SMP_verifyRspParams},
                {SMP_CC_VERIFY_INIT, &SMP_INTERFACE_SHADOW_SMP_verifyInitRspParams},
                /* {SMP_CC_VERIFY_UPDATE, 0}, */
                {SMP_CC_VERIFY_FINAL, &SMP_INTERFACE_SHADOW_SMP_verifyFinalRspParams},
                {SMP_CC_SIGN_DIGEST, &SMP_INTERFACE_SHADOW_SMP_signDigestRspParams},
                {SMP_CC_SIGN_BUFFER, &SMP_INTERFACE_SHADOW_SMP_signBufferRspParams},
                {SMP_CC_SIGN_INIT, &SMP_INTERFACE_SHADOW_SMP_signInitRspParams},
                /* {SMP_CC_SIGN_UPDATE, 0}, */
                {SMP_CC_SIGN_FINAL, &SMP_INTERFACE_SHADOW_SMP_signFinalRspParams},
                /* {SMP_CC_FREE_SIGNATURE_BUFFER, 0}, */
                {SMP_CC_ENCRYPT, &SMP_INTERFACE_SHADOW_SMP_encryptRspParams},
                {SMP_CC_ENCRYPT_INIT, &SMP_INTERFACE_SHADOW_SMP_encryptInitRspParams},
                {SMP_CC_ENCRYPT_UPDATE, &SMP_INTERFACE_SHADOW_SMP_encryptUpdateRspParams},
                {SMP_CC_ENCRYPT_FINAL, &SMP_INTERFACE_SHADOW_SMP_encryptFinalRspParams},
                {SMP_CC_DECRYPT, &SMP_INTERFACE_SHADOW_SMP_decryptRspParams},
                {SMP_CC_DECRYPT_INIT, &SMP_INTERFACE_SHADOW_SMP_decryptInitRspParams},
                {SMP_CC_DECRYPT_UPDATE, &SMP_INTERFACE_SHADOW_SMP_decryptUpdateRspParams},
                {SMP_CC_DECRYPT_FINAL, &SMP_INTERFACE_SHADOW_SMP_decryptFinalRspParams},
                {SMP_CC_DIGEST, &SMP_INTERFACE_SHADOW_SMP_digestRspParams},
                {SMP_CC_DIGEST_INIT, &SMP_INTERFACE_SHADOW_SMP_digestInitRspParams},
                /* {SMP_CC_DIGEST_UPDATE, 0}, */
                {SMP_CC_DIGEST_FINAL, &SMP_INTERFACE_SHADOW_SMP_digestFinalRspParams},
                {SMP_CC_GET_RANDOM, &SMP_INTERFACE_SHADOW_SMP_getRandomRspParams},
                /* {SMP_CC_STIR_RANDOM, 0}, */
                {SMP_CC_GET_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_getTrustedDataRspParams},
                {SMP_CC_UPDATE_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_updateTrustedDataRspParams},
                {SMP_CC_SEAL_WITH_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_sealWithTrustedDataRspParams},
                {SMP_CC_UNSEAL_WITH_TRUSTED_DATA, &SMP_INTERFACE_SHADOW_SMP_unsealWithTrustedDataRspParams},
                {SMP_CC_GET_POLICY_STORAGE, &SMP_INTERFACE_SHADOW_SMP_getPolicyStorageRspParams},
                {SMP_CC_SET_POLICY_STORAGE,&SMP_INTERFACE_SHADOW_SMP_setPolicyStorageRspParams},
                {SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS, &SMP_INTERFACE_SHADOW_SMP_getCertificateRequestValidationAttrsRspParams},
                {SMP_CC_UNWRAP_KEY_VALIDATED_SECRET, &SMP_INTERFACE_SHADOW_SMP_unWrapKeyValidatedSecretRspParams},
                {SMP_CC_SMP_GET_QUOTE, &SMP_INTERFACE_SHADOW_SMP_getQuoteRspParams},
                {SMP_CC_CREATE_ASYMMETRIC_KEY, &SMP_INTERFACE_SHADOW_SMP_createAsymmetricKeyRspParams},
                {SMP_CC_GET_PUBLIC_KEY, &SMP_INTERFACE_SHADOW_SMP_getPublicKeyRspParams},
                /* {SMP_CC_FREE_PUBLIC_KEY, 0}, */
                {SMP_CC_CREATE_SYMMETRIC_KEY, &SMP_INTERFACE_SHADOW_SMP_createSymmetricKeyRspParams},
                {SMP_CC_EXPORT_OBJECT, &SMP_INTERFACE_SHADOW_SMP_exportObjectRspParams},
                {SMP_CC_SERIALIZE_OBJECT, &SMP_INTERFACE_SHADOW_SMP_serializeObjectRspParams},
                {SMP_CC_CREATE_OBJECT, &SMP_INTERFACE_SHADOW_SMP_createObjectRspParams},
                /* {SMP_CC_DELETE_OBJECT, 0}, */
                {SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE, &SMP_INTERFACE_SHADOW_SMP_getRootOfTrustCertificateRspParams},
                {SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE, &SMP_INTERFACE_SHADOW_SMP_getRootOfTrustKeyHandleRspParams},
                {SMP_CC_GET_LAST_ERROR, &SMP_INTERFACE_SHADOW_SMP_getLastErrorRspParams},
                {SMP_CC_SELF_TEST, &SMP_INTERFACE_SHADOW_SMP_selfTestRspParams},
                {SMP_CC_SELF_TEST_POLL, &SMP_INTERFACE_SHADOW_SMP_selfTestPollCmdParams},
                {SMP_CC_GET_PUBLIC_KEY_BLOB, &SMP_INTERFACE_SHADOW_SMP_getPublicKeyBlobRspParams},
                {SMP_CC_DUPLICATEKEY, &SMP_INTERFACE_SHADOW_SMP_duplicateKeyRspParams},
                {SMP_CC_IMPORTDUPLICATEKEY, &SMP_INTERFACE_SHADOW_SMP_importDuplicateKeyRspParams},
                {SMP_CC_GET_MODULE_CAPABILITY, &SMP_INTERFACE_SHADOW_SMP_getModuleCapRspParams},
                {SMP_CC_ECDH_GENERATE_SHARED_SECRET, &SMP_INTERFACE_SHADOW_SMP_ecdhGenerateSharedSecretRspParams},
                /* {SMP_CC_PURGE_OBJECT, 0}, */
                {SMP_CC_IMPORT_EXTERNAL_KEY, &SMP_INTERFACE_SHADOW_SMP_createObjectRspParams},
                /* {SMP_CC_EVICT_OBJECT, 0}, */
                /* {SMP_CC_PERSIST_OBJECT, 0}, */
    }
};


const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_CmdReq = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_CmdReq),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(SMP_CmdReq, cmdCode),
        .unionSelectorSize = SIZEOF(SMP_CmdReq, cmdCode),
        .pFieldList = {
                {TAP_OFFSETOF(SMP_CmdReq, cmdCode), &TAP_SHADOW_SMP_CC},
                {TAP_OFFSETOF(SMP_CmdReq, reqParams), &SMP_INTERFACE_SHADOW_SMP_CmdReqParams},
        },
};

MOC_EXTERN_DATA_DEF const tap_shadow_struct SMP_INTERFACE_SHADOW_SMP_CmdRsp = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(SMP_CmdRsp),
        .numFields = 3,
        .unionSelectorOffset = TAP_OFFSETOF(SMP_CmdRsp, cmdCode),
        .unionSelectorSize = SIZEOF(SMP_CmdRsp, cmdCode),
        .pFieldList = {
                {TAP_OFFSETOF(SMP_CmdRsp, cmdCode), &TAP_SHADOW_SMP_CC},
                {TAP_OFFSETOF(SMP_CmdRsp, returnCode), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(SMP_CmdRsp, rspParams), &SMP_INTERFACE_SHADOW_SMP_CmdRspParams}
        },

};


#endif /* if defined(__ENABLE_DIGICERT_SMP__) */
