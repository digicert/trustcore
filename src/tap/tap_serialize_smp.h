/**
 * @file tap_serialize_smp.h
 *
 * @brief  Trust Anchor Platform (TAP) serialization code for structures defined in tap_smp.h
 * @details This file contains definitions for Mocana Trust Anchor Platform (TAP) serialization of structures defined in tap_smp.h.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular HW security module:
 *    + \c \__ENABLE_MOCANA_TPM__
 *    + \c \__ENABLE_MOCANA_TPM2__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 * 
 */


/*------------------------------------------------------------------*/

#ifndef __TAP_SERIALIZE_SMP_HEADER__
#define __TAP_SERIALIZE_SMP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/moptions.h"

#if (defined(__ENABLE_MOCANA_TAP__))

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"

#include "tap_base_serialize.h"
#include "tap_serialize.h"

/***************************************************************
   Structure  Definitions
****************************************************************/

extern const tap_shadow_struct TAP_SHADOW_SMP_CC;

extern const tap_shadow_struct TAP_SHADOW_TAP_HANDLE;

extern const tap_shadow_struct TAP_SHADOW_TAP_ID;

extern const tap_shadow_struct TAP_SHADOW_TAP_SHA256Buffer;

extern const tap_shadow_struct TAP_SHADOW_TAP_RequestContext;
extern const tap_shadow_struct TAP_SHADOW_TAP_TestContext;
extern const tap_shadow_struct TAP_SHADOW_TAP_TestContext_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_ErrorContext;

extern const tap_shadow_struct TAP_SHADOW_TAP_PROVIDER;

extern const tap_shadow_struct TAP_SHADOW_TAP_KEY_ALGORITHM;

extern const tap_shadow_struct TAP_SHADOW_TAP_KEY_SIZE;

extern const tap_shadow_struct TAP_SHADOW_TAP_RAW_KEY_SIZE;

extern const tap_shadow_struct TAP_SHADOW_TAP_SYM_KEY_MODE;

extern const tap_shadow_struct TAP_SHADOW_TAP_HASH_ALG;

extern const tap_shadow_struct TAP_SHADOW_TAP_KEY_USAGE;

extern const tap_shadow_struct TAP_SHADOW_TAP_KEY_CMK;

extern const tap_shadow_struct TAP_SHADOW_TAP_KEY_WRAP_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_CREDENTIAL_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_CREDENTIAL_FORMAT;

extern const tap_shadow_struct TAP_SHADOW_TAP_MODULE_PROVISION_STATE;

extern const tap_shadow_struct TAP_SHADOW_TAP_BLOB_FORMAT;

extern const tap_shadow_struct TAP_SHADOW_TAP_BLOB_ENCODING;

extern const tap_shadow_struct TAP_SHADOW_TAP_CREDENTIAL_CONTEXT;

extern const tap_shadow_struct TAP_SHADOW_TAP_OP_EXEC_FLAG;

extern const tap_shadow_struct TAP_SHADOW_TAP_RNG_PROPERTY;

extern const tap_shadow_struct TAP_SHADOW_TAP_WRITE_OP_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_TRUSTED_DATA_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_TRUSTED_DATA_SUBTYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_ROOT_OF_TRUST_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_TRUSTED_DATA_OPERATION;

extern const tap_shadow_struct TAP_SHADOW_TAP_ATTR_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_ENTITY_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_TOKEN_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_TEST_MODE;

extern const tap_shadow_struct TAP_SHADOW_TAP_TEST_STATUS;

extern const tap_shadow_struct TAP_SHADOW_TAP_PERMISSION_BITMASK;

extern const tap_shadow_struct TAP_SHADOW_TAP_CAPABILITY_CATEGORY;

extern const tap_shadow_struct TAP_SHADOW_TAP_CAPABILITY_FUNCTIONALITY;

extern const tap_shadow_struct TAP_SHADOW_TAP_SMPContext;

extern const tap_shadow_struct TAP_SHADOW_TAP_Buffer;
extern const tap_shadow_struct TAP_SHADOW_TAP_Buffer_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_Buffer_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_BufferList;

extern const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfo;
extern const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfo_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfo_ptr_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfoList;
extern const tap_shadow_struct TAP_SHADOW_TAP_ConfigInfoList_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_Blob;
extern const tap_shadow_struct TAP_SHADOW_TAP_Blob_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_Attribute;
extern const tap_shadow_struct TAP_SHADOW_TAP_Attribute_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_Attribute_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_AttributeList;
extern const tap_shadow_struct TAP_SHADOW_TAP_AttributeList_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapabilityAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapabilityAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleProvisionAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleProvisionAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ErrorAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_ErrorAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_RngAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_RngAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_TokenCapabilityAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_TokenCapabilityAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_TokenProvisionAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_TokenProvisionAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectCapabilityAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectCapabilityAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_MechanismAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_MechanismAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_SignAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_SignAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_SealAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_SealAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_PolicyStorageAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_PolicyStorageAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_KeyAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_KeyAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_OperationAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_OperationAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_TestRequestAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_TestRequestAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_TestResponseAttributes;
extern const tap_shadow_struct TAP_SHADOW_TAP_TestResponseAttributes_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_PROVIDER_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_PROVIDER_ptr_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_CmdCodeList;
extern const tap_shadow_struct TAP_SHADOW_TAP_CmdCodeList_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ProviderCmdList;
extern const tap_shadow_struct TAP_SHADOW_TAP_ProviderCmdList_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ProviderList;
extern const tap_shadow_struct TAP_SHADOW_TAP_ProviderList_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_Version;
extern const tap_shadow_struct TAP_SHADOW_TAP_FirmwareVersion;
extern const tap_shadow_struct TAP_SHADOW_TAP_HardwareVersion;
extern const tap_shadow_struct TAP_SHADOW_TAP_SMPVersion;

extern const tap_shadow_struct TAP_SHADOW_TAP_ErrorAttributes_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_Error;

extern const tap_shadow_struct TAP_SHADOW_TAP_TrustData;

extern const tap_shadow_struct TAP_SHADOW_TAP_AuthData;

extern const tap_shadow_struct TAP_SHADOW_TAP_KeyHandle;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleHandle;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectHandle;
extern const tap_shadow_struct TAP_SHADOW_TAP_TokenHandle;
extern const tap_shadow_struct TAP_SHADOW_TAP_OperationHandle;

extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleId;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectId;
extern const tap_shadow_struct TAP_SHADOW_TAP_TokenId;
extern const tap_shadow_struct TAP_SHADOW_TAP_SlotId;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityId;

extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleSlotInfo;

extern const tap_shadow_struct TAP_SHADOW_TAP_SlotId_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_SlotId_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleSlotList;

extern const tap_shadow_struct TAP_SHADOW_TAP_Credential;
extern const tap_shadow_struct TAP_SHADOW_TAP_Credential_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_Credential_ptr_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_CredentialList;
extern const tap_shadow_struct TAP_SHADOW_TAP_CredentialList_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_EntityId_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityId_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityIdList;

extern const tap_shadow_struct TAP_SHADOW_TAP_EntityList;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityList_ptr;


extern const tap_shadow_struct TAP_SHADOW_TAP_EntityCredential;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityCredential_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityCredential_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_EntityCredentialList;

extern const tap_shadow_struct TAP_SHADOW_TAP_PolicyInfo;

extern const tap_shadow_struct TAP_SHADOW_TAP_TrustedDataInfo;
extern const tap_shadow_struct TAP_SHADOW_TAP_TrustedDataInfo_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_RSASignature;
extern const tap_shadow_struct TAP_SHADOW_TAP_ECCSignature;
extern const tap_shadow_struct TAP_SHADOW_TAP_DSASignature;
extern const tap_shadow_struct TAP_SHADOW_TAP_SymSignature;
extern const tap_shadow_struct TAP_SHADOW_TAP_Signature_Union;
MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_SHADOW_TAP_Signature;
extern const tap_shadow_struct TAP_SHADOW_TAP_Signature_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_Signature_ptr_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_ENC_SCHEME;

extern const tap_shadow_struct TAP_SHADOW_TAP_SIG_SCHEME;

extern const tap_shadow_struct TAP_SHADOW_TAP_ECC_CURVE;


extern const tap_shadow_struct TAP_SHADOW_TAP_RSAPublicKey;
extern const tap_shadow_struct TAP_SHADOW_TAP_ECCPublicKey;
extern const tap_shadow_struct TAP_SHADOW_TAP_DSAPublicKey;
extern const tap_shadow_struct TAP_SHADOW_TAP_PublicKey_Union;
extern const tap_shadow_struct TAP_SHADOW_TAP_PublicKey;
extern const tap_shadow_struct TAP_SHADOW_TAP_PublicKey_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_PublicKey_ptr_ptr;

extern const tap_shadow_struct TAP_SHADOW_TAP_MODULE_CAP_PROPERTY_TAG;
extern const tap_shadow_struct TAP_SHADOW_TAP_MODULE_CAP_CAP_T;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapPropertyList;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleCapPropertyAttributes_ptr;

/***************************************************************
   Function Definitions
****************************************************************/

MOC_EXTERN const tap_shadow_struct *
TAP_SERALIZE_SMP_getPublicKeyShadowStruct(void);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_MOCANA_TAP__ */
#endif /* __TAP_SERIALIZE_SMP_HEADER__ */
