/**
 * @file tap_serialize.h
 *
 * @brief  Trust Anchor Platform (TAP) serialization code for structures defined in tap.h
 * @details This file contains definitions for Trust Anchor Platform (TAP) serialization of structures defined in tap.h.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular HW security module:
 *    + \c \__ENABLE_DIGICERT_TPM__
 *    + \c \__ENABLE_DIGICERT_TPM2__
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

/*------------------------------------------------------------------*/

#ifndef __TAP_SERIALIZE_HEADER__
#define __TAP_SERIALIZE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TAP__))

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"

#include "tap_base_serialize.h"

/***************************************************************
   Structure  Definitions
****************************************************************/

extern const tap_shadow_struct TAP_SHADOW_MOC_UUID_NODE;
extern const tap_shadow_struct TAP_SHADOW_MOC_UUID;

extern const tap_shadow_struct TAP_SHADOW_TCP_SOCKET;


extern const tap_shadow_struct TAP_SHADOW_DATA_SOURCE;

extern const tap_shadow_struct TAP_SHADOW_OBJECT_TYPE;

extern const tap_shadow_struct TAP_SHADOW_TAP_BufferPacked;

extern const tap_shadow_struct TAP_SHADOW_TAP_ServerName;

extern const tap_shadow_struct TAP_SHADOW_TAP_FileInfo;

extern const tap_shadow_struct TAP_SHADOW_TAP_ConnectionInfo;

extern const tap_shadow_struct TAP_SHADOW_TAP_SHA1_DIGEST;

extern const tap_shadow_struct TAP_SHADOW_TAP_Module;
extern const tap_shadow_struct TAP_SHADOW_TAP_Module_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_Module_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_ModuleList;

extern const tap_shadow_struct TAP_SHADOW_TAP_HostDeviceInfo;


extern const tap_shadow_struct TAP_SHADOW_FirmwareVersion;

extern const tap_shadow_struct TAP_SHADOW_TAP_SessionInfo;

extern const tap_shadow_struct TAP_SHADOW_TAP_LocalContext;
extern const tap_shadow_struct TAP_SHADOW_TAP_Context;

extern const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_RSA;
extern const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_ECC;
extern const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_AES;
extern const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_HMAC;
extern const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo_Union;
extern const tap_shadow_struct TAP_SHADOW_TAP_KeyInfo;

extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectInfo;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectInfo_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectInfoList;
extern const tap_shadow_struct TAP_SHADOW_TAP_ObjectData;

extern const tap_shadow_struct TAP_SHADOW_TAP_KeyData;

MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_SHADOW_TAP_Key;

MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_SHADOW_TAP_Object;

extern const tap_shadow_struct TAP_SHADOW_TAP_StorageInfo;
extern const tap_shadow_struct TAP_SHADOW_TAP_StorageInfo_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_StorageInfo_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_StorageInfoList;

MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_SHADOW_TAP_StorageObject;
extern const tap_shadow_struct TAP_SHADOW_TAP_StorageObject_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_StorageObject_ptr_ptr;
extern const tap_shadow_struct TAP_SHADOW_TAP_StorageObjectList;

extern const tap_shadow_struct TAP_SHADOW_TAP_AttributeStructUnion;
extern const tap_shadow_struct TAP_SHADOW_TAP_AttributeStructUnion_ptr;


/***************************************************************
   Function Definitions
****************************************************************/


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* __TAP_SERIALIZE_HEADER__ */
