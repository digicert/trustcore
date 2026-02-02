/*
 * smp_tpm2.h
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
 * @file       smp_tpm2.h
 * @brief      NanoSMP for TPM2 Header file
 * @details    This header file contains private structure
               definitions needed by TPM2 SMP
 */

#ifndef __SMP_TPM2_HEADER__
#define __SMP_TPM2_HEADER__ 

/*************************************
  MACRO Definitions
*************************************/
/*! Used in configuration file to declare a range device names to look for
  the TPM2 secure element with matching "moduleidstr" in a range of device
  names. For example, setting  moduleName=/dev/tpm* in the configuration 
  file will result in search for the matching moduleidstr in any one of 
  /dev/tpm0 - /dev/tpm9 devices
 */
#define WILDCARD            '*'
#define WILDCARD_STR_LEN    8
#define MAX_TPM2_DEVICES    10 

/*! OID Length is used to skip the OID during software verification of 
  RSA signature */
#define SHA256_OID_LEN     19
#define MIN(a,b) ((a < b) ? a : b)
#define MAX_ACTIVE_IDS 64

#define LOCKOUT_HIERARCHY_AUTH          1
#define OWNER_HIERARCHY_AUTH            2
#define ENDORSEMENT_HIERARCHY_AUTH      3

/* Reserved NVRAM IDs for retrieving EK Certificates */
#define TPM2_RSA_EK_CERTIFICATE_NVRAM_ID    0x01c00002
#define TPM2_ECC_EK_CERTIFICATE_NVRAM_ID    0x01c0000a

/* TPM2 Entity IDs, used during authorization */
#define TPM2_RH_SRK_ID             0x40000000           
#define TPM2_RH_EK_ID              0x40000006
#define TPM2_RH_OWNER_ID           0x40000001
#define TPM2_RH_ENDORSEMENT_ID     0x4000000B
#define TPM2_RH_LOCKOUT_ID         0x4000000A


typedef struct 
{
    TAP_MODULE_PROVISION_STATE *pIsTpmConfigured;
    ubyte4 *pManufacturer;
    ubyte4 *pVendorString1;
    ubyte4 *pVendorString2;
    ubyte4 *pFirmwareVersionLow;
    ubyte4 *pFirmwareVersionHigh;
    ubyte  *pModuleIdStr;
} TPM2_MODULE_INFO;

typedef ubyte4 TPM2_ObjectType;

#define TPM2_OBJECT_TYPE_UNKNOWN    (TPM2_ObjectType)0
#define TPM2_OBJECT_TYPE_KEY        (TPM2_ObjectType)1
#define TPM2_OBJECT_TYPE_NV         (TPM2_ObjectType)2

typedef struct 
{
    /* Object Type, set to TPM2_OBJECT_TYPE_KEY */
    TPM2_ObjectType objectType;

    /* Key Id, if set the key field is not valid */
    TAP_ObjectId id;

    /* Key Name */
    TPM2B_NAME keyName;
    
    /* Key Algorithm */
    TPMI_ALG_PUBLIC keyAlgorithm;
    
    /* Serialized key */
    FAPI2B_OBJECT key;
} CACHED_KeyInfo;

typedef struct _TPM2_OBJECT
{
    /* Object Type, set to TPM2_OBJECT_TYPE_NV */
    TPM2_ObjectType objectType;

    /* Key Id, w this is clear */
    TAP_ObjectId id;

    ubyte4 size;
    TPM2B_AUTH auth;
    struct _TPM2_OBJECT *pNext;
} TPM2_OBJECT;

typedef struct 
{
    /* Active Id count */
    ubyte4 numActiveIds;

    /* Active ID buffer */
    TAP_ObjectId *pActiveIds;
} SMP_TPM2_ID_INFO;

typedef struct _TPM2_MODULE_CONFIG_SECTION
{
    TAP_Buffer moduleName;
    ubyte2 modulePort;
    ubyte configuredModuleIdStr[SHA256_RESULT_SIZE];
    ubyte *pConfiguredModuleIdStrStart; /* Points to the location in the buffer where the module id string starts */
    ubyte4 configuredModuleIdStrLen;
    TAP_ID moduleId;
    RTOS_MUTEX moduleMutex;

    /* Populated at run time */
    /* Device Module ID, read from secure element during initialization */
    ubyte deviceModuleIdStr[SHA256_RESULT_SIZE];
    TAP_TEST_STATUS testResult;
    TAP_Buffer credentialFile;

    /* Config that controls reuse of Device handle received from TAPS.
     * i.e. open-close device handle only once
     * This is not part of tpm2.conf, it is passed from TAP server program */
    byteBoolean reuseDeviceFd;

    /* Platform authentication if configured */
    TAP_Buffer platformAuth;

    struct _TPM2_MODULE_CONFIG_SECTION *pNext;
} TPM2_MODULE_CONFIG_SECTION;

typedef struct
{
    TAP_TokenId id;
    TPM2B_AUTH keyAuth;

    /* Active Objects */
    TPM2_OBJECT *pTpm2ObjectFirst;
} TOKEN_Context;

typedef struct 
{
    TAP_ModuleId moduleId;

    FAPI2_CONTEXT *pFapiContext;

    /* Auth value */
    /* lockoutAuth is not used for windows */
    TPM2B_AUTH lockoutAuth;
    /* ownerAuth is equivalent to SRK auth on windows */
    TPM2B_AUTH ownerAuth;
    TPM2B_AUTH endorsementAuth;

    /* Optional platform auth if explicitly provided by user in tpm2.conf */
    TPM2B_AUTH platformAuth;

    RTOS_MUTEX moduleMutex;
} SMP_Context;

/***********************************
   Private Functions 
***********************************/
MSTATUS TPM2_validateModuleList(
        TPM2_MODULE_CONFIG_SECTION *pModuleInfo);

#endif /* __SMP_TPM2_HEADER__ */
