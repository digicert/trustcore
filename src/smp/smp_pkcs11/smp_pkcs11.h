/*
 * smp_pkcs11.h
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

/**
@file       smp_pkcs11.h
@ingroup    nanosmp_tree
@brief      PKCS11 specific header file
@details    This header file contains structures required to work with NanoSMP
            and helper function declarations required by PKCS11 API.
*/

#ifndef __SMP_PKCS11_HEADER__
#define __SMP_PKCS11_HEADER__

#include <stdlib.h>
#include <stdio.h>

#include "include/cryptoki.h"
#include "../../common/mrtos.h"
#include "../../common/debug_console.h"

/* Maximum No. of Slots for Pkcs11 in a system */
#define MAX_MODULE_SLOTS 6
/* Tokens are mapped to Slots */
#define MAX_TOKEN_SLOTS MAX_MODULE_SLOTS
/* Maximum size of a pin description */
#define MAX_DESC_SZ 33
#define MAX_LABEL_DESC_SZ 37
#define MAX_LABEL_REQD 5
#define MAX_SLOT_DESC_SZ 65
#define SO_PIN_LEN 24
#define DEFAULT_USER_PIN_LEN 4
#define EMULATED_MODULE_ID 0
#define MAX_DATA_STORAGE 1024
#define MAX_ERROR_BUFFER 128
#define MAX_BUFFER_SIZE 256
#define RESET_PIN_CODE "0000"
#define MAX_CAP_SUPPORTED 4
#define SHA1_HASH_LENGTH 20
#define SHA224_HASH_LENGTH 28
#define SHA256_HASH_LENGTH 32
#define SHA384_HASH_LENGTH 48
#define SHA512_HASH_LENGTH 64
#define PKCS11_SERIAL_NO_BUF_LEN 16
/* The id from which the unique identification for the
   object starts */
#define PKCS11_OBJECT_ID_START 0x01

#define MODULE_NAME "Pkcs11"
#define PROVIDER_NAME "PKCS11"

#define MOC_DEFAULT_LABEL_PREFIX "MOCANA-TAP"
#define MOC_LABEL_PUB            "PUB"
#define MOC_LABEL_PRIV           "PRIV"
#define MOC_LABEL_SYM            "SYM"

#define GDEBUG_ERROR(...) DEBUG_ERROR(DEBUG_TAP_MESSAGES,  __VA_ARGS__)
#define GDEBUG_PRINT(...) DEBUG_PRINT(DEBUG_TAP_MESSAGES,  __VA_ARGS__)
#define GDEBUG_PRINT3(...) DEBUG_PRINT3(DEBUG_TAP_MESSAGES, __VA_ARGS__)
#define GDEBUG_PTR(...) DEBUG_PTR(DEBUG_TAP_MESSAGES,  __VA_ARGS__)
#define GDEBUG_INT(...) DEBUG_INT2(DEBUG_TAP_MESSAGES,  __VA_ARGS__)
#define GDEBUG_HEXINT(...) DEBUG_HEXINT2(DEBUG_TAP_MESSAGES,  __VA_ARGS__)
#define GDEBUG_PRINTSTR1INT1(...) DEBUG_PRINTSTR1INT1(DEBUG_TAP_MESSAGES, __VA_ARGS__)
#define GDEBUG_PRINTSTR1HEXINT1(...) DEBUG_PRINTSTR1HEXINT1(DEBUG_TAP_MESSAGES, __VA_ARGS__)

#define PKCS11_MAX_KEY_ID_SZ 20
#define PKCS11_DEFAULT_KEY_SZ 2048
#define MAX_SIGN_DATA_SZ 256
#define MAX_NUM_OBJECTS_IN_SLOT 30

#ifndef MAX_ID_BYTE_SIZE
#define MAX_ID_BYTE_SIZE 50
#endif

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
#define CALL_PKCS11_API(apiName, ...) pFuncTable->apiName(__VA_ARGS__)
#else
#define CALL_PKCS11_API(apiName, ...) apiName(__VA_ARGS__)
#endif

/* PIN Roles for Pkcs11 Device */
typedef enum
{
    PIN_NONE = 0x00,
    PIN_USER = 0x01,
    PIN_ADMIN = 0x02,
    PIN_3 = 0x04,
    PIN_4 = 0x08,
    PIN_5 = 0x10,
    PIN_6 = 0x20,
    PIN_7 = 0x40
} PIN_ROLES;

/* PIN Lablels for the corresponding PIN Roles */
typedef enum
{
    PIN_LABEL_1 = 1,
    PIN_LABEL_SO,
    PIN_LABEL_3,
    PIN_LABEL_4,
    PIN_LABEL_5,
    PIN_LABEL_6,
    PIN_LABEL_7
} PIN_LABELS;

typedef enum
{
    TOKEN_0,
    TOKEN_1,
    TOKEN_2,
    TOKEN_3,
    TOKEN_4,
    TOKEN_5
} TOKEN_ID;

typedef enum
{
    SLOT_0,
    SLOT_1,
    SLOT_2,
    SLOT_3,
    SLOT_4,
    SLOT_5,
} SLOT_ID;

typedef enum
{
    LIBTYPE_UNKNOWN,
    LIBTYPE_SOFTHSM2,
    LIBTYPE_CLOUDHSM,
    LIBTYPE_DSSM
} PKCS11_LIBTYPE;

typedef struct Pkcs11_ModuleList Pkcs11_ModuleList;
typedef struct Pkcs11_Module Pkcs11_Module;
typedef struct Pkcs11_Token Pkcs11_Token;
typedef struct Pkcs11_Object Pkcs11_Object;
typedef struct Pkcs11_Config Pkcs11_Config;


struct Pkcs11_Config
{
    ubyte4                     moduleId; /* Module Id, identifies a particular module */
    ubyte*                     modDesc; /* Module description */
    ubyte deviceModuleIdStr[SHA256_RESULT_SIZE];
    TAP_Buffer                 credentialFile; /* Credential File */
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    ubyte*                     modLib;
#endif
    Pkcs11_Config*            pNext; /* Points to next configuration */
};

struct Pkcs11_ModuleList
{
    ubyte4                     moduleId; /* module Id, identifies a particular module from a list of modules */
    ubyte4                     phySlotId; /* main Slot ID for a particular module */
    ubyte                      labelStr[MAX_LABEL_REQD][MAX_LABEL_DESC_SZ]; /* labels for PIN3-PIN7, token Id's 1-5 */
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    PKCS11_LIBTYPE             libType;
    void*                     pLib;
    CK_FUNCTION_LIST_PTR      pFuncTable;
#endif
    Pkcs11_Module*            pModuleHead; /* corresponds to TAPT_MODULE_HANDLE */
    Pkcs11_ModuleList*        pNext; /* To store a list of all modules in the system */
};

struct Pkcs11_Module
{
    ubyte4                     phySlotId; /* Main slot Id for a particular module */
    byteBoolean                isLoggedIn;
    CK_SESSION_HANDLE          moduleSession; /* Session handle for the module */
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    PKCS11_LIBTYPE             libType;
    CK_FUNCTION_LIST_PTR      pFuncTable;
#endif
    Pkcs11_Token*             pTokenHead;
    Pkcs11_Module*            pNext; /* To store a list of all module handles for a single module Id */
    TAP_TokenId                provisionTokenId; /* Temporary Token Id to be provisioned */
    TAP_Error                  error;
};

struct Pkcs11_Token
{
    TAP_TokenId                tokenId; /* Token Id which will map to Slot Id */
    ubyte4                     userPin;
    byteBoolean                isLoggedIn;
    TAP_AuthData               credential;
    CK_SESSION_HANDLE          tokenSession; /* Session handle when token is initialized */
    Pkcs11_Object*            pObjectHead; /* corresponds to TAPT_OBJECT_HANDLE */
    Pkcs11_Token*             pNext; /* To store a list of all tokens in a module */
};

struct Pkcs11_Object
{
    TAP_Buffer                objectId;
    CK_OBJECT_HANDLE          pubObject; /* pointer to Public Object Handle */
    CK_OBJECT_HANDLE          prvObject; /* pointer to Private Object Handle */
    Pkcs11_Object*           pNext; /* To store a list of all object list in a token */
    ubyte4                    refCount; /* How many times this object has been initialized */
};


/*
 * Init routine called from SMP_PKCS11_register API.
 * Allocate all necessary objects and also initialize module if config
 * file provided and initialize pkcs11 cryptoki library.
 */

MSTATUS PKCS11_init(
        TAP_ConfigInfo *pConfigInfo
);

/*
 * DeInit routine called from SMP_PKCS11_unregister API.
 * Free all allocations done for the pkcs11 modules and finalize cryptoki library.
 */
MSTATUS PKCS11_deInit(
);

/* logout from all sessions inside module */
MSTATUS PKCS11_logoutAllModuleSessions(
        Pkcs11_Module* pGemModule
);

/* Close all Sessions inside module */
MSTATUS PKCS11_closeAllModuleSessions(
        Pkcs11_Module* pGemModule
);

/* deletes all objects the token */
MSTATUS PKCS11_deleteAllObjects(
        Pkcs11_Module* pGemModule,
        Pkcs11_Token* pGemToken
);

/* Parse pkcs11 config file */
Pkcs11_Config* PKCS11_parseConf(
    ubyte* pBufHead
);

/* parse the pkcs11 ini file for labels */
MSTATUS PKCS11_parseIni(
    const sbyte* pIniFile,
    ubyte pLabels[][MAX_LABEL_DESC_SZ]
);

/* Fetches the label for the token Id */
void PKCS11_fetchTokenLabel(
            ubyte4 mainSlotId,
            ubyte4 tokenId,
            ubyte* tokLabelStr
);

/* Copy the Slot Description */
MSTATUS PKCS11_copySlotDesc(
            CK_CHAR* pCopySlotDesc,
            CK_CHAR* pSlotDesc,
            ubyte4 size
);

/* Check Substring */
byteBoolean PKCS11_checkSubString(
        CK_CHAR* pStr,
        CK_CHAR* pSubStr
);

/* Fetch the Pin Description of the SlotId */
MSTATUS PKCS11_fetchPinDesc(
        Pkcs11_Module* pGemModule,
        ubyte4 slotId,
        ubyte* sPinDesc
);

/* Create pkcs11 module list using configuration or by searching Pkcs11 Slots */
MSTATUS PKCS11_createModuleList(
        Pkcs11_Config* pGemConfigHead
);

/* Fetch the Credential from the List */
TAP_Credential* PKCS11_fetchCredentialFromList(
        TAP_CredentialList *pCredentials,
        TAP_CREDENTIAL_CONTEXT pwdType
);

/* Fetch the Credential from the List */
TAP_Credential* PKCS11_fetchCredentialFromEntityList(
        TAP_EntityCredentialList *pCredentials,
        TAP_CREDENTIAL_CONTEXT pwdType
);

/* Fetch the Attribute Value from the list */
void* PKCS11_fetchAttributeFromIdx(
        TAP_AttributeList* pAttributeList,
        TAP_ATTR_TYPE type,
        ubyte4 idx,
        ubyte4* pLength
);

/* Fetch the Attribute Value from the list */
void* PKCS11_fetchAttributeFromList(
        TAP_AttributeList* pAttributeList,
        TAP_ATTR_TYPE type,
        ubyte4* pLength
);

/* Find the Module for the session handle passed */
Pkcs11_Module* PKCS11_findModule(
        CK_SESSION_HANDLE hSession
);

/* Find the token for the session handle passed */
Pkcs11_Token* PKCS11_findToken(
        CK_SESSION_HANDLE hSession
);

/* Generate a random object Id */
TAP_Buffer PKCS11_generateNextObjectId(
        Pkcs11_Module *pGemModule,
        Pkcs11_Token* pGemToken,
        CK_OBJECT_CLASS obj
);

/* Sort and Add a new object */
MSTATUS PKCS11_addNewObject(
        Pkcs11_Module* pGemModule,
        Pkcs11_Object** pObjectHead,
        Pkcs11_Object* pNewObject
);

/* Remove a object from the object list */
MSTATUS PKCS11_removeObject(
        Pkcs11_Module* pGemModule,
        Pkcs11_Object** pObjectHead,
        Pkcs11_Object* pRemObject
);

/* Return the object Handle for the object Id passed */
Pkcs11_Object* PKCS11_findAndAllocObject(
        Pkcs11_Module* pGemModule,
        Pkcs11_Token* pGemToken,
        TAP_Buffer objectId
);

/* Token ID to User PIN mapping */
ubyte4 PKCS11_tokenToPin(
        TAP_TokenId tokenId
);

/* Callback function for C_GenerateKeyPair(), will only be used in case of Headless */
CK_RV PKCS11_notificationCallback(
        CK_SESSION_HANDLE hSession,
        CK_NOTIFICATION event,
        CK_VOID_PTR pApplication
);

/* Check the Attribute exists or not in the list for the Attribute Value passed */
byteBoolean PKCS11_attrCheck(
        TAP_ModuleCapabilityAttributes *pGemModuleAttributes,
        TAP_ATTR_TYPE attrType,
        void* attrValue
);

/* Check the supported algorithm for the SlotId */
MSTATUS PKCS11_supportedAlgorithm(
        Pkcs11_ModuleList* pModuleList,
        ubyte* structType,
        CK_SLOT_ID slotId,
        ubyte4* algoCount
);

/* Get the supported attributes count */
ubyte4 PKCS11_supportedAttributesCount(
        TAP_ModuleCapabilityAttributes *pGemModuleAttributes
);

/* Check Attributes Type */
byteBoolean PKCS11_checkAttributesType(
        TAP_ModuleCapabilityAttributes *pGemModuleAttributes,
        TAP_ATTR_TYPE type
);

/* Get the object handles of an objectId. */
MSTATUS PKCS11_getObjectHandles(Pkcs11_Module *pGemModule,
                                Pkcs11_Token *pGemToken,
                                TAP_Buffer objectId,
                                CK_OBJECT_HANDLE *pprvHandle,
                                CK_OBJECT_HANDLE *ppubHandle);

/* Fetch Key Size from the Attributes passed */
ubyte4 PKCS11_fetchKeyAttrlength(
        TAP_KeyAttributes *pKeyAttributes,
        TAP_ATTR_TYPE type
);

/* Fill the last error */
void PKCS11_FillError(
        TAP_Error* error,
        MSTATUS* pStatus,
        MSTATUS statusVal,
        const char* pErrString

);

/* Converts pkcs11 error to NanoSMP error */
MSTATUS PKCS11_nanosmpErr(
        Pkcs11_Module* pGemModule,
        CK_RV rVal
);

/* Create a new key label */
MSTATUS PKCS11_createKeyLabelAlloc(
    const sbyte *pPrefix,
    const sbyte *pKeyClass,
    TAP_KEY_ALGORITHM keyAlgorithm,
    TAP_RAW_KEY_SIZE keySize,  /* TAP_RAW_KEY_SIZE is big enough type for TAP_KEY_SIZE too */
    TAP_ECC_CURVE eccCurve,
    TAP_Buffer objId,
    sbyte **ppLabel
);

#endif /* __SMP_PKCS11_HEADER__ */

