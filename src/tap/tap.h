/**
 * @file tap.h
 *
 * @ingroup nanotap_tree
 *
 * @brief Trust Anchor Platform (TAP) Base Definitions and Types
 * @details This file contains base definitions and functions for the Trust Anchor Platform (TAP) modules.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_TAP__
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

#ifndef __TAP_HEADER__
#define __TAP_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mtcp.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/random.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha256.h"

#include "tap_smp.h"
#include "../smp/smp_cc.h"

/*! @cond */
#ifdef __cplusplus
extern "C" {
#endif
/*! @endcond */

/*! @cond */
#ifdef __ENABLE_DIGICERT_TAP__
/*! @endcond */

/*
 * This enum defines the list of supported TAP Operations.
 */
typedef enum tapOperation
{
    tap_rsa_sign     = 1,
    tap_rsa_verify   = 2,
    tap_rsa_encrypt  = 3,
    tap_rsa_decrypt  = 4,
    tap_ecc_sign     = 5,
    tap_ecc_verify   = 6,
    tap_aes_encrypt  = 7,
    tap_aes_decrypt  = 8,
    tap_des_encrypt  = 9,
    tap_des_decrypt  = 10,
    tap_tdes_encrypt = 11,
    tap_tdes_decrypt = 12,
    tap_hmac_sign    = 13,
    tap_rsa_generate = 14,
    tap_ecc_generate = 15,
    tap_seed         = 16,
    tap_token_unload = 17,
    tap_key_unload   = 18,
    tap_key_import   = 19,
    tap_key_load     = 20,
    tap_key_store    = 21

} TapOperation;

/***************************************************************
   Constant Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @details The major version number of the current TAP API.
 */
#define TAP_VERSION_MAJOR 2

/**
 * @ingroup tap_definitions
 * @details The minor version number of the current TAP API.
 */
#define TAP_VERSION_MINOR 0

/*! @cond */
/** @private
 *  @internal
 */
#define TAP_SIGNATURE 0xc0de

/** @private
 *  @internal
 */
#define TAP_DEFAULT_SERVER_PORT 8277

/**
 *  @private
 *  @internal
 */
#define MODULE_NAME_SIZE    128

/**
 *  @private
 *  @internal
 */
#define MAX_TAP_REMOTE_TX_BUFFER    8192

/**
 * @private
 * @internal
 * @details  The maximum number of instances of a particular security module */
#define MAX_TAP_INSTANCES 32

/***************************************************************
   "enum" Definitions - use #defines for compiler compatibility
****************************************************************/


/**
 * @ingroup tap_definitions
 * @brief Value to indicate the source from which to write to NV.
 * @details Value to indicate the source from which to write to NV.
 *  <p> TAP_DATA_SOURCE must be one of the following values:
 *  - #TAP_DATA_SOURCE_BUFFER
 *  - #TAP_DATA_SOURCE_FILE
 *  - #TAP_DATA_SOURCE_FILL
 */
typedef ubyte TAP_DATA_SOURCE;
/*! TAP_DATA_SOURCE_UNDEFINED */
#define TAP_DATA_SOURCE_UNDEFINED   ((ubyte)0)
/*! TAP_DATA_SOURCE_BUFFER - Data is located in a buffer */
#define TAP_DATA_SOURCE_BUFFER      ((ubyte)1)
/*! TAP_DATA_SOURCE_FILE - Data is located in a file */
#define TAP_DATA_SOURCE_FILE        ((ubyte)2)
/*! TAP_DATA_SOURCE_FILL - Data is a fill value.  This is used in NV write commands. */
#define TAP_DATA_SOURCE_FILL        ((ubyte)3)

/*! @endcond */

/**
 * @ingroup tap_definitions
 * @brief Value to indicate the type of TAP object.
 * @details Value to indicate the type of TAP object being passed to a function.
 *  <p> TAP_OBJECT_TYPE must be one of the following values:
 *  - #TAP_OBJECT_TYPE_STORAGE
 *  - #TAP_OBJECT_TYPE_KEY
 */
typedef ubyte TAP_OBJECT_TYPE;
/*! TAP_OBJECT_TYPE_UNDEFINED */
#define TAP_OBJECT_TYPE_UNDEFINED      ((ubyte)0)
/*! TAP_OBJECT_TYPE_OBJECT - Structure being passed is a TAP_Object. */
#define TAP_OBJECT_TYPE_OBJECT         ((ubyte)1)
/*! TAP_OBJECT_TYPE_KEY - Structure being passed is a TAP_Key.*/
#define TAP_OBJECT_TYPE_KEY            ((ubyte)2)
/*! TAP_OBJECT_TYPE_STORAGE - Structure being passed is a TAP_StorageObject. */
#define TAP_OBJECT_TYPE_STORAGE        ((ubyte)3)
/*! TAP_OBJECT_TYPE_PUBLIC_KEY - Structure being passed is a TAP2B_PUBLIC.*/
#define TAP_OBJECT_TYPE_PUBLIC_KEY     ((ubyte)4)
/*! TAP_OBJECT_TYPE_PRIVATE_KEY - Structure being passed is a TAP2B_PRIVATE.*/
#define TAP_OBJECT_TYPE_PRIVATE_KEY    ((ubyte)5)


/***************************************************************
   General Structure Definitions
****************************************************************/

/*! @cond */
#pragma pack(push, 1)
/*! @endcond */

/** @private
 *  @internal
 *  @details Internal structure for serializing a generic data buffer
 */
typedef struct
{
    /*! Size of data buffer */
    ubyte4  bufferLen;
    /*! Buffer containing data */
    ubyte   *pBuffer;
} TAP_BufferPacked;

/*! @cond */
#pragma pack (pop)
/*! @endcond */

/*! File information buffer */
typedef TAP_Buffer TAP_FileInfo;


/*! Server name buffer */
typedef TAP_Buffer TAP_ServerName;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing TAP connection information.
 */
typedef struct
{
    /*! Buffer containing the server name or IP address string for remote connection */
    TAP_ServerName  serverName;
    /*! server port number for remote connection */
    ubyte2          serverPort;
} TAP_ConnectionInfo;


/**
 * @ingroup tap_definitions
 * @details TAP structure to identify a particular security module
 */
typedef struct
{
    /*! security module type; must be value #TAP_PROVIDER value */
    TAP_PROVIDER             providerType;
    /*! unique identifier for security module; typically a SHA256 hash */
    TAP_ModuleId             moduleId;
    /*! The connection info for the host on which the TAP module resides. */
    TAP_ConnectionInfo       hostInfo;

} TAP_Module;


/**
 * @ingroup tap_definitions
 * @details TAP structure containing a list of available modules
 */
typedef struct
{
    /*! The number of modules contained in the list */
    ubyte4 numModules;
    /*! The list of #TAP_Module structures containing the various modules available */
    TAP_Module *pModuleList;
} TAP_ModuleList;

/**
 * @ingroup tap_definitions
 * @details TAP structure containing a list of available modules
 */typedef struct
{
    /*! Connection info for the host containing the module(s) in the list.  */
    TAP_ConnectionInfo hostConnInfo;
    /*! The list of modules available on the host */
    TAP_ModuleList     moduleList;
} TAP_HostDeviceInfo;


/***************************************************************
   Context Structure Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @details Opaque structure containing TAP context information.
 */
typedef struct _TAP_Context TAP_Context;

/**
 * @ingroup tap_definitions
 * @details Structure containing TAP session information.
 */
typedef struct
{
    /*! The TCP socket for the connection */
    TCP_SOCKET sockfd;
    /*! The SSL session ID */
    ubyte4 sslSessionId;
    /*! Boolean indicating if the session is initialized */
    ubyte sessionInit;
    /*! Session connection information */
    TAP_ConnectionInfo connInfo;
    ubyte txBuffer[MAX_TAP_REMOTE_TX_BUFFER];
} TAP_SessionInfo;

/*! @cond */
/** @private
 *  @internal
 *
 *  @details  The context containing all information needed to talk to a module. In a client-server build, this is a thread-specific context. In a local-only build, the server-side context is NULL.
 */
typedef struct
{
    /*! The context containing information on the specific module, which is read from a config file. */
    const TAP_Module   *pTapModule;
    /* Module specific configuration information eg. Platform, Conformance files */
    const void         *pTapConfig;
    /*! Context specific to a security module. The underlying context structure depends on the providerType. */
    void               *pModuleContext;
    /*! Credential Context specific to a security module. The underlying context structure depends on the providerType. */
    void               *pCredentialsContext;
} TAP_LocalContext;
/*! @endcond */



/***************************************************************
   Key Information Definitions
****************************************************************/

/* Key information is translated to an attribute list before sending to SMP */

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate an RSA key.
 */
typedef struct
{
    /*! Key size */
    TAP_KEY_SIZE      keySize;
    /*! Exponent;  Can be 0 if default is allowed by module */
    ubyte4            exponent;
    /*! Encryption scheme.  Must be a valid TAP_ENC_SCHEME value. */
    TAP_ENC_SCHEME    encScheme;
    /*! Signature scheme.  Must be a valid TAP_SIG_SCHEME value. */
    TAP_SIG_SCHEME    sigScheme;
} TAP_KeyInfo_RSA;

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate an ECC key.
 */
typedef struct
{
    /*! ECC curve */
    TAP_ECC_CURVE     curveId;
    /*! Signature scheme.  Must be a valid TAP_SIG_SCHEME value. */
    TAP_SIG_SCHEME    sigScheme;
} TAP_KeyInfo_ECC;

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate an MLDSA key.
 */
typedef struct
{
    /*! MLDSA cid */
    ubyte4     qsAlg;
    /*! Signature scheme.  Must be a valid TAP_SIG_SCHEME value. */
    TAP_SIG_SCHEME    sigScheme;
} TAP_KeyInfo_MLDSA;

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate an AES key.
 */
typedef struct
{
    /*! Key size */
    TAP_KEY_SIZE        keySize;
    /*! The mode of operations.  Must be a valid TAP_KeyInfo value. */
    TAP_SYM_KEY_MODE    symMode;
} TAP_KeyInfo_AES;

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate a DES or TDES key.
 */
typedef TAP_KeyInfo_AES  TAP_KeyInfo_DES, TAP_KeyInfo_TDES;

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate an HMAC key.
 */
typedef struct
{
    /*! The hash type to be used for signing.  Must be a valid TAP_HASH_ALG value. */
    TAP_HASH_ALG        hashAlg;
    TAP_RAW_KEY_SIZE    keyLen;   /* in bytes */
} TAP_KeyInfo_HMAC;

/**
 * @ingroup tap_definitions
 * @details The union of algorithm-specific information needed to generate a key.  They type is determined by the TAP_KEY_ALGORITHM.
 */
typedef union
{
    /*! The key info for an RSA Key */
    TAP_KeyInfo_RSA   rsaInfo;
    /*! The key info for an ECC Key */
    TAP_KeyInfo_ECC   eccInfo;
    /*! The key info for an AES Key */
    TAP_KeyInfo_AES   aesInfo;
    /*! The key info for an DES Key */
    TAP_KeyInfo_DES   desInfo;
    /*! The key info for an TDES Key */
    TAP_KeyInfo_TDES  tdesInfo;
    /*! The key info for an HMAC Key */
    TAP_KeyInfo_HMAC  hmacInfo;
    /*! The key info for an MLDSA Key */
    TAP_KeyInfo_MLDSA  mldsaInfo;

} TAP_KeyInfo_Union;

/**
 * @ingroup tap_definitions
 * @details The information needed by all security modules to generate a key.
 */
typedef struct
{
    /*! The key algorithm.  Must be TAP_KEY_ALGORITHM_RSA, TAP_KEY_ALGORITHM_ECC, TAP_KEY_ALGORITHM_AES, etc. */
    TAP_KEY_ALGORITHM        keyAlgorithm;
    /*! Intended usage of the key.  If not applicable to a module, can be TAP_KEY_USAGE_UNDEFINED. */
    TAP_KEY_USAGE            keyUsage;
    /*! Optional token Id.  If 0, the default token is used. */
    TAP_TokenId              tokenId;
    /*! Optional object ID.  If 0, the SMP will create the key at its location of choice.
      If set, the SMP will create the new key at the location indicated by the object ID. */
    TAP_ObjectId             objectId;
    /*! The algorithm-specific key information.  This structure is selected by keyAlgorithm, and is either TAP_KeyInfo_RSA or TAP_KeyInfo_ECC. */
    TAP_KeyInfo_Union        algKeyInfo;
} TAP_KeyInfo;


/***************************************************************
   Object Structure Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @details The information about an object.
 */
typedef struct
{
    /*! The module type with which the object is associated */
    TAP_PROVIDER          providerType;
    /*! The ID of the module with which the object is associated */
    TAP_ModuleId          moduleId;
    /*! The ID of the token with which the object is associated */
    TAP_EntityId          tokenId;
    /*! The ID of the object */
    TAP_EntityId          objectId;
    /*! The list of one or more object attributes */
    TAP_ObjectAttributes  objectAttributes;
} TAP_ObjectInfo;

/**
 * @ingroup tap_definitions
 * @brief  An object info list.
 * @details An object info list.  This can be a list of any object type, depending on the query used to obtain the object list.  For example, the response to TAP_getPolicyStorageList will return a list of policy storage locations.
 */
typedef struct
{
    /*! The number of #TAP_ObjectInfo structures in the list. */
    ubyte4   count;
    /*! The list of object information entries for the objects queried. */
    TAP_ObjectInfo *pInfo;
} TAP_ObjectInfoList;

/**
 * @ingroup tap_definitions
 * @details The object data.  This includes the object information and module-specific blob.
 */
typedef struct
{
    /*! The object information */
    TAP_ObjectInfo        objectInfo;
    /*! Serialized and encoded module-specific object structure that contains all information needed to use the object. */
    TAP_Blob              objectBlob;
} TAP_ObjectData;

/***************************************************************
   Structures Needing Context Structure Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @details The information needed to create a key.  These will get translated to the attributes needed for the underlying SMP.
 */
typedef struct
{
    /*! The key algorithm, such as RSA, ECC, AES, etc */
    TAP_KEY_ALGORITHM     keyAlgorithm;
    /*! Intended usage of the key.  If not applicable to a module, can be TAP_KEY_USAGE_UNDEFINED. */
    TAP_KEY_USAGE         keyUsage;
    /*! The algorithm-specific key information.  This structure is selected by keyAlgorithm. */
    TAP_KeyInfo_Union     algKeyInfo;
    /*! Algorithm-specific public key structure that contains all information needed to use the public key in SW. */
    TAP_PublicKey         publicKey;
} TAP_KeyData;

/**
 * @ingroup tap_definitions
 * @details The key structure for all TAP asymmetric and symmetric keys.  The underlying module key contains the key specifics.
 */
typedef struct
{
    /*! The object data for the key.  This includes the module-specific key blob. */
    TAP_ObjectData         providerObjectData;
    /*! The key information, including the public key for asymmetric keys. */
    TAP_KeyData            keyData;
    /*! The context associated with the key.  This should contain information needed to communicate with the module in order to use the key. This information is not serialized with the key.  When the key is read from a file, a valid context must be associated with the deserialized key via TAP_loadKey. */
    TAP_Context            *pTapContext;
    /*! Token handle provided by the module.  This field is not serialized out with the key. */
    TAP_TokenHandle        tokenHandle;
    /*! Key handle provided by the module, typically a hash. This field is not serialized out with the key. */
    TAP_KeyHandle          keyHandle;
    /* Boolean indicating whether this key should uninitialize the token when freed or unloaded */
    ubyte4                 deferredTokenUnload;
    /* Boolean indicating whether this key requires credentials */
    ubyte4                 hasCreds;
} TAP_Key;


/**
 * @ingroup tap_definitions
 * @details The key structure for all TAP asymmetric and symmetric keys.  The underlying module key contains the key specifics.
 */
typedef struct
{
    /*! The object data. */
    TAP_ObjectData          providerObjectData;
    /*! The context associated with the object.  This should contain information needed to communicate with the module in order to use the object.
    This information is not serialized with the object.  When the object is read from a file, a valid context must be associated with the deserialized object via TAP_loadObject. */
    TAP_Context             *pTapContext;
    /*! Token handle provided by the module when the object is loaded.  This field is not serialized out with the object. */
    TAP_TokenHandle         tokenHandle;
    /*! Object handle provided by the module when the object is loaded, typically a hash. This field is not serialized out with the object. */
    TAP_ObjectHandle        objectHandle;
} TAP_Object;


/***************************************************************
      Policy Storage Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @details The data associated with a policy storage object.
 */
typedef struct
{
    /*! Index of the policy storage */
    ubyte4                  index;
    /*! Size in bytes of the policy storage */
    ubyte4                  size;
    /*! TAP is unaware of the values; refer to SMP documentation for storage type values.
        This can be a buffer, a bit field, measurement data, etc. */
    ubyte4                  storageType;
    /*! Bitmask indicating owner permissions. Refer to the SMP documentation for the meaning of the permission values. */
    TAP_PERMISSION_BITMASK  ownerPermission;
    /*! Bitmask indicating public permissions. Refer to the SMP documentation for the meaning of the permission values. */
    TAP_PERMISSION_BITMASK  publicPermission;
    /*! Attributes specific to policy storage, such as size, offset, etc. */
    TAP_PolicyStorageAttributes  *pAttributes;
    /*! Optional auth-context.  default is storage auth */
    TAP_AUTH_CONTEXT_PROPERTY authContext;
} TAP_StorageInfo;

/**
 * @ingroup tap_definitions
 * @details The storage info list, returned by TAP_getPolicyStorageDetails.
 */
typedef struct
{
    /*! The number of #TAP_StorageInfo structures in the list. */
    ubyte4   count;
    /*! The list of storage information entries, containing the details about the policy storage locations queried. */
    TAP_StorageInfo *pInfo;
} TAP_StorageInfoList;

/**
 * @ingroup tap_definitions
 * @details The policy storage object.
 */
typedef struct
{
    /*! The object information with which the storage location is associated. */
    TAP_ObjectInfo           providerObjectInfo;
    /*! The storage location information */
    TAP_StorageInfo          storageInfo;
    /*! The context associated with the key.  This should contain information needed to communicate with the module in order to use the key. This information is not serialized with the key.  When the key is read from a file, a valid context must be associated with the deserialized key via TAP_loadKey. */
    TAP_Context              *pTapContext;
    /*! Token handle provided by the module when the object is loaded.  This field is not serialized out with the object. */
    TAP_TokenHandle          tokenHandle;
    /*! Object handle provided by the module when the object is created or loaded, typically a hash. This field is not serialized out with the object. */
    TAP_ObjectHandle         objectHandle;
} TAP_StorageObject;

/**
 * @ingroup tap_definitions
 * @details The storage object list.
 */
typedef struct
{
    /*! The number of storage objects in the list */
    ubyte4   count;
    /*! The list of storage objects detailing the available storage locations. */
    TAP_StorageObject *pObjects;
} TAP_StorageObjectList;


/***************************************************************
   Attribute Union Definition
****************************************************************/

/**
 * @internal
 * @dont_show
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The union of attributes.
 *
 * This structure must be kept in sync with the TAP_ATTR_* definitions in tap_smp.h
 */
typedef union
{
    ubyte                           none;
    TAP_Version                     firmwareVersion;
    TAP_PROVIDER                    providerType;
    TAP_KEY_ALGORITHM               keyAlgorithm;
    TAP_KEY_USAGE                   keyUsage;
    TAP_KEY_SIZE                    keySize;
    TAP_KEY_CMK                     keyCmk;
    TAP_ECC_CURVE                   eccCurve;
    TAP_ENC_SCHEME                  encScheme;
    TAP_SIG_SCHEME                  sigScheme;
    TAP_Credential                  credential;
    TAP_SYM_KEY_MODE                symKeyMode;
    TAP_HASH_ALG                    hashAlg;
    TAP_KeyHandle                   keyHandle;
    TAP_Buffer                      moduleKey;
    TAP_PublicKey                   publicKey;
    TAP_RNG_PROPERTY                rngProperty;
    TAP_Buffer                      rngSeed;
    TAP_Buffer                      rndStir;
    ubyte                           preloadKey;
    ubyte                           storageType;
    ubyte4                          storageSize;
    ubyte4                          offset;
    ubyte                           readOp;
    TAP_WRITE_OP_TYPE               writeOp;
    TAP_Buffer                      label;
    TAP_Buffer                      buffer;
    TAP_CAPABILITY_CATEGORY         capabiityCategory;
    TAP_CAPABILITY_FUNCTIONALITY    capabiityFunctionality;
    ubyte4                          provisionType;
    TAP_EntityCredential            entityCredentials;
    TAP_Buffer                      trustedDataKey;
    TAP_Buffer                      trustedDataValue;
    ubyte                           trustedDataType;
    TAP_TrustedDataInfo             trustedDataInfo;
    TAP_ObjectHandle                objectHandle;
    TAP_TOKEN_TYPE                  tokenType;
    TAP_SlotId                      slotId;
    ubyte4                          objectProperty;
    TAP_PERMISSION_BITMASK          permission;
    TAP_Buffer                      vendorInfo;
    TAP_OP_EXEC_FLAG                opExecFlag;
    ubyte4                          storageIndex;
    TAP_TEST_MODE                   testMode;
    TAP_TEST_STATUS                 testStatus;
    TAP_TestContext                 testContext;
    TAP_Buffer                      testReport;
    TAP_Buffer                      testRequestData;
} TAP_AttributeStructUnion;




/*! @cond */
#endif /* __ENABLE_DIGICERT_TAP__ */
/*! @endcond */

/*! @cond */
#ifdef __cplusplus
}
#endif
/*! @endcond */

#endif /* __TAP_HEADER__ */
