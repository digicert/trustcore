/**
 * @file tap_smp.h
 *
 * @ingroup nanotap_tree
 *
 * @brief Types and structures common to Trust Anchor Platform (TAP) APIs and Security Module Plugin (SMP) providers
 * @details This file contains types and structures common to Mocana Trust Anchor Platform (TAP) APIs and Security Module Plugin (SMP) providers
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_TAP__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


/*------------------------------------------------------------------*/

#ifndef __TAP_SMP_HEADER__
#define __TAP_SMP_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../crypto/hw_accel.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha256.h"

#include "../smp/smp_cc.h"


/*! @cond */
#if (defined __ENABLE_MOCANA_TAP__) || (defined __ENABLE_MOCANA_SMP__)
/*! @endcond */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * IMPORTANT: Macro values are used during TAP object serialization and may be
 * stored in the serialized blob. To ensure backwards compatability do NOT
 * change existing macros. Changing these macros will cause old TAP keys to
 * be incorrectly interpreted.
 */

/***************************************************************
   Constant Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details  The maximum size of a password in bytes.
 */
#define TAP_CREDENTIAL_PASSWORD_MAX_SIZE   200

/***************************************************************
   Base Type Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief  Generic handle definiton.
 * @details  Generic handle definiton.  This is an opaque value interpreted by the SMP.
 *           This may be a pointer to an internal context, but it is up to the SMP to manage its own handles.
 *           An 8-byte value is used to accomodate 64-bit operating environments.
 */
typedef ubyte8 TAP_HANDLE;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details  Generic ID definiton
 */
typedef ubyte8 TAP_ID;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details A buffer of SHA256 result size
 */
typedef ubyte TAP_SHA256Buffer[SHA256_RESULT_SIZE];


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details  A context for a module test that may need time to run.
 *           This is used to access the results when the test has completed.
 */
 typedef void * TAP_RequestContext;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details A context for a module test that may need time to run.  This is used to access the results when the test has completed.
 */
 typedef void * TAP_TestContext;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Error Context definition
 */
 typedef void * TAP_ErrorContext;


/***************************************************************
   "enum" Definitions - use #defines for compiler compatibility
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Value to indicate the security module provider (SMP) type (e.g. TPM 2.0, SGX, etc).
 *  <p> TAP_PROVIDER must be one of the following values:
 *  - #TAP_PROVIDER_SW
 *  - #TAP_PROVIDER_TPM
 *  - #TAP_PROVIDER_TPM2
 *  - #TAP_PROVIDER_SGX
 *  - #TAP_PROVIDER_STSAFE
 *  - #TAP_PROVIDER_GEMSIM
 *  - #TAP_PROVIDER_PKCS11
 *  - #TAP_PROVIDER_RENS5
 *  - #TAP_PROVIDER_TRUSTX
 *  - #TAP_PROVIDER_ARMM23
 *  - #TAP_PROVIDER_ARMM33
 *  - #TAP_PROVIDER_EPID
 *  - #TAP_PROVIDER_TEE
 *  - #TAP_PROVIDER_NANOROOT
 */
 /* This must stay in sync with the pTapProviderNames definition above */
typedef ubyte2 TAP_PROVIDER;
/*! TAP_PROVIDER_UNDEFINED - Undefined security module.  This can be used in TAP_getModuleList to specify to get all types. */
#define  TAP_PROVIDER_UNDEFINED     ((ubyte2)0)
/*! TAP_PROVIDER_SW - Software key. */
#define  TAP_PROVIDER_SW            ((ubyte2)1)
/*! TAP_PROVIDER_TPM - TPM 1.2 security module */
#define  TAP_PROVIDER_TPM           ((ubyte2)2)
/*! TAP_PROVIDER_TPM2 - TPM 2.0 security module */
#define  TAP_PROVIDER_TPM2          ((ubyte2)3)
/*! TAP_PROVIDER_SGX - SGX security module */
#define  TAP_PROVIDER_SGX           ((ubyte2)4)
/*! TAP_PROVIDER_STSAFE - STSAFE security module */
#define  TAP_PROVIDER_STSAFE        ((ubyte2)5)
/*! TAP_PROVIDER_GEMSIM - Gemalto SIM security module */
#define  TAP_PROVIDER_GEMSIM        ((ubyte2)6)
/*! TAP_PROVIDER_RENS5 - Renesas S5 security module */
#define  TAP_PROVIDER_RENS5         ((ubyte2)7)
/*! TAP_PROVIDER_TRUSTX - Trust X security module */
#define  TAP_PROVIDER_TRUSTX        ((ubyte2)8)
/*! TAP_PROVIDER_ARMM23 - ARM M23 security module */
#define  TAP_PROVIDER_ARMM23        ((ubyte2)9)
/*! TAP_PROVIDER_ARMM33 - ARM M33 security module */
#define  TAP_PROVIDER_ARMM33        ((ubyte2)10)
/*! TAP_PROVIDER_EPID */
#define  TAP_PROVIDER_EPID          ((ubyte2)11)
/*! TAP_PROVIDER_TEE */
#define  TAP_PROVIDER_TEE           ((ubyte2)12)
/*! TAP_PROVIDER_PKCS11 - PKCS11 security module */
#define  TAP_PROVIDER_PKCS11        ((ubyte2)13)
/*! TAP_PROVIDER_NXPA71 - NXP A71 security module */
#define  TAP_PROVIDER_NXPA71        ((ubyte2)14)
/*! TAP_PROVIDER_NANOROOT */
#define  TAP_PROVIDER_NANOROOT       ((ubyte2)15)
/*! TAP_PROVIDER_MAX */
#define  TAP_PROVIDER_MAX           ((ubyte2)15)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Value to indicate key algorithm
 *     <p> TAP_KEY_ALGORITHM must be one of the following:
 *      - #TAP_KEY_ALGORITHM_RSA
 *      - #TAP_KEY_ALGORITHM_ECC
 *      - #TAP_KEY_ALGORITHM_DSA
 *      - #TAP_KEY_ALGORITHM_AES
 *      - #TAP_KEY_ALGORITHM_HMAC
 *      - #TAP_KEY_ALGORITHM_DES
 *      - #TAP_KEY_ALGORITHM_TDES
 */
typedef ubyte TAP_KEY_ALGORITHM;
/*! Undefined algorithm - should never happen */
#define TAP_KEY_ALGORITHM_UNDEFINED     ((ubyte)0)
/*! TAP_KEY_ALGORITHM_RSA - Indicates have RSA asymmetric key */
#define TAP_KEY_ALGORITHM_RSA           ((ubyte)1)
/*! TAP_KEY_ALGORITHM_ECC - Indicates have ECC asymmetric key */
#define TAP_KEY_ALGORITHM_ECC           ((ubyte)2)
/*! TAP_KEY_ALGORITHM_DSA - Indicates have DSA asymmetric key */
#define TAP_KEY_ALGORITHM_DSA           ((ubyte)3)
/*! TAP_KEY_ALGORITHM_AES - Indicates have AES symmetric key */
#define TAP_KEY_ALGORITHM_AES           ((ubyte)4)
/*! TAP_KEY_ALGORITHM_HMAC - Indicates have HMAC symmetric key */
#define TAP_KEY_ALGORITHM_HMAC          ((ubyte)5)
/*! TAP_KEY_ALGORITHM_DES - Indicates have DES symmetric key */
#define TAP_KEY_ALGORITHM_DES           ((ubyte)6)
/*! TAP_KEY_ALGORITHM_TDES - Indicates have TDES symmetric key */
#define TAP_KEY_ALGORITHM_TDES          ((ubyte)7)
/*! TAP_KEY_ALGORITHM_TDES - Indicates have MLDSA asymmetric key */
#define TAP_KEY_ALGORITHM_MLDSA         ((ubyte)8)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate key size in bits.
 * @details Value to indicate key size in bits.
 *     <p> TAP_KEY_SIZE must be one of the following:
 *     <p> For Asymmetric keys:
 *      - #TAP_KEY_SIZE_1024
 *      - #TAP_KEY_SIZE_2048
 *      - #TAP_KEY_SIZE_4096
 *      - #TAP_KEY_SIZE_ASYM_DEFAULT (same as #TAP_KEY_SIZE_2048)
 *     <p> For Symmetric keys:
 *      - #TAP_KEY_SIZE_128
 *      - #TAP_KEY_SIZE_192
 *      - #TAP_KEY_SIZE_256
 *      - #TAP_KEY_SIZE_SYM_DEFAULT (same as #TAP_KEY_SIZE_128)
 *      <p>
 *      #TAP_KEY_SIZE_UNDEFINED should be used for algorithms that don't support a key size, such as ECC.
 */
typedef ubyte TAP_KEY_SIZE;
/*! Undefined size - this can be used if not applicable to the key algorithm, such as ECC. */
#define TAP_KEY_SIZE_UNDEFINED      ((ubyte)0)
/*! TAP_KEY_SIZE_1024 - 1024-bit asymmetric key */
#define TAP_KEY_SIZE_1024           ((ubyte)1)
/*! TAP_KEY_SIZE_2048 - 2048-bit asymmetric key */
#define TAP_KEY_SIZE_2048           ((ubyte)2)
/*! TAP_KEY_SIZE_4096 -  4096-bit asymmetric key */
#define TAP_KEY_SIZE_4096           ((ubyte)3)
/*! TAP_KEY_SIZE_3072 -  3072-bit asymmetric key */
#define TAP_KEY_SIZE_3072           ((ubyte)4)
/*! TAP_KEY_SIZE_8192 -  8192-bit asymmetric key */
#define TAP_KEY_SIZE_8192           ((ubyte)5)
/*! TAP_KEY_SIZE_ASYM_DEFAULT - default for an asymmetric key is a 2048-bit key */
#define TAP_KEY_SIZE_ASYM_DEFAULT    TAP_KEY_SIZE_2048

/*! TAP_KEY_SIZE_128 -  128-bit symmetric key */
#define TAP_KEY_SIZE_128             ((ubyte)10)
/*! TAP_KEY_SIZE_192 -  192-bit symmetric key */
#define TAP_KEY_SIZE_192             ((ubyte)11)
/*! TAP_KEY_SIZE_256 -  256-bit symmetric key */
#define TAP_KEY_SIZE_256             ((ubyte)12)
/*! TAP_KEY_SIZE_SYM_DEFAULT - default for a symmetric key is a 128-bit key */
#define TAP_KEY_SIZE_SYM_DEFAULT     TAP_KEY_SIZE_128

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate an arbitrary key size in bytes.
 * @details Value to indicate the key size in bytes.
 */
typedef ubyte4 TAP_RAW_KEY_SIZE;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Value to indicate symmetric cipher to be used with a symmetric key
 *     <p> TAP_SYM_KEY_MODE must be one of the following:
 *      - #TAP_SYM_KEY_MODE_CTR
 *      - #TAP_SYM_KEY_MODE_OFB
 *      - #TAP_SYM_KEY_MODE_CBC
 *      - #TAP_SYM_KEY_MODE_CFB
 *      - #TAP_SYM_KEY_MODE_ECB
 *      - #TAP_SYM_KEY_MODE_UNDEFINED
 */
typedef ubyte TAP_SYM_KEY_MODE;
/*! Undefined mode */
#define TAP_SYM_KEY_MODE_UNDEFINED     ((ubyte)0)
/*! TAP_SYM_KEY_MODE_CTR - Counter mode */
#define TAP_SYM_KEY_MODE_CTR           ((ubyte)1)
/*! TAP_SYM_KEY_MODE_OFB - Output Feedback mode */
#define TAP_SYM_KEY_MODE_OFB           ((ubyte)2)
/*! TAP_SYM_KEY_MODE_CBC - Cipher Block Chaining mode */
#define TAP_SYM_KEY_MODE_CBC           ((ubyte)3)
/*! TAP_SYM_KEY_MODE_CFB - Cipher Feedback mode */
#define TAP_SYM_KEY_MODE_CFB           ((ubyte)4)
/*! TAP_SYM_KEY_MODE_ECB - Electronic Codebook mode */
#define TAP_SYM_KEY_MODE_ECB           ((ubyte)5)
/*! TAP_SYM_KEY_MODE_GCM - Galois Counter mode */
#define TAP_SYM_KEY_MODE_GCM           ((ubyte)6)


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the hash type
 * @details Value to indicate the hash type.
 *  <p> TAP_HASH_ALG must be one of the following values:
 *  - #TAP_HASH_ALG_SHA1
 *  - #TAP_HASH_ALG_SHA256
 *  - #TAP_HASH_ALG_SHA224
 *  - #TAP_HASH_ALG_SHA384
 *  - #TAP_HASH_ALG_SHA512
 *  - #TAP_HASH_ALG_NONE
 */
typedef ubyte TAP_HASH_ALG;
/*! TAP_HASH_ALG_NONE */
#define TAP_HASH_ALG_NONE       ((ubyte)0)
/*! TAP_HASH_ALG_SHA1 */
#define TAP_HASH_ALG_SHA1       ((ubyte)1)
/*! TAP_HASH_ALG_SHA256 */
#define TAP_HASH_ALG_SHA256     ((ubyte)2)
/*! TAP_HASH_ALG_SHA224 */
#define TAP_HASH_ALG_SHA224     ((ubyte)3)
/*! TAP_HASH_ALG_SHA384 */
#define TAP_HASH_ALG_SHA384     ((ubyte)4)
/*! TAP_HASH_ALG_SHA512 */
#define TAP_HASH_ALG_SHA512     ((ubyte)5)



/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Value to indicate key usage when using the TAP_asymGenerateKey or TAP_symGenerateKey API.
 *  <p> TAP_KEY_USAGE must be one of the following values:
 *  - #TAP_KEY_USAGE_SIGNING
 *  - #TAP_KEY_USAGE_DECRYPT
 *  - #TAP_KEY_USAGE_GENERAL
 *  - #TAP_KEY_USAGE_ATTESTATION
 *  - #TAP_KEY_USAGE_STORAGE
 *  - #TAP_KEY_USAGE_UNDEFINED
 *  <p> For extended key types, the module-specific APIs and usage values should be used.
 */
typedef ubyte TAP_KEY_USAGE;
/*! TAP_KEY_USAGE_UNDEFINED */
#define TAP_KEY_USAGE_UNDEFINED          ((ubyte)0)
/*! TAP_KEY_USAGE_SIGNING - Signing key type */
#define TAP_KEY_USAGE_SIGNING            ((ubyte)1)
/*! TAP_KEY_USAGE_DECRYPT - Key used to decrypt data. */
#define TAP_KEY_USAGE_DECRYPT            ((ubyte)2)
/*! TAP_KEY_USAGE_GENERAL - General purpose key. */
#define TAP_KEY_USAGE_GENERAL            ((ubyte)3)
/*! TAP_KEY_USAGE_ATTESTATION - Attestation key type */
#define TAP_KEY_USAGE_ATTESTATION        ((ubyte)4)
/*! TAP_KEY_USAGE_STORAGE - Storage key type */
#define TAP_KEY_USAGE_STORAGE            ((ubyte)5)


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the type of credential supplied.
 * @details Value to indicate the type of credential supplied.  Not all types are valid for all supported security modules.
 *  <p> TAP_CREDENTIAL_TYPE must be one of the following values:
 *  - #TAP_CREDENTIAL_TYPE_UNDEFINED
 *  - #TAP_CREDENTIAL_TYPE_PASSWORD
 *  - #TAP_CREDENTIAL_TYPE_CERT
 *  - #TAP_CREDENTIAL_TYPE_KEY
 */
typedef ubyte TAP_CREDENTIAL_TYPE;
/*! TAP_CREDENTIAL_TYPE_UNDEFINED */
#define  TAP_CREDENTIAL_TYPE_UNDEFINED           ((ubyte)0)
/*! TAP_CREDENTIAL_TYPE_PASSWORD */
#define  TAP_CREDENTIAL_TYPE_PASSWORD            ((ubyte)1)
/*! TAP_CREDENTIAL_TYPE_CERT */
#define  TAP_CREDENTIAL_TYPE_CERT                ((ubyte)2)
/*! TAP_CREDENTIAL_TYPE_KEY */
#define  TAP_CREDENTIAL_TYPE_KEY                 ((ubyte)3)
/*! TAP_CREDENTIAL_TYPE_OBJECT */
#define  TAP_CREDENTIAL_TYPE_OBJECT              ((ubyte)4)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the format of a credential supplied.
 * @details Value to indicate the format of a credential supplied.
 *  <p> TAP_CREDENTIAL_FORMAT must be one of the following values:
 *  - #TAP_CREDENTIAL_FORMAT_PLAINTEXT
 *  - #TAP_CREDENTIAL_FORMAT_SHA1
 *  - #TAP_CREDENTIAL_FORMAT_SHA256
 *  - #TAP_CREDENTIAL_FORMAT_DER
 *  - #TAP_CREDENTIAL_FORMAT_PEM
 *  - #TAP_CREDENTIAL_FORMAT_BYTE_BUFFER
 */
typedef ubyte TAP_CREDENTIAL_FORMAT;
/*! TAP_CREDENTIAL_FORMAT_UNDEFINED */
#define  TAP_CREDENTIAL_FORMAT_UNDEFINED    ((ubyte)0)
/*! TAP_CREDENTIAL_FORMAT_PLAINTEXT - Indicates that credential is in plain text form. */
#define  TAP_CREDENTIAL_FORMAT_PLAINTEXT    ((ubyte)1)
/*! TAP_CREDENTIAL_FORMAT_SHA1 - Indicates that credential is in SHA1 form. This is typically used for passwords. */
#define  TAP_CREDENTIAL_FORMAT_SHA1         ((ubyte)2)
/*! TAP_CREDENTIAL_FORMAT_SHA256 - Indicates that credential is in SHA256 form. This is typically used for passwords. */
#define  TAP_CREDENTIAL_FORMAT_SHA256       ((ubyte)3)
/*! TAP_CREDENTIAL_FORMAT_DER - Indicates that credential is in DER form. */
#define  TAP_CREDENTIAL_FORMAT_DER          ((ubyte)4)
/*! TAP_CREDENTIAL_FORMAT_PEM - Indicates that credential is in PEM form. */
#define  TAP_CREDENTIAL_FORMAT_PEM          ((ubyte)5)
/*! TAP_CREDENTIAL_FORMAT_BYTE_BUFFER - Indicates that credential is a byte array. */
#define  TAP_CREDENTIAL_FORMAT_BYTE_BUFFER  ((ubyte)6)


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Indicates if this module has been provisioned for use
 */
typedef byteBoolean TAP_MODULE_PROVISION_STATE;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the format of a serialized key or object blob.
 * @details Value to indicate the format of a serialized key or object blob.
 *  <p> TAP_BLOB_FORMAT must be one of the following values:
 *  - #TAP_BLOB_FORMAT_MOCANA
 *  - #TAP_BLOB_FORMAT_DER
 *  - #TAP_BLOB_FORMAT_PEM
 */
typedef ubyte TAP_BLOB_FORMAT;
/*! TAP_BLOB_FORMAT_MOCANA - Blob contains data in Mocana format */
#define TAP_BLOB_FORMAT_MOCANA    (TAP_BLOB_FORMAT)0
/*! TAP_BLOB_FORMAT_DER - Blob contains DER format data */
#define TAP_BLOB_FORMAT_DER       (TAP_BLOB_FORMAT)1
/*! TAP_BLOB_FORMAT_PEM - Blob contains PEM format data */
#define TAP_BLOB_FORMAT_PEM       (TAP_BLOB_FORMAT)2


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the encoding of a blob.
 * @details Value to indicate the encoding of a blob.
 *  <p> TAP_BLOB_ENCODING must be one of the following values:
 *  - #TAP_BLOB_ENCODING_BINARY
 *  - #TAP_BLOB_ENCODING_BASE64
 */
typedef ubyte TAP_BLOB_ENCODING;
/*! TAP_BLOB_ENCODING_BINARY - Blob contains binary data */
#define TAP_BLOB_ENCODING_BINARY    (TAP_BLOB_ENCODING)0
/*! TAP_BLOB_ENCODING_BASE64 - Blob contains BASE64 encoded data */
#define TAP_BLOB_ENCODING_BASE64    (TAP_BLOB_ENCODING)1

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the context for the credential supplied.
 * @details Value to indicate the context for the credential supplied.
 *  <p> TAP_CREDENTIAL_CONTEXT must be one of the following values:
 *  - #TAP_CREDENTIAL_CONTEXT_OWNER
 *  - #TAP_CREDENTIAL_CONTEXT_USER
 *  - #TAP_CREDENTIAL_CONTEXT_ENTITY
 *  - #TAP_CREDENTIAL_CONTEXT_DYNAMIC_ENTITY
 */
typedef ubyte TAP_CREDENTIAL_CONTEXT;
/*! TAP_CREDENTIAL_CONTEXT_UNDEFINED - Undefined context type */
#define  TAP_CREDENTIAL_CONTEXT_UNDEFINED           ((ubyte)0)
/*! TAP_CREDENTIAL_CONTEXT_OWNER - Credential belongs to an owner. */
#define  TAP_CREDENTIAL_CONTEXT_OWNER               ((ubyte)1)
/*! TAP_CREDENTIAL_CONTEXT_USER - Credential belongs to a user */
#define  TAP_CREDENTIAL_CONTEXT_USER                 ((ubyte)2)
/*! TAP_CREDENTIAL_CONTEXT_ENTITY - Credential belongs to an entity.  This can be for a key, object or policy storage. */
#define  TAP_CREDENTIAL_CONTEXT_ENTITY               ((ubyte)3)
/*! TAP_CREDENTIAL_CONTEXT_DYNAMIC_ENTITY - Credential belongs to a dynamic entity.  This can be for a key, object or policy storage. */
#define  TAP_CREDENTIAL_CONTEXT_DYNAMIC_ENTITY               ((ubyte)4)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Value to indicate whether a public key operation should be done in SW, HW, or attempt one then
 *          fall back to the other.  If a user wants to force a public key operation to be done in HW, then
 *          TAP_OP_EXEC_FLAG_HW should be specified.  If the module does not support public key operations in HW,
 *          this will result in an error.
 *  <p> TAP_OP_EXEC_FLAG must be one of the following values:
 *  - #TAP_OP_EXEC_FLAG_SW
 *  - #TAP_OP_EXEC_FLAG_HW
 *  - #TAP_OP_EXEC_FLAG_HW_THEN_SW
 *  - #TAP_OP_EXEC_FLAG_SW_THEN_HW
 */
typedef ubyte TAP_OP_EXEC_FLAG;
/*! TAP_OP_EXEC_FLAG_SW - The operation must be perfomed in SW. */
#define TAP_OP_EXEC_FLAG_SW            ((ubyte)0)
/*! TAP_OP_EXEC_FLAG_HW - The operation must be perfomed in HW. */
#define TAP_OP_EXEC_FLAG_HW            ((ubyte)1)
/*! TAP_OP_EXEC_FLAG_HW_THEN_SW - The SMP should attempt to perform the operation in HW first.  It should attempt SW if HW operation is not supported. */
#define TAP_OP_EXEC_FLAG_HW_THEN_SW    ((ubyte)2)
/*! TAP_OP_EXEC_FLAG_SW_THEN_HW - The SMP should attempt to perform the operation in SW first.  It should attempt HW if SW operation is not supported. */
#define TAP_OP_EXEC_FLAG_SW_THEN_HW    ((ubyte)3)


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Trusted data types
 * @details TAP_TRUSTED_DATA_TYPE indicates the type of trusted data.  This must be one of the following values:
 *   - #TAP_TRUSTED_DATA_TYPE_MEASUREMENT
 *   - #TAP_TRUSTED_DATA_TYPE_IDENTIFIER
 *   - #TAP_TRUSTED_DATA_TYPE_REPORT
 *   - #TAP_TRUSTED_DATA_TYPE_TIME
 */
typedef ubyte TAP_TRUSTED_DATA_TYPE;
/*! TAP_TRUSTED_DATA_TYPE_NONE */
#define TAP_TRUSTED_DATA_TYPE_NONE           (TAP_TRUSTED_DATA_TYPE)0
/*! TAP_TRUSTED_DATA_TYPE_MEASUREMENT -  Secure module measurement data type. */
#define TAP_TRUSTED_DATA_TYPE_MEASUREMENT    (TAP_TRUSTED_DATA_TYPE)1
/*! TAP_TRUSTED_DATA_TYPE_IDENTIFIER - Secure module data type that provides unique identification.  */
#define TAP_TRUSTED_DATA_TYPE_IDENTIFIER     (TAP_TRUSTED_DATA_TYPE)2
/*! TAP_TRUSTED_DATA_TYPE_REPORT - Secure module data type that provides a report. */
#define TAP_TRUSTED_DATA_TYPE_REPORT         (TAP_TRUSTED_DATA_TYPE)3
/*! TAP_TRUSTED_DATA_TYPE_TIME - Secure module Time data type */
#define TAP_TRUSTED_DATA_TYPE_TIME           (TAP_TRUSTED_DATA_TYPE)4

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Trusted data subtypes
 * @details TAP_TRUSTED_DATA_SUBTYPE indicates the subtype of trusted data.
 *          This value is defined by the individual SMPs and the meaning must be documented by the SMP.
 *          Not all TAP_TRUSTED_DATA_TYPEs require a subtype.  This does not require a subtype and any value provided will be ignored.
 */
typedef ubyte TAP_TRUSTED_DATA_SUBTYPE;


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Root of trust types
 * @details TAP_ROOT_OF_TRUST_TYPE indicates the type of root of trust.  This must be one of the following values:
 *   - #TAP_ROOT_OF_TRUST_TYPE_UNKNOWN
 */
typedef ubyte TAP_ROOT_OF_TRUST_TYPE;
/*! TAP_ROOT_OF_TRUST_TYPE_UNKNOWN */
#define TAP_ROOT_OF_TRUST_TYPE_UNKNOWN           (TAP_ROOT_OF_TRUST_TYPE)0


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Trusted data types
 * @details TAP_TRUSTED_DATA_OPERATION indicates the type of trusted data operation to be performed.  This must be one of the following values:
 *   - #TAP_TRUSTED_DATA_OPERATION_NONE
 *   - #TAP_TRUSTED_DATA_OPERATION_WRITE
 *   - #TAP_TRUSTED_DATA_OPERATION_READ
 *   - #TAP_TRUSTED_DATA_OPERATION_UPDATE
 *   - #TAP_TRUSTED_DATA_OPERATION_RESET
 */
typedef ubyte TAP_TRUSTED_DATA_OPERATION;
/*! TAP_TRUSTED_DATA_OPERATION_NONE */
#define TAP_TRUSTED_DATA_OPERATION_NONE         (TAP_TRUSTED_DATA_OPERATION)0
/*! TAP_TRUSTED_DATA_OPERATION_WRITE - Trusted data write operation */
#define TAP_TRUSTED_DATA_OPERATION_WRITE        (TAP_TRUSTED_DATA_OPERATION)1
/*! TAP_TRUSTED_DATA_OPERATION_READ - Trusted data read operation */
#define TAP_TRUSTED_DATA_OPERATION_READ         (TAP_TRUSTED_DATA_OPERATION)2
/*! TAP_TRUSTED_DATA_OPERATION_UPDATE - Trusted data update operation */
#define TAP_TRUSTED_DATA_OPERATION_UPDATE       (TAP_TRUSTED_DATA_OPERATION)3
/*! TAP_TRUSTED_DATA_OPERATION_RESET - Trusted data reset/clear operation */
#define TAP_TRUSTED_DATA_OPERATION_RESET        (TAP_TRUSTED_DATA_OPERATION)4


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate the attribute type of a TAP_Attribute.
 * @details Value to indicate the attribute type of a TAP_Attribute.
 *  <p> TAP_ATTR_TYPE must be one of the following values:
 *  - #TAP_ATTR_NONE
 *  - #TAP_ATTR_FIRMWARE_VERSION
 *  - #TAP_ATTR_TAP_PROVIDER
 *  - #TAP_ATTR_KEY_ALGORITHM
 *  - #TAP_ATTR_KEY_USAGE
 *  - #TAP_ATTR_KEY_SIZE
 *  - #TAP_ATTR_CURVE
 *  - #TAP_ATTR_ENC_SCHEME
 *  - #TAP_ATTR_SIG_SCHEME
 *  - #TAP_ATTR_CREDENTIAL
 *  - #TAP_ATTR_SYM_KEY_MODE
 *  - #TAP_ATTR_HASH_ALG
 *  - #TAP_ATTR_KEY_HANDLE
 *  - #TAP_ATTR_MODULE_KEY
 *  - #TAP_ATTR_PUBLIC_KEY
 *  - #TAP_ATTR_RNG_PROPERTY
 *  - #TAP_ATTR_RNG_SEED
 *  - #TAP_ATTR_RND_STIR
 *  - #TAP_ATTR_PRELOAD_KEY
 *  - #TAP_ATTR_STORAGE_TYPE
 *  - #TAP_ATTR_STORAGE_SIZE
 *  - #TAP_ATTR_STORAGE_OFFSET
 *  - #TAP_ATTR_READ_OP
 *  - #TAP_ATTR_WRITE_OP
 *  - #TAP_ATTR_LABEL
 *  - #TAP_ATTR_BUFFER
 *  - #TAP_ATTR_CAPABILITY_CATEGORY
 *  - #TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *  - #TAP_ATTR_MODULE_PROVISION_TYPE
 *  - #TAP_ATTR_ENTITY_CREDENTIAL
 *  - #TAP_ATTR_TRUSTED_DATA_KEY
 *  - #TAP_ATTR_TRUSTED_DATA_VALUE
 *  - #TAP_ATTR_TRUSTED_DATA_TYPE
 *  - #TAP_ATTR_TRUSTED_DATA_INFO
 *  - #TAP_ATTR_OBJECT_HANDLE
 *  - #TAP_ATTR_TOKEN_TYPE
 *  - #TAP_ATTR_SLOT_ID
 *  - #TAP_ATTR_OBJECT_PROPERTY
 *  - #TAP_ATTR_PERMISSION_BITMASK
 *  - #TAP_ATTR_VENDOR_INFO
 *  - #TAP_ATTR_OP_EXEC_FLAG
 *  - #TAP_ATTR_STORAGE_INDEX
 *  - #TAP_ATTR_TEST_MODE
 *  - #TAP_ATTR_TEST_STATUS
 *  - #TAP_ATTR_TEST_CONTEXT
 *  - #TAP_ATTR_TEST_REPORT
 *  - #TAP_ATTR_TEST_REQUEST_DATA
 *  - #TAP_ATTR_PERMISSION_BITMASK_OWNER
 *  - #TAP_ATTR_OBJECT_ID_BYTESTRING
 */
typedef ubyte4 TAP_ATTR_TYPE;
/*! TAP_ATTR_NONE - Default 0 value to force an attribute type. */
#define TAP_ATTR_NONE                          (TAP_ATTR_TYPE)0
/*! TAP_ATTR_FIRMWARE_VERSION - The TAP_Attribute represents the firmware version of the Secure Element. */
#define TAP_ATTR_FIRMWARE_VERSION              (TAP_ATTR_TYPE)1
/*! TAP_ATTR_TAP_PROVIDER - The TAP_Attribute represents the TAP_PROVIDER of the Secure Element. eg. TPM2, GEMALTO. Uses TAP_PROVIDER structure */
#define TAP_ATTR_TAP_PROVIDER                  (TAP_ATTR_TYPE)2
/*! TAP_ATTR_KEY_ALGORITHM - This TAP_Attribute represents the Key Algorithm to use for the newly generated key. eg. RSA / ECC. Uses TAP_KEY_ALGORITHM structure */
#define TAP_ATTR_KEY_ALGORITHM                 (TAP_ATTR_TYPE)3
/*! TAP_ATTR_KEY_USAGE - This TAP_Attribute declares the intent of the newly generated key. eg. Signing, Decrypt. Uses TAP_KEY_USAGE structure */
#define TAP_ATTR_KEY_USAGE                     (TAP_ATTR_TYPE)4
/*! TAP_ATTR_KEY_SIZE - This TAP_Attribute defines the keysize of the newly generated key. Uses TAP_KEY_SIZE structure */
#define TAP_ATTR_KEY_SIZE                      (TAP_ATTR_TYPE)5
/*! TAP_ATTR_CURVE - This TAP_Attribute defines the ECC Curve ID of the newly generated key. Uses TAP_ECC_CURVE structure */
#define TAP_ATTR_CURVE                         (TAP_ATTR_TYPE)6
/*! TAP_ATTR_ENC_SCHEME - This TAP_Attribute defines the Encryption Scheme used by the newly generated key. Uses TAP_ENC_SCHEME structure */
#define TAP_ATTR_ENC_SCHEME                    (TAP_ATTR_TYPE)7
/*! TAP_ATTR_SIG_SCHEME - This TAP_Attribute defines the Signing Scheme used by the newly generated key. Uses TAP_SIG_SCHEME structure */
#define TAP_ATTR_SIG_SCHEME                    (TAP_ATTR_TYPE)8
/*! TAP_ATTR_CREDENTIAL - This TAP_Attribute supplies the Credentials associated with the newly generated key. Uses TAP_Credential structure */
#define TAP_ATTR_CREDENTIAL                    (TAP_ATTR_TYPE)9
/*! TAP_ATTR_SYM_KEY_MODE - This TAP_Attribute sets the Symmetric Encryption mode on the newly generated key. Uses TAP_SYM_KEY_MODE structure */
#define TAP_ATTR_SYM_KEY_MODE                  (TAP_ATTR_TYPE)10
/*! TAP_ATTR_HASH_ALG - This TAP_Attribute sets the Hash Algorithm on the newly generated key. Uses TAP_HASH_ALG structure */
#define TAP_ATTR_HASH_ALG                      (TAP_ATTR_TYPE)11
/*! TAP_ATTR_KEY_HANDLE - This TAP_Attribute contains the TAP_KeyHandle of a generated key. */
#define TAP_ATTR_KEY_HANDLE                    (TAP_ATTR_TYPE)12
/*! TAP_ATTR_MODULE_KEY - - This TAP_Attribute contains serialized stream of the newly generated key. Uses TAP_Buffer structure. */
#define TAP_ATTR_MODULE_KEY                    (TAP_ATTR_TYPE)13
/*! TAP_ATTR_PUBLIC_KEY - This TAP_Attribute contains the Public portion of the newly generated key. Uses TAP_PublicKey structure */
#define TAP_ATTR_PUBLIC_KEY                    (TAP_ATTR_TYPE)14
/*! TAP_ATTR_RNG_PROPERTY -   */
#define TAP_ATTR_RNG_PROPERTY                  (TAP_ATTR_TYPE)15
/*! TAP_ATTR_RNG_SEED - This is of type TAP_Buffer. */
#define TAP_ATTR_RNG_SEED                      (TAP_ATTR_TYPE)16
/*! TAP_ATTR_RND_STIR - This TAP_Attribute passes the seed value to use for stirring the random number generator in the SE. Uses TAP_Buffer field containing the number to use as the seed */
#define TAP_ATTR_RND_STIR                      (TAP_ATTR_TYPE)17
/*! TAP_ATTR_PRELOAD_KEY - This TAP_Attribute indicates to the SE, if supported and possible, preload this key for future crypto operations. Uses ubyte field, set to 0 or 1 */
#define TAP_ATTR_PRELOAD_KEY                   (TAP_ATTR_TYPE)18
/*! TAP_ATTR_STORAGE_TYPE - uses ubyte data type */
#define TAP_ATTR_STORAGE_TYPE                  (TAP_ATTR_TYPE)19
/*! TAP_ATTR_STORAGE_SIZE - Storage size attribute that can be interpreted by an SMP based on command/context usage. Uses a ubyte4. */
#define TAP_ATTR_STORAGE_SIZE                  (TAP_ATTR_TYPE)20
/*! TAP_ATTR_STORAGE_OFFSET - Storage offset attribute that can be interpreted by an SMP based on command/context usage. Uses a ubyte4. */
#define TAP_ATTR_STORAGE_OFFSET                (TAP_ATTR_TYPE)21
/*! TAP_ATTR_READ_OP - Generic read attribute that can be interpreted by an SMP based on command/context usage. Uses a ubyte. */
#define TAP_ATTR_READ_OP                       (TAP_ATTR_TYPE)22
/*! TAP_ATTR_WRITE_OP - Generic write attribute that can be interpreted by an SMP based on command/context usage.  Uses a ubyte.
     This can be options such as a direct write, fill, update/extend, bit set/clear, etc. */
#define TAP_ATTR_WRITE_OP                      (TAP_ATTR_TYPE)23
/*! TAP_ATTR_ENC_LABEL - Text associated with a message or digest.  Uses a TAP_Buffer structure. */
#define TAP_ATTR_ENC_LABEL                     (TAP_ATTR_TYPE)24
/*! TAP_ATTR_BUFFER - TAP_Buffer */
#define TAP_ATTR_BUFFER                        (TAP_ATTR_TYPE)25
/*! TAP_ATTR_CAPABILITY_CATEGORY - Attribute type for identifying module capabilities */
#define TAP_ATTR_CAPABILITY_CATEGORY           (TAP_ATTR_TYPE)26
/*! TAP_ATTR_CAPABILITY_FUNCTIONALITY - Attribute type for identifying token and object functionality */
#define TAP_ATTR_CAPABILITY_FUNCTIONALITY      (TAP_ATTR_TYPE)27
/*! TAP_ATTR_MODULE_PROVISION_TYPE - Attribute type to pass additional information to provision API */
#define TAP_ATTR_MODULE_PROVISION_TYPE         (TAP_ATTR_TYPE)28
/*! TAP_ATTR_ENTITY_CREDENTIAL - Credentials with associated entity information */
#define TAP_ATTR_ENTITY_CREDENTIAL             (TAP_ATTR_TYPE)29
/*! TAP_ATTR_TRUSTED_DATA_KEY - Secure module specific stored data category.  This is of type TAP_Buffer. */
#define TAP_ATTR_TRUSTED_DATA_KEY              (TAP_ATTR_TYPE)30
/*! TAP_ATTR_TRUSTED_DATA_VALUE - Secure Module specific stored values. This is of type TAP_Buffer. */
#define TAP_ATTR_TRUSTED_DATA_VALUE            (TAP_ATTR_TYPE)31
/*! TAP_ATTR_TRUSTED_DATA_TYPE - SMP supported Trusted data like Measurement, Time, Report, Identity */
#define TAP_ATTR_TRUSTED_DATA_TYPE             (TAP_ATTR_TYPE)32
/*! TAP_ATTR_TRUSTED_DATA_INFO - Information corresponds to Trusted Data Type */
#define TAP_ATTR_TRUSTED_DATA_INFO             (TAP_ATTR_TYPE)33
/*! TAP_ATTR_OBJECT_HANDLE - Handle to the Object context */
#define TAP_ATTR_OBJECT_HANDLE                 (TAP_ATTR_TYPE)34
/*! TAP_ATTR_TOKEN_TYPE - SMP specific token categorizations */
#define TAP_ATTR_TOKEN_TYPE                    (TAP_ATTR_TYPE)35
/*! TAP_ATTR_SLOT_ID - Slot identifier */
#define TAP_ATTR_SLOT_ID                       (TAP_ATTR_TYPE)36
/*! TAP_ATTR_OBJECT_PROPERTY - Object properties such as persistence or dynamic etc */
#define TAP_ATTR_OBJECT_PROPERTY               (TAP_ATTR_TYPE)37
/*! TAP_ATTR_PERMISSION - Policy storage permissions */
#define TAP_ATTR_PERMISSION                    (TAP_ATTR_TYPE)38
/*! TAP_ATTR_VENDOR_INFO - Vendor information */
#define TAP_ATTR_VENDOR_INFO                   (TAP_ATTR_TYPE)39
/*! TAP_ATTR_OP_EXEC_FLAG - Perform operation in Hardware/Software */
#define TAP_ATTR_OP_EXEC_FLAG                  (TAP_ATTR_TYPE)40
/*! TAP_ATTR_STORAGE_INDEX - SMP-specific index associated with the storage object. This can be interpreted by an SMP based on command/context usage. Uses a ubyte4. */
#define TAP_ATTR_STORAGE_INDEX                 (TAP_ATTR_TYPE)41
/*! TAP_ATTR_TEST_MODE - Specified scope of the test. Uses the TAP_TEST_MODE type.  */
#define TAP_ATTR_TEST_MODE                     (TAP_ATTR_TYPE)42
/*! TAP_ATTR_TEST_STATUS - Identifies status of a selfTest command.  Uses the TAP_TEST_STATUS type */
#define TAP_ATTR_TEST_STATUS                   (TAP_ATTR_TYPE)43
/*! TAP_ATTR_TEST_CONTEXT - Identifies the test context to be used in subsequent polling APIs. Uses TAP_HANDLE. */
#define TAP_ATTR_TEST_CONTEXT                  (TAP_ATTR_TYPE)44
/*! TAP_ATTR_TEST_REPORT - Detailed SMP specific test report (in case of success and failure) */
#define TAP_ATTR_TEST_REPORT                   (TAP_ATTR_TYPE)45
/*! TAP_ATTR_TEST_REQUEST_DATA - Extended information along with test mode. */
#define TAP_ATTR_TEST_REQUEST_DATA             (TAP_ATTR_TYPE)46
/*! TAP_ATTR_CREDENTIAL_SET - Specifies the credentials to be set during create/update operations. Uses TAP_EntityCredentialList structure */
#define TAP_ATTR_CREDENTIAL_SET                (TAP_ATTR_TYPE)47
/*! TAP_ATTR_CREDENTIAL_USAGE - Specifies the credentials to be used for performing an operation. Uses TAP_EntityCredentialList structure */
#define TAP_ATTR_CREDENTIAL_USAGE              (TAP_ATTR_TYPE)48
/*! TAP_ATTR_MODULE_PROVISION_STATE - Indicates the state of this module's provisioning, whether or not it is available for use. uses TAP_MODULE_PROVISION_STATE structure */
#define TAP_ATTR_MODULE_PROVISION_STATE        (TAP_ATTR_TYPE)49
/*! TAP_ATTR_PERMISSION_OWNER - Policy storage permissions for an owner */
#define TAP_ATTR_PERMISSION_OWNER              (TAP_ATTR_TYPE)50
/*! TAP_ATTR_MODULE_ID_STRING - 32 byte ID that identifies this secure element uniquely */
#define TAP_ATTR_MODULE_ID_STRING              (TAP_ATTR_TYPE)51
/*! TAP_ATTR_GET_MODULE_CREDENTIALS - Returns TAP_Buffer containing Mocana credential file contents */
#define TAP_ATTR_GET_MODULE_CREDENTIALS        (TAP_ATTR_TYPE)52
/*! TAP_ATTR_KEY_CMK */
#define TAP_ATTR_KEY_CMK                       (TAP_ATTR_TYPE)53
/*! TAP_ATTR_GET_CAP_CAPABILITY */
#define TAP_ATTR_GET_CAP_CAPABILITY            (TAP_ATTR_TYPE)54
/*! TAP_ATTR_GET_CAP_PROPERTY */
#define TAP_ATTR_GET_CAP_PROPERTY              (TAP_ATTR_TYPE)55
/*! TAP_ATTR_GET_CAP_PROPERTY_COUNT */
#define TAP_ATTR_GET_CAP_PROPERTY_COUNT        (TAP_ATTR_TYPE)56
/*! TAP_ATTR_IS_DATA_NOT_DIGEST  - Indicates whether the input data is digested or plain. uses byteBoolean */
#define TAP_ATTR_IS_DATA_NOT_DIGEST            (TAP_ATTR_TYPE)57
/*! TAP_ATTR_SALT_LEN */
#define TAP_ATTR_SALT_LEN                      (TAP_ATTR_TYPE)58
/* TAP_ATTR_ADDITIONAL_AUTH_DATA - Additional auth data, originally designed for AES-GCM */
#define TAP_ATTR_ADDITIONAL_AUTH_DATA          (TAP_ATTR_TYPE)59
/* TAP_ATTR_TAG_LEN_BITS - Bit length of desired tag generation, originally designed for AES-GCM */
#define TAP_ATTR_TAG_LEN_BITS                  (TAP_ATTR_TYPE)60
/* TAP_ATTR_TOKEN_OBJECT - Indicates whether this object was generated on the token. Should only be used for testing. */
#define TAP_ATTR_TOKEN_OBJECT                  (TAP_ATTR_TYPE)61
/* TAP_ATTR_OBJECT_VALUE - The value of the object being created */
#define TAP_ATTR_OBJECT_VALUE                  (TAP_ATTR_TYPE)62
/* TAP_ATTR_RAW_KEY_SIZE - an arbitrary key size up to 4 bytes in length */
#define TAP_ATTR_RAW_KEY_SIZE                  (TAP_ATTR_TYPE)63
/* TAP_ATTR_OBJECT_ID_BYTESTRING - attribute for object IDs that do not fit in the ubyte8 form */
#define TAP_ATTR_OBJECT_ID_BYTESTRING          (TAP_ATTR_TYPE)64
/* TAP_ATTR_SERIALIZED_OBJECT_BLOB - special attribute for keys that were generated with IDs > 8 bytes. */
#define TAP_ATTR_SERIALIZED_OBJECT_BLOB        (TAP_ATTR_TYPE)65
/* TAP_ATTR_KEY_WRAP_TYPE - Type of key wrap to perform. One of { TAP_KEY_WRAP_RSA, TAP_KEY_WRAP_AES } */
#define TAP_ATTR_KEY_WRAP_TYPE                 (TAP_ATTR_TYPE)66
/* TAP_ATTR_KEY_TO_BE_WRAPPED_ID - 8 byte value containing ID of the key to be wrapped */
#define TAP_ATTR_KEY_TO_BE_WRAPPED_ID          (TAP_ATTR_TYPE)67
/* TAP_ATTR_WRAPPING_KEY_ID - 8 byte value containing ID of the wrapping key */
#define TAP_ATTR_WRAPPING_KEY_ID               (TAP_ATTR_TYPE)68
/* TAP_ATTR_HIERARCHY - Specifies the hierarchy under which a key is to be created 
   takes on values TAP_HIERARCHY_STORAGE or TAP_HIERARCHY_ENDORSEMENT
*/
#define TAP_ATTR_HIERARCHY                     (TAP_ATTR_TYPE)69
/* TAP_ATTR_CREATE_KEY_TYPE - specifies if the key to create has to be a primary key.
 * Takes a boolean value. TRUE(1) specifies the key to be a primary key.
 */
#define TAP_ATTR_CREATE_KEY_TYPE               (TAP_ATTR_TYPE)70

/* TAP_ATTR_CREATE_KEY_ENTROPY - Specifies entropy data of 256 bytes to be used in key creation
 */
#define TAP_ATTR_CREATE_KEY_ENTROPY            (TAP_ATTR_TYPE)71

/* TAP_ATTR_AUTH_CONTEXT - Specifies auth context/handle-type to use.
 * Used in Policy-Storage operations.
 */
#define TAP_ATTR_AUTH_CONTEXT                  (TAP_ATTR_TYPE)72

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Random Number Generation Properties
 * @details TAP_RNG_PROPERTY indicates the types of random numbers allowed.  This must be one of the following values:
 *   - #TAP_RNG_PROPERTY_NO_ZERO
 *   - #TAP_RNG_PROPERTY_ALL_ONES_ALLOWED
 */
typedef ubyte TAP_RNG_PROPERTY;
/*! TAP_RNG_PROPERTY_NO_ZERO - indicates to the SE if all 0s are permissible as a random number. */
#define TAP_RNG_PROPERTY_NO_ZERO              (TAP_RNG_PROPERTY)0x01
/*! TAP_RNG_PROPERTY_ALL_ONES_ALLOWED - indicates to the SE if all 1s are permissible as a random number. */
#define TAP_RNG_PROPERTY_ALL_ONES_ALLOWED     (TAP_RNG_PROPERTY)0x02

typedef TAP_ID TAP_HIERARCHY_PROPERTY;
#define TAP_HIERARCHY_NONE          (TAP_HIERARCHY_PROPERTY)0
/*! TAP_HIERARCHY_STORAGE identifies Storage as hierarchy for the given key */
#define TAP_HIERARCHY_STORAGE       (TAP_HIERARCHY_PROPERTY)1
/*! TAP_HIERARCHY_ENDORSEMENT identifies Endorsement as hierarchy for the given key */
#define TAP_HIERARCHY_ENDORSEMENT   (TAP_HIERARCHY_PROPERTY)2
/*! TAP_HIERARCHY_PLATFORM identifies Platform as hierarchy for the given key */
#define TAP_HIERARCHY_PLATFORM      (TAP_HIERARCHY_PROPERTY)3

typedef TAP_ID TAP_AUTH_CONTEXT_PROPERTY;
#define TAP_AUTH_CONTEXT_NONE          (TAP_AUTH_CONTEXT_PROPERTY)0
/*! TAP_AUTH_CONTEXT_STORAGE identifies Storage as auth-context/handle-type */
#define TAP_AUTH_CONTEXT_STORAGE       (TAP_AUTH_CONTEXT_PROPERTY)1
/*! TAP_AUTH_CONTEXT_ENDORSEMENT identifies Endorsement as auth-context/handle-type */
#define TAP_AUTH_CONTEXT_ENDORSEMENT   (TAP_AUTH_CONTEXT_PROPERTY)2
/*! TAP_AUTH_CONTEXT_PLATFORM identifies Endorsement as auth-context/handle-type */
#define TAP_AUTH_CONTEXT_PLATFORM      (TAP_AUTH_CONTEXT_PROPERTY)3


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Write Operation Type
 * @details TAP_WRITE_OP_TYPE indicates the types of write operation to be performed.  This must be one of the following values:
 *   - #TAP_WRITE_OP_DIRECT
 *   - #TAP_WRITE_OP_FILL
 *   - #TAP_WRITE_OP_EXTEND
 *   - #TAP_WRITE_OP_BIT_SET
 *   - #TAP_WRITE_OP_CLEAR
 */
typedef ubyte TAP_WRITE_OP_TYPE;
/*! TAP_WRITE_OP_UNKNOWN - this should never be allowed */
#define TAP_WRITE_OP_UNKNOWN                   (TAP_WRITE_OP_TYPE)0x00
/*! TAP_WRITE_OP_DIRECT */
#define TAP_WRITE_OP_DIRECT                    (TAP_WRITE_OP_TYPE)0x01
/*! TAP_WRITE_OP_FILL */
#define TAP_WRITE_OP_FILL                      (TAP_WRITE_OP_TYPE)0x02
/*! TAP_WRITE_OP_EXTEND */
#define TAP_WRITE_OP_EXTEND                    (TAP_WRITE_OP_TYPE)0x03
/*! TAP_WRITE_OP_BIT_SET */
#define TAP_WRITE_OP_BIT_SET                   (TAP_WRITE_OP_TYPE)0x04
/*! TAP_WRITE_OP_CLEAR */
#define TAP_WRITE_OP_CLEAR                     (TAP_WRITE_OP_TYPE)0x05

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate the type of a TAP_Entity.
 * @details Value to indicate the type of a TAP_Entity.
 *  <p> TAP_ENTITY_TYPE must be one of the following values:
 *  - #TAP_ENTITY_TYPE_UNKNOWN
 *  - #TAP_ENTITY_TYPE_MODULE
 *  - #TAP_ENTITY_TYPE_TOKEN
 *  - #TAP_ENTITY_TYPE_OBJECT
 */
typedef ubyte4 TAP_ENTITY_TYPE;
/*! TAP_ENTITY_TYPE_UNKNOWN - No entity type specified by the caller.
    For example, if an entity has no parent, the parentType would be TAP_ENTITY_TYPE_UNKNOWN */
#define TAP_ENTITY_TYPE_UNKNOWN    (TAP_ENTITY_TYPE)0
/*! TAP_ENTITY_TYPE_MODULE - Specifies that the entity is a module. */
#define TAP_ENTITY_TYPE_MODULE     (TAP_ENTITY_TYPE)1
/*! TAP_ENTITY_TYPE_TOKEN - Specifies that the entity is a token. */
#define TAP_ENTITY_TYPE_TOKEN      (TAP_ENTITY_TYPE)2
/*! TAP_ENTITY_TYPE_OBJECT - Specifies that the entity is an object. */
#define TAP_ENTITY_TYPE_OBJECT     (TAP_ENTITY_TYPE)3

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate the type of a TAP_Token.
 * @details Value to indicate the type of a TAP_Token.  All values, except the DEFAULT, are defined by the SMPs.
 *          An SMP provider may or may not accept a value of #TAP_TOKEN_TYPE_DEFAULT.  Refer to the documentation for
 *          the desired SMP for details on token types supported by that SMP.
 *          If an SMP provider accepts a value of #TAP_TOKEN_TYPE_DEFAULT, it internally chooses the correct token
 *          for the requested task.
 *  <p> TAP_TOKEN_TYPE must be one of the following values:
 *  - #TAP_TOKEN_TYPE_DEFAULT
 *  - value defined by the SMP
 */
typedef ubyte4 TAP_TOKEN_TYPE;
/*! TAP_TOKEN_TYPE_DEFAULT - If supported by an SMP, this will tell the SMP to use the appropriate default token. */
#define TAP_TOKEN_TYPE_DEFAULT    (TAP_TOKEN_TYPE)0

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate the type of test requested that a module perform.
 * @details Value to indicate the type of test requested that a module perform.
 *  <p> TAP_TEST_MODE must be one of the following values:
 *  - #TAP_TEST_MODE_HW_ONLY
 *  - #TAP_TEST_MODE_FULL
 *  - #TAP_TEST_MODE_PARTIAL
 *  - #TAP_TEST_MODE_LAST_RESULTS
 *  - #TAP_TEST_MODE_CAPABILITY
 */
typedef ubyte TAP_TEST_MODE;
/*! TAP_TEST_MODE_HW_ONLY - Indicates to the SMP to run a HW test. */
#define TAP_TEST_MODE_HW_ONLY        (TAP_TEST_MODE)0
/*! TAP_TEST_MODE_FULL - Indicates to the SMP to run a full test. */
#define TAP_TEST_MODE_FULL           (TAP_TEST_MODE)1
/*! TAP_TEST_MODE_PARTIAL - Indicates to the SMP to run a partial test. */
#define TAP_TEST_MODE_PARTIAL        (TAP_TEST_MODE)2
/*! TAP_TEST_MODE_LAST_RESULTS - Indicates to the SMP to return the last test results without running a new test. */
#define TAP_TEST_MODE_LAST_RESULTS   (TAP_TEST_MODE)3
/*! TAP_TEST_MODE_CAPABILITY - Indicates to the SMP to return the capabilities of the module. */
#define TAP_TEST_MODE_CAPABILITY     (TAP_TEST_MODE)4

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate the results of a module test.
 * @details Value to indicate the results of a module test.
 *  <p> TAP_TEST_STATUS must be one of the following values:
 *  - #TAP_TEST_STATUS_SUCCESS
 *  - #TAP_TEST_STATUS_FAILURE
 *  - #TAP_TEST_STATUS_PENDING
 */
typedef ubyte TAP_TEST_STATUS;
/*! TAP_TEST_STATUS_SUCCESS - indicates the test was successful */
#define TAP_TEST_STATUS_SUCCESS        (TAP_TEST_STATUS)0
/*! TAP_TEST_STATUS_FAILURE - indicates the test was NOT successful */
#define TAP_TEST_STATUS_FAILURE        (TAP_TEST_STATUS)1
/*! TAP_TEST_STATUS_PENDING - indicates the test has not yet completed */
#define TAP_TEST_STATUS_PENDING        (TAP_TEST_STATUS)2


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate permissions.
 * @details Value to indicate permissions.
 *  <p> TAP_PERMISSION_BITMASK must be one of the following values:
 *  - #TAP_PERMISSION_BITMASK_READ
 *  - #TAP_PERMISSION_BITMASK_WRITE
 *  - #TAP_PERMISSION_BITMASK_WRITE_ONCE
 *  - #TAP_PERMISSION_BITMASK_DELETE
 */
typedef ubyte4  TAP_PERMISSION_BITMASK;
/*! TAP_PERMISSION_READ - permission to perform a read operation */
#define TAP_PERMISSION_BITMASK_READ            0x0001
/*! TAP_PERMISSION_WRITE - permission to perform a write operation */
#define TAP_PERMISSION_BITMASK_WRITE           0x0002
/*! TAP_PERMISSION_WRITE_ONCE - permission to perform a one-time write operation */
#define TAP_PERMISSION_BITMASK_WRITE_ONCE      0x0004
/*! TAP_PERMISSION_DELETE - permission to perform a delete/clear operation */
#define TAP_PERMISSION_BITMASK_DELETE          0x0008

/***************************************************************
   TAP Capability Attribute values
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate capability categories.
 * @details Value to indicate capability categories.  This can be used as a bitmask to filter out capabilities by categories.
 *  <p> TAP_CAPABILITY_CATEGORY must be one of the following values:
 *  - #TAP_CAPABILITY_RNG
 *  - #TAP_CAPABILITY_TRUSTED_DATA
 *  - #TAP_CAPABILITY_CRYPTO_OP
 *  - #TAP_CAPABILITY_KEY_STORAGE
 *  - #TAP_CAPABILITY_SECURE_STORAGE
 *  - #TAP_CAPABILITY_CERTIFICATE_STORE
 *  - #TAP_CAPABILITY_SECURE_TRANSPORT
 *  - #TAP_CAPABILITY_REMOTE_ATTESTATION
 */
typedef ubyte2 TAP_CAPABILITY_CATEGORY;
/*! TAP_CAPABILITY_RNG - Category containing capabilities related to Random Number Generation. */
#define TAP_CAPABILITY_RNG                           (TAP_CAPABILITY_CATEGORY)0x0100
/*! TAP_CAPABILITY_TRUSTED_DATA - Category containing capabilities related to trusted data. */
#define TAP_CAPABILITY_TRUSTED_DATA                  (TAP_CAPABILITY_CATEGORY)0x0200
/*! TAP_CAPABILITY_CRYPTO_OP - Category containing capabilities related to crypto operations. */
#define TAP_CAPABILITY_CRYPTO_OP                     (TAP_CAPABILITY_CATEGORY)0x0300
/*! TAP_CAPABILITY_KEY_STORAGE - Category containing capabilities related to key storage. */
#define TAP_CAPABILITY_KEY_STORAGE                   (TAP_CAPABILITY_CATEGORY)0x0400
/*! TAP_CAPABILITY_SECURE_STORAGE - Category containing capabilities related to secure storage. */
#define TAP_CAPABILITY_SECURE_STORAGE                (TAP_CAPABILITY_CATEGORY)0x0500
/*! TAP_CAPABILITY_CERTIFICATE_STORE - Category containing capabilities related to certificate store. */
#define TAP_CAPABILITY_CERTIFICATE_STORE             (TAP_CAPABILITY_CATEGORY)0x0600
/*! TAP_CAPABILITY_SECURE_TRANSPORT - Category containing capabilities related to secure transport. */
#define TAP_CAPABILITY_SECURE_TRANSPORT              (TAP_CAPABILITY_CATEGORY)0x0700
/*! TAP_CAPABILITY_REMOTE_ATTESTATION - Category containing capabilities related to remote attestation. */
#define TAP_CAPABILITY_REMOTE_ATTESTATION            (TAP_CAPABILITY_CATEGORY)0x0800

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Value to indicate capability values/functionalities.
 * @details Value to indicate capability values/functionalities.
 *  <p> TAP_CAPABILITY_FUNCTIONALITY must be one of the following values:
 *  - #TAP_CAPABILITY_RNG_TRNG
 *  - #TAP_CAPABILITY_RNG_PRNG
 *  - #TAP_CAPABILITY_RNG_SEED
 *  - #TAP_CAPABILITY_TRUSTED_DATA_TIME
 *  - #TAP_CAPABILITY_TRUSTED_DATA_MEASUREMENT
 *  - #TAP_CAPABILITY_TRUSTED_DATA_IDENTITY
 *  - #TAP_CAPABILITY_CRYPTO_OP_SIGN
 *  - #TAP_CAPABILITY_CRYPTO_OP_DIGEST
 *  - #TAP_CAPABILITY_CRYPTO_OP_DIGEST_MULTIPART
 *  - #TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC
 *  - #TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC_MULTIPART
 *  - #TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC
 *  - #TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC_MULTIPART
 *  - #TAP_CAPABILITY_CRYPTO_OP_SIGN_MULTIPART
 *  - #TAP_CAPABILITY_CRYPTO_OP_VERIFY
 *  - #TAP_CAPABILITY_CRYPTO_OP_VERIFY_MULTIPART
 *  - #TAP_CAPABILITY_CRYPTO_OP_ENCRYPT
 *  - #TAP_CAPABILITY_CRYPTO_OP_ENCRYPT_MULTIPART
 *  - #TAP_CAPABILITY_CRYPTO_OP_DECRYPT
 *  - #TAP_CAPABILITY_CRYPTO_OP_DECRYPT_MULTIPART
 *  - #TAP_CAPABILITY_KEY_STORAGE_SYMMETRIC_KEY
 *  - #TAP_CAPABILITY_KEY_STORAGE_ASYMMETRIC_KEY
 *  - #TAP_CAPABILITY_STORAGE_WITH_POLICY
 *  - #TAP_CAPABILITY_STORAGE_WITH_TRUSTED_DATA
 *  - #TAP_CAPABILITY_ATTESTATION_BASIC
 *  - #TAP_CAPABILITY_ATTESTATION_ANONYMOUS
 *
 */

typedef ubyte2 TAP_CAPABILITY_FUNCTIONALITY;
/*! TAP_CAPABILITY_RNG_TRNG */
#define TAP_CAPABILITY_RNG_TRNG                      (TAP_CAPABILITY_FUNCTIONALITY)0x0101
/*! TAP_CAPABILITY_RNG_PRNG */
#define TAP_CAPABILITY_RNG_PRNG                      (TAP_CAPABILITY_FUNCTIONALITY)0x0102
/*! TAP_CAPABILITY_RNG_SEED */
#define TAP_CAPABILITY_RNG_SEED                      (TAP_CAPABILITY_FUNCTIONALITY)0x0103

/*! TAP_CAPABILITY_TRUSTED_DATA_TIME */
#define TAP_CAPABILITY_TRUSTED_DATA_TIME             (TAP_CAPABILITY_FUNCTIONALITY)0x0201
/*! TAP_CAPABILITY_TRUSTED_DATA_MEASUREMENT */
#define TAP_CAPABILITY_TRUSTED_DATA_MEASUREMENT      (TAP_CAPABILITY_FUNCTIONALITY)0x0202
/*! TAP_CAPABILITY_TRUSTED_DATA_IDENTITY */
#define TAP_CAPABILITY_TRUSTED_DATA_IDENTITY         (TAP_CAPABILITY_FUNCTIONALITY)0x0203

/*! TAP_CAPABILITY_CRYPTO_OP_SIGN */
#define TAP_CAPABILITY_CRYPTO_OP_SIGN                (TAP_CAPABILITY_FUNCTIONALITY)0x0301
/*! TAP_CAPABILITY_CRYPTO_OP_DIGEST */
#define TAP_CAPABILITY_CRYPTO_OP_DIGEST              (TAP_CAPABILITY_FUNCTIONALITY)0x0302
/*! TAP_CAPABILITY_CRYPTO_OP_DIGEST_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_DIGEST_MULTIPART    (TAP_CAPABILITY_FUNCTIONALITY)0x0303
/*! TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC */
#define TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC           (TAP_CAPABILITY_FUNCTIONALITY)0x0304
/*! TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC_MULTIPART (TAP_CAPABILITY_FUNCTIONALITY)0x0305
/*! TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC */
#define TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC          (TAP_CAPABILITY_FUNCTIONALITY)0x0306
/*! TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC_MULTIPART (TAP_CAPABILITY_FUNCTIONALITY)0x0307
/*! TAP_CAPABILITY_CRYPTO_OP_SIGN_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_SIGN_MULTIPART      (TAP_CAPABILITY_FUNCTIONALITY)0x0309
/*! TAP_CAPABILITY_CRYPTO_OP_VERIFY */
#define TAP_CAPABILITY_CRYPTO_OP_VERIFY              (TAP_CAPABILITY_FUNCTIONALITY)0x030A
/*! TAP_CAPABILITY_CRYPTO_OP_VERIFY_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_VERIFY_MULTIPART    (TAP_CAPABILITY_FUNCTIONALITY)0x030B
/*! TAP_CAPABILITY_CRYPTO_OP_ENCRYPT */
#define TAP_CAPABILITY_CRYPTO_OP_ENCRYPT             (TAP_CAPABILITY_FUNCTIONALITY)0x030C
/*! TAP_CAPABILITY_CRYPTO_OP_ENCRYPT_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_ENCRYPT_MULTIPART   (TAP_CAPABILITY_FUNCTIONALITY)0x030D
/*! TAP_CAPABILITY_CRYPTO_OP_DECRYPT */
#define TAP_CAPABILITY_CRYPTO_OP_DECRYPT             (TAP_CAPABILITY_FUNCTIONALITY)0x030E
/*! TAP_CAPABILITY_CRYPTO_OP_DECRYPT_MULTIPART */
#define TAP_CAPABILITY_CRYPTO_OP_DECRYPT_MULTIPART   (TAP_CAPABILITY_FUNCTIONALITY)0x030F

/*! TAP_CAPABILITY_KEY_STORAGE_SYMMETRIC_KEY */
#define TAP_CAPABILITY_KEY_STORAGE_SYMMETRIC_KEY     (TAP_CAPABILITY_FUNCTIONALITY)0x0401
/*! TAP_CAPABILITY_KEY_STORAGE_ASYMMETRIC_KEY */
#define TAP_CAPABILITY_KEY_STORAGE_ASYMMETRIC_KEY    (TAP_CAPABILITY_FUNCTIONALITY)0x0402

/*! TAP_CAPABILITY_STORAGE_WITH_POLICY */
#define TAP_CAPABILITY_STORAGE_WITH_POLICY           (TAP_CAPABILITY_FUNCTIONALITY)0x0501
/*! TAP_CAPABILITY_STORAGE_WITH_TRUSTED_DATA */
#define TAP_CAPABILITY_STORAGE_WITH_TRUSTED_DATA     (TAP_CAPABILITY_FUNCTIONALITY)0x0502

/*! TAP_CAPABILITY_ATTESTATION_BASIC */
#define TAP_CAPABILITY_ATTESTATION_BASIC             (TAP_CAPABILITY_FUNCTIONALITY)0x0601
/*! TAP_CAPABILITY_ATTESTATION_ANONYMOUS */
#define TAP_CAPABILITY_ATTESTATION_ANONYMOUS         (TAP_CAPABILITY_FUNCTIONALITY)0x0602

/*! TAP_MAX_MODULE_CREDENTIALS : Maximum number of credentials needed for a module of a provider */
#define TAP_MAX_MODULE_CREDENTIALS                   8

/***************************************************************
   General Structure Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 *
 * @brief Context returned by the module during initModuleContext
 */
typedef struct
{
    /*! Internal SMP context placeholder */
    void *pPlaceHolder;
} TAP_SMPContext;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing generic data buffer
 */
typedef struct
{
    /*! Size of data buffer */
    ubyte4  bufferLen;
    /*! Buffer containing data */
    ubyte   *pBuffer;
} TAP_Buffer;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing a list of TAP_Buffer entries.
 */
typedef struct
{
    /*! The number of TAP_Buffer entries in the list. */
    ubyte4 count;
    /*! A list of TAP_Buffer entries. */
    TAP_Buffer    *pBufferList;
} TAP_BufferList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing a configuration information entry.  This is needed to provide configuration info when
 *          there is no file system.
 */
typedef struct
{
    /*! Provider to which the configuration information belongs.  Must be a valid #TAP_PROVIDER */
    TAP_PROVIDER  provider;

    /*! Configuration information read from config file */
    TAP_Buffer    configInfo;

    /* If true, reuse device handle. open-close only once */
    byteBoolean   useSharedHandle;

} TAP_ConfigInfo;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing a list of configuration information entries.
 */
typedef struct
{
    /*! The number of TAP_ConfigInfo entries in the list. */
    ubyte4 count;
    /*! A list of TAP_ConfigInfo entries. */
    TAP_ConfigInfo    *pConfig;
} TAP_ConfigInfoList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing a TAP_Buffer and the format and encoding of the blob.
 */
typedef struct
{
    /*! The format of the blob.  This must be a valid #TAP_BLOB_FORMAT value. */
    TAP_BLOB_FORMAT     format;
    /*! The encoding of the blob.  This must be a valid #TAP_BLOB_ENCODING value. */
    TAP_BLOB_ENCODING   encoding;
    /*! The TAP_Buffer containing the serialized and/or encoded data. */
    TAP_Buffer          blob;
} TAP_Blob;


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute structure used to represent entities or module-specific information.
 */
typedef struct
{
    /*! Attribute type.  Must be a valid TAP_ATTR_* value. */
    TAP_ATTR_TYPE type;
    /*! Length of the data structure that represents the type field */
    ubyte4 length;
    /*! Pointer to structure that represents the type field */
    void *pStructOfType;
} TAP_Attribute;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing list of TAP_Attribute elements
 */
typedef struct
{
    /*! The number of entries in the list */
    ubyte4 listLen;
    /*! The list of TAP_Attribute items */
    TAP_Attribute *pAttributeList;
} TAP_AttributeList;

/**
* @ingroup tap_definitions
* @ingroup tap_smp_definitions
* @details Attribute list containing information about module capabilities
*/
typedef TAP_AttributeList TAP_ModuleCapabilityAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about module capabilities
 */
typedef TAP_AttributeList TAP_ModuleCapPropertyAttributes;

typedef ubyte4 TAP_MODULE_CAP_CAP_T;
typedef ubyte4 TAP_MODULE_CAP_PROPERTY_TAG;
/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP Module capability's property structure
 */
typedef struct
{
    /*! The tag/id of property */
    TAP_MODULE_CAP_PROPERTY_TAG propertyId;
    /*! The value of the property corresponding to propertyId */
    TAP_Buffer                  propertyValue;
    /*! The text description of the property corresponding to propertyId */
    TAP_Buffer                  propertyDescription;
} TAP_ModuleCapProperty;

/**
* @ingroup tap_definitions
* @ingroup tap_smp_definitions
* @details List containing properties of a module capability
*/
typedef struct
{
    /*! The number of properties contained in the list */
    ubyte4                  numProperties;
    /*! The list of #TAP_EntityId */
    TAP_ModuleCapProperty   *pPropertyList;
} TAP_ModuleCapPropertyList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information needed for module provisioning.
 */
typedef TAP_AttributeList TAP_ModuleProvisionAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about module-specific errors
 */
typedef TAP_AttributeList TAP_ErrorAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information needed for Random Number Generation
 */
typedef TAP_AttributeList TAP_RngAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information specific to objects.
 */
typedef TAP_AttributeList TAP_ObjectAttributes;


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about token capabilities
 */
typedef TAP_AttributeList TAP_TokenCapabilityAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information needed for token provisioning.
 */
typedef TAP_AttributeList TAP_TokenProvisionAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about object capabilities
 */
typedef TAP_AttributeList TAP_ObjectCapabilityAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about mechanisms??
 */
typedef TAP_AttributeList TAP_MechanismAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information needed for signing.
 */
typedef TAP_AttributeList TAP_SignAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information needed for sealing.
 */
typedef TAP_AttributeList TAP_SealAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about policy storage.
 */
typedef TAP_AttributeList TAP_PolicyStorageAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about keys.
 */
typedef TAP_AttributeList TAP_KeyAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about an operation
 */
 typedef TAP_AttributeList TAP_OperationAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information needed for a test request.
 */
typedef TAP_AttributeList TAP_TestRequestAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about a test response.
 */
typedef TAP_AttributeList TAP_TestResponseAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Attribute list containing information about a CSR.
 */
typedef TAP_AttributeList TAP_CSRAttributes;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing list of commands supported by a provider
 */
typedef struct
{
    /*! The number of entries in the list */
    ubyte4 listLen;
#ifdef __ENABLE_MOCANA_SMP__
    /*! The list of SMP_CC items */
    SMP_CC *pCmdList;
#endif
} TAP_CmdCodeList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing a provider with the list of commands supported by that provider
 */
typedef struct
{
    /*! The TAP_PROVIDER with which the list is associated */
    TAP_PROVIDER provider;
    /*! The list of SMP_CC items */
    TAP_CmdCodeList cmdList;
} TAP_ProviderCmdList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing list of TAP_PROVIDER elements and their supported command codes
 */
typedef struct
{
    /*! The number of entries in the list */
    ubyte4 listLen;
    /*! The list of providers and supported command codes */
    TAP_ProviderCmdList *pProviderCmdList;
} TAP_ProviderList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing the firmware or hardware version of the module.
 */
typedef struct
{
    /*! Major version number */
    ubyte4 major;
    /*! Minor version number */
    ubyte4 minor;
} TAP_Version;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Firmware version information */
typedef TAP_Version TAP_FirmwareVersion;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Hardware version information */
typedef TAP_Version TAP_HardwareVersion;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details SMP version information */
typedef TAP_Version TAP_SMPVersion;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing error information
 */
typedef struct
{
    /*! Last error code received */
    MSTATUS                tapError;
    /*! Human readable error string */
    TAP_Buffer             tapErrorString;
    /*! Provider-specific error attributes */
    TAP_ErrorAttributes    *pErrorAttributes;
} TAP_Error;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Trust Data
 */
typedef TAP_Buffer TAP_TrustData;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Auth data buffer */
typedef TAP_Buffer TAP_AuthData;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque key handle, interpreted by an SMP
 */
typedef TAP_HANDLE TAP_KeyHandle;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque module handle, interpreted by an SMP
 */
typedef TAP_HANDLE TAP_ModuleHandle;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque object handle, interpreted by an SMP
 */
typedef TAP_HANDLE TAP_ObjectHandle;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque token handle, interpreted by an SMP
 */
typedef TAP_HANDLE TAP_TokenHandle;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque operation handle, interpreted by an SMP
 */
typedef TAP_HANDLE TAP_OperationHandle;


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The module identifier
 */
typedef TAP_ID TAP_ModuleId;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque Object Id, interpreted by an SMP
 */
typedef TAP_ID TAP_ObjectId;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque token ID, interpreted by an SMP
 */
typedef TAP_ID TAP_TokenId;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque slot ID, interpreted by an SMP
 */
typedef TAP_ID TAP_SlotId;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Opaque entity ID, interpreted by an SMP
 */
typedef TAP_ID TAP_EntityId;

/* TODO: This definition needs the actual slot information sub-structure definition.
         Perhaps an attribute list? */
/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing information about the slots supported by a module
 */
typedef struct
{
    ubyte4 numSlots;
} TAP_ModuleSlotInfo;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP module slot list structure
 */
typedef struct
{
    /*! The number of entities contained in the list */
    ubyte4          numSlots;
    /*! The list of #TAP_SlotId */
    TAP_SlotId      *pSlotIdList;
} TAP_ModuleSlotList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP credential structure
 */
typedef struct
{
    /*! The type of credential provided.  This must be a value #TAP_CREDENTIAL_TYPE value. */
    TAP_CREDENTIAL_TYPE     credentialType;
    /*! The format of the authorization information.  This must be a valid #TAP_CREDENTIAL_FORMAT value. */
    TAP_CREDENTIAL_FORMAT   credentialFormat;
    /*! Used to indicate the context associated with the credential. This must be a valid #TAP_CREDENTIAL_CONTEXT value. */
    TAP_CREDENTIAL_CONTEXT  credentialContext;
    /*! The authorization data (credential) buffer */
    TAP_AuthData            credentialData;
} TAP_Credential;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP credential list structure
 */
typedef struct
{
    /*! The number of credentials contained in the list */
    ubyte4         numCredentials;
    /*! The list of #TAP_Credential structures containing the various credentials supplied */
    TAP_Credential *pCredentialList;
} TAP_CredentialList;


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP entity ID list structure
 */
typedef struct
{
    /*! The number of entities contained in the list */
    ubyte4             numEntities;
    /*! The list of #TAP_EntityId */
    TAP_EntityId      *pEntityIdList;
} TAP_EntityIdList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details TAP entity list structure
 */
typedef struct
{
    /*! The type of entity in the list */
    TAP_ENTITY_TYPE    entityType;
    /*! The #TAP_EntityIdList containing the entities */
    TAP_EntityIdList   entityIdList;
} TAP_EntityList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details List of credentials for a single entity type.
 */
typedef struct
{
    TAP_ENTITY_TYPE  parentType;
    /*! ModuleId, TokenId or ObjectId */
    TAP_EntityId     parentId;
    /*! The number of credentials contained in the list */
    TAP_ENTITY_TYPE  entityType;
    /*! ModuleId, TokenId or ObjectId */
    TAP_EntityId     entityId;
    /*! The list of #TAP_Credential structures containing the various credentials supplied */
    TAP_CredentialList credentialList;
} TAP_EntityCredential;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details List of credentials for one or more entity types.
 */
typedef struct
{
    /*! The number of TAP_EntityCredential contained in the list.  There should be one TAP_EntityCredentials for each entity. */
    ubyte4         numCredentials;
    /*! The list of #TAP_EntityCredential structures containing the various credentials supplied */
    TAP_EntityCredential *pEntityCredentials;
} TAP_EntityCredentialList;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Policy Information structure
 */
typedef struct
{
    /*! Length of pPolicyInfo */
    ubyte4 policyInfoLen;
    /*! Pointer to policy info structure */
    void  *pPolicyInfo;
} TAP_PolicyInfo;


/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details Structure containing a measurement data entry.
 */
typedef struct
{
    /*! TAP_TRUSTED_DATA_SUBTYPE value, which may be TAP_TRUSTED_DATA_SUBTYPE_NONE.
        Refer to the SMP documentation for valid values for each type and their meanings. */
    TAP_TRUSTED_DATA_SUBTYPE  subType;
    /*! Attributes associated with the subType and type (which is not included in this structure and must be passed separately. */
    TAP_AttributeList         attributes;
} TAP_TrustedDataInfo;

/***************************************************************
   Signature Structure Definitions
****************************************************************/

#pragma pack(push, 1)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature structure for a TAP RSA key.
 */
typedef struct
{
    /*! The length of the signature buffer. */
    ubyte4 signatureLen;
    /*! The signature buffer. */
    ubyte *pSignature;
} TAP_RSASignature;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature structure for a TAP MLDSA key.
 */
typedef struct
{
    /*! The length of the signature buffer. */
    ubyte4 signatureLen;
    /*! The signature buffer. */
    ubyte *pSignature;
} TAP_MLDSASignature;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature structure for a TAP ECC key.
 */
typedef struct
{
    /*! The length of the R value */
    ubyte4 rDataLen;
    /*! The R value */
    ubyte *pRData;
    /*! The length of the S value */
    ubyte4 sDataLen;
    /*! The S value */
    ubyte *pSData;
} TAP_ECCSignature;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature structure for a TAP DSA key.
 */
typedef struct
{
    /*! The length of the R value */
    ubyte4 rDataLen;
    /*! The R value */
    ubyte *pRData;
    /*! The length of the S value */
    ubyte4 sDataLen;
    /*! The S value */
    ubyte *pSData;
} TAP_DSASignature;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature structure for a TAP symmetric key, such as AES.
 */
typedef struct
{
    /*! The length of the signature buffer. */
    ubyte4 signatureLen;
    /*! The signature buffer. */
    ubyte *pSignature;
} TAP_SymSignature;

#pragma pack (pop)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The union of signature structures for all TAP asymmetric and symmetric keys.
 */
typedef union
{
    /*! If have TAP_KEY_ALGORITHM_UNDEFINED. */
    ubyte             nullSignature;
    /*! Signature, when keyAlgorithm is TAP_KEY_ALGORITHM_RSA. */
    TAP_RSASignature  rsaSignature;
    /*! Signature, when keyAlgorithm is TAP_KEY_ALGORITHM_ECC. */
    TAP_ECCSignature  eccSignature;
    /*! Signature, when keyAlgorithm is TAP_KEY_ALGORITHM_DSA. */
    TAP_DSASignature  dsaSignature;
    /*! Signature, when keyAlgorithm is TAP_KEY_ALGORITHM_AES. */
    TAP_SymSignature  aesSignature;
    /*! Signature, when keyAlgorithm is TAP_KEY_ALGORITHM_HMAC. */
    TAP_SymSignature  hmacSignature;
    /*! Signature, when keyAlgorithm is TAP_KEY_ALGORITHM_MLDSA. */
    TAP_MLDSASignature  mldsaSignature;

} TAP_Signature_Union;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature structure for all TAP asymmetric and symmetric keys.  The underlying signature structure is based on the key algorithm.
 */
typedef struct
{
    /*! Flag indicating whether or not module has returned a DER-encoded buffer. */
    byteBoolean          isDEREncoded;
    /*! The key algorithm. This must be a TAP_KEY_ALGORITHM_x value. */
    TAP_KEY_ALGORITHM    keyAlgorithm;
    /*! The algorithm-specific signature, if isDEREncoded is FALSE */
    TAP_Signature_Union  signature;
    /*! Optional field, if signature is already DER encoded by the module and isDEREncoded is TRUE */
    TAP_Buffer           derEncSignature;
} TAP_Signature;

/***************************************************************
   Key Information Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the encryption scheme.
 * @details Value to indicate the encryption scheme.  Not all types are valid for all supported security modules.
 *  <p> TAP_ENC_SCHEME must be one of the following values:
 *  - #TAP_ENC_SCHEME_NONE
 *  - #TAP_ENC_SCHEME_PKCS1_5
 *  - #TAP_ENC_SCHEME_OAEP_SHA1
 *  - #TAP_ENC_SCHEME_OAEP_SHA256
 *  - #TAP_ENC_SCHEME_OAEP_SHA384
 *  - #TAP_ENC_SCHEME_OAEP_SHA512
 *  - #TAP_ENC_SCHEME_OAEP_SHA224
 */
typedef ubyte TAP_ENC_SCHEME;
/*! TAP_ENC_SCHEME_NONE */
#define  TAP_ENC_SCHEME_NONE               ((ubyte)0)
/*! TAP_ENC_SCHEME_PKCS1_5 */
#define  TAP_ENC_SCHEME_PKCS1_5            ((ubyte)1)
/*! TAP_ENC_SCHEME_OAEP_SHA1 */
#define  TAP_ENC_SCHEME_OAEP_SHA1          ((ubyte)2)
/*! TAP_ENC_SCHEME_OAEP_SHA256 */
#define  TAP_ENC_SCHEME_OAEP_SHA256        ((ubyte)3)
/*! TAP_ENC_SCHEME_OAEP_SHA384 */
#define  TAP_ENC_SCHEME_OAEP_SHA384        ((ubyte)4)
/*! TAP_ENC_SCHEME_OAEP_SHA512 */
#define  TAP_ENC_SCHEME_OAEP_SHA512        ((ubyte)5)
/*! TAP ENC_SCHEME_OAEP_SHA224 */
#define  TAP_ENC_SCHEME_OAEP_SHA224        ((ubyte)6)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the signature scheme.
 * @details Value to indicate the signature scheme.  Not all types are valid for all supported security modules.
 *  <p> TAP_SIG_SCHEME must be one of the following values:
 *  - #TAP_SIG_SCHEME_NONE
 *  - #TAP_SIG_SCHEME_PKCS1_5
 *  - #TAP_SIG_SCHEME_PSS_SHA1
 *  - #TAP_SIG_SCHEME_PSS_SHA256
 *  - #TAP_SIG_SCHEME_PKCS1_5_SHA1
 *  - #TAP_SIG_SCHEME_PKCS1_5_SHA256
 *  - #TAP_SIG_SCHEME_PKCS1_5_DER
 *  - #TAP_SIG_SCHEME_ECDSA_SHA1
 *  - #TAP_SIG_SCHEME_ECDSA_SHA224
 *  - #TAP_SIG_SCHEME_ECDSA_SHA256
 *  - #TAP_SIG_SCHEME_ECDSA_SHA384
 *  - #TAP_SIG_SCHEME_ECDSA_SHA512
 *  - #TAP_SIG_SCHEME_PSS_SHA384
 *  - #TAP_SIG_SCHEME_PSS_SHA512
 *  - #TAP_SIG_SCHEME_PKCS1_5_SHA384
 *  - #TAP_SIG_SCHEME_PKCS1_5_SHA512
 *  - #TAP_SIG_SCHEME_PSS
 *  - #TAP_SIG_SCHEME_HMAC_SHA1
 *  - #TAP_SIG_SCHEME_HMAC_SHA224
 *  - #TAP_SIG_SCHEME_HMAC_SHA256
 *  - #TAP_SIG_SCHEME_HMAC_SHA384
 *  - #TAP_SIG_SCHEME_HMAC_SHA512
 *  - #TAP_SIG_SCHEME_PKCS1_5_SHA224
 *  - #TAP_SIG_SCHEME_PSS_SHA224
 */
typedef ubyte TAP_SIG_SCHEME;
/*! TAP_SIG_SCHEME_NONE */
#define TAP_SIG_SCHEME_NONE              ((ubyte)0)
/*! TAP_SIG_SCHEME_PKCS1_5 */
#define TAP_SIG_SCHEME_PKCS1_5           ((ubyte)1)
/*! TAP_SIG_SCHEME_PSS_SHA1 */
#define TAP_SIG_SCHEME_PSS_SHA1          ((ubyte)2)
/*! TAP_SIG_SCHEME_PSS_SHA256 */
#define TAP_SIG_SCHEME_PSS_SHA256        ((ubyte)3)
/*! TAP_SIG_SCHEME_PKCS1_5_SHA1 */
#define TAP_SIG_SCHEME_PKCS1_5_SHA1      ((ubyte)4)
/*! TAP_SIG_SCHEME_PKCS1_5_SHA256 */
#define TAP_SIG_SCHEME_PKCS1_5_SHA256    ((ubyte)5)
/*! TAP_SIG_SCHEME_PKCS1_5_DER */
#define TAP_SIG_SCHEME_PKCS1_5_DER       ((ubyte)6)
/*! TAP_SIG_SCHEME_ECDSA_SHA1 */
#define TAP_SIG_SCHEME_ECDSA_SHA1        ((ubyte)7)
/*! TAP_SIG_SCHEME_ECDSA_SHA224 */
#define TAP_SIG_SCHEME_ECDSA_SHA224      ((ubyte)8)
/*! TAP_SIG_SCHEME_ECDSA_SHA256 */
#define TAP_SIG_SCHEME_ECDSA_SHA256      ((ubyte)9)
/*! TAP_SIG_SCHEME_ECDSA_SHA384 */
#define TAP_SIG_SCHEME_ECDSA_SHA384      ((ubyte)10)
/*! TAP_SIG_SCHEME_ECDSA_SHA512 */
#define TAP_SIG_SCHEME_ECDSA_SHA512      ((ubyte)11)
/*! TAP_SIG_SCHEME_PSS_SHA384 */
#define TAP_SIG_SCHEME_PSS_SHA384        ((ubyte)12)
/*! TAP_SIG_SCHEME_PSS_SHA512 */
#define TAP_SIG_SCHEME_PSS_SHA512        ((ubyte)13)
/*! TAP_SIG_SCHEME_PKCS1_5_SHA384 */
#define TAP_SIG_SCHEME_PKCS1_5_SHA384    ((ubyte)14)
/*! TAP_SIG_SCHEME_PKCS1_5_SHA512 */
#define TAP_SIG_SCHEME_PKCS1_5_SHA512    ((ubyte)15)
/*! TAP_SIG_SCHEME_PSS */
#define TAP_SIG_SCHEME_PSS               ((ubyte)16)
/*! TAP_SIG_SCHEME_HMAC_SHA1 */
#define TAP_SIG_SCHEME_HMAC_SHA1         ((ubyte)17)
/*! TAP_SIG_SCHEME_HMAC_SHA224 */
#define TAP_SIG_SCHEME_HMAC_SHA224       ((ubyte)18)
/*! TAP_SIG_SCHEME_HMAC_SHA256 */
#define TAP_SIG_SCHEME_HMAC_SHA256       ((ubyte)19)
/*! TAP_SIG_SCHEME_HMAC_SHA384 */
#define TAP_SIG_SCHEME_HMAC_SHA384       ((ubyte)20)
/*! TAP_SIG_SCHEME_HMAC_SHA512 */
#define TAP_SIG_SCHEME_HMAC_SHA512       ((ubyte)21)
/*! TAP_SIG_SCHEME_PKCS1_5_SHA224 */
#define TAP_SIG_SCHEME_PKCS1_5_SHA224    ((ubyte)22)
/*! TAP_SIG_SCHEME_PSS_SHA224 */
#define TAP_SIG_SCHEME_PSS_SHA224        ((ubyte)23)

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the ECC curve.
 * @details Value to indicate the ECC curve.  Not all types are valid for all supported security modules.
 *  <p> TAP_ECC_CURVE must be one of the following values:
 *  - #TAP_ECC_CURVE_NONE
 *  - #TAP_ECC_CURVE_NIST_P192
 *  - #TAP_ECC_CURVE_NIST_P224
 *  - #TAP_ECC_CURVE_NIST_P256
 *  - #TAP_ECC_CURVE_NIST_P384
 *  - #TAP_ECC_CURVE_NIST_P521
 *  - #TAP_ECC_CURVE_BRAINPOOL_P256
 *  - #TAP_ECC_CURVE_BRAINPOOL_P384
 */
typedef ubyte TAP_ECC_CURVE;
/*! TAP_ECC_CURVE_NONE */
#define TAP_ECC_CURVE_NONE             ((ubyte)0)
/*! TAP_ECC_CURVE_NIST_P192 */
#define TAP_ECC_CURVE_NIST_P192        ((ubyte)1)
/*! TAP_ECC_CURVE_NIST_P224 */
#define TAP_ECC_CURVE_NIST_P224        ((ubyte)2)
/*! TAP_ECC_CURVE_NIST_P256 */
#define TAP_ECC_CURVE_NIST_P256        ((ubyte)3)
/*! TAP_ECC_CURVE_NIST_P384 */
#define TAP_ECC_CURVE_NIST_P384        ((ubyte)4)
/*! TAP_ECC_CURVE_NIST_P521 */
#define TAP_ECC_CURVE_NIST_P521        ((ubyte)5)
/*! TAP_ECC_CURVE_BRAINPOOL_P256 */
#define TAP_ECC_CURVE_BRAINPOOL_P256   ((ubyte)6)
/*! TAP_ECC_CURVE_BRAINPOOL_P384 */
#define TAP_ECC_CURVE_BRAINPOOL_P384   ((ubyte)7)

/***************************************************************
   Signature Information Definitions
****************************************************************/

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @brief Value to indicate the MGF.
 * @details Value to indicate the MGF.  Not all types are valid for all supported security modules.
 */
typedef ubyte TAP_MGF;
/*! TAP_MGF1 */
#define TAP_MGF1                ((ubyte)1)

typedef struct
{
    /*! MGF1 hash algorithm. */
    TAP_HASH_ALG hashAlgo;
} TAP_MGF1_mgfInfo;

typedef union
{
    /*! MGF1 parameters */
    TAP_MGF1_mgfInfo mgf1;
} TAP_mgfInfo_Union;

typedef struct
{
    /*! MGF scheme */
    TAP_MGF                 mgfScheme;
    /*! MGF algorithm information. */
    TAP_mgfInfo_Union       mgfInfo;
} TAP_mgfInfo;

typedef struct
{
    /*! RSA-PSS message hash. */
    TAP_HASH_ALG hashAlgo;
    /*! RSA-PSS salt length in bytes. */
    ubyte4 saltLen;
    /*! RSA-PSS MGF. */
    TAP_mgfInfo mgf;
} TAP_RSA_PSS_SignatureInfo;

typedef union
{
    /*! RSA-PSS parameters. */
    TAP_RSA_PSS_SignatureInfo rsaPss;
} TAP_SignatureInfo_Union;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The signature information structure for TAP asymmetric keys. This
 *          structure provides signature algorithm specific information.
 */
typedef struct
{
    /*! Signature scheme */
    TAP_SIG_SCHEME              sigScheme;
    /*! Signature algorithm information. */
    TAP_SignatureInfo_Union     sigInfo;
} TAP_SignatureInfo;

/***************************************************************
   Public Key Structure Definitions
****************************************************************/

/*! @cond */
#pragma pack(push, 1)
/*! @endcond */

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The public key structure for a TAP RSA key.
 */
typedef struct
{
  /*! The length of the RSA key modulus */
  ubyte4  modulusLen;
  /*! The RSA key modulus */
  ubyte   *pModulus;
  /*! The length of the RSA key exponent */
  ubyte4  exponentLen;
  /*! The RSA key exponent */
  ubyte   *pExponent;
  /*! The RSA key encryption scheme.  Must be a valid #TAP_ENC_SCHEME value. */
  TAP_ENC_SCHEME  encScheme;
  /*! The RSA key signature scheme.  Must be a valid #TAP_SIG_SCHEME value. */
  TAP_SIG_SCHEME  sigScheme;
} TAP_RSAPublicKey;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The public key structure for a TAP ECC key.
 */
typedef struct
{
  /*! The ECC curve */
  ubyte4  curveId;
  /*! The length of the ECC key pubX */
  ubyte4  pubXLen;
  /*! The ECC key pubX */
  ubyte   *pPubX;
  /*! The length of the ECC pubY */
  ubyte4  pubYLen;
  /*! The ECC key pubY */
  ubyte   *pPubY;
  /*! The ECC key encryption scheme.  Must be a valid #TAP_ENC_SCHEME value. */
  TAP_ENC_SCHEME  encScheme;
  /*! The ECC key signature scheme.  Must be a valid #TAP_SIG_SCHEME value. */
  TAP_SIG_SCHEME  sigScheme;
} TAP_ECCPublicKey;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The public key structure for a TAP DSA key.
 */
typedef struct
{
  /*! The length of the DSA key prime */
  ubyte4  primeLen;
  /*! The DSA key prime */
  ubyte   *pPrime;
  /*! The length of the DSA key subprime */
  ubyte4  subprimeLen;
  /*! The DSA key subprime */
  ubyte   *pSubprime;
  /*! The length of the DSA key base */
  ubyte4  baseLen;
  /*! The DSA key base */
  ubyte   *pBase;
  /*! The length of the DSA public value */
  ubyte4  pubValLen;
  /*! The DSA public value */
  ubyte   *pPubVal;
} TAP_DSAPublicKey;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The public key structure for a TAP MLDSA key.
 */
typedef struct
{
  /*! The length of the MLDSA publicKey*/
  ubyte4  publicKeyLen;
  /*! The MLDSA Public key */
  ubyte   *pPublicKey;
  /*! MLDSA cid value */
  ubyte4 qsAlg;
  /*! The MLDSA key signature scheme.  Must be a valid #TAP_SIG_SCHEME value. */
  TAP_SIG_SCHEME  sigScheme;
} TAP_MLDSAPublicKey;

/*! @cond */
#pragma pack (pop)
/*! @endcond */

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The union of public key structures for all TAP asymmetric and symmetric keys.
 */
typedef union
{
    /*! An RSA public key, when keyAlgorithm is TAP_KEY_ALGORITHM_RSA. */
    TAP_RSAPublicKey  rsaKey;
    /*! An ECC public key, when keyAlgorithm is TAP_KEY_ALGORITHM_ECC. */
    TAP_ECCPublicKey  eccKey;
    /*! A DSA public key, when keyAlgorithm is TAP_KEY_ALGORITHM_DSA. */
    TAP_DSAPublicKey  dsaKey;
    /*! A MLDSA public key, when keyAlgorithm is TAP_KEY_ALGORITHM_MLDSA. */
    TAP_MLDSAPublicKey  mldsaKey;
    /*! Needed for compilers that do not accept an empty union */
    ubyte   nullKey;
} TAP_PublicKey_Union;

/**
 * @ingroup tap_definitions
 * @ingroup tap_smp_definitions
 * @details The public key structure for all TAP asymmetric and symmetric keys.  The underlying publicKey structure is based on the algorithm.
 */
typedef struct
{
    /*! The key algorithm. This must be a TAP_KEY_ALGORITHM_x value. */
    TAP_KEY_ALGORITHM keyAlgorithm;
    /*! The algorithm-specific public key. */
    TAP_PublicKey_Union publicKey;
} TAP_PublicKey;

typedef ubyte TAP_KEY_CMK;

#define TAP_KEY_CMK_DISABLE        (TAP_KEY_CMK)0
#define TAP_KEY_CMK_ENABLE           (TAP_KEY_CMK)1

typedef ubyte TAP_KEY_WRAP_TYPE;

#define TAP_KEY_WRAP_RSA      (TAP_KEY_WRAP_TYPE)1
#define TAP_KEY_WRAP_RSA_OAEP (TAP_KEY_WRAP_TYPE)2
#define TAP_KEY_WRAP_AES      (TAP_KEY_WRAP_TYPE)3


typedef ubyte TAP_CREATE_KEY_TYPE;

#define TAP_CREATE_KEY_TYPE_PRIMARY         (TAP_CREATE_KEY_TYPE)1
#define TAP_CREATE_KEY_TYPE_NON_PRIMARY     (TAP_CREATE_KEY_TYPE)0

#ifdef __cplusplus
}
#endif

/*! @cond */
#endif /* __ENABLE_MOCANA_TAP__ || __ENABLE_MOCANA_SMP__*/
/*! @endcond */

#endif /* __TAP_SMP_HEADER__ */
