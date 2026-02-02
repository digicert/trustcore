/**
 * @file tpm2_types.h
 * 
 * @ingroup tpm2_tree
 *
 * @brief TPM2 structures extracted from the TPM specification 2.0,
 *        Part 2 (Structures), rev 01.38; September 29, 2016.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined:
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
#ifndef __TPM2_TYPES_H__
#define __TPM2_TYPES_H__

#include "../../../common/moptions.h"

/*! @cond */

#if (defined(__ENABLE_DIGICERT_TPM2__))

/*! @endcond */

#include "../../../common/mtypes.h"

/*-------------------------------------------------------------------*/
/*  Name Prefix Convention:
    _TPM_        an indication/signal fom the TPM's system interface
    TPM_         a constant or an enumerated type
    TPM2_        a command defined by the 2.0 specification
    TPM2B_       a structure that is a sized buffer
    TPMA_        a structure where each of the fields defines an attribute
    TPM_ALG_     an enumerated type that indicates an algorithm
    TPMI_        an interface type
    TPML_        a list length followed by the indicated number of entries
    TPMS_        a structure that is not a size buffer or tagged buffer
    TPMT_        a structure with the first parameter being a structure tag
    TPMU_        a union of structures, lists or unions
    TPM_xx_      an enumerated value of a particular type
 */
/*-------------------------------------------------------------------*/

/*
 * ABI Constants
 */
/**
 * @ingroup tpm_common_definitions
 * @details This denotes the algorithms supported by the TPM 2.0.
 *     Because some algorithm values are common between TPM 1.2 TPM_ALGORITHM_ID and 2.0 TPM2_ALG_ID,
 *     they are all defined in this common file.
 *  <p> TPM2_ALG_ID is the TPM 2.0 algorithm speicifier.  It can have one of the following values:
 *  - #TPM2_ALG_ERROR
 *  - #TPM2_ALG_RSA
 *  - #TPM2_ALG_SHA
 *  - #TPM2_ALG_SHA1
 *  - #TPM2_ALG_HMAC
 *  - #TPM2_ALG_AES
 *  - #TPM2_ALG_MGF1
 *  - #TPM2_ALG_KEYEDHASH
 *  - #TPM2_ALG_XOR
 *  - #TPM2_ALG_SHA256
 *  - #TPM2_ALG_SHA384
 *  - #TPM2_ALG_SHA512
 *  - #TPM2_ALG_NULL
 *  - #TPM2_ALG_SM3_256
 *  - #TPM2_ALG_SM4
 *  - #TPM2_ALG_RSASSA
 *  - #TPM2_ALG_RSAES
 *  - #TPM2_ALG_RSAPSS
 *  - #TPM2_ALG_OAEP
 *  - #TPM2_ALG_ECDSA
 *  - #TPM2_ALG_ECDH
 *  - #TPM2_ALG_ECDAA
 *  - #TPM2_ALG_SM2
 *  - #TPM2_ALG_ECSCHNORR
 *  - #TPM2_ALG_ECMQV
 *  - #TPM2_ALG_KDF1_SP800_56A
 *  - #TPM2_ALG_KDF2
 *  - #TPM2_ALG_KDF1_SP800_108
 *  - #TPM2_ALG_ECC
 *  - #TPM2_ALG_SYMCIPHER
 *  - #TPM2_ALG_CAMELLIA
 *  - #TPM2_ALG_CTR
 *  - #TPM2_ALG_OFB
 *  - #TPM2_ALG_CBC
 *  - #TPM2_ALG_CFB
 *  - #TPM2_ALG_ECB
 *  - 0x00C1 - 0x00C6 reserved to prevent any overlap with the TPM 1.2 command structure tags
 *  - 0x8000 - 0xFFFF reserved for other structure tags
 */
typedef ubyte2 TPM2_ALG_ID;
/*! TPM2_ALG_ERROR - Should not occur. */
#define TPM2_ALG_ERROR          ((TPM2_ALG_ID)0x00000000)
/*! TPM2_ALG_RSA - the RSA algorithm. */
#define TPM2_ALG_RSA            ((TPM2_ALG_ID)0x00000001)
/*! TPM2_ALG_DES - eliminated in 1.2 rev 104; value now reserved */
#define TPM2_ALG_DES            ((TPM2_ALG_ID)0x00000002)
/*! TPM2_ALG_3DES - eliminated in 1.2 rev 104; value now reserved */
#define TPM2_ALG_3DES           ((TPM2_ALG_ID)0x00000003)
/*! TPM2_ALG_SHA - the SHA1 algorithm for TPM 1.2. */
#define TPM2_ALG_SHA            ((TPM2_ALG_ID)0x00000004)
/*! TPM2_ALG_SHA1 - the SHA1 algorithm for TPM 2.0; TPM_ALG_SHA redefined for naming consistency */
#define TPM2_ALG_SHA1           ((TPM2_ALG_ID)0x00000004)
/*! TPM2_ALG_HMAC - Hash Message Authentication Code (HMAC) algorithm - RFC 2104 */
#define TPM2_ALG_HMAC           ((TPM2_ALG_ID)0x00000005)
/*! TPM2_ALG_AES - the AES algorithm with various key sizes for TPM 2.0. */
#define TPM2_ALG_AES            ((TPM2_ALG_ID)0x00000006)
/*! TPM2_ALG_AES128 - the AES algorithm, key size 128. */
#define TPM2_ALG_AES128         (TPM_ALG_AES)
/*! TPM2_ALG_MGF1 - The XOR algorithm using MGF1 to create a string the size of the encrypted block. */
#define TPM2_ALG_MGF1           ((TPM2_ALG_ID)0x00000007)
/*! TPM2_ALG_AES192 - the AES algorithm, key size 192. */
#define TPM2_ALG_AES192         ((TPM2_ALG_ID)0x00000011)
/*! TPM2_ALG_KEYEDHASH - an encryption or signing algorithm using a keyed hash
<p> May also refer to a data object that is neither signing nor encrypting. */
#define TPM2_ALG_KEYEDHASH      ((TPM2_ALG_ID)0x00000008)
/*! TPM2_ALG_AES256 - the AES algorithm, key size 256. */
#define TPM2_ALG_AES256         ((TPM2_ALG_ID)0x00000009)
/*! TPM2_ALG_XOR - XOR using the rolling nonces */
#define TPM2_ALG_XOR            ((TPM2_ALG_ID)0x0000000a)
/*! TPM2_ALG_SHA256 - the SHA 256 algorithm */
#define TPM2_ALG_SHA256         ((TPM2_ALG_ID)0x0000000b)
/*! TPM2_ALG_SHA384 - the SHA 384 algorithm */
#define TPM2_ALG_SHA384         ((TPM2_ALG_ID)0x0000000c)
/*! TPM2_ALG_SHA512 - the SHA 512 algorithm */
#define TPM2_ALG_SHA512         ((TPM2_ALG_ID)0x0000000d)
/*! TPM2_ALG_NULL - Null algorithm */
#define TPM2_ALG_NULL           ((TPM2_ALG_ID)0x00000010)
/*! TPM2_ALG_SM3_256 - SM3 hash algorithm */
#define TPM2_ALG_SM3_256        ((TPM2_ALG_ID)0x00000012)
/*! TPM2_ALG_SM4 - SM4 symmetric block cipher */
#define TPM2_ALG_SM4            ((TPM2_ALG_ID)0x00000013)
/*! TPM2_ALG_RSASSA - a signature algorithm defined in section 8.2 (RSASSA- PKCS1-v1_5) */
#define TPM2_ALG_RSASSA         ((TPM2_ALG_ID)0x00000014)
/*! TPM2_ALG_RSAES - a padding algorithm defined in section 7.2 (RSAES-PKCS1- v1_5) */
#define TPM2_ALG_RSAES          ((TPM2_ALG_ID)0x00000015)
/*! TPM2_ALG_RSAPSS - a signature algorithm defined in section 8.1 (RSASSA-PSS) */
#define TPM2_ALG_RSAPSS         ((TPM2_ALG_ID)0x00000016)
/*! TPM2_ALG_OAEP - a padding algorithm defined in section 7.1 (RSAES_OAEP) */
#define TPM2_ALG_OAEP           ((TPM2_ALG_ID)0x00000017)
/*! TPM2_ALG_ECDSA - signature algorithm using elliptic curve cryptography (ECC) */
#define TPM2_ALG_ECDSA          ((TPM2_ALG_ID)0x00000018)
/*! TPM2_ALG_ECDH - secret sharing using ECC
  <p> Based on context, this can be either One-Pass Diffie- Hellman, C(1, 1, ECC CDH) defined in 6.2.2.2 or Full Unified Model C(2, 2, ECC CDH) defined in 6.1.1.2 */
#define TPM2_ALG_ECDH           ((TPM2_ALG_ID)0x00000019)
/*! TPM2_ALG_ECDAA - elliptic-curve based, anonymous signing scheme */
#define TPM2_ALG_ECDAA          ((TPM2_ALG_ID)0x0000001a)
/*! TPM2_ALG_SM2 - SM2 – depending on context, either an elliptic-curve based, signature algorithm or a key exchange protocol */
#define TPM2_ALG_SM2            ((TPM2_ALG_ID)0x0000001b)
/*! TPM2_ALG_ECSHNORR - elliptic-curve based Schnorr signature */
#define TPM2_ALG_ECSCHNORR      ((TPM2_ALG_ID)0x0000001c)
/*! TPM2_ALG_ECMQV - two-phase elliptic-curve key exchange – C(2, 2, ECC MQV) section 6.1.1.4 */
#define TPM2_ALG_ECMQV          ((TPM2_ALG_ID)0x0000001d)
/*! TPM2_ALG_KDF1_SP800_56A - concatenation key derivation function (approved alternative 1) section 5.8.1 */
#define TPM2_ALG_KDF1_SP800_56A ((TPM2_ALG_ID)0x00000020)
/*! TPM2_ALG_KDF2 - key derivation function KDF2 section 13.2 */
#define TPM2_ALG_KDF2           ((TPM2_ALG_ID)0x00000021)
/*! TPM2_ALG_KDF1_SP800_108 - a key derivation method; Section 5.1 KDF in Counter Mode */
#define TPM2_ALG_KDF1_SP800_108 ((TPM2_ALG_ID)0x00000022)
/*! TPM2_ALG_ECC - prime field ECC */
#define TPM2_ALG_ECC            ((TPM2_ALG_ID)0x00000023)
/*! TPM2_ALG_SYMCIPHER - the object type for a symmetric block cipher */
#define TPM2_ALG_SYMCIPHER      ((TPM2_ALG_ID)0x00000025)
/*! TPM2_ALG_CAMELLIA - Camellia is symmetric block cipher. The Camellia algorithm with various key sizes */
#define TPM2_ALG_CAMELLIA       ((TPM2_ALG_ID)0x00000026)
/*! TPM2_ALG_CTR - Counter mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode. */
#define TPM2_ALG_CTR            ((TPM2_ALG_ID)0x00000040)
/*! TPM2_ALG_OFB - Output Feedback mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode. */
#define TPM2_ALG_OFB            ((TPM2_ALG_ID)0x00000041)
/*! TPM2_ALG_CBC - Cipher Block Chaining mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode. */
#define TPM2_ALG_CBC            ((TPM2_ALG_ID)0x00000042)
/*! TPM2_ALG_CFB - Cipher Feedback mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode. */
#define TPM2_ALG_CFB            ((TPM2_ALG_ID)0x00000043)
/*! TPM2_ALG_ECB - Electronic Codebook mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
<p> NOTE: This mode is not recommended for uses unless the key is frequently rotated such as in video codecs  */
#define TPM2_ALG_ECB            ((TPM2_ALG_ID)0x00000044)

/*! Default SHA hash digest size */
#define TPM2_SHA_DIGEST_SIZE       20
/*! Size of SHA-1 digest */
#define TPM2_SHA1_DIGEST_SIZE      20
/*! Size of SHA-256 digest */
#define TPM2_SHA256_DIGEST_SIZE    32
/*! Size of SHA-384 digest */
#define TPM2_SHA384_DIGEST_SIZE    48
/*! Size of SHA-512 digest */
#define TPM2_SHA512_DIGEST_SIZE    64
/*! Size of SM3-256 digest */
#define TPM2_SM3_256_DIGEST_SIZE   32
/*! Number of PCR banks */
#define TPM2_NUM_PCR_BANKS          8
/*! Maximum size needed for digest buffer */
#define TPM2_MAX_DIGEST_BUFFER   1024
/*! Maximum size needed for NV buffer */
#define TPM2_MAX_NV_BUFFER_SIZE  2048
/*! Maximum number of PCRs supported by TPM 2.0 chip */
#define TPM2_MAX_PCRS              32
/*! Maximum number of supported algorithms */
#define TPM2_MAX_ALG_LIST_SIZE    128
#define TPM2_MAX_CAP_CC           256
#define TPM2_MAX_CAP_BUFFER      1024
#define TPM2_MAX_CONTEXT_SIZE    3072
#define TPM2_MAX_SYM_BLOCK_SIZE    16
#define TPM2_MAX_SYM_DATA         256
#define TPM2_MAX_ECC_KEY_BYTES    128
#define TPM2_MAX_SYM_KEY_BYTES     32
#define TPM2_MAX_RSA_KEY_BYTES    512
#define TPM2_LABEL_MAX_BUFFER      32
#define TPM2_PCR_SELECT_MAX       ((TPM2_MAX_PCRS+7)/8)
#define TPM2_MAX_CAP_HANDLES      ((TPM2_MAX_CAP_BUFFER - sizeof(TPM2_CAP) - sizeof(ubyte4))/sizeof(TPM2_HANDLE))
#define TPM2_MAX_CAP_ALGS         ((TPM2_MAX_CAP_BUFFER - sizeof(TPM2_CAP) - sizeof(ubyte4))/sizeof(TPMS_ALG_PROPERTY))
#define TPM2_MAX_TPM_PROPERTIES   ((TPM2_MAX_CAP_BUFFER - sizeof(TPM2_CAP) - sizeof(ubyte4))/sizeof(TPMS_TAGGED_PROPERTY))
#define TPM2_MAX_PCR_PROPERTIES   ((TPM2_MAX_CAP_BUFFER - sizeof(TPM2_CAP) - sizeof(ubyte4))/sizeof(TPMS_TAGGED_PCR_SELECT))
#define TPM2_MAX_ECC_CURVES       ((TPM2_MAX_CAP_BUFFER - sizeof(TPM2_CAP) - sizeof(ubyte4))/sizeof(TPM2_ECC_CURVE))
#define TPM2_MAX_TAGGED_POLICIES  ((TPM2_MAX_CAP_BUFFER - sizeof(TPM2_CAP) - sizeof(ubyte4))/sizeof(TPMS_TAGGED_POLICY))
#define TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES  ((TPM2_MAX_RSA_KEY_BYTES/2) * (3 + 2))


/*-------------------------------------------------------------------*/
/* Part 2, section 5.1: Base types
   and
   Part 2, section 5.2: Logic Value Constants
   defined in tpm_common/tpm_common.h
 */

/*-------------------------------------------------------------------*/
/* Part 2, section 5.3: Miscellaneous Types */
/*   Many of the helper redefinitions appear later in this file
     so that they are declared next to the list of valid values
     they may hold.
*/

/**
 * @ingroup tpm2_definitions
 * @brief Indicates the type of algorithm
 * @details Indicates the type of algorithm
 */
typedef ubyte4  TPM2_ALGORITHM_ID;
/**
 * @ingroup tpm2_definitions
 * @brief  The locality modifier
 * @details  The locality modifier
 */
typedef ubyte4  TPM2_MODIFIER_INDICATOR;
/**
 * @ingroup tpm2_definitions
 * @brief Indicates the authorization size
 * @details Indicates the authorization size
 */
typedef ubyte4  TPM2_AUTHORIZATION_SIZE;
/**
 * @ingroup tpm2_definitions
 * @brief Indicates the parameter size
 * @details Indicates the parameter size
 */
typedef ubyte4  TPM2_PARAMETER_SIZE;
/**
 * @ingroup tpm2_definitions
 * @brief Indicates the key size
 * @details Indicates the key size
 */
typedef ubyte2  TPM2_KEY_SIZE;
/**
 * @ingroup tpm2_definitions
 * @brief Indicates the number of bits in a key
 * @details Indicates the number of bits in a key
 */
typedef ubyte2  TPM2_KEY_BITS;


/*-------------------------------------------------------------------*/
/* Part 2, section 6.1: Specification Version Values                 */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Specification version values
 * @details These specification version values are readable with TPM2_GetCapability.
 *  <p>If the TPM implements errata, the year and day of year indicate the release date of the errata document.
 *  <p> A TPM2_GetCapability request for TPM2_SPEC returns one of the following values:
 *  - #TPM2_SPEC_FAMILY
 *  - #TPM2_SPEC_LEVEL
 *  - #TPM2_SPEC_VERSION
 *  - #TPM2_SPEC_YEAR
 *  - #TPM2_SPEC_DAY_OF_YEAR
 */
typedef ubyte2  TPM2_SPEC;
/*! TPM2_SPEC_FAMILY -  ASCII "2.0" with null terminator */
#define TPM2_SPEC_FAMILY       0x322E3000
/*! TPM2_SPEC_LEVEL */
#define TPM2_SPEC_LEVEL        00
/*! TPM2_SPEC_VERSION - version 1.38 */
#define TPM2_SPEC_VERSION      138
/*! TPM2_SPEC_YEAR */
#define TPM2_SPEC_YEAR         2016
/*! TPM2_SPEC_DAY_OF_YEAR  - 273 = September 29, 2016 */
#define TPM2_SPEC_DAY_OF_YEAR  273

/*-------------------------------------------------------------------*/
/* Part 2, section 6.2: TPM Generated constants                      */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Differentiates TPM-generated structures from non-TPM structures
 * @details Constant value that differentiates TPM-generated structures from non-TPM structures
 * <p> Value of TPM2_GENERATED is defined by #TPM2_GENERATED_VALUE.
 */
typedef ubyte4  TPM2_GENERATED;
/*! TPM2_GENERATED_VALUE - FF"TCG" */
#define TPM2_GENERATED_VALUE   0xFF544347

/*-------------------------------------------------------------------*/
/* Part 2, section 6.3: TPM2_ALG_ID                                  */
/*-------------------------------------------------------------------*/

/* see tpm_common/tpm_common.h for TPM2_ALG_* definitions for both 1.2 and 2.0 */

/*-------------------------------------------------------------------*/
/* Part 2, section 6.4: TPM2_ECC_CURVE                               */
/*-------------------------------------------------------------------*/
/**
 * @ingroup tpm2_definitions
 * @brief List of registered ECC curves that may be supported by a TPM
 * @details List of registered ECC curves that may be supported by a TPM 
 * <p> Value can be one of the following:
 *      -  #TPM2_ECC_NONE
 *      -  #TPM2_ECC_NIST_P192
 *      -  #TPM2_ECC_NIST_P224
 *      -  #TPM2_ECC_NIST_P256
 *      -  #TPM2_ECC_NIST_P384
 *      -  #TPM2_ECC_NIST_P521
 *      -  #TPM2_ECC_BN_P256
 *      -  #TPM2_ECC_BN_P638
 *      -  #TPM2_ECC_SM2_P256
 */
typedef ubyte2 TPM2_ECC_CURVE;
/*! TPM2_ECC_NONE */
#define TPM2_ECC_NONE       ((TPM2_ECC_CURVE) 0x0000)
/*! TPM2_ECC_NIST_P192 */
#define TPM2_ECC_NIST_P192  ((TPM2_ECC_CURVE) 0x0001)
/*! TPM2_ECC_NIST_P224 */
#define TPM2_ECC_NIST_P224  ((TPM2_ECC_CURVE) 0x0002)
/*! TPM2_ECC_NIST_P256 */
#define TPM2_ECC_NIST_P256  ((TPM2_ECC_CURVE) 0x0003)
/*! TPM2_ECC_NIST_P384 */
#define TPM2_ECC_NIST_P384  ((TPM2_ECC_CURVE) 0x0004)
/*! TPM2_ECC_NIST_P521 */
#define TPM2_ECC_NIST_P521  ((TPM2_ECC_CURVE) 0x0005)
/*! TPM2_ECC_BN_P256 - for ECDAA support */
#define TPM2_ECC_BN_P256    ((TPM2_ECC_CURVE) 0x0010)
/*! TPM2_ECC_BN_P638 - for ECDAA support */
#define TPM2_ECC_BN_P638    ((TPM2_ECC_CURVE) 0x0011)
/*! TPM2_ECC_SM2_P256 */
#define TPM2_ECC_SM2_P256   ((TPM2_ECC_CURVE) 0x0020)

/*-------------------------------------------------------------------*/
/* Part 2, section 6.5: TPM2_CC (Command Codes) */
/* Format:
           3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
           1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
   31:30   0 0 
   29:         V  - Vendor specific bit - SET [1] = vendor specific command
   28:16         0 0 0 0 0 0 0 0 0 0 0 0 0
   15:0                                   | command index (TPM2_CC_*)      |
 */
/**
 * @ingroup tpm2_definitions
 * @brief List of TPM 2.0 command codes
 * @details List of TPM 2.0 command codes
 * <p> Value can be one of the following:
 *       - #TPM2_CC_FIRST
 *       - #TPM2_CC_NV_UndefineSpaceSpecial
 *       - #TPM2_CC_EvictControl
 *       - #TPM2_CC_HierarchyControl
 *       - #TPM2_CC_NV_UndefineSpace
 *       - #TPM2_CC_ChangeEPS
 *       - #TPM2_CC_ChangePPS
 *       - #TPM2_CC_Clear
 *       - #TPM2_CC_ClearControl
 *       - #TPM2_CC_ClockSet
 *       - #TPM2_CC_HierarchyChangeAuth
 *       - #TPM2_CC_NV_DefineSpace
 *       - #TPM2_CC_PCR_Allocate
 *       - #TPM2_CC_PCR_SetAuthPolicy
 *       - #TPM2_CC_PP_Commands
 *       - #TPM2_CC_SetPrimaryPolicy
 *       - #TPM2_CC_FieldUpgradeStart
 *       - #TPM2_CC_ClockRateAdjust
 *       - #TPM2_CC_CreatePrimary
 *       - #TPM2_CC_NV_GlobalWriteLock
 *       - #TPM2_CC_GetCommandAuditDigest
 *       - #TPM2_CC_NV_Increment
 *       - #TPM2_CC_NV_SetBits
 *       - #TPM2_CC_NV_Extend
 *       - #TPM2_CC_NV_Write
 *       - #TPM2_CC_NV_WriteLock
 *       - #TPM2_CC_DictionaryAttackLockReset
 *       - #TPM2_CC_DictionaryAttackParameters
 *       - #TPM2_CC_NV_ChangeAuth
 *       - #TPM2_CC_PCR_Event
 *       - #TPM2_CC_PCR_Reset
 *       - #TPM2_CC_SequenceComplete
 *       - #TPM2_CC_SetAlgorithmSet
 *       - #TPM2_CC_SetCommandCodeAuditStatus
 *       - #TPM2_CC_FieldUpgradeData
 *       - #TPM2_CC_IncrementalSelfTest
 *       - #TPM2_CC_SelfTest
 *       - #TPM2_CC_Startup
 *       - #TPM2_CC_Shutdown
 *       - #TPM2_CC_StirRandom
 *       - #TPM2_CC_ActivateCredential
 *       - #TPM2_CC_Certify
 *       - #TPM2_CC_PolicyNV
 *       - #TPM2_CC_CertifyCreation
 *       - #TPM2_CC_Duplicate
 *       - #TPM2_CC_GetTime
 *       - #TPM2_CC_GetSessionAuditDigest
 *       - #TPM2_CC_NV_Read
 *       - #TPM2_CC_NV_ReadLock
 *       - #TPM2_CC_ObjectChangeAuth
 *       - #TPM2_CC_PolicySecret
 *       - #TPM2_CC_Rewrap
 *       - #TPM2_CC_Create
 *       - #TPM2_CC_ECDH_ZGen
 *       - #TPM2_CC_HMAC
 *       - #TPM2_CC_Import
 *       - #TPM2_CC_Load
 *       - #TPM2_CC_Quote
 *       - #TPM2_CC_RSA_Decrypt
 *       - #TPM2_CC_HMAC_Start
 *       - #TPM2_CC_SequenceUpdate
 *       - #TPM2_CC_Sign
 *       - #TPM2_CC_Unseal
 *       - #TPM2_CC_PolicySigned
 *       - #TPM2_CC_ContextLoad
 *       - #TPM2_CC_ContextSave
 *       - #TPM2_CC_ECDH_KeyGen
 *       - #TPM2_CC_EncryptDecrypt
 *       - #TPM2_CC_FlushContext
 *       - #TPM2_CC_LoadExternal
 *       - #TPM2_CC_MakeCredential
 *       - #TPM2_CC_NV_ReadPublic
 *       - #TPM2_CC_PolicyAuthorize
 *       - #TPM2_CC_PolicyAuthValue
 *       - #TPM2_CC_PolicyCommandCode
 *       - #TPM2_CC_PolicyCounterTimer
 *       - #TPM2_CC_PolicyCpHash
 *       - #TPM2_CC_PolicyLocality
 *       - #TPM2_CC_PolicyNameHash
 *       - #TPM2_CC_PolicyOR
 *       - #TPM2_CC_PolicyTicket
 *       - #TPM2_CC_ReadPublic
 *       - #TPM2_CC_RSA_Encrypt
 *       - #TPM2_CC_StartAuthSession
 *       - #TPM2_CC_VerifySignature
 *       - #TPM2_CC_ECC_Parameters
 *       - #TPM2_CC_FirmwareRead
 *       - #TPM2_CC_GetCapability
 *       - #TPM2_CC_GetRandom
 *       - #TPM2_CC_GetTestResult
 *       - #TPM2_CC_Hash
 *       - #TPM2_CC_PCR_Read
 *       - #TPM2_CC_PolicyPCR
 *       - #TPM2_CC_PolicyRestart
 *       - #TPM2_CC_ReadClock
 *       - #TPM2_CC_PCR_Extend
 *       - #TPM2_CC_PCR_SetAuthValue
 *       - #TPM2_CC_NV_Certify
 *       - #TPM2_CC_EventSequenceComplete
 *       - #TPM2_CC_HashSequenceStart
 *       - #TPM2_CC_PolicyPhsicalPresence
 *       - #TPM2_CC_PolicyDuplicationSelect
 *       - #TPM2_CC_PolicyGetDigest
 *       - #TPM2_CC_TestParms
 *       - #TPM2_CC_Commit
 *       - #TPM2_CC_PolicyPassword
 *       - #TPM2_CC_ZGen_2Phase
 *       - #TPM2_CC_EC_Ephemeral
 *       - #TPM2_CC_PolicyNvWritten
 *       - #TPM2_CC_PolicyTemplate
 *       - #TPM2_CC_CreateLoaded
 *       - #TPM2_CC_PolicyAuthorizeNV
 *       - #TPM2_CC_EncryptDecrypt2
 *       - #TPM2_CC_LAST
 *       - #TPM2_CC_VEND
 *       - #TPM2_CC_Vendor_TCG_Test
 */
typedef ubyte4 TPM2_CC;
/*! TPM2_CC_FIRST - Used to indicate first valid command code */
#define TPM2_CC_FIRST                       ((TPM2_CC) 0x0000011F)
/*! TPM2_CC_NV_UndefineSpaceSpecial*/
#define TPM2_CC_NV_UndefineSpaceSpecial     ((TPM2_CC) 0x0000011F)
/*! TPM2_CC_EvictControl */
#define TPM2_CC_EvictControl                ((TPM2_CC) 0x00000120)
/*! TPM2_CC_HierarchyControl */
#define TPM2_CC_HierarchyControl            ((TPM2_CC) 0x00000121)
/*! TPM2_CC_NV_UndefineSpace */
#define TPM2_CC_NV_UndefineSpace            ((TPM2_CC) 0x00000122)
/*! TPM2_CC_ChangeEPS */
#define TPM2_CC_ChangeEPS                   ((TPM2_CC) 0x00000124)
/*! TPM2_CC_ChangePPS */
#define TPM2_CC_ChangePPS                   ((TPM2_CC) 0x00000125)
/*! TPM2_CC_Clear */
#define TPM2_CC_Clear                       ((TPM2_CC) 0x00000126)
/*! TPM2_CC_ClearControl */
#define TPM2_CC_ClearControl                ((TPM2_CC) 0x00000127)
/*! TPM2_CC_ClockSet */
#define TPM2_CC_ClockSet                    ((TPM2_CC) 0x00000128)
/*! TPM2_CC_HierarchyChangeAuth */
#define TPM2_CC_HierarchyChangeAuth         ((TPM2_CC) 0x00000129)
/*! TPM2_CC_NV_DefineSpace */
#define TPM2_CC_NV_DefineSpace              ((TPM2_CC) 0x0000012A)
/*! TPM2_CC_PCR_Allocate */
#define TPM2_CC_PCR_Allocate                ((TPM2_CC) 0x0000012B)
/*! TPM2_CC_PCR_SetAuthPolicy */
#define TPM2_CC_PCR_SetAuthPolicy           ((TPM2_CC) 0x0000012C)
/*! TPM2_CC_PP_Commands */
#define TPM2_CC_PP_Commands                 ((TPM2_CC) 0x0000012D)
/*! TPM2_CC_SetPrimaryPolicy */
#define TPM2_CC_SetPrimaryPolicy            ((TPM2_CC) 0x0000012E)
/*! TPM2_CC_FieldUpgradeStart */
#define TPM2_CC_FieldUpgradeStart           ((TPM2_CC) 0x0000012F)
/*! TPM2_CC_ClockRateAdjust */
#define TPM2_CC_ClockRateAdjust             ((TPM2_CC) 0x00000130)
/*! TPM2_CC_CreatePrimary */
#define TPM2_CC_CreatePrimary               ((TPM2_CC) 0x00000131)
/*! TPM2_CC_NV_GlobalWriteLock */
#define TPM2_CC_NV_GlobalWriteLock          ((TPM2_CC) 0x00000132)
/*! TPM2_CC_GetCommandAuditDigest */
#define TPM2_CC_GetCommandAuditDigest       ((TPM2_CC) 0x00000133)
/*! TPM2_CC_NV_Increment */
#define TPM2_CC_NV_Increment                ((TPM2_CC) 0x00000134)
/*! TPM2_CC_NV_SetBits */
#define TPM2_CC_NV_SetBits                  ((TPM2_CC) 0x00000135)
/*! TPM2_CC_NV_Extend */
#define TPM2_CC_NV_Extend                   ((TPM2_CC) 0x00000136)
/*! TPM2_CC_NV_Write */
#define TPM2_CC_NV_Write                    ((TPM2_CC) 0x00000137)
/*! TPM2_CC_NV_WriteLock */
#define TPM2_CC_NV_WriteLock                ((TPM2_CC) 0x00000138)
/*! TPM2_CC_DictionaryAttackLockReset */
#define TPM2_CC_DictionaryAttackLockReset   ((TPM2_CC) 0x00000139)
/*! TPM2_CC_DictionaryAttackParameters */
#define TPM2_CC_DictionaryAttackParameters  ((TPM2_CC) 0x0000013A)
/*! TPM2_CC_NV_ChangeAuth */
#define TPM2_CC_NV_ChangeAuth               ((TPM2_CC) 0x0000013B)
/*! TPM2_CC_PCR_Event */
#define TPM2_CC_PCR_Event                   ((TPM2_CC) 0x0000013C)
/*! TPM2_CC_PCR_Reset */
#define TPM2_CC_PCR_Reset                   ((TPM2_CC) 0x0000013D)
/*! TPM2_CC_SequenceComplete */
#define TPM2_CC_SequenceComplete            ((TPM2_CC) 0x0000013E)
/*! TPM2_CC_SetAlgorithmSet */
#define TPM2_CC_SetAlgorithmSet             ((TPM2_CC) 0x0000013F)
/*! TPM2_CC_SetCommandCodeAuditStatus */
#define TPM2_CC_SetCommandCodeAuditStatus   ((TPM2_CC) 0x00000140)
/*! TPM2_CC_FieldUpgradeData */
#define TPM2_CC_FieldUpgradeData            ((TPM2_CC) 0x00000141)
/*! TPM2_CC_IncrementalSelfTest */
#define TPM2_CC_IncrementalSelfTest         ((TPM2_CC) 0x00000142)
/*! TPM2_CC_SelfTest */
#define TPM2_CC_SelfTest                    ((TPM2_CC) 0x00000143)
/*! TPM2_CC_Startup */
#define TPM2_CC_Startup                     ((TPM2_CC) 0x00000144)
/*! TPM2_CC_Shutdown */
#define TPM2_CC_Shutdown                    ((TPM2_CC) 0x00000145)
/*! TPM2_CC_StirRandom */
#define TPM2_CC_StirRandom                  ((TPM2_CC) 0x00000146)
/*! TPM2_CC_ActivateCredential */
#define TPM2_CC_ActivateCredential          ((TPM2_CC) 0x00000147)
/*! TPM2_CC_Certify */
#define TPM2_CC_Certify                     ((TPM2_CC) 0x00000148)
/*! TPM2_CC_PolicyNV */
#define TPM2_CC_PolicyNV                    ((TPM2_CC) 0x00000149)
/*! TPM2_CC_CertifyCreation */
#define TPM2_CC_CertifyCreation             ((TPM2_CC) 0x0000014A)
/*! TPM2_CC_Duplicate */
#define TPM2_CC_Duplicate                   ((TPM2_CC) 0x0000014B)
/*! TPM2_CC_GetTime */
#define TPM2_CC_GetTime                     ((TPM2_CC) 0x0000014C)
/*! TPM2_CC_GetSessionAuditDigest */
#define TPM2_CC_GetSessionAuditDigest       ((TPM2_CC) 0x0000014D)
/*! TPM2_CC_NV_Read */
#define TPM2_CC_NV_Read                     ((TPM2_CC) 0x0000014E)
/*! TPM2_CC_NV_ReadLock */
#define TPM2_CC_NV_ReadLock                 ((TPM2_CC) 0x0000014F)
/*! TPM2_CC_ObjectChangeAuth */
#define TPM2_CC_ObjectChangeAuth            ((TPM2_CC) 0x00000150)
/*! TPM2_CC_PolicySecret */
#define TPM2_CC_PolicySecret                ((TPM2_CC) 0x00000151)
/*! TPM2_CC_Rewrap */
#define TPM2_CC_Rewrap                      ((TPM2_CC) 0x00000152)
/*! TPM2_CC_Create */
#define TPM2_CC_Create                      ((TPM2_CC) 0x00000153)
/*! TPM2_CC_ECDH_ZGen */
#define TPM2_CC_ECDH_ZGen                   ((TPM2_CC) 0x00000154)
/*! TPM2_CC_HMAC */
#define TPM2_CC_HMAC                        ((TPM2_CC) 0x00000155)
/*! TPM2_CC_Import */
#define TPM2_CC_Import                      ((TPM2_CC) 0x00000156)
/*! TPM2_CC_Load */
#define TPM2_CC_Load                        ((TPM2_CC) 0x00000157)
/*! TPM2_CC_Quote */
#define TPM2_CC_Quote                       ((TPM2_CC) 0x00000158)
/*! TPM2_CC_RSA_Decrypt */
#define TPM2_CC_RSA_Decrypt                 ((TPM2_CC) 0x00000159)
/*! TPM2_CC_HMAC_Start */
#define TPM2_CC_HMAC_Start                  ((TPM2_CC) 0x0000015B)
/*! TPM2_CC_SequenceUpdate */
#define TPM2_CC_SequenceUpdate              ((TPM2_CC) 0x0000015C)
/*! TPM2_CC_Sign */
#define TPM2_CC_Sign                        ((TPM2_CC) 0x0000015D)
/*! TPM2_CC_Unseal */
#define TPM2_CC_Unseal                      ((TPM2_CC) 0x0000015E)
/*! TPM2_CC_PolicySigned */
#define TPM2_CC_PolicySigned                ((TPM2_CC) 0x00000160)
/*! TPM2_CC_ContextLoad */
#define TPM2_CC_ContextLoad                 ((TPM2_CC) 0x00000161)
/*! TPM2_CC_ContextSave */
#define TPM2_CC_ContextSave                 ((TPM2_CC) 0x00000162)
/*! TPM2_CC_ECDH_KeyGen */
#define TPM2_CC_ECDH_KeyGen                 ((TPM2_CC) 0x00000163)
/*! TPM2_CC_EncryptDecrypt */
#define TPM2_CC_EncryptDecrypt              ((TPM2_CC) 0x00000164)
/*! TPM2_CC_FlushContext */
#define TPM2_CC_FlushContext                ((TPM2_CC) 0x00000165)
/*! TPM2_CC_LoadExternal */
#define TPM2_CC_LoadExternal                ((TPM2_CC) 0x00000167)
/*! TPM2_CC_MakeCredential */
#define TPM2_CC_MakeCredential              ((TPM2_CC) 0x00000168)
/*! TPM2_CC_NV_ReadPublic */
#define TPM2_CC_NV_ReadPublic               ((TPM2_CC) 0x00000169)
/*! TPM2_CC_PolicyAuthorize */
#define TPM2_CC_PolicyAuthorize             ((TPM2_CC) 0x0000016A)
/*! TPM2_CC_PolicyAuthValue */
#define TPM2_CC_PolicyAuthValue             ((TPM2_CC) 0x0000016B)
/*! TPM2_CC_PolicyCommandCode */
#define TPM2_CC_PolicyCommandCode           ((TPM2_CC) 0x0000016C)
/*! TPM2_CC_PolicyCounterTimer */
#define TPM2_CC_PolicyCounterTimer          ((TPM2_CC) 0x0000016D)
/*! TPM2_CC_PolicyCpHash */
#define TPM2_CC_PolicyCpHash                ((TPM2_CC) 0x0000016E)
/*! TPM2_CC_PolicyLocality */
#define TPM2_CC_PolicyLocality              ((TPM2_CC) 0x0000016F)
/*! TPM2_CC_PolicyNameHash */
#define TPM2_CC_PolicyNameHash              ((TPM2_CC) 0x00000170)
/*! TPM2_CC_PolicyOR */
#define TPM2_CC_PolicyOR                    ((TPM2_CC) 0x00000171)
/*! TPM2_CC_PolicyTicket */
#define TPM2_CC_PolicyTicket                ((TPM2_CC) 0x00000172)
/*! TPM2_CC_ReadPublic */
#define TPM2_CC_ReadPublic                  ((TPM2_CC) 0x00000173)
/*! TPM2_CC_RSA_Encrypt */
#define TPM2_CC_RSA_Encrypt                 ((TPM2_CC) 0x00000174)
/*! TPM2_CC_StartAuthSession */
#define TPM2_CC_StartAuthSession            ((TPM2_CC) 0x00000176)
/*! TPM2_CC_VerifySignature */
#define TPM2_CC_VerifySignature             ((TPM2_CC) 0x00000177)
/*! TPM2_CC_ECC_Parameters */
#define TPM2_CC_ECC_Parameters              ((TPM2_CC) 0x00000178)
/*! TPM2_CC_FirmwareRead */
#define TPM2_CC_FirmwareRead                ((TPM2_CC) 0x00000179)
/*! TPM2_CC_GetCapability */
#define TPM2_CC_GetCapability               ((TPM2_CC) 0x0000017A)
/*! TPM2_CC_GetRandom */
#define TPM2_CC_GetRandom                   ((TPM2_CC) 0x0000017B)
/*! TPM2_CC_GetTestResult */
#define TPM2_CC_GetTestResult               ((TPM2_CC) 0x0000017C)
/*! TPM2_CC_Hash */
#define TPM2_CC_Hash                        ((TPM2_CC) 0x0000017D)
/*! TPM2_CC_PCR_Read */
#define TPM2_CC_PCR_Read                    ((TPM2_CC) 0x0000017E)
/*! TPM2_CC_PolicyPCR */
#define TPM2_CC_PolicyPCR                   ((TPM2_CC) 0x0000017F)
/*! TPM2_CC_PolicyRestart */
#define TPM2_CC_PolicyRestart               ((TPM2_CC) 0x00000180)
/*! TPM2_CC_ReadClock */
#define TPM2_CC_ReadClock                   ((TPM2_CC) 0x00000181)
/*! TPM2_CC_PCR_Extend */
#define TPM2_CC_PCR_Extend                  ((TPM2_CC) 0x00000182)
/*! TPM2_CC_PCR_SetAuthValue */
#define TPM2_CC_PCR_SetAuthValue            ((TPM2_CC) 0x00000183)
/*! TPM2_CC_NV_Certify */
#define TPM2_CC_NV_Certify                  ((TPM2_CC) 0x00000184)
/*! TPM2_CC_EventSequenceComplete */
#define TPM2_CC_EventSequenceComplete       ((TPM2_CC) 0x00000185)
/*! TPM2_CC_HashSequenceStart */
#define TPM2_CC_HashSequenceStart           ((TPM2_CC) 0x00000186)
/*! TPM2_CC_PolicyPhsicalPresence */
#define TPM2_CC_PolicyPhysicalPresence      ((TPM2_CC) 0x00000187)
/*! TPM2_CC_PolicyDuplicationSelect */
#define TPM2_CC_PolicyDuplicationSelect     ((TPM2_CC) 0x00000188)
/*! TPM2_CC_PolicyGetDigest */
#define TPM2_CC_PolicyGetDigest             ((TPM2_CC) 0x00000189)
/*! TPM2_CC_TestParms */
#define TPM2_CC_TestParms                   ((TPM2_CC) 0x0000018A)
/*! TPM2_CC_Commit */
#define TPM2_CC_Commit                      ((TPM2_CC) 0x0000018B)
/*! TPM2_CC_PolicyPassword */
#define TPM2_CC_PolicyPassword              ((TPM2_CC) 0x0000018C)
/*! TPM2_CC_ZGen_2Phase */
#define TPM2_CC_ZGen_2Phase                 ((TPM2_CC) 0x0000018D)
/*! TPM2_CC_EC_Ephemeral */
#define TPM2_CC_EC_Ephemeral                ((TPM2_CC) 0x0000018E)
/*! TPM2_CC_PolicyNvWritten */
#define TPM2_CC_PolicyNvWritten             ((TPM2_CC) 0x0000018F)
/*! TPM2_CC_PolicyTemplate */
#define TPM2_CC_PolicyTemplate              ((TPM2_CC) 0x00000190)
/*! TPM2_CC_CreateLoaded */
#define TPM2_CC_CreateLoaded                ((TPM2_CC) 0x00000191)
/*! TPM2_CC_PolicyAuthorizeNV */
#define TPM2_CC_PolicyAuthorizeNV           ((TPM2_CC) 0x00000192)
/*! TPM2_CC_EncryptDecrypt2 */
#define TPM2_CC_EncryptDecrypt2             ((TPM2_CC) 0x00000193)
/*! TPM2_CC_LAST - Used to indicate last valid command code */
#define TPM2_CC_LAST                        ((TPM2_CC) 0x00000193)
/*! TPM2_CC_VEND */
#define TPM2_CC_VEND                        ((TPM2_CC) 0x20000000)
/*! TPM2_CC_Vendor_TCG_Test - used for testing of command dispatch */
#define TPM2_CC_Vendor_TCG_Test             ((TPM2_CC) (TPM2_CC_VEND+0x0000))

/*-------------------------------------------------------------------*/
/* Part 2, section 6.6: TPM2_RC (Response Codes) - See tpm_common/tpm2_error.h */

/**
 * @ingroup tpm2_definitions
 * @brief List of TPM 2.0 response codes
 * @details List of TPM 2.0 response codes
 * <p> Value can be one of the following:
 *       - #TPM2_RC_SUCCESS
 *       - #TPM2_RC_BAD_TAG
 *       - #TPM2_RC_VER1
 *       - #TPM2_RC_INITIALIZE
 *       - #TPM2_RC_FAILURE
 *       - #TPM2_RC_SEQUENCE
 *       - #TPM2_RC_PRIVATE
 *       - #TPM2_RC_HMAC
 *       - #TPM2_RC_DISABLED
 *       - #TPM2_RC_EXCLUSIVE
 *       - #TPM2_RC_AUTH_TYPE
 *       - #TPM2_RC_AUTH_MISSING
 *       - #TPM2_RC_POLICY
 *       - #TPM2_RC_PCR
 *       - #TPM2_RC_PCR_CHANGED
 *       - #TPM2_RC_UPGRADE
 *       - #TPM2_RC_TOO_MANY_CONTEXTS
 *       - #TPM2_RC_AUTH_UNAVAILABLE
 *       - #TPM2_RC_REBOOT
 *       - #TPM2_RC_UNBALANCED
 *       - #TPM2_RC_COMMAND_SIZE
 *       - #TPM2_RC_COMMAND_CODE
 *       - #TPM2_RC_AUTHSIZE
 *       - #TPM2_RC_AUTH_CONTEXT
 *       - #TPM2_RC_NV_RANGE
 *       - #TPM2_RC_NV_SIZE
 *       - #TPM2_RC_NV_LOCKED
 *       - #TPM2_RC_NV_AUTHORIZATION
 *       - #TPM2_RC_NV_UNINITIALIZED
 *       - #TPM2_RC_NV_SPACE
 *       - #TPM2_RC_NV_DEFINED
 *       - #TPM2_RC_BAD_CONTEXT
 *       - #TPM2_RC_CPHASH
 *       - #TPM2_RC_PARENT
 *       - #TPM2_RC_NEEDS_TEST
 *       - #TPM2_RC_NO_RESULT
 *       - #TPM2_RC_SENSITIVE
 *       - #TPM2_RC_MAX_FM0
 *       - #TPM2_RC_FMT1
 *       - #TPM2_RC_ASYMMETRIC
 *       - #TPM2_RC_ATTRIBUTES
 *       - #TPM2_RC_HASH
 *       - #TPM2_RC_VALUE
 *       - #TPM2_RC_HIERARCHY
 *       - #TPM2_RC_KEY_SIZE
 *       - #TPM2_RC_MGF
 *       - #TPM2_RC_MODE
 *       - #TPM2_RC_TYPE
 *       - #TPM2_RC_HANDLE
 *       - #TPM2_RC_KDF
 *       - #TPM2_RC_RANGE
 *       - #TPM2_RC_AUTH_FAIL
 *       - #TPM2_RC_NONCE
 *       - #TPM2_RC_PP
 *       - #TPM2_RC_SCHEME
 *       - #TPM2_RC_SIZE
 *       - #TPM2_RC_SYMMETRIC
 *       - #TPM2_RC_TAG
 *       - #TPM2_RC_SELECTOR
 *       - #TPM2_RC_INSUFFICIENT
 *       - #TPM2_RC_SIGNATURE
 *       - #TPM2_RC_KEY
 *       - #TPM2_RC_POLICY_FAIL
 *       - #TPM2_RC_INTEGRITY
 *       - #TPM2_RC_TICKET
 *       - #TPM2_RC_RESERVED_BITS
 *       - #TPM2_RC_BAD_AUTH
 *       - #TPM2_RC_EXPIRED
 *       - #TPM2_RC_POLICY_CC
 *       - #TPM2_RC_BINDING
 *       - #TPM2_RC_CURVE
 *       - #TPM2_RC_ECC_POINT
 *       - #TPM2_RC_WARN
 *       - #TPM2_RC_CONTEXT_GAP
 *       - #TPM2_RC_OBJECT_MEMORY
 *       - #TPM2_RC_SESSION_MEMORY
 *       - #TPM2_RC_MEMORY
 *       - #TPM2_RC_SESSION_HANDLES
 *       - #TPM2_RC_OBJECT_HANDLES
 *       - #TPM2_RC_LOCALITY
 *       - #TPM2_RC_YIELDED
 *       - #TPM2_RC_CANCELED
 *       - #TPM2_RC_TESTING
 *       - #TPM2_RC_REFERNCE_H0
 *       - #TPM2_RC_REFERNCE_H1
 *       - #TPM2_RC_REFERNCE_H2
 *       - #TPM2_RC_REFERNCE_H3
 *       - #TPM2_RC_REFERNCE_H4
 *       - #TPM2_RC_REFERNCE_H5
 *       - #TPM2_RC_REFERNCE_H6
 *       - #TPM2_RC_REFERNCE_S0
 *       - #TPM2_RC_REFERNCE_S1
 *       - #TPM2_RC_REFERNCE_S2
 *       - #TPM2_RC_REFERNCE_S3
 *       - #TPM2_RC_REFERNCE_S4
 *       - #TPM2_RC_REFERNCE_S5
 *       - #TPM2_RC_REFERNCE_S6
 *       - #TPM2_RC_NV_RATE
 *       - #TPM2_RC_LOCKOUT
 *       - #TPM2_RC_RETRY
 *       - #TPM2_RC_NV_UNAVAILABLE
 *       - #TPM2_RC_NOT_USED
 *       - #TPM2_RC_H
 *       - #TPM2_RC_P
 *       - #TPM2_RC_S
 *       - #TPM2_RC_1
 *       - #TPM2_RC_2
 *       - #TPM2_RC_3
 *       - #TPM2_RC_4
 *       - #TPM2_RC_5
 *       - #TPM2_RC_6
 *       - #TPM2_RC_7
 *       - #TPM2_RC_8
 *       - #TPM2_RC_9
 *       - #TPM2_RC_A
 *       - #TPM2_RC_B
 *       - #TPM2_RC_C
 *       - #TPM2_RC_D
 *       - #TPM2_RC_E
 *       - #TPM2_RC_F
 *       - #TPM2_RC_N_MASK
 */
typedef ubyte4 TPM2_RC;
/*! TPM2_RC_SUCCESS */
#define TPM2_RC_SUCCESS             ((TPM2_RC) 0x000)
/*! TPM2_RC_BAD_TAG */
#define TPM2_RC_BAD_TAG             ((TPM2_RC) 0x01E)
/*! TPM2_RC_VER1 */
#define TPM2_RC_VER1                ((TPM2_RC) 0x100)
/*! TPM2_RC_INITIALIZE */
#define TPM2_RC_INITIALIZE          ((TPM2_RC) (TPM2_RC_VER1 + 0x000))
/*! TPM2_RC_FAILURE */
#define TPM2_RC_FAILURE             ((TPM2_RC) (TPM2_RC_VER1 + 0x001))
/*! TPM2_RC_SEQUENCE */
#define TPM2_RC_SEQUENCE            ((TPM2_RC) (TPM2_RC_VER1 + 0x003))
/*! TPM2_RC_PRIVATE */
#define TPM2_RC_PRIVATE             ((TPM2_RC) (TPM2_RC_VER1 + 0x00B))
/*! TPM2_RC_HMAC */
#define TPM2_RC_HMAC                ((TPM2_RC) (TPM2_RC_VER1 + 0x019))
/*! TPM2_RC_DISABLED */
#define TPM2_RC_DISABLED            ((TPM2_RC) (TPM2_RC_VER1 + 0x020))
/*! TPM2_RC_EXCLUSIVE */
#define TPM2_RC_EXCLUSIVE           ((TPM2_RC) (TPM2_RC_VER1 + 0x021))
/*! TPM2_RC_AUTH_TYPE */
#define TPM2_RC_AUTH_TYPE           ((TPM2_RC) (TPM2_RC_VER1 + 0x024))
/*! TPM2_RC_AUTH_MISSING */
#define TPM2_RC_AUTH_MISSING        ((TPM2_RC) (TPM2_RC_VER1 + 0x025))
/*! TPM2_RC_POLICY */
#define TPM2_RC_POLICY              ((TPM2_RC) (TPM2_RC_VER1 + 0x026))
/*! TPM2_RC_PCR */
#define TPM2_RC_PCR                 ((TPM2_RC) (TPM2_RC_VER1 + 0x027))
/*! TPM2_RC_PCR_CHANGED */
#define TPM2_RC_PCR_CHANGED         ((TPM2_RC) (TPM2_RC_VER1 + 0x028))
/*! TPM2_RC_UPGRADE */
#define TPM2_RC_UPGRADE             ((TPM2_RC) (TPM2_RC_VER1 + 0x02D))
/*! TPM2_RC_TOO_MANY_CONTEXTS */
#define TPM2_RC_TOO_MANY_CONTEXTS   ((TPM2_RC) (TPM2_RC_VER1 + 0x02E))
/*! TPM2_RC_AUTH_UNAVAILABLE */
#define TPM2_RC_AUTH_UNAVAILABLE    ((TPM2_RC) (TPM2_RC_VER1 + 0x02F))
/*! TPM2_RC_REBOOT */
#define TPM2_RC_REBOOT              ((TPM2_RC) (TPM2_RC_VER1 + 0x030))
/*! TPM2_RC_UNBALANCED */
#define TPM2_RC_UNBALANCED          ((TPM2_RC) (TPM2_RC_VER1 + 0x031))
/*! TPM2_RC_COMMAND_SIZE */
#define TPM2_RC_COMMAND_SIZE        ((TPM2_RC) (TPM2_RC_VER1 + 0x042))
/*! TPM2_RC_COMMAND_CODE */
#define TPM2_RC_COMMAND_CODE        ((TPM2_RC) (TPM2_RC_VER1 + 0x043))
/*! TPM2_RC_AUTHSIZE */
#define TPM2_RC_AUTHSIZE            ((TPM2_RC) (TPM2_RC_VER1 + 0x044))
/*! TPM2_RC_AUTH_CONTEXT */
#define TPM2_RC_AUTH_CONTEXT        ((TPM2_RC) (TPM2_RC_VER1 + 0x045))
/*! TPM2_RC_NV_RANGE */
#define TPM2_RC_NV_RANGE            ((TPM2_RC) (TPM2_RC_VER1 + 0x046))
/*! TPM2_RC_NV_SIZE */
#define TPM2_RC_NV_SIZE             ((TPM2_RC) (TPM2_RC_VER1 + 0x047))
/*! TPM2_RC_NV_LOCKED */
#define TPM2_RC_NV_LOCKED           ((TPM2_RC) (TPM2_RC_VER1 + 0x048))
/*! TPM2_RC_NV_AUTHORIZATION */
#define TPM2_RC_NV_AUTHORIZATION    ((TPM2_RC) (TPM2_RC_VER1 + 0x049))
/*! TPM2_RC_NV_UNINITIALIZED */
#define TPM2_RC_NV_UNINITIALIZED    ((TPM2_RC) (TPM2_RC_VER1 + 0x04A))
/*! TPM2_RC_NV_SPACE */
#define TPM2_RC_NV_SPACE            ((TPM2_RC) (TPM2_RC_VER1 + 0x04B))
/*! TPM2_RC_NV_DEFINED */
#define TPM2_RC_NV_DEFINED          ((TPM2_RC) (TPM2_RC_VER1 + 0x04C))
/*! TPM2_RC_BAD_CONTEXT */
#define TPM2_RC_BAD_CONTEXT         ((TPM2_RC) (TPM2_RC_VER1 + 0x050))
/*! TPM2_RC_CPHASH */
#define TPM2_RC_CPHASH              ((TPM2_RC) (TPM2_RC_VER1 + 0x051))
/*! TPM2_RC_PARENT */
#define TPM2_RC_PARENT              ((TPM2_RC) (TPM2_RC_VER1 + 0x052))
/*! TPM2_RC_NEEDS_TEST */
#define TPM2_RC_NEEDS_TEST          ((TPM2_RC) (TPM2_RC_VER1 + 0x053))
/*! TPM2_RC_NO_RESULT */
#define TPM2_RC_NO_RESULT           ((TPM2_RC) (TPM2_RC_VER1 + 0x054))
/*! TPM2_RC_SENSITIVE */
#define TPM2_RC_SENSITIVE           ((TPM2_RC) (TPM2_RC_VER1 + 0x055))
/*! TPM2_RC_MAX_FM0 */
#define TPM2_RC_MAX_FM0             ((TPM2_RC) (TPM2_RC_VER1 + 0x07F))
/*! TPM2_RC_FMT1 */
#define TPM2_RC_FMT1                ((TPM2_RC) 0x080)
/*! TPM2_RC_ASYMMETRIC */
#define TPM2_RC_ASYMMETRIC          ((TPM2_RC) (TPM2_RC_FMT1 + 0x001))
/*! TPM2_RC_ATTRIBUTES */
#define TPM2_RC_ATTRIBUTES          ((TPM2_RC) (TPM2_RC_FMT1 + 0x002))
/*! TPM2_RC_HASH */
#define TPM2_RC_HASH                ((TPM2_RC) (TPM2_RC_FMT1 + 0x003))
/*! TPM2_RC_VALUE */
#define TPM2_RC_VALUE               ((TPM2_RC) (TPM2_RC_FMT1 + 0x004))
/*! TPM2_RC_HIERARCHY */
#define TPM2_RC_HIERARCHY           ((TPM2_RC) (TPM2_RC_FMT1 + 0x005))
/*! TPM2_RC_KEY_SIZE */
#define TPM2_RC_KEY_SIZE            ((TPM2_RC) (TPM2_RC_FMT1 + 0x007))
/*! TPM2_RC_MGF */
#define TPM2_RC_MGF                 ((TPM2_RC) (TPM2_RC_FMT1 + 0x008))
/*! TPM2_RC_MODE */
#define TPM2_RC_MODE                ((TPM2_RC) (TPM2_RC_FMT1 + 0x009))
/*! TPM2_RC_TYPE */
#define TPM2_RC_TYPE                ((TPM2_RC) (TPM2_RC_FMT1 + 0x00A))
/*! TPM2_RC_HANDLE */
#define TPM2_RC_HANDLE              ((TPM2_RC) (TPM2_RC_FMT1 + 0x00B))
/*! TPM2_RC_KDF */
#define TPM2_RC_KDF                 ((TPM2_RC) (TPM2_RC_FMT1 + 0x00C))
/*! TPM2_RC_RANGE */
#define TPM2_RC_RANGE               ((TPM2_RC) (TPM2_RC_FMT1 + 0x00D))
/*! TPM2_RC_AUTH_FAIL */
#define TPM2_RC_AUTH_FAIL           ((TPM2_RC) (TPM2_RC_FMT1 + 0x00E))
/*! TPM2_RC_NONCE */
#define TPM2_RC_NONCE               ((TPM2_RC) (TPM2_RC_FMT1 + 0x00F))
/*! TPM2_RC_PP */
#define TPM2_RC_PP                  ((TPM2_RC) (TPM2_RC_FMT1 + 0x010))
/*! TPM2_RC_SCHEME */
#define TPM2_RC_SCHEME              ((TPM2_RC) (TPM2_RC_FMT1 + 0x012))
/*! TPM2_RC_SIZE */
#define TPM2_RC_SIZE                ((TPM2_RC) (TPM2_RC_FMT1 + 0x015))
/*! TPM2_RC_SYMMETRIC */
#define TPM2_RC_SYMMETRIC           ((TPM2_RC) (TPM2_RC_FMT1 + 0x016))
/*! TPM2_RC_TAG */
#define TPM2_RC_TAG                 ((TPM2_RC) (TPM2_RC_FMT1 + 0x017))
/*! TPM2_RC_SELECTOR */
#define TPM2_RC_SELECTOR            ((TPM2_RC) (TPM2_RC_FMT1 + 0x018))
/*! TPM2_RC_INSUFFICIENT */
#define TPM2_RC_INSUFFICIENT        ((TPM2_RC) (TPM2_RC_FMT1 + 0x01A))
/*! TPM2_RC_SIGNATURE */
#define TPM2_RC_SIGNATURE           ((TPM2_RC) (TPM2_RC_FMT1 + 0x01B))
/*! TPM2_RC_KEY */
#define TPM2_RC_KEY                 ((TPM2_RC) (TPM2_RC_FMT1 + 0x01C))
/*! TPM2_RC_POLICY_FAIL */
#define TPM2_RC_POLICY_FAIL         ((TPM2_RC) (TPM2_RC_FMT1 + 0x01D))
/*! TPM2_RC_INTEGRITY */
#define TPM2_RC_INTEGRITY           ((TPM2_RC) (TPM2_RC_FMT1 + 0x01F))
/*! TPM2_RC_TICKET */
#define TPM2_RC_TICKET              ((TPM2_RC) (TPM2_RC_FMT1 + 0x020))
/*! TPM2_RC_RESERVED_BITS */
#define TPM2_RC_RESERVED_BITS       ((TPM2_RC) (TPM2_RC_FMT1 + 0x021))
/*! TPM2_RC_BAD_AUTH */
#define TPM2_RC_BAD_AUTH            ((TPM2_RC) (TPM2_RC_FMT1 + 0x022))
/*! TPM2_RC_EXPIRED */
#define TPM2_RC_EXPIRED             ((TPM2_RC) (TPM2_RC_FMT1 + 0x023))
/*! TPM2_RC_POLICY_CC */
#define TPM2_RC_POLICY_CC           ((TPM2_RC) (TPM2_RC_FMT1 + 0x024))
/*! TPM2_RC_BINDING */
#define TPM2_RC_BINDING             ((TPM2_RC) (TPM2_RC_FMT1 + 0x025))
/*! TPM2_RC_CURVE */
#define TPM2_RC_CURVE               ((TPM2_RC) (TPM2_RC_FMT1 + 0x026))
/*! TPM2_RC_ECC_POINT */
#define TPM2_RC_ECC_POINT           ((TPM2_RC) (TPM2_RC_FMT1 + 0x027))
/*! TPM2_RC_WARN */
#define TPM2_RC_WARN                ((TPM2_RC) 0x900)
/*! TPM2_RC_CONTEXT_GAP */
#define TPM2_RC_CONTEXT_GAP         ((TPM2_RC) (TPM2_RC_WARN + 0x001))
/*! TPM2_RC_OBJECT_MEMORY */
#define TPM2_RC_OBJECT_MEMORY       ((TPM2_RC) (TPM2_RC_WARN + 0x002))
/*! TPM2_RC_SESSION_MEMORY */
#define TPM2_RC_SESSION_MEMORY      ((TPM2_RC) (TPM2_RC_WARN + 0x003))
/*! TPM2_RC_MEMORY */
#define TPM2_RC_MEMORY              ((TPM2_RC) (TPM2_RC_WARN + 0x004))
/*! TPM2_RC_SESSION_HANDLES */
#define TPM2_RC_SESSION_HANDLES     ((TPM2_RC) (TPM2_RC_WARN + 0x005))
/*! TPM2_RC_OBJECT_HANDLES */
#define TPM2_RC_OBJECT_HANDLES      ((TPM2_RC) (TPM2_RC_WARN + 0x006))
/*! TPM2_RC_LOCALITY */
#define TPM2_RC_LOCALITY            ((TPM2_RC) (TPM2_RC_WARN + 0x007))
/*! TPM2_RC_YIELDED */
#define TPM2_RC_YIELDED             ((TPM2_RC) (TPM2_RC_WARN + 0x008))
/*! TPM2_RC_CANCELED */
#define TPM2_RC_CANCELED            ((TPM2_RC) (TPM2_RC_WARN + 0x009))
/*! TPM2_RC_TESTING */
#define TPM2_RC_TESTING             ((TPM2_RC) (TPM2_RC_WARN + 0x00A))
/*! TPM2_RC_REFERNCE_H0 */
#define TPM2_RC_REFERENCE_H0        ((TPM2_RC) (TPM2_RC_WARN + 0x010))
/*! TPM2_RC_REFERNCE_H1 */
#define TPM2_RC_REFERENCE_H1        ((TPM2_RC) (TPM2_RC_WARN + 0x011))
/*! TPM2_RC_REFERNCE_H2 */
#define TPM2_RC_REFERENCE_H2        ((TPM2_RC) (TPM2_RC_WARN + 0x012))
/*! TPM2_RC_REFERNCE_H3 */
#define TPM2_RC_REFERENCE_H3        ((TPM2_RC) (TPM2_RC_WARN + 0x013))
/*! TPM2_RC_REFERNCE_H4 */
#define TPM2_RC_REFERENCE_H4        ((TPM2_RC) (TPM2_RC_WARN + 0x014))
/*! TPM2_RC_REFERNCE_H5 */
#define TPM2_RC_REFERENCE_H5        ((TPM2_RC) (TPM2_RC_WARN + 0x015))
/*! TPM2_RC_REFERNCE_H6 */
#define TPM2_RC_REFERENCE_H6        ((TPM2_RC) (TPM2_RC_WARN + 0x016))
/*! TPM2_RC_REFERNCE_S0 */
#define TPM2_RC_REFERENCE_S0        ((TPM2_RC) (TPM2_RC_WARN + 0x018))
/*! TPM2_RC_REFERNCE_S1 */
#define TPM2_RC_REFERENCE_S1        ((TPM2_RC) (TPM2_RC_WARN + 0x019))
/*! TPM2_RC_REFERNCE_S2 */
#define TPM2_RC_REFERENCE_S2        ((TPM2_RC) (TPM2_RC_WARN + 0x01A))
/*! TPM2_RC_REFERNCE_S3 */
#define TPM2_RC_REFERENCE_S3        ((TPM2_RC) (TPM2_RC_WARN + 0x01B))
/*! TPM2_RC_REFERNCE_S4 */
#define TPM2_RC_REFERENCE_S4        ((TPM2_RC) (TPM2_RC_WARN + 0x01C))
/*! TPM2_RC_REFERNCE_S5 */
#define TPM2_RC_REFERENCE_S5        ((TPM2_RC) (TPM2_RC_WARN + 0x01D))
/*! TPM2_RC_REFERNCE_S6 */
#define TPM2_RC_REFERENCE_S6        ((TPM2_RC) (TPM2_RC_WARN + 0x01E))
/*! TPM2_RC_NV_RATE */
#define TPM2_RC_NV_RATE             ((TPM2_RC) (TPM2_RC_WARN + 0x020))
/*! TPM2_RC_LOCKOUT */
#define TPM2_RC_LOCKOUT             ((TPM2_RC) (TPM2_RC_WARN + 0x021))
/*! TPM2_RC_RETRY */
#define TPM2_RC_RETRY               ((TPM2_RC) (TPM2_RC_WARN + 0x022))
/*! TPM2_RC_NV_UNAVAILABLE */
#define TPM2_RC_NV_UNAVAILABLE      ((TPM2_RC) (TPM2_RC_WARN + 0x023))
/*! TPM2_RC_NOT_USED */
#define TPM2_RC_NOT_USED            ((TPM2_RC) (TPM2_RC_WARN + 0x7F))
/*! TPM2_RC_H */
#define TPM2_RC_H                   ((TPM2_RC) 0x000)
/*! TPM2_RC_P */
#define TPM2_RC_P                   ((TPM2_RC) 0x040)
/*! TPM2_RC_S */
#define TPM2_RC_S                   ((TPM2_RC) 0x800)
/*! TPM2_RC_1 */
#define TPM2_RC_1                   ((TPM2_RC) 0x100)
/*! TPM2_RC_2 */
#define TPM2_RC_2                   ((TPM2_RC) 0x200)
/*! TPM2_RC_3 */
#define TPM2_RC_3                   ((TPM2_RC) 0x300)
/*! TPM2_RC_4 */
#define TPM2_RC_4                   ((TPM2_RC) 0x400)
/*! TPM2_RC_5 */
#define TPM2_RC_5                   ((TPM2_RC) 0x500)
/*! TPM2_RC_6 */
#define TPM2_RC_6                   ((TPM2_RC) 0x600)
/*! TPM2_RC_7 */
#define TPM2_RC_7                   ((TPM2_RC) 0x700)
/*! TPM2_RC_8 */
#define TPM2_RC_8                   ((TPM2_RC) 0x800)
/*! TPM2_RC_9 */
#define TPM2_RC_9                   ((TPM2_RC) 0x900)
/*! TPM2_RC_A */
#define TPM2_RC_A                   ((TPM2_RC) 0xA00)
/*! TPM2_RC_B */
#define TPM2_RC_B                   ((TPM2_RC) 0xB00)
/*! TPM2_RC_C */
#define TPM2_RC_C                   ((TPM2_RC) 0xC00)
/*! TPM2_RC_D */
#define TPM2_RC_D                   ((TPM2_RC) 0xD00)
/*! TPM2_RC_E */
#define TPM2_RC_E                   ((TPM2_RC) 0xE00)
/*! TPM2_RC_F */
#define TPM2_RC_F                   ((TPM2_RC) 0xF00)
/*! TPM2_RC_N_MASK */
#define TPM2_RC_N_MASK              ((TPM2_RC) 0xF00)

/*-------------------------------------------------------------------*/
/* Part 2, section 6.7: TPM2_CLOCK_ADJUST                            */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Value used to change the rate at which the TPM internal oscillator is divided.
 * @details Value used to change the rate at which the TPM internal oscillator is divided.
 *  <p> A change to the divider will change gthe rate at which Clock and Time change.
 *  <p> TPM2_CLOCK_ADJUST must be one of the following values:
 *  - #TPM2_CLOCK_COARSE_SLOWER
 *  - #TPM2_CLOCK_MEDIUM_SLOWER
 *  - #TPM2_CLOCK_FINE_SLOWER
 *  - #TPM2_CLOCK_NO_CHANGE
 *  - #TPM2_CLOCK_FINE_FASTER
 *  - #TPM2_CLOCK_MEDIUM_FASTER
 *  - #TPM2_CLOCK_COARSE_FASTER
 */
typedef sbyte TPM2_CLOCK_ADJUST;
/*! TPM2_CLOCK_COARSE_SLOWER - Slow the Clock update rate by one coarse adjustment step. */
#define TPM2_CLOCK_COARSE_SLOWER    ((TPM2_CLOCK_ADJUST) -3)
/*! TPM2_CLOCK_MEDIUM_SLOWER - Slow the Clock update rate by one medium adjustment step. */
#define TPM2_CLOCK_MEDIUM_SLOWER    ((TPM2_CLOCK_ADJUST) -2)
/*! TPM2_CLOCK_FINE_SLOWER - Slow the Clock update rate by one fine adjustment step. */
#define TPM2_CLOCK_FINE_SLOWER      ((TPM2_CLOCK_ADJUST) -1)
/*! TPM2_CLOCK_NO_CHANGE - No change to the Clock update rate. */
#define TPM2_CLOCK_NO_CHANGE        ((TPM2_CLOCK_ADJUST) 0)
/*! TPM2_CLOCK_FINE_FASTER - Speed the Clock update rate by one fine adjustment step. */
#define TPM2_CLOCK_FINE_FASTER      ((TPM2_CLOCK_ADJUST) 1)
/*! TPM2_CLOCK_MEDIUM_FASTER - Speed the Clock update rate by one medium adjustment step. */
#define TPM2_CLOCK_MEDIUM_FASTER    ((TPM2_CLOCK_ADJUST) 2)
/*! TPM2_CLOCK_COARSE_FASTER - Speed the Clock update rate by one coarse adjustment step. */
#define TPM2_CLOCK_COARSE_FASTER    ((TPM2_CLOCK_ADJUST) 3)

/*-------------------------------------------------------------------*/
/* Part 2, section 6.8: TPM2_EO (EA Arithmetic Operands)             */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief EA Arithmetic Operands
 * @details TPM2_EO must be one of the following values:
 *  - #TPM2_EO_EQ
 *  - #TPM2_EO_NEQ
 *  - #TPM2_EO_SIGNED_GT
 *  - #TPM2_EO_UNSIGNED_GT
 *  - #TPM2_EO_SIGNED_LT
 *  - #TPM2_EO_UNSIGNED_LT
 *  - #TPM2_EO_SIGNED_GE
 *  - #TPM2_EO_UNSIGNED_GE
 *  - #TPM2_EO_SIGNED_LE
 *  - #TPM2_EO_UNSIGNED_LE
 *  - #TPM2_EO_BITSET
 *  - #TPM2_EO_BITCLEAR
 */
typedef ubyte2 TPM2_EO;
/*! TPM2_EO_EQ - A = B */
#define TPM2_EO_EQ              ((TPM2_EO) 0x0000)
/*! TPM2_EO_NEQ - A != B */
#define TPM2_EO_NEQ             ((TPM2_EO) 0x0001)
/*! TPM2_EO_SIGNED_GT - A > B signed */
#define TPM2_EO_SIGNED_GT       ((TPM2_EO) 0x0002)
/*! TPM2_EO_UNSIGNED_GT - A > B unsigned */
#define TPM2_EO_UNSIGNED_GT     ((TPM2_EO) 0x0003)
/*! TPM2_EO_SIGNED_LT - A < B signed */
#define TPM2_EO_SIGNED_LT       ((TPM2_EO) 0x0004)
/*! TPM2_EO_UNSIGNED_LT - A < B unsigned */
#define TPM2_EO_UNSIGNED_LT     ((TPM2_EO) 0x0005)
/*! TPM2_EO_SIGNED_GE - A >= B signed */
#define TPM2_EO_SIGNED_GE       ((TPM2_EO) 0x0006)
/*! TPM2_EO_UNSIGNED_GE - A >= B unsigned */
#define TPM2_EO_UNSIGNED_GE     ((TPM2_EO) 0x0007)
/*! TPM2_EO_SIGNED_LE - A <= B signed */
#define TPM2_EO_SIGNED_LE       ((TPM2_EO) 0x0008)
/*! TPM2_EO_UNSIGNED_LE - A <= B unsigned */
#define TPM2_EO_UNSIGNED_LE     ((TPM2_EO) 0x0009)
/*! TPM2_EO_BITSET - All bits SET in B are SET in A ((A&B)=B) */
#define TPM2_EO_BITSET          ((TPM2_EO) 0x000A)
/*! TPM2_EO_BITCLEAR - All bits SET in B are CLEAR in A ((A&B)=0) */
#define TPM2_EO_BITCLEAR        ((TPM2_EO) 0x000B)


/*-------------------------------------------------------------------*/
/* Part 2, section 6.9: Structure Tags                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm_definitions
 * @brief Structure tag used to disambiguate structures in a TPM 2.0 command/response.
 * @details 16-bit tag value with the most significant bit SET so that they do not overlap TPM2_ALG_ID values.
 *  <p>The definition of many structures is context-sensitive using an algorithm ID. In cases where an algorithm ID is not a meaningful way to designate the structure, a TPM2_ST_xx value is used.
 *  <p> TPM2_ST must be one of the following values:
 *  - #TPM2_ST_RSP_COMMAND
 *  - #TPM2_ST_NULL
 *  - #TPM2_ST_NO_SESSIONS
 *  - #TPM2_ST_SESSIONS
 *  - #TPM2_ST_ATTEST_NV
 *  - #TPM2_ST_ATTEST_COMMAND_AUDIT
 *  - #TPM2_ST_ATTEST_SESSION_AUDIT
 *  - #TPM2_ST_ATTEST_CERTIFY
 *  - #TPM2_ST_ATTEST_QUOTE
 *  - #TPM2_ST_ATTEST_TIME
 *  - #TPM2_ST_ATTEST_CREATION
 *  - #TPM2_ST_CREATION
 *  - #TPM2_ST_VERIFIED
 *  - #TPM2_ST_AUTH_SECRET
 *  - #TPM2_ST_HASHCHECK
 *  - #TPM2_ST_AUTH_SIGNED
 *  - #TPM2_ST_FU_MANIFEST
 *
 * <p> The following values are reserved: 0x8003, 0x8004, and 0x801B
 */
typedef ubyte2  TPM2_ST;
/*! TPM2_ST_RSP_COMMAND -  response-only value used when there is an error in the tag.  Also the value returned from a TPM 1.2 where an error occurs. This is the only overlapping value; it is the same as TPM2_TAG_RSP_COMMAND. */
#define TPM2_ST_RSP_COMMAND            ((TPM2_ST) 0x00C4)
/*! TPM2_ST_NULL - no structure type specified */
#define TPM2_ST_NULL                   ((TPM2_ST) 0x8000)
/*! TPM2_ST_NO_SESSIONS - indicates that the command/response has no attached sessions and no authorizationSize/parameterSize value is present. If the responseCode from the TPM is not #TPM2_RC_SUCCESS, then the response tag shall have this value. */
#define TPM2_ST_NO_SESSIONS            ((TPM2_ST) 0x8001)
/*! TPM2_ST_SESSIONS - indicates that the command/response has one or more attached sessions and hte authorizationSize/parameterSize field is present.  */
#define TPM2_ST_SESSIONS               ((TPM2_ST) 0x8002)
/* 0x8003 and 0x8004 are reserved */
/*! TPM2_ST_ATTEST_NV - tag for attestation structure generated by TPM2_NV_Certify() */
#define TPM2_ST_ATTEST_NV              ((TPM2_ST) 0x8014)
/*! TPM2_ST_ATTEST_COMMAND_AUDIT - tag for attestation structure generated by TPM2_GetCommandAuditDigest() */
#define TPM2_ST_ATTEST_COMMAND_AUDIT   ((TPM2_ST) 0x8015)
/*! TPM2_ST_ATTEST_SESSION_AUDIT - tag for attestation structure generated by TPM2_GetSessionAuditDigest() */
#define TPM2_ST_ATTEST_SESSION_AUDIT   ((TPM2_ST) 0x8016)
/*! TPM2_ST_ATTEST_CERTIFY - tag for attestation structure generated by TPM2_Certify() */
#define TPM2_ST_ATTEST_CERTIFY         ((TPM2_ST) 0x8017)
/*! TPM2_ST_ATTEST_QUOTE - tag for attestation structure generated by TPM2_Quote() */
#define TPM2_ST_ATTEST_QUOTE           ((TPM2_ST) 0x8018)
/*! TPM2_ST_ATTEST_TIME - tag for attestation structure generated by TPM2_GetTime() */
#define TPM2_ST_ATTEST_TIME            ((TPM2_ST) 0x8019)
/*! TPM2_ST_ATTEST_CREATION - tag for attestation structure generated by TPM2_CertifyCreation() */
#define TPM2_ST_ATTEST_CREATION        ((TPM2_ST) 0x801A)
/* 0x801B reserved */
/*! TPM2_ST_CREATION - tag for a ticket type */
#define TPM2_ST_CREATION               ((TPM2_ST) 0x8021)
/*! TPM2_ST_VERIFIED - tag for a ticket type */ 
#define TPM2_ST_VERIFIED               ((TPM2_ST) 0x8022)
/*! TPM2_ST_AUTH_SECRET - tag for a ticket type */
#define TPM2_ST_AUTH_SECRET            ((TPM2_ST) 0x8023)
/*! TPM2_ST_HASHCHECK - tag for a ticket type */
#define TPM2_ST_HASHCHECK              ((TPM2_ST) 0x8024)
/*! TPM2_ST_AUTH_SIGNED - tag for a ticket type */
#define TPM2_ST_AUTH_SIGNED            ((TPM2_ST) 0x8025)
/*! TPM2_ST_FU_MANIFEST - tag for a structure describing a Field Upgrade Policy */
#define TPM2_ST_FU_MANIFEST            ((TPM2_ST) 0x0029)


/*-------------------------------------------------------------------*/
/* Part 2, section 6.10: Startup Type                                */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Startup Type
 * @details Values used in TPM2_Startup() to indicate the shutdown and startup mode.
 * <p> TPM2_SU must be one of the following values:
 *  - #TPM2_SU_CLEAR
 *  - #TPM2_SU_STATE
 */
typedef ubyte2  TPM2_SU;
/*! TPM2_SU_CLEAR - on TPM2_Shutdown(), indicates that the TPM should prepare
 for loss of power and save state required for an orderly startup (TPM Reset).
 On TPM2_Startup(), indicates that the TPM should perform TPM Reset or TPM Restart.
 */
#define TPM2_SU_CLEAR                  ((TPM2_SU) 0x0000)
/*! TPM2_SU_STATE - on TPM2_Shutdown(), indicates that the TPM should prepare
 for loss of power and save state required for an orderly startup (TPM Reset).
 On TPM2_Startup(), indicates that the TPM should restore the state saved by TPM2_Shutdown(TPM2_SU_STATE).
 */
#define TPM2_SU_STATE                  ((TPM2_SU) 0x0001)


/*-------------------------------------------------------------------*/
/* Part 2, section 6.11: Session Type                                */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Session Type
 * @details Values used in TPM2_StartAuthSession() to indicate the type of the session to be created.
 * <p> TPM2_SE must be one of the following values:
 *  - #TPM2_SE_HMAC
 *  - #TPM2_SE_POLICY
 *  - #TPM2_SE_TRIAL
 */
typedef ubyte  TPM2_SE;
/*! TPM2_SE_HMAC  */
#define TPM2_SE_HMAC                   ((TPM2_SE) 0x00)
/*! TPM2_SE_POLICY  */
#define TPM2_SE_POLICY                 ((TPM2_SE) 0x01)
/*! TPM2_SE_TRIAL - The policy session is being used to compute the policyHash and not for command authorization.  This setting modifies some policy commands and prevents a session from being used to authorize a command. */
#define TPM2_SE_TRIAL                  ((TPM2_SE) 0x03)

/*-------------------------------------------------------------------*/
/* Part 2, section 6.12: Capabilities                                */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Capabilities
 * @details Values used in TPM2_GetCapability() to select the type of the value to be returned.  The format of the response varies according to the TPM2_CAP_xx value.
 * <p> TPM2_CAP must be one of the following values:
 *  - #TPM2_CAP_FIRST
 *  - #TPM2_CAP_ALGS
 *  - #TPM2_CAP_HANDLES
 *  - #TPM2_CAP_COMMANDS
 *  - #TPM2_CAP_PP_COMMANDS
 *  - #TPM2_CAP_AUDIT_COMMANDS
 *  - #TPM2_CAP_PCRS
 *  - #TPM2_CAP_TPM_PROPERTIES
 *  - #TPM2_CAP_PCR_PROPERTIES
 *  - #TPM2_CAP_ECC_CURVES
 *  - #TPM2_CAP_AUTH_POLICIES
 *  - #TPM2_CAP_LAST
 *  - #TPM2_CAP_VENDOR_PROPERTY
 */
typedef ubyte4  TPM2_CAP;
/*! TPM2_CAP_FIRST  - first valid value for TPM2_CAP */
#define TPM2_CAP_FIRST              ((TPM2_CAP) 0x00000000)
/*! TPM2_CAP_ALGS - Property Type = TPM2_ALG_ID; Return Type = TPML_ALG_PROPERTY */
#define TPM2_CAP_ALGS               ((TPM2_CAP) 0x00000000)
/*! TPM2_CAP_HANDLES - Property Type = TPM2_HANDLE; Return Type = TPML_HANDLE */
#define TPM2_CAP_HANDLES            ((TPM2_CAP) 0x00000001)
/*! TPM2_CAP_COMMANDS - Property Type = TPM2_CC; Return Type = TPML_CCA */
#define TPM2_CAP_COMMANDS           ((TPM2_CAP) 0x00000002)
/*! TPM2_CAP_PP_COMMANDS - Property Type = TPM2_CC; Return Type = TPML_CC */
#define TPM2_CAP_PP_COMMANDS        ((TPM2_CAP) 0x00000003)
/*! TPM2_CAP_AUDIT_COMMANDS - Property Type = TPM2_CC; Return Type = TPML_CC */
#define TPM2_CAP_AUDIT_COMMANDS     ((TPM2_CAP) 0x00000004)
/*! TPM2_CAP_PCRS - Property Type = reserved; Return Type = TPML_PCR_SELECTION */
#define TPM2_CAP_PCRS               ((TPM2_CAP) 0x00000005)
/*! TPM2_CAP_TPM_PROPERTIES - Property Type = TPM2_PT; Return Type = TPML_TAGGED_TPM_PROPERTY */
#define TPM2_CAP_TPM_PROPERTIES     ((TPM2_CAP) 0x00000006)
/*! TPM2_CAP_PCR_PROPERTIES - Property Type = TPM2_PT_PCR; Return Type = TPML_TAGGED_PCR_PROPERTY */
#define TPM2_CAP_PCR_PROPERTIES     ((TPM2_CAP) 0x00000007)
/*! TPM2_CAP_ECC_CURVES - Property Type = TPM2_ECC_CURVE; Return Type = TPML_ECC_CURVE */
#define TPM2_CAP_ECC_CURVES         ((TPM2_CAP) 0x00000008)
/*! TPM2_CAP_AUTH_POLICIES - Property Type = null; Return Type = TPML_TAGGED_POLICY */
#define TPM2_CAP_AUTH_POLICIES      ((TPM2_CAP) 0x00000009)
/*! TPM2_CAP_LAST  - last valid value for TPM2_CAP */
#define TPM2_CAP_LAST               ((TPM2_CAP) 0x00000009)
/*! TPM2_CAP_VENDOR_PROPERTY - Property Type = manufacturer-specific; Return Type = manufacturer-specific */
#define TPM2_CAP_VENDOR_PROPERTY    ((TPM2_CAP) 0x00000100)


/*-------------------------------------------------------------------*/
/* Part 2, section 6.13: Property Tag                                */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Property Tag
 * @details Constants used in TPM2_GetCapability(capability = TPM2_CAP_TPM_PROPERTIES) to indicate the property being selected or returned.
 * <p> The values in the fixed group (TPM2_PT_FIXED) are not changeable through programmtic means other than a firmware update.
 * <p> The values in the variable group (TPM2_PT_VAR) may be changed with TPM commands but should be persistent over power cycles.
 * <p> The following TPM2_PT values define the different groups:
 *  - #TPM2_PT_NONE
 *  - #TPM2_PT_GROUP
 *  - #TPM2_PT_FIXED
 *  - #TPM2_PT_VAR
 * <p> The following TPM2_PT values are in the TPM2_PT_FIXED group:
 *  - #TPM2_PT_FAMILY_INDICATOR
 *  - #TPM2_PT_LEVEL
 *  - #TPM2_PT_REVISION
 *  - #TPM2_PT_DAY_OF_YEAR
 *  - #TPM2_PT_YEAR
 *  - #TPM2_PT_MANUFACTURER
 *  - #TPM2_PT_VENDOR_STRING_1
 *  - #TPM2_PT_VENDOR_STRING_2
 *  - #TPM2_PT_VENDOR_STRING_3
 *  - #TPM2_PT_VENDOR_STRING_4
 *  - #TPM2_PT_VENDOR_TPM_TYPE
 *  - #TPM2_PT_FIRMWARE_VERSION_1
 *  - #TPM2_PT_FIRMWARE_VERSION_2
 *  - #TPM2_PT_INPUT_BUFFER
 *  - #TPM2_PT_HR_TRANSIENT_MIN
 *  - #TPM2_PT_HR_PERSISTENT_MIN
 *  - #TPM2_PT_HR_LOADED_MIN
 *  - #TPM2_PT_ACTIVE_SESSIONS_MAX
 *  - #TPM2_PT_PCR_COUNT
 *  - #TPM2_PT_PCR_SELECT_MIN
 *  - #TPM2_PT_CONTEXT_GAP_MAX
 *  - #TPM2_PT_NV_COUNTERS_MAX
 *  - #TPM2_PT_NV_INDEX_MAX
 *  - #TPM2_PT_MEMORY
 *  - #TPM2_PT_CLOCK_UPDATE
 *  - #TPM2_PT_CONTEXT_HASH
 *  - #TPM2_PT_CONTEXT_SYM
 *  - #TPM2_PT_CONTEXT_SYM_SIZE
 *  - #TPM2_PT_ORDERLY_COUNT
 *  - #TPM2_PT_MAX_COMMAND_SIZE
 *  - #TPM2_PT_MAX_RESPONSE_SIZE
 *  - #TPM2_PT_MAX_DIGEST
 *  - #TPM2_PT_MAX_OBJECT_CONTEXT
 *  - #TPM2_PT_MAX_SESSION_CONTEXT
 *  - #TPM2_PT_PS_FAMILY_INDICATOR
 *  - #TPM2_PT_PS_LEVEL
 *  - #TPM2_PT_PS_REVISION
 *  - #TPM2_PT_PS_DAY_OF_YEAR
 *  - #TPM2_PT_PS_YEAR
 *  - #TPM2_PT_SPLIT_MAX
 *  - #TPM2_PT_TOTAL_COMMANDS
 *  - #TPM2_PT_LIBRARY_COMMANDS
 *  - #TPM2_PT_VENDOR_COMMANDS
 *  - #TPM2_PT_NV_BUFFER_MAX
 *  - #TPM2_PT_MODES
 *  - #TPM2_PT_MAX_CAP_BUFFER
 * <p> The following TPM2_PT values are in the TPM2_PT_VAR group:
 *  - #TPM2_PT_PERMANENT
 *  - #TPM2_PT_STARTUP_CLEAR
 *  - #TPM2_PT_HR_NV_INDEX
 *  - #TPM2_PT_HR_LOADED
 *  - #TPM2_PT_HR_LOADED_AVAIL
 *  - #TPM2_PT_HR_ACTIVE
 *  - #TPM2_PT_HR_ACTIVE_AVAIL
 *  - #TPM2_PT_HR_TRANSIENT_AVAIL
 *  - #TPM2_PT_HR_PERSISTENT
 *  - #TPM2_PT_HR_PERSISTENT_AVAIL
 *  - #TPM2_PT_NV_COUNTERS
 *  - #TPM2_PT_NV_COUNTERS_AVAIL
 *  - #TPM2_PT_ALGORITHM_SET
 *  - #TPM2_PT_LOADED_CURVES
 *  - #TPM2_PT_LOCKOUT_COUNTER
 *  - #TPM2_PT_MAX_AUTH_FAIL
 *  - #TPM2_PT_LOCKOUT_INTERVAL
 *  - #TPM2_PT_LOCKOUT_RECOVERY
 *  - #TPM2_PT_NV_WRITE_RECOVERY
 *  - #TPM2_PT_AUDIT_COUNTER_0
 *  - #TPM2_PT_AUDIT_COUNTER_1
 */
typedef ubyte4  TPM2_PT;
/*! TPM2_PT_NONE - indicates no property type */
#define TPM2_PT_NONE                  ((TPM2_PT) 0x00000000)
/*! TPM2_PT_GROUP - the number of properties in each group.  Group 0 is reserved. */
#define TPM2_PT_GROUP                 ((TPM2_PT) 0x00000100)
/* The group of fixed properties returned as TPMS_TAGGED_PROPERTY */
/*! TPM2_PT_FIXED - Group 1: The group of fixed properties returned as TPMS_TAGGED_PROPERTY.
<p> The values in this group are only changed due to a firmware change in the TPM.
*/
#define TPM2_PT_FIXED                   ((TPM2_PT) (TPM2_PT_GROUP * 1))
/*! TPM2_PT_FAMILY_INDICATOR - 4-octect character string containing the TPM Family value (#TPM2_SPEC_FAMILY) */
#define TPM2_PT_FAMILY_INDICATOR        ((TPM2_PT) (TPM2_PT_FIXED + 0))
/*! TPM2_PT_LEVEL - the level of the specification */
#define TPM2_PT_LEVEL                   ((TPM2_PT) (TPM2_PT_FIXED + 1))
/*! TPM2_PT_REVISION - the specification revision times 100 (e.g. revision 1.01 would have a value of 101) */
#define TPM2_PT_REVISION                ((TPM2_PT) (TPM2_PT_FIXED + 2))
/*! TPM2_PT_DAY_OF_YEAR - the specification day of year using the TCG calendar. */
#define TPM2_PT_DAY_OF_YEAR             ((TPM2_PT) (TPM2_PT_FIXED + 3))
/*! TPM2_PT_YEAR - the specification year using the CE */
#define TPM2_PT_YEAR                    ((TPM2_PT) (TPM2_PT_FIXED + 4))
/*! TPM2_PT_MANUFACTURER - the vendor ID unique to each TPM manufacturer */
#define TPM2_PT_MANUFACTURER            ((TPM2_PT) (TPM2_PT_FIXED + 5))
/*! TPM2_PT_VENDOR_STRING_1 - the first 4 characters of the vendor ID string */
#define TPM2_PT_VENDOR_STRING_1         ((TPM2_PT) (TPM2_PT_FIXED + 6))
/*! TPM2_PT_VENDOR_STRING_2 - the second 4 characters of the vendor ID string */
#define TPM2_PT_VENDOR_STRING_2         ((TPM2_PT) (TPM2_PT_FIXED + 7))
/*! TPM2_PT_VENDOR_STRING_3 - the third 4 characters of the vendor ID string */
#define TPM2_PT_VENDOR_STRING_3         ((TPM2_PT) (TPM2_PT_FIXED + 8))
/*! TPM2_PT_VENDOR_STRING_4 - the fourth 4 characters of the vendor ID string */
#define TPM2_PT_VENDOR_STRING_4         ((TPM2_PT) (TPM2_PT_FIXED + 9))
/*! TPM2_PT_VENDOR_TPM_TYPE - vendor-defined value indicating the TPM model */
#define TPM2_PT_VENDOR_TPM_TYPE         ((TPM2_PT) (TPM2_PT_FIXED + 10))
/*! TPM2_PT_FIRMWARE_VERSION_1 - the most-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware. */
#define TPM2_PT_FIRMWARE_VERSION_1      ((TPM2_PT) (TPM2_PT_FIXED + 11))
/*! TPM2_PT_FIRMWARE_VERSION_2 - the least-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware. */
#define TPM2_PT_FIRMWARE_VERSION_2      ((TPM2_PT) (TPM2_PT_FIXED + 12))
/*! TPM2_PT_INPUT_BUFFER - the maximum size of a parameter (typically, a TPM2B_MAX_BUFFER */
#define TPM2_PT_INPUT_BUFFER            ((TPM2_PT) (TPM2_PT_FIXED + 13))
/*! TPM2_PT_HR_TRANSIENT_MIN - the minimum number of transient objects that can be held in TPM RAM. */
#define TPM2_PT_HR_TRANSIENT_MIN        ((TPM2_PT) (TPM2_PT_FIXED + 14))
/*! TPM2_PT_HR_PERSISTENT_MIN - the minimum number of persistent objects that can be held in TPM NV memory. */
#define TPM2_PT_HR_PERSISTENT_MIN       ((TPM2_PT) (TPM2_PT_FIXED + 15))
/*! TPM2_PT_HR_LOADED_MIN - the minimum number of authorization sessions that can be held in TPM RAM */
#define TPM2_PT_HR_LOADED_MIN           ((TPM2_PT) (TPM2_PT_FIXED + 16))
/*! TPM2_PT_ACTIVE_SESSIONS_MAX - the number of authorization sessions that may be active at a time */
#define TPM2_PT_ACTIVE_SESSIONS_MAX     ((TPM2_PT) (TPM2_PT_FIXED + 17))
/*! TPM2_PT_PCR_COUNT - the number of PCRs implemented */
#define TPM2_PT_PCR_COUNT               ((TPM2_PT) (TPM2_PT_FIXED + 18))
/*! TPM2_PT_PCR_SELECT_MIN - the miniumum number of octets in a TPMS_PCR_SELECT.sizeOfSelect */
#define TPM2_PT_PCR_SELECT_MIN          ((TPM2_PT) (TPM2_PT_FIXED + 19))
/*! TPM2_PT_CONTEXT_GAP_MAX - the maximum allowed difference (unsigned) between the contextID values of two saved session contexts */
#define TPM2_PT_CONTEXT_GAP_MAX         ((TPM2_PT) (TPM2_PT_FIXED + 20))
/*! TPM2_PT_NV_COUNTERS_MAX - the maxumum number of NV indices that are allowed to have the TPM2_NT_COUNTER attribute */
#define TPM2_PT_NV_COUNTERS_MAX         ((TPM2_PT) (TPM2_PT_FIXED + 22))
/*! TPM2_PT_NV_INDEX_MAX - the maximum size of an NV Index data area */
#define TPM2_PT_NV_INDEX_MAX            ((TPM2_PT) (TPM2_PT_FIXED + 23))
/*! TPM2_PT_MEMORY - a TPMA_MEMORY indicating the memory management method for the TPM */
#define TPM2_PT_MEMORY                  ((TPM2_PT) (TPM2_PT_FIXED + 24))
/*! TPM2_PT_CLOCK_UPDATE - interval, in milliseconds, between updates to the copy of TPM2_CLOCK_INFO.clock in NV */
#define TPM2_PT_CLOCK_UPDATE            ((TPM2_PT) (TPM2_PT_FIXED + 25))
/*! TPM2_PT_CONTEXT_HASH - the algorithm used for the integrity HMAC on saved contexts and for hashing the fuData of TPM2_FirmwareRead() */
#define TPM2_PT_CONTEXT_HASH            ((TPM2_PT) (TPM2_PT_FIXED + 26))
/*! TPM2_PT_CONTEXT_SYM - TPM2_ALG_ID, the algorithm used for encryption of saved contexts */
#define TPM2_PT_CONTEXT_SYM             ((TPM2_PT) (TPM2_PT_FIXED + 27))
/*! TPM2_PT_CONTEXT_SYM_SIZE - TPM2_KEY_BITS, the size of the key used for encryption of saved contexts */
#define TPM2_PT_CONTEXT_SYM_SIZE        ((TPM2_PT) (TPM2_PT_FIXED + 28))
/*! TPM2_PT_ORDERLY_COUNT - the (modulus - 1) of the count for NV update of an orderly counter.  The returned value is MAX_ORDERLY_COUNT.
<p> This will have a value of 2^N –1, where 1 ≤ N ≤ 32. */
#define TPM2_PT_ORDERLY_COUNT           ((TPM2_PT) (TPM2_PT_FIXED + 29))
/*! TPM2_PT_MAX_COMMAND_SIZE - the maximum value for commandSize in a command */
#define TPM2_PT_MAX_COMMAND_SIZE        ((TPM2_PT) (TPM2_PT_FIXED + 30))
/*! TPM2_PT_MAX_RESPONSE_SIZE - the maximum value for responseSize in a response */
#define TPM2_PT_MAX_RESPONSE_SIZE       ((TPM2_PT) (TPM2_PT_FIXED + 31))
/*! TPM2_PT_MAX_DIGEST - the maximum size of a digest that can be produced by the TPM */
#define TPM2_PT_MAX_DIGEST              ((TPM2_PT) (TPM2_PT_FIXED + 32))
/*! TPM2_PT_MAX_OBJECT_CONTEXT - the maximum size of an object context that wil be returned by TPM2_ContextSave */
#define TPM2_PT_MAX_OBJECT_CONTEXT      ((TPM2_PT) (TPM2_PT_FIXED + 33))
/*! TPM2_PT_MAX_SESSION_CONTEXT - the maximum size of a session context that wil be returned by TPM2_ContextSave */
#define TPM2_PT_MAX_SESSION_CONTEXT     ((TPM2_PT) (TPM2_PT_FIXED + 34))
/*! TPM2_PT_PS_FAMILY_INDICATOR - platform-specific family (#TPM2_PS value) */
#define TPM2_PT_PS_FAMILY_INDICATOR     ((TPM2_PT) (TPM2_PT_FIXED + 35))
/*! TPM2_PT_PS_LEVEL - the level of the platform-specific specification */
#define TPM2_PT_PS_LEVEL                ((TPM2_PT) (TPM2_PT_FIXED + 36))
/*! TPM2_PT_PS_REVISION - the specification Revision times 100 for the platform-specific specification */
#define TPM2_PT_PS_REVISION             ((TPM2_PT) (TPM2_PT_FIXED + 37))
/*! TPM2_PT_PS_DAY_OF_YEAR - the platform-specific specification day of year using the TCG calendar */
#define TPM2_PT_PS_DAY_OF_YEAR          ((TPM2_PT) (TPM2_PT_FIXED + 38))
/*! TPM2_PT_PS_YEAR - the platform-specific specification year using the CE */
#define TPM2_PT_PS_YEAR                 ((TPM2_PT) (TPM2_PT_FIXED + 39))
/*! TPM2_PT_SLIT_MAX - the number of split signing operations supported by the TPM */
#define TPM2_PT_SPLIT_MAX               ((TPM2_PT) (TPM2_PT_FIXED + 40))
/*! TPM2_PT_TOTAL_COMMANDS - total number of commands implemented in the TPM */
#define TPM2_PT_TOTAL_COMMANDS          ((TPM2_PT) (TPM2_PT_FIXED + 41))
/*! TPM2_PT_LIBRARY_COMMANDS - number of commands from the TPM library that are implemented */
#define TPM2_PT_LIBRARY_COMMANDS        ((TPM2_PT) (TPM2_PT_FIXED + 42))
/*! TPM2_PT_VENDOR_COMMANDS - number of vendor commands that are implemented */
#define TPM2_PT_VENDOR_COMMANDS         ((TPM2_PT) (TPM2_PT_FIXED + 43))
/*! TPM2_PT_NV_BUFFER_MAX - the maximum data size in one NV write, NV read, or NV certify command */
#define TPM2_PT_NV_BUFFER_MAX           ((TPM2_PT) (TPM2_PT_FIXED + 44))
/*! TPM2_PT_MODES - a TPMA_MODES value, indicating that the TPM is designed for these modes. */
#define TPM2_PT_MODES                   ((TPM2_PT) (TPM2_PT_FIXED + 45))
/*! TPM2_PT_MAX_CAP_BUFFER - the maximum size ofa  TPMS_CAPABILITY_DATA structure returned in TPM2_GetCapability() */
#define TPM2_PT_MAX_CAP_BUFFER          ((TPM2_PT) (TPM2_PT_FIXED + 46))
/*! TPM2_PT_VAR - Group 2: The group of variable properties returned as #TPMS_TAGGED_PROPERTY */
#define TPM2_PT_VAR                     ((TPM2_PT) (TPM2_PT_GROUP * 2))
/*! TPM2_PT_PERMANENT - #TPMA_PERMANENT */
#define TPM2_PT_PERMANENT               ((TPM2_PT) (TPM2_PT_VAR + 0))
/*! TPM2_PT_STARTUP_CLEAR - #TPMA_STARTUP_CLEAR */
#define TPM2_PT_STARTUP_CLEAR           ((TPM2_PT) (TPM2_PT_VAR + 1))
/*! TPM2_PT_HR_NV_INDEX - the number of NV indices currently defined */
#define TPM2_PT_HR_NV_INDEX             ((TPM2_PT) (TPM2_PT_VAR + 2))
/*! TPM2_PT_HR_LOADED - the number of authorization sessions currently loaded into TPM RAM */
#define TPM2_PT_HR_LOADED               ((TPM2_PT) (TPM2_PT_VAR + 3))
/*! TPM2_PT_HR_LOADED_AVAIL - the number of additional authorization sessions, of any type, that could be loaded into TPM RAM. */
#define TPM2_PT_HR_LOADED_AVAIL         ((TPM2_PT) (TPM2_PT_VAR + 4))
/*! TPM2_PT_HR_ACTIVE - the number of active authorization sessions currently being tracked by the TPM */
#define TPM2_PT_HR_ACTIVE               ((TPM2_PT) (TPM2_PT_VAR + 5))
/*! TPM2_PT_HR_ACTIVE_AVAIL - the number of additional authorization sessions, of any type, that could be created */
#define TPM2_PT_HR_ACTIVE_AVAIL         ((TPM2_PT) (TPM2_PT_VAR + 6))
/*! TPM2_PT_HR_TRANSIENT_AVAILestimate of the number of additional transient objects that could be loaded into TPM RAM */
#define TPM2_PT_HR_TRANSIENT_AVAIL      ((TPM2_PT) (TPM2_PT_VAR + 7))
/*! TPM2_PT_HR_PERSISTENT - the number of persistent objects currently loaded into TPM NV memory */
#define TPM2_PT_HR_PERSISTENT           ((TPM2_PT) (TPM2_PT_VAR + 8))
/*! TPM2_PT_HR_PERSISTENT_AVAIL - the number of additional persistent objects that could be loaded into TPM NV memory */
#define TPM2_PT_HR_PERSISTENT_AVAIL     ((TPM2_PT) (TPM2_PT_VAR + 9))
/*! TPM2_PT_NV_COUNTERS - the number of defined NV indices that have the #TPM2_NT_COUNTER attribute */
#define TPM2_PT_NV_COUNTERS             ((TPM2_PT) (TPM2_PT_VAR + 10))
/*! TPM2_PT_NV_COUNTERS_AVAIL - the number of additional NV indices that can be defined with their #TPM2_NT or #TPM2_NT_COUNTER and the #TPMA_NV_ORDERLY attribute SET */
#define TPM2_PT_NV_COUNTERS_AVAIL       ((TPM2_PT) (TPM2_PT_VAR + 11))
/*! TPM2_PT_ALGORITHM_SET - code tha tlimits the algorithms that may be used with the TPM */
#define TPM2_PT_ALGORITHM_SET           ((TPM2_PT) (TPM2_PT_VAR + 12))
/*! TPM2_PT_LOADED_CURVES - the number of loaded ECC curves */
#define TPM2_PT_LOADED_CURVES           ((TPM2_PT) (TPM2_PT_VAR + 13))
/*! TPM2_PT_LOCKOUT_COUNTER - the current value of the lockout counter (failedTries) */
#define TPM2_PT_LOCKOUT_COUNTER         ((TPM2_PT) (TPM2_PT_VAR + 14))
/*! TPM2_PT_MAX_AUTH_FAIL - the number of authorization failures before DA lockout is invoked */
#define TPM2_PT_MAX_AUTH_FAIL           ((TPM2_PT) (TPM2_PT_VAR + 15))
/*! TPM2_PT_LOCKOUT_INTERVAL - the number of seconds before the value reported by #TPM2_PT_LOCKOUT_COUNTER is decremented */
#define TPM2_PT_LOCKOUT_INTERVAL        ((TPM2_PT) (TPM2_PT_VAR + 16))
/*! TPM2_PT_LOCKOUT_RECOVER - the number of seconds after a lockoutAuth failure before use of lockoutAuth may be attempted again */
#define TPM2_PT_LOCKOUT_RECOVERY        ((TPM2_PT) (TPM2_PT_VAR + 17))
/*! TPM2_PT_NV_WRITE_RECOVERY - number of milliseconds before the TPM will accept another command that will modify NV */
#define TPM2_PT_NV_WRITE_RECOVERY       ((TPM2_PT) (TPM2_PT_VAR + 18))
/*! TPM2_PT_AUDIT_COUNTER_0 - the high-order 32 bits of the command audit counter */
#define TPM2_PT_AUDIT_COUNTER_0         ((TPM2_PT) (TPM2_PT_VAR + 19))
/*! TPM2_PT_AUDIT_COUNTER_1 - the low-order 32 bits of the command audit counter */
#define TPM2_PT_AUDIT_COUNTER_1         ((TPM2_PT) (TPM2_PT_VAR + 20))


/*-------------------------------------------------------------------*/
/* Part 2, section 6.14: PCR Property Tag                            */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief PCR Property Tag
 * @details Constants used in TPM2_GetCapability() to indicate the property being selected or returned. The PCR properties can be read when capability == #TPM2_CAP_PCR_PROPERTIES. If there is no property that corresponds to the value of property, the next higher value is returned.
 * <p> TPM2_PT_PCR must be one of the following values:
 *  - #TPM2_PT_PCR_SAVE
 *  - #TPM2_PT_PCR_EXTEND_LO
 *  - #TPM2_PT_PCR_RESET_LO
 *  - #TPM2_PT_PCR_EXTEND_L1
 *  - #TPM2_PT_PCR_RESET_L1
 *  - #TPM2_PT_PCR_EXTEND_L2
 *  - #TPM2_PT_PCR_RESET_L2
 *  - #TPM2_PT_PCR_EXTEND_L3
 *  - #TPM2_PT_PCR_RESET_L3
 *  - #TPM2_PT_PCR_EXTEND_L4
 *  - #TPM2_PT_PCR_RESET_L4
 *  - #TPM2_PT_PCR_NO_INCREMENT
 *  - #TPM2_PT_PCR_DRTM_RESET
 *  - #TPM2_PT_PCR_POLICY
 *  - #TPM2_PT_PCR_AUTH
 */
typedef ubyte4 TPM2_PT_PCR;
/*! TPM2_PT_PCR_FIRST - the first value in the range of #TPM2_PT_PCR properties */
#define TPM2_PT_PCR_FIRST           ((TPM2_PT_PCR) 0x00000000)
/*! TPM2_PT_PCR_SAVE - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR is saved and restored by #TPM2_SU_STATE */
#define TPM2_PT_PCR_SAVE            ((TPM2_PT_PCR) 0x00000000)
/*! TPM2_PT_PCR_EXTEND_L0 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be extended from locality 0.  This property is only present if a locality other than 0 is implemented. */
#define TPM2_PT_PCR_EXTEND_L0       ((TPM2_PT_PCR) 0x00000001)
/*! TPM2_PT_PCR_RESET_L0 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 0 */
#define TPM2_PT_PCR_RESET_L0        ((TPM2_PT_PCR) 0x00000002)
/*! TPM2_PT_PCR_EXTEND_L1 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be extended from locality 1.  This property is only present if a locality other than 1 is implemented. */
#define TPM2_PT_PCR_EXTEND_L1       ((TPM2_PT_PCR) 0x00000003)
/*! TPM2_PT_PCR_RESET_L1 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 1 */
#define TPM2_PT_PCR_RESET_L1        ((TPM2_PT_PCR) 0x00000004)
/*! TPM2_PT_PCR_EXTEND_L2 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be extended from locality 2.  This property is only present if a locality other than 2 is implemented. */
#define TPM2_PT_PCR_EXTEND_L2       ((TPM2_PT_PCR) 0x00000005)
/*! TPM2_PT_PCR_RESET_L2 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 2 */
#define TPM2_PT_PCR_RESET_L2        ((TPM2_PT_PCR) 0x00000006)
/*! TPM2_PT_PCR_EXTEND_L3 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be extended from locality 3.  This property is only present if a locality other than 3 is implemented. */
#define TPM2_PT_PCR_EXTEND_L3       ((TPM2_PT_PCR) 0x00000007)
/*! TPM2_PT_PCR_RESET_L3 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 3 */
#define TPM2_PT_PCR_RESET_L3        ((TPM2_PT_PCR) 0x00000008)
/*! TPM2_PT_PCR_EXTEND_L4 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be extended from locality 4.  This property is only present if a locality other than 4 is implemented. */
#define TPM2_PT_PCR_EXTEND_L4       ((TPM2_PT_PCR) 0x00000009)
/*! TPM2_PT_PCR_RESET_L4 - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 4 */
#define TPM2_PT_PCR_RESET_L4        ((TPM2_PT_PCR) 0x0000000A)
/*! TPM2_PT_PCR_NO_INCREMENT - a SET bit in the #TPMS_PCR_SELECT indicates that modifications to this PCR (Reset or Extend) will not increment the pcrUpdateCounter */
#define TPM2_PT_PCR_NO_INCREMENT    ((TPM2_PT_PCR) 0x00000011)
/*! TPM2_PT_PCR_DRTM_RESET - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR is reset by a D-RTM event.
<p>These PCRs are reset to -1 on TPM2_Startup() and reset to 0 on a _TPM2_Hash_End event following a _TPM2_Hash_Start event. 
*/
#define TPM2_PT_PCR_DRTM_RESET      ((TPM2_PT_PCR) 0x00000012)
/*! TPM2_PT_PCR_POLICY - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR is controlled by policy.
<p>This property is only present if the TPM supports policy control of a PCR.
*/
#define TPM2_PT_PCR_POLICY          ((TPM2_PT_PCR) 0x00000013)
/*! TPM2_PT_PCR_AUTH - a SET bit in the #TPMS_PCR_SELECT indicates that the PCR is controlled by an authorization value.
<p>This property is only present if the TPM supports authorization control of a PCR.
*/
#define TPM2_PT_PCR_AUTH            ((TPM2_PT_PCR) 0x00000014)
/*! TPM2_PT_PCR_LAST - the last value in the range of #TPM2_PT_PCR properties */
#define TPM2_PT_PCR_LAST            ((TPM2_PT_PCR) 0x00000014)


/*-------------------------------------------------------------------*/
/* Part 2, section 6.15: Platform Specific                           */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Plaform Specific
 * @details Platform values used for the #TPM2_PT_PS_FAMILY_INDICATOR.
 * <p> TPM2_PS must be one of the following values:
 *  - #TPM2_PS_MAIN
 *  - #TPM2_PS_PC
 *  - #TPM2_PS_PDA
 *  - #TPM2_PS_CELL_PHONE
 *  - #TPM2_PS_SERVER
 *  - #TPM2_PS_PERIPHERAL
 *  - #TPM2_PS_TSS
 *  - #TPM2_PS_STORAGE
 *  - #TPM2_PS_AUTHENTICATION
 *  - #TPM2_PS_EMBEDDED
 *  - #TPM2_PS_HARDCOPY
 *  - #TPM2_PS_INFRASTRUCTURE
 *  - #TPM2_PS_VIRTUALIZATION
 *  - #TPM2_PS_TNC
 *  - #TPM2_PS_MULTI_TENANT
 *  - #TPM2_PS_TC
 */
typedef ubyte4 TPM2_PS;
/*! TPM2_PS_MAIN - not plaftorm specific */
#define TPM2_PS_MAIN            ((TPM2_PS) 0x00000000)
/*! TPM2_PS_PC - PC Client */
#define TPM2_PS_PC              ((TPM2_PS) 0x00000001)
/*! TPM2_PS_PDA - PDA (includes all mobile devices that are not specifically cell phones) */
#define TPM2_PS_PDA             ((TPM2_PS) 0x00000002)
/*! TPM2_PS_CELL_PHONE - Cell Phone */
#define TPM2_PS_CELL_PHONE      ((TPM2_PS) 0x00000003)
/*! TPM2_PS_SERVER - Server WG */
#define TPM2_PS_SERVER          ((TPM2_PS) 0x00000004)
/*! TPM2_PS_PERIPHERAL - Peripheral WG */
#define TPM2_PS_PERIPHERAL      ((TPM2_PS) 0x00000005)
/*! TPM2_PS_TSS - TSS WG */
#define TPM2_PS_TSS             ((TPM2_PS) 0x00000006)
/*! TPM2_PS_STORAGE - Storage WG */
#define TPM2_PS_STORAGE         ((TPM2_PS) 0x00000007)
/*! TPM2_PS_AUTHENTICATION - Authentication WG */
#define TPM2_PS_AUTHENTICATION  ((TPM2_PS) 0x00000008)
/*! TPM2_PS_EMBEDDED - Embedded WG */
#define TPM2_PS_EMBEDDED        ((TPM2_PS) 0x00000009)
/*! TPM2_PS_HARDCOPY - Hardcopy WG */
#define TPM2_PS_HARDCOPY        ((TPM2_PS) 0x0000000A)
/*! TPM2_PS_INFRASTRUCTURE - Infrastructure WG */
#define TPM2_PS_INFRASTRUCTURE  ((TPM2_PS) 0x0000000B)
/*! TPM2_PS_VIRTUALIZATION - Virtualization WG */
#define TPM2_PS_VIRTUALIZATION  ((TPM2_PS) 0x0000000C)
/*! TPM2_PS_TNC - Trusted Network Connect WG */
#define TPM2_PS_TNC             ((TPM2_PS) 0x0000000D)
/*! TPM2_PS_MULTI_TENANT - Multi-tenant WG */
#define TPM2_PS_MULTI_TENANT    ((TPM2_PS) 0x0000000E)
/*! TPM2_PS_TC - Techical Committee */
#define TPM2_PS_TC              ((TPM2_PS) 0x0000000F)


/*-------------------------------------------------------------------*/
/* Part 2, section 7.1: Handles                                      */
/*-------------------------------------------------------------------*/

/*! TPM2_HANDLE - 32-bit value used to reference shielded locations of various types within the TPM */
typedef ubyte4 TPM2_HANDLE;

/*-------------------------------------------------------------------*/
/* Part 2, section 7.2: Handle Types                                 */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Handle Types
 * @details The 32-bit handle space is divided into 256 regions of equal size with 224 values in each. Each of these ranges represents a handle type.
 * <p> The type of the entity is indicated by the MSO of its handle.
 * <p> TPM2_HT must be one of the following values:
 *  - #TPM2_HT_PCR
 *  - #TPM2_HT_NV_INDEX
 *  - #TPM2_HT_HMAC_SESSION
 *  - #TPM2_HT_LOADED_SESSION
 *  - #TPM2_HT_POLICY_SESSION
 *  - #TPM2_HT_SAVED_SESSION
 *  - #TPM2_HT_PERMANENT
 *  - #TPM2_HT_TRANSIENT
 *  - #TPM2_HT_PERSISTENT
 */
typedef ubyte TPM2_HT;
/*! TPM2_HT_PCR - entity = PCR; consecutive numbers, starting at 0, that reference the PCR registers */  
#define TPM2_HT_PCR             ((TPM2_HT) 0x00)
/*! TPM2_HT_NV_INDEX - entity = NV Index; assigned by the caller */ 
#define TPM2_HT_NV_INDEX        ((TPM2_HT) 0x01)
/*! TPM2_HT_HMAC_SESSION - entity = HMAC Authorization Session; assigned by the TPM when the session is created */
#define TPM2_HT_HMAC_SESSION    ((TPM2_HT) 0x02)
/*! TPM2_HT_LOADED_SESSION - entity = Loaded Authorization Session; used only in the context of #TPM2_GetCapability.  This type references both loaded HMAC and loaded policy authorization sessions. */
#define TPM2_HT_LOADED_SESSION  ((TPM2_HT) 0x02)
/*! TPM2_HT_POLICY_SESSION - entity = Policy Authorization Session; assigned by the TPM when the session is created */
#define TPM2_HT_POLICY_SESSION  ((TPM2_HT) 0x03)
/*! TPM2_HT_SAVE_SESSION - entity = Saved Authorization Session; used only in the context of #TPM2_GetCapability.  This type references saved authorization session contexts for which the TPM is maintaining tracking information. */ 
#define TPM2_HT_SAVED_SESSION   ((TPM2_HT) 0x03)
/*! TPM2_HT_PERMANENT - entity = Permanent Values; assigned by the specification */
#define TPM2_HT_PERMANENT       ((TPM2_HT) 0x40)
/*! TPM2_HT_TRANSIENT - entity = Transient Objects; assigned by the TPM when an object is loaded into transient-object memory or when a persistent object is converted to a transient object. */
#define TPM2_HT_TRANSIENT       ((TPM2_HT) 0x80)
/*! TPM2_HT_PERSISTENT - entity = Persistent Objects; assigned by the TPM when a loaded transient object is made persistent. */
#define TPM2_HT_PERSISTENT      ((TPM2_HT) 0x81)


/*-------------------------------------------------------------------*/
/* Part 2, section 7.4: Permanent Handles                            */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Permanent Handles
 * @details Architecturally defined handles that cannot be changed.  The handle include authorization handles and special handles.
 * <p> TPM2_RH must be one of the following values:
 *  - #TPM2_RH_SRK
 *  - #TPM2_RH_OWNER
 *  - #TPM2_RH_REVOKE
 *  - #TPM2_RH_TRANSPORT
 *  - #TPM2_RH_OPERATOR
 *  - #TPM2_RH_ADMIN
 *  - #TPM2_RH_EK
 *  - #TPM2_RH_NULL
 *  - #TPM2_RH_UNASSIGNED
 *  - #TPM2_RH_PW
 *  - #TPM2_RH_LOCKOUT
 *  - #TPM2_RH_ENDORSEMENT
 *  - #TPM2_RH_PLATFORM
 *  - #TPM2_RH_PLATFORM_NV
 *  - #TPM2_RH_AUTH_00
 *  - #TPM2_RH_AUTH_FF
 */
typedef TPM2_HANDLE TPM2_RH;
/*! TPM2_RH_FIRST  - first valid value for TPM2_RH */
#define TPM2_RH_FIRST           ((TPM2_RH) 0x40000000)
/*! TPM2_RH_SRK - Not used; for compatability with previous version of spec */
#define TPM2_RH_SRK             ((TPM2_RH) 0x40000000)
/*! TPM2_RH_OWNER - handle referencing the Storage Primary Seed (SPS), the ownerAuth, and the ownerPolicy */ 
#define TPM2_RH_OWNER           ((TPM2_RH) 0x40000001)
/*! TPM2_RH_REVOKE - Not used - for compatability with previous version of spec */
#define TPM2_RH_REVOKE          ((TPM2_RH) 0x40000002)
/*! TPM2_RH_TRANSPORT - Not used - for compatability with previous version of spec */
#define TPM2_RH_TRANSPORT       ((TPM2_RH) 0x40000003)
/*! TPM2_RH_OPERATOR - Not used - for compatability with previous version of spec */
#define TPM2_RH_OPERATOR        ((TPM2_RH) 0x40000004)
/*! TPM2_RH_ADMIN - Not used - for compatability with previous version of spec */
#define TPM2_RH_ADMIN           ((TPM2_RH) 0x40000005)
/*! TPM2_RH_EK - Not used - for compatability with previous version of spec */
#define TPM2_RH_EK              ((TPM2_RH) 0x40000006)
/*! TPM2_RH_NULL - a handle associated with the null hierarchy, an EmptyAuth authValue, and an Empty Policy authPolicy */
#define TPM2_RH_NULL            ((TPM2_RH) 0x40000007)
/*! TPM2_RH_UNASSIGNED - value reserved to the TPM to indicate a handle location that has not been initialized or assigned */
#define TPM2_RH_UNASSIGNED      ((TPM2_RH) 0x40000008)
/*! TPM2_RH_PW - authorization value used to indicate a password authorization session */
#define TPM2_RS_PW              ((TPM2_RH) 0x40000009)
/*! TPM2_RH_LOCKOUT - references the authorization associated with the dictionary attack lockout reset */
#define TPM2_RH_LOCKOUT         ((TPM2_RH) 0x4000000A)
/*! TPM2_RH_ENDORSEMENT - references the Endorsement Primary Seed (EPS), endorsementAuth, and endorsementPolicy */
#define TPM2_RH_ENDORSEMENT     ((TPM2_RH) 0x4000000B)
/*! TPM2_RH_PLATFORM - references the Platform Primary Seed (PPS), platformAuth, and platformPolicy */
#define TPM2_RH_PLATFORM        ((TPM2_RH) 0x4000000C)
/*! TPM2_RH_PLATFORM_NV - for phEnableNV */
#define TPM2_RH_PLATFORM_NV     ((TPM2_RH) 0x4000000D)
/*! TPM2_RH_AUTH_00 - start of a range of authorization values that are vendor-specific.  A TPM may support any of the values in this range as are needed for vendor-specific purposes.
<p> Disabled if ehEnable is CLEAR */
#define TPM2_RH_AUTH_00         ((TPM2_RH) 0x40000010)
/*! TPM2_RH_AUTH_FF - end of the range of vendor-specific authorization values */
#define TPM2_RH_AUTH_FF         ((TPM2_RH) 0x4000010F)
/*! TPM2_RH_LAST - last valid value for TPM2_RH */
#define TPM2_RH_LAST            ((TPM2_RH) 0x4000010F)


/*-------------------------------------------------------------------*/
/* Part 2, section 7.5: Handle Value Constants                       */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief Handle Value Constants
 * @details Definitions used to define many of the interface data types.
 * <p> These values, that indicate ranges, are informative and may be changed by an implementation. The TPM will always return the correct handle type.
 * <p> TPM2_HC must be one of the following values:
 *  - #TPM2_HR_PCR
 *  - #TPM2_HR_HMAC_SESSION
 *  - #TPM2_HR_POLICY_SESSION
 *  - #TPM2_HR_TRANSIENT
 *  - #TPM2_HR_PERSISTENT
 *  - #TPM2_HR_NV_INDEX
 *  - #TPM2_HR_PERMANENT
 *  - #TPM2_HR_PCR_FIRST
 *  - #TPM2_HR_PCR_LAST
 *  - #TPM2_HR_HMAC_SESSION_FIRST
 *  - #TPM2_HR_HMAC_SESSION_LAST
 *  - #TPM2_HR_LOADED_SESSION_FIRST
 *  - #TPM2_HR_LOADED_SESSION_LAST
 *  - #TPM2_HR_POLICY_SESSION_FIRST
 *  - #TPM2_HR_POLICY_SESSION_LAST
 *  - #TPM2_HR_TRANSIENT_FIRST
 *  - #TPM2_HR_ACTIVE_SESSION_FIRST
 *  - #TPM2_HR_ACTIVE_SESSION_LAST
 *  - #TPM2_HR_TRANSIENT_LAST
 *  - #TPM2_HR_PERSISTENT_FIRST
 *  - #TPM2_HR_PERSISTENT_LAST
 *  - #TPM2_HR_PLATFORM_PERSISTENT
 *  - #TPM2_HR_NV_INDEX_FIRST
 *  - #TPM2_HR_NV_INDEX_LAST
 *  - #TPM2_HR_PERMANENT_FIRST
 *  - #TPM2_HR_PERMANENT_LAST
 */
typedef TPM2_HANDLE TPM2_HC;
/*! TPM2_HR_HANDLE_MASK - used to mask off the HR */
#define TPM2_HR_HANDLE_MASK         ((TPM2_HC) 0x00FFFFFF)
/*! TPM2_HR_RANGE_MASK - used to mask off the variable part */
#define TPM2_HR_RANGE_MASK          ((TPM2_HC) 0xFF000000)
/*! TPM2_HR_SHIFT - number of bits to shift to get value */
#define TPM2_HR_SHIFT               ((TPM2_HC) 24)
/*! TPM2_HR_PCR - (#TPM2_HT_PCR << #HR_SHIFT) */
#define TPM2_HR_PCR                 ((TPM2_HC) (TPM2_HT_PCR << TPM2_HR_SHIFT))
/*! TPM2_HR_HMAC_SESSION - (#TPM2_HT_HMAC_SESSION << #HR_SHIFT) */
#define TPM2_HR_HMAC_SESSION        ((TPM2_HC) (TPM2_HT_HMAC_SESSION << TPM2_HR_SHIFT))
/*! TPM2_HR_POLICY_SESSION - (#TPM2_HT_POLICY_SESSION << #HR_SHIFT) */
#define TPM2_HR_POLICY_SESSION      ((TPM2_HC) (TPM2_HT_POLICY_SESSION << TPM2_HR_SHIFT))
/*! TPM2_HR_TRANSIENT - (#TPM2_HT_TRANSIENT << #HR_SHIFT) */
#define TPM2_HR_TRANSIENT           ((TPM2_HC) (TPM2_HT_TRANSIENT << TPM2_HR_SHIFT))
/*! TPM2_HR_PERSISTENT - (#TPM2_HT_PERSISTENT << #HR_SHIFT) */
#define TPM2_HR_PERSISTENT          ((TPM2_HC) (TPM2_HT_PERSISTENT << TPM2_HR_SHIFT))
/*! TPM2_HR_NV_INDEX - (#TPM2_HT_NV_INDEX << #HR_SHIFT) */
#define TPM2_HR_NV_INDEX            ((TPM2_HC) (TPM2_HT_NV_INDEX << TPM2_HR_SHIFT))
/*! TPM2_HR_PERMANENT - (#TPM2_HT_PERMANENT << #HR_SHIFT) */
#define TPM2_HR_PERMANENT           ((TPM2_HC) (TPM2_HT_PERMANENT << TPM2_HR_SHIFT))
/*! TPM2_PCR_FIRST - first PCR */
#define TPM2_PCR_FIRST              ((TPM2_HC) (TPM2_HR_PCR + 0))
/*! TPM2_PCR_LAST - last PCR */
#define TPM2_PCR_LAST               ((TPM2_HC) (TPM2_PCR_FIRST + TPM2_MAX_PCRS-1))
/*! TPM2_HMAC_SESSION_FIRST - first HMAC session */
#define TPM2_HMAC_SESSION_FIRST     ((TPM2_HC) (TPM2_HR_HMAC_SESSION+ 0))
/*! TPM2_HMAC_SESSION_LAST - last HMAC session */
#define TPM2_HMAC_SESSION_LAST      ((TPM2_HC) (TPM2_HMAC_SESSION_FIRST+0x00fffffe))
/*! TPM2_LOADED_SESSION_FIRST - used in GetCapability */
#define TPM2_LOADED_SESSION_FIRST   ((TPM2_HC) TPM2_HMAC_SESSION_FIRST)
/*! TPM2_LOADED_SESSION_LAST - used in GetCapability */
#define TPM2_LOADED_SESSION_LAST    ((TPM2_HC) TPM2_HMAC_SESSION_LAST)
/*! TPM2_POLICY_SESSION_FIRST - first policy session */
#define TPM2_POLICY_SESSION_FIRST   ((TPM2_HC) (TPM2_HR_POLICY_SESSION+ 0))
/*! TPM2_POLICY_SESSION_LAST - last policy session */
#define TPM2_POLICY_SESSION_LAST    ((TPM2_HC) (TPM2_POLICY_SESSION_FIRST + 0x00fffffe))
/*! TPM2_TRANSIENT_FIRST - first transient object */
#define TPM2_TRANSIENT_FIRST        ((TPM2_HC) (TPM2_HR_TRANSIENT +0))
/*! TPM2_ACTIVE_SESSION_FIRST - used in GetCapability */
#define TPM2_ACTIVE_SESSION_FIRST   ((TPM2_HC) TPM2_POLICY_SESSION_FIRST)
/*! TPM2_ACTIVE_SESSION_LAST - used in GetCapability */
#define TPM2_ACTIVE_SESSION_LAST    ((TPM2_HC) TPM2_POLICY_SESSION_LAST)
/*! TPM2_TRANSIENT_LAST - last transient object */
#define TPM2_TRANSIENT_LAST         ((TPM2_HC) (TPM2_TRANSIENT_FIRST+0x00fffffe))
/*! TPM2_PERSISTENT_FIRST - first persistent object */
#define TPM2_PERSISTENT_FIRST       ((TPM2_HC) (TPM2_HR_PERSISTENT+0))
/*! TPM2_PERSISTENT_LAST - last persistent object */
#define TPM2_PERSISTENT_LAST        ((TPM2_HC) (TPM2_PERSISTENT_FIRST+0x00FFFFFF))
/*! TPM2_PLATFORM_PERSISTENT - first platform persistent object */
#define TPM2_PLATFORM_PERSISTENT    ((TPM2_HC) (TPM2_PERSISTENT_FIRST + 0x00800000))
/*! TPM2_NV_INDEX_FIRST - first allowed NV Index */
#define TPM2_NV_INDEX_FIRST         ((TPM2_HC) (TPM2_HR_NV_INDEX + 0))
/*! TPM2_NV_INDEX_LAST - last allowed NV Index */
#define TPM2_NV_INDEX_LAST          ((TPM2_HC) (TPM2_NV_INDEX_FIRST + 0x00FFFFFF))
/*! TPM2_PERMANENT_FIRST - #TPM2_RH_FIRST */
#define TPM2_PERMANENT_FIRST        ((TPM2_HC) TPM2_RH_FIRST)
/*! TPM2_PERMANENT_LAST - #TPM2_RH_LAST */
#define TPM2_PERMANENT_LAST         ((TPM2_HC) TPM2_RH_LAST)



/*-------------------------------------------------------------------*/
/* Part 2, section 8: Attribute Structures                           */
/*-------------------------------------------------------------------*/

/*-------------------------------------------------------------------*/
/* Part 2, section 8.2: TPMA_ALGORITHM bits                          */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_ALGORITHM bits
 * @details The bit definitions used to indicate one or more attributes of an algorithm.
<p> Each algorithm has a fundamental attribute: asymmetric, symmetric, or hash.  In some cases (e.g. TPM2_ALG_RSA or TPM2_ALG_AES), this is the only attribute.  Thus, only 1 bit will be set.
 * <p> The following bit masks are defined for #TPMA_ALGORITHM:
 *  - #TPMA_ALGORITHM_ASYMMETRIC
 *  - #TPMA_ALGORITHM_SYMMETRIC
 *  - #TPMA_ALGORITHM_HASH
 *  - #TPMA_ALGORITHM_OBJECT
 *  - #TPMA_ALGORITHM_RESERVED1_MASK
 *  - #TPMA_ALGORITHM_SIGNING
 *  - #TPMA_ALGORITHM_ENCRYPTING
 *  - #TPMA_ALGORITHM_METHOD
 *  - #TPMA_ALGORITHM_RESERVED2_MASK
 */
typedef ubyte4 TPMA_ALGORITHM;
/*! TPMA_ALGORITHM_ASYMMETRIC - Bit 0; when SET, indicates an assymetric algorithm with public and private portions */
#define TPMA_ALGORITHM_ASYMMETRIC         ((TPMA_ALGORITHM) 0x00000001)
/*! TPMA_ALGORITHM_SYMMETRIC - Bit 1; when SET, indicates a symetric block cipher */
#define TPMA_ALGORITHM_SYMMETRIC          ((TPMA_ALGORITHM) 0x00000002)
/*! TPMA_ALGORITHM_HASH -  Bit 2; when SET, indicates a hash algorithm */
#define TPMA_ALGORITHM_HASH               ((TPMA_ALGORITHM) 0x00000004)
/*! TPMA_ALGORITHM_OBJECT -  Bit 3; when SET, indicates an algorithm that may be used as an object type */
#define TPMA_ALGORITHM_OBJECT             ((TPMA_ALGORITHM) 0x00000008)
/*! TPMA_ALGORITHM_RESERVED1_MASK - Bits 7:4 are reserved */
#define TPMA_ALGORITHM_RESERVED1_MASK     ((TPMA_ALGORITHM) 0x000000f0)
/*! TPMA_ALGORITHM_SIGNING - Bit 8; when SET, indicates a signing algorithm.  The setting of asymmetric, symmetric, and hash will indicate the type of signing algorithm. */
#define TPMA_ALGORITHM_SIGNING            ((TPMA_ALGORITHM) 0x00000100)
/*! TPMA_ALGORITHM_ENCRYPTING - Bit 9; when SET, indicates an encryption/decryption algorithm.  The setting of asymmetric, symmetric, and hash will indicate the type of encryption/decryption algorithm. */
#define TPMA_ALGORITHM_ENCRYPTING         ((TPMA_ALGORITHM) 0x00000200)
/*! TPMA_ALGORITHM_METHOD  - Bit 10: when SET, indicates a method such as the key derivation function */
#define TPMA_ALGORITHM_METHOD             ((TPMA_ALGORITHM) 0x00000400)
/*! TPMA_ALGORITHM_RESERVED2_MASK  - Bits 31:11 are reserved */
#define TPMA_ALGORITHM_RESERVED2_MASK     ((TPMA_ALGORITHM) 0xfffff800)


/*-------------------------------------------------------------------*/
/* Part 2, section 8.3: TPMA_OBJECT bits                             */
/* See section 8.3.3 for descriptions of each bit                    */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_OBJECT bits
 * @details The bit definitions used to indicate an object's use, its authorization types, and its relationship to other objects.
<p> The state of the attributes is determined when the object is created and they are never changed by the TPM.
 * <p> The following bit masks are defined for #TPMA_OBJECT:
 *  - #TPMA_OBJECT_FIXEDTPM
 *  - #TPMA_OBJECT_STCLEAR
 *  - #TPMA_OBJECT_FIXEDPARENT
 *  - #TPMA_OBJECT_SENSITIVEDATAORIGIN
 *  - #TPMA_OBJECT_USERWITHAUTH
 *  - #TPMA_OBJECT_ADMINWITHPOLICY
 *  - #TPMA_OBJECT_NODA
 *  - #TPMA_OBJECT_ENCRYPTEDDUPLICATION
 *  - #TPMA_OBJECT_RESTRICTED
 *  - #TPMA_OBJECT_DECRYPT
 *  - #TPMA_OBJECT_SIGN_ENCRYPT
 * <p> The following bit masks define reserved bits for #TPMA_OBJECT:
 *  - #TPMA_OBJECT_RESERVED1_MASK
 *  - #TPMA_OBJECT_RESERVED2_MASK
 *  - #TPMA_OBJECT_RESERVED3_MASK
 *  - #TPMA_OBJECT_RESERVED4_MASK
 *  - #TPMA_OBJECT_RESERVED5_MASK
 */
typedef ubyte4 TPMA_OBJECT;
/*! TPMA_OBJECT_RESERVED1_MASK - reserved bit; shall be zero */
#define TPMA_OBJECT_RESERVED1_MASK            ((TPMA_OBJECT) 0x00000001)
/*! TPMA_OBJECT_FIXEDTPM - if SET, hierarchy of object may not change */
#define TPMA_OBJECT_FIXEDTPM                  ((TPMA_OBJECT) 0x00000002)
/*! TPMA_OBJECT_STCLEAR - if SET, previously saved contexts of this object may not be loaded after Startup(CLEAR) */
#define TPMA_OBJECT_STCLEAR                   ((TPMA_OBJECT) 0x00000004)
/*! TPMA_OBJECT_RESERVED2_MASK - reserved bit; shall be zero */
#define TPMA_OBJECT_RESERVED2_MASK            ((TPMA_OBJECT) 0x00000008)
/*! TPMA_OBJECT_FIXEDPARENT - if SET, parent of object may not change */
#define TPMA_OBJECT_FIXEDPARENT               ((TPMA_OBJECT) 0x00000010)
/*! TPMA_OBJECT_SENSITIVEDATAORIGIN - if SET, TPM generated all sensitive data on creation, except for the authData */
#define TPMA_OBJECT_SENSITIVEDATAORIGIN       ((TPMA_OBJECT) 0x00000020)
/*! TPMA_OBJECT_USERWITHAUTH - if SET, Approval of USER role actions may be with HMAC session or with a password */
#define TPMA_OBJECT_USERWITHAUTH              ((TPMA_OBJECT) 0x00000040)
/*! TPMA_OBJECT_ADMINWITHPOLICY - if SET, Approval of ADMIN role actions may only be done with a policy session */
#define TPMA_OBJECT_ADMINWITHPOLICY           ((TPMA_OBJECT) 0x00000080)
/*! TPMA_OBJECT_RESERVED3_MASK - reserved bits; shall be zero */
#define TPMA_OBJECT_RESERVED3_MASK            ((TPMA_OBJECT) 0x00000300)
/*! TPMA_OBJECT_NODA - if SET, object is not subject to dictionary attack protections */
#define TPMA_OBJECT_NODA                      ((TPMA_OBJECT) 0x00000400)
/*! TPMA_OBJECT_ENCRYPTDUPLICATION - if SET, if object is duplicated, symmetricAlg shall not be TPM2_ALG_NULL and newParentHandle shall not be TPM2_RH_NULL */
#define TPMA_OBJECT_ENCRYPTEDDUPLICATION      ((TPMA_OBJECT) 0x00000800)
/*! TPMA_OBJECT_RESERVED4_MASK - reserved bits; shall be zero */
#define TPMA_OBJECT_RESERVED4_MASK            ((TPMA_OBJECT) 0x0000f000)
/*! TPMA_OBJECT_RESTRICTED - if SET, key usage is restricted to manipulate structures of known format */
#define TPMA_OBJECT_RESTRICTED                ((TPMA_OBJECT) 0x00010000)
/*! TPMA_OBJECT_DECRYPT - if SET, private portion of key may be used to decrypt */
#define TPMA_OBJECT_DECRYPT                   ((TPMA_OBJECT) 0x00020000)
/*! TPMA_OBJECT_SIGN_ENCRYPT - if SET, private portion of key may be used to sign */
#define TPMA_OBJECT_SIGN_ENCRYPT              ((TPMA_OBJECT) 0x00040000)
/*! TPMA_OBJECT_RESERVED5_MASK - reserved bits; shall be zero */
#define TPMA_OBJECT_RESERVED5_MASK            ((TPMA_OBJECT) 0xfff80000)


/*-------------------------------------------------------------------*/
/* Part 2, section 8.4: TPMA_SESSION bits                            */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_SESSION bits
 * @details The bit definitions used to identify the session type, indicate its relationship to any handles in the command, and indicate its use in parameter encryption.
<p> If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be SET.
 * <p> The following bit masks are defined for #TPMA_SESSION:
 *  - #TPMA_SESSION_CONTINUESESSION
 *  - #TPMA_SESSION_AUDITEXCLUSIVE
 *  - #TPMA_SESSION_AUDITRESET
 *  - #TPMA_SESSION_RESERVED1_MASK
 *  - #TPMA_SESSION_DECRYPT
 *  - #TPMA_SESSION_ENCRYPT
 *  - #TPMA_SESSION_AUDIT
 */
typedef ubyte TPMA_SESSION;
/*! TPMA_SESSION_CONTINUESESSION - if SET: In a command, indicates the session is to remain active after successful completion of command.  In a response, indicates that the session is still active. */
#define TPMA_SESSION_CONTINUESESSION      ((TPMA_SESSION) 0x01)
/*! TPMA_SESSION_AUDITEXCLUSIVE - if SET: In a command, indicates that the command should only be executed if session is exclusive at start of the command. In a response, indicates that the session is exclusive. */
#define TPMA_SESSION_AUDITEXCLUSIVE       ((TPMA_SESSION) 0x02)
/*! TPMA_SESSION_AUDITRESET - if SET: In a command, indicates that the audit digest of the session should be initialized and the exclusive status of the session SET. This setting is only allowed if the audit attribute is SET (#TPM2_RC_ATTRIBUTES) */
#define TPMA_SESSION_AUDITRESET           ((TPMA_SESSION) 0x04)
/*! TPMA_SESSION_RESERVED1_MASK - Reserved bits; should be CLEAR */
#define TPMA_SESSION_RESERVED1_MASK       ((TPMA_SESSION) 0x18)
/*! TPMA_SESSION_DECRYPT - If SET: In a command, indicates that the first parameter in the command is symmetrically encrypted. The TPM will decrypt the parameter.  In a response, the attribute is copied from the request but has not effect on the response. */
#define TPMA_SESSION_DECRYPT              ((TPMA_SESSION) 0x20)
/*! TPMA_SESSION_ENCRYPT - If SET: In a command, indicates that the TPM should use this session to encrypt the first parameter in the response.  In a response, indicates that the attribute was set in the command and the TPM used the session to encrypt the first parameter in the response. */
#define TPMA_SESSION_ENCRYPT              ((TPMA_SESSION) 0x40)
/*! TPMA_SESSION_AUDIT - If SET: In a command or response, indicates that the session is for audit and that auditExclusive and auditReset have meaning. */
#define TPMA_SESSION_AUDIT                ((TPMA_SESSION) 0x80)



/*-------------------------------------------------------------------*/
/* Part 2, section 8.5: TPM2_LOC bits defined in tpm_common.h        */
/* Redefined here with new 2.0 names                                 */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_LOCALITY
 * @details Bit map indicating the locality
  <p> In a TPMS_CREATION_DATA structure, this is used in indicate the locality of the command that created the object.  No more than one of the locality attributes shall be set in the creation data.
  <p> When used in TPM2_PolicyLocality(), this indicates which localities are approved by the policy.  When a policy is started, all localities are allowed.  TPM2_PolicyLocality() is used to restrict commands to only be executed at specific localities  More than one locality may be selected.
 * <p> The following bit masks are defined for #TPMA_LOCALITY:
 *  - #TPMA_LOCALITY_TPM2_LOC_ZERO
 *  - #TPMA_LOCALITY_TPM2_LOC_ONE
 *  - #TPMA_LOCALITY_TPM2_LOC_TWO
 *  - #TPMA_LOCALITY_TPM2_LOC_THREE
 *  - #TPMA_LOCALITY_TPM2_LOC_FOUR
 *  - #TPMA_LOCALITY_EXTENDED_MASK
 *  - #TPMA_LOCALITY_EXTENDED_SHIFT
 */
typedef ubyte TPMA_LOCALITY;
/*! TPMA_LOCALITY_TPM2_LOC_ZERO - same as TPM_LOC_ZERO */
#define TPMA_LOCALITY_TPM2_LOC_ZERO       ((TPMA_LOCALITY) 0x01)
/*! TPMA_LOCALITY_TPM2_LOC_ONE - same as TPM_LOC_ONE */
#define TPMA_LOCALITY_TPM2_LOC_ONE        ((TPMA_LOCALITY) 0x02)
/*! TPMA_LOCALITY_TPM2_LOC_TWO - same as TPM_LOC_TWO */
#define TPMA_LOCALITY_TPM2_LOC_TWO        ((TPMA_LOCALITY) 0x04)
/*! TPMA_LOCALITY_TPM2_LOC_THREE - same as TPM_LOC_THREE */
#define TPMA_LOCALITY_TPM2_LOC_THREE      ((TPMA_LOCALITY) 0x08)
/*! TPMA_LOCALITY_TPM2_LOC_FOUR - same as TPM_LOC_FOUR */
#define TPMA_LOCALITY_TPM2_LOC_FOUR       ((TPMA_LOCALITY) 0x10)
/*! TPMA_LOCALITY_EXTENDED_MASK - masks off bits 7:4 for extended locality */
#define TPMA_LOCALITY_EXTENDED_MASK       ((TPMA_LOCALITY) 0xe0)
/*! TPMA_LOCALITY_EXTENDED_SHIFT */
#define TPMA_LOCALITY_EXTENDED_SHIFT      (5)


/*-------------------------------------------------------------------*/
/* Part 2, section 8.6: TPMA_PERMANENT bits                          */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_PERMANENT
 * @details Bit map indicating permanent properties
  <p> These values are read using TPM2_GetCapability() with capability = #TPM2_CAP_TPM_PROPERTIES and property = #TPM2_PT_PERMANENT.
  <p> These attributes are persistent and may only change as the result of specific Protected Capabilities.
 * <p> The following bit masks are defined for #TPMA_PERMANENT:
 *  - #TPMA_PERMANENT_OWNERAUTHSET
 *  - #TPMA_PERMANENT_ENDORSEMENTAUTHSET
 *  - #TPMA_PERMANENT_LOCKOUTAUTHSET
 *  - #TPMA_PERMANENT_DISABLECLEAR
 *  - #TPMA_PERMANENT_INLOCKOUT
 *  - #TPMA_PERMANENT_TPMGENERATEDEPS
 */
typedef ubyte TPMA_PERMANENT;
/*! TPMA_PERMANENT_OWNERAUTHSET - if SET: TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear()
<p> if CLEAR: ownerAuth has not been changed since TPM2_Clear().
 */
#define TPMA_PERMANENT_OWNERAUTHSET           ((TPMA_PERMANENT) 0x00000001)
/*! TPMA_PERMANENT_ENDORSEMENTAUTHSET - if SET: TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear()
<p> if CLEAR: endorsementAuth has not been changed since TPM2_Clear().
 */
#define TPMA_PERMANENT_ENDORSEMENTAUTHSET     ((TPMA_PERMANENT) 0x00000002)
/*! TPMA_PERMANENT_LOCKOUTAUTHSET - if SET: TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear()
<p> if CLEAR: lockoutAuth has not been changed since TPM2_Clear().
 */
#define TPMA_PERMANENT_LOCKOUTAUTHSET         ((TPMA_PERMANENT) 0x00000004)
/*! TPMA_PERMANENT_RESERVED1_MASK - Bits 7:3 are reserved */
#define TPMA_PERMANENT_RESERVED1_MASK         ((TPMA_PERMANENT) 0x000000F8)
/*! TPMA_PERMANENT_DISABLECLEAR - if SET: TPM2_Clear() is disabled.
<p> if CLEAR: TPM2_Clear() is enabled.
 */
#define TPMA_PERMANENT_DISABLECLEAR           ((TPMA_PERMANENT) 0x00000100)
/*! TPMA_PERMANENT_INLOCKOUT - if SET: The TPM is in lockout, when failedTries is equal to maxTries. */
#define TPMA_PERMANENT_INLOCKOUT              ((TPMA_PERMANENT) 0x00000200)
/*! TPMA_PERMANENT_TPMGENERATEDEPS - if SET: The EPS was created by the TPM.
<p> if CLEAR: The EPS was created outside of the TPM using a manufacturer-specific process.
 */
#define TPMA_PERMANENT_TPMGENERATEDEPS        ((TPMA_PERMANENT) 0x00000400)
/*! TPMA_PERMANENT_RESERVED1_MASK - Bits 31:11 are reserved */
#define TPMA_PERMANENT_RESERVED2_MASK         ((TPMA_PERMANENT) 0xFFFFF800)

/*-------------------------------------------------------------------*/
/* Part 2, section 8.7: TPMA_STARTUP_CLEAR bits                      */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_STARTUP_CLEAR
 * @details Bit map indicating startup state properties
  <p> These values are read using TPM2_GetCapability() with capability = #TPM2_CAP_TPM_PROPERTIES and property = #TPM2_PT_PERMANENT.
  <p> These attributes are persistent and may only change as the result of specific Protected Capabilities.
 * <p> The following bit masks are defined for #TPMA_PERMANENT:
 *  - #TPMA_STARTUP_CLEAR_PHENABLE
 *  - #TPMA_STARTUP_CLEAR_SHENABLE
 *  - #TPMA_STARTUP_CLEAR_EHENABLE
 *  - #TPMA_STARTUP_CLEAR_PHENABLENV
 *  - #TPMA_STARTUP_CLEAR_ORDERLY
 */
typedef ubyte4 TPMA_STARTUP_CLEAR;
/*! TPMA_STARTUP_CLEAR_PHENABLE - if SET: The platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization.
<p> if CLEAR: platformAuth and plaformPolicy may not be used for authorizations, and objects in the platform hierarchy, including persistent objects, cannot be used.
 */
#define TPMA_STARTUP_CLEAR_PHENABLE           ((TPMA_STARTUP_CLEAR) 0x00000001)
/*! TPMA_STARTUP_CLEAR_SHENABLE - if SET: The storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization.
<p> if CLEAR: ownerAuth and ownerPolicy may not be used for authorizations, and objects in the Storage hierarchy, persistent objects, and NV indices defined using owner authorization cannot be used.
 */
#define TPMA_STARTUP_CLEAR_SHENABLE           ((TPMA_STARTUP_CLEAR) 0x00000002)
/*! TPMA_STARTUP_CLEAR_EHENABLE - if SET: The EPS hierarchy is enabled and Endorsement Authorization may be used for authorization.
<p> if CLEAR: Endorsement Authroization may not be used for authorizations, and objects in the endorsement hierarchy, including persistent objects, cannot be used.
 */
#define TPMA_STARTUP_CLEAR_EHENABLE           ((TPMA_STARTUP_CLEAR) 0x00000004)
/*! TPMA_STARTUP_CLEAR_PHENABLENV - if SET: NV indices that have TPMA_PLATFORM_CREATE SET may be read or written.  The platform can create, define and undefine indices.
<p> if CLEAR: NV indices that have TPMA_PLATFORM_CREATE_SET may not be read or written.  Teh platform cannot define or undefine indices.
 */
#define TPMA_STARTUP_CLEAR_PHENABLENV         ((TPMA_STARTUP_CLEAR) 0x00000008)
/*! TPMA_STARTUP_CLEAR_RESERVED1_MASK - Bits 30:4 are reserved and shall be zero. */
#define TPMA_STARTUP_CLEAR_RESERVED1_MASK     ((TPMA_STARTUP_CLEAR) 0x7ffffff0)
/*! TPMA_STARTUP_CLEAR_ORDERLY - if SET: The TPM received a TPM2_Shutdown() and a matching TPM2_Startup().
<p> if CLEAR: TPM2_Startup(TPM2_SU_CLEAR) was not preceded by a TPM2_Shutdown() of any type.
 */
#define TPMA_STARTUP_CLEAR_ORDERLY            ((TPMA_STARTUP_CLEAR) 0x80000000)

/*-------------------------------------------------------------------*/
/* Part 2, section 8.8: TPMA_MEMORY bits                             */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_MEMORY
 * @details Bit map indicating the memory management method used by the TPM for transient objects and authorization sessions.
  <p> These values are read using TPM2_GetCapability() with capability = #TPM2_CAP_TPM_PROPERTIES and property = #TPM2_PT_MEMORY.
 * <p> The following bit masks are defined for #TPMA_MEMORY:
 *  - #TPMA_MEMORY_SHAREDRAM
 *  - #TPMA_MEMORY_SHAREDNV
 *  - #TPMA_MEMORY_OBJECTCOPIEDTORAM
 */
typedef ubyte4 TPMA_MEMORY;
/*! TPMA_MEMORY_SHAREDRAM - if SET: the RAM memory used for authorization session contexts is shared with the memory used for transient objects.
 <p> if CLEAR:  the memory used for authorization sessions is not shared with memory used for transient objects.
 */
#define TPMA_MEMORY_SHAREDRAM             ((TPMA_MEMORY) 0x00000001)
/*! TPMA_MEMORY_SHAREDRAM - if SET: the NV memory used for persistent objects is shared with the NV memory used for NV index values.
 <p> if CLEAR: the persistent objects and NV index values are allocated from separate sections of NV.
 */
#define TPMA_MEMORY_SHAREDNV              ((TPMA_MEMORY) 0x00000002)
/*! TPMA_MEMORY_OBJECTCOPIEDTORAM - if SET: the TPM copies persistent objects to a transient-object slot in RAM when the persisted object is referenced in a command.
 <p> if CLEAR: the TPM does not use transient-object slots when persistent objects are referenced.
 */
#define TPMA_MEMORY_OBJECTCOPIEDTORAM     ((TPMA_MEMORY) 0x00000004)
/*! TPMA_MEMORY_RESERVED1_MASK - Bits 31:3 are reserved and shall be zero. */
#define TPMA_MEMORY_RESERVED1_MASK        ((TPMA_MEMORY) 0xFFFFFFF8)


/*-------------------------------------------------------------------*/
/* Part 2, section 8.9: TPMA_CC Bits                                 */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_CC
 * @details Bit map indicating the attributes of a command from a context management perspective.  The fields of the structure indicate to the TPM Resource Manager (TRM) the nubmer of resources required by a command and how the command affects the TPM's resources.
  <p> These values are only used in a list returned by the TPM in response to TPM2_GetCapability() with capability = #TPM2_CAP_COMMANDS.
  <p> For a command to the TPM, only the commandIndex and V attribute are allowed to be non-zero.
 * <p> The following bit masks are defined for #TPMA_CC:
 *  - #TPMA_CC_NV
 *  - #TPMA_CC_EXTENSIVE
 *  - #TPMA_CC_FLUSHED
 *  - #TPMA_CC_RHANDLE
 *  - #TPMA_CC_V
 */
typedef ubyte4 TPMA_CC;
/*! TPMA_CC_COMMANDINDEX_MASK - Bit mask indicating the command being selected */
#define TPMA_CC_COMMANDINDEX_MASK     ((TPMA_CC) 0x0000ffff)
/*! TPMA_CC_COMMANDINDEX_SHIFT */
#define TPMA_CC_COMMANDINDEX_SHIFT    (0)
/*! TPMA_CC_RESERVED1_MASK - Bits 21:16 are reserved and shall be zero. */
#define TPMA_CC_RESERVED1_MASK        ((TPMA_CC) 0x003f0000)
/*! TPMA_CC_NV - if SET: the command may write to NV
 <p> if CLEAR: the command does not write to NV
 */
#define TPMA_CC_NV                    ((TPMA_CC) 0x00400000)
/*! TPMA_CC_EXTENSIVE - if SET: command could flush any number of loaded contexts
<p> if CLEAR: no additional changes other than indicated by the flushed attribute
 */
#define TPMA_CC_EXTENSIVE             ((TPMA_CC) 0x00800000)
/*! TPM2_CC_FLUSHED - if SET: The context associated with any transient handle in the command will be flushed when this command completes.
<p> if CLEAR: No context is flushed as a side effect of this command.
 */
#define TPMA_CC_FLUSHED               ((TPMA_CC) 0x01000000)
/*! TPMA_CC_CHANDLES_MASK - indicates the number of handles in the handle area for this command */
#define TPMA_CC_CHANDLES_MASK         ((TPMA_CC) 0x0e000000)
/*! TPMA_CC_CHANDLES_SHIFT */
#define TPMA_CC_CHANDLES_SHIFT        (25)
/*! TPMA_CC_RHANDLE - if SET: indicates the prsence of the handle area in the response */
#define TPMA_CC_RHANDLE               ((TPMA_CC) 0x10000000)
/*! TPMA_CC_V - if SET: indicates that the command is vendor-specific
<p> if CLEAR: indicates that the command is defined ina  version of the TPM 2.0 specification
 */
#define TPMA_CC_V                     ((TPMA_CC) 0x20000000)
/*! TPMA_CC_RES_MASK - Bits 31:30 are reserved for software and shall be zero. */
#define TPMA_CC_RES_MASK              ((TPMA_CC) 0xc0000000)
/*! TPMA_CC_RES_SHIFT */
#define TPMA_CC_RES_SHIFT             (30)

/*-------------------------------------------------------------------*/
/* Part 2, section 8.10: TPMA_MODES                                  */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMA_MODES
 * @details Bit map indicating the modes for which the TPM is designed.
  <p> These values are read using TPM2_GetCapability() with capability = #TPM2_CAP_TPM_PROPERTIES and property = #TPM2_PT_MODES.
 * <p> The following bit masks are defined for #TPMA_MODES:
 *  - #TPMA_MODES_FIPS_140_2
 */
typedef ubyte4 TPMA_MODES;
/*! TPMA_MODES_FIPS_140_2 - if SET: indicates that the TPM is designed to comply with all of the FIPS 140-2 requirements at Level 1 or higher. */
#define TPMA_MODES_FIPS_140_2         ((TPMA_MODES) 0x00000001)
/*! TPMA_MODES_RESERVED1_MASK - Bits 31:1 are reserved and shall be zero */
#define TPMA_MODES_RESERVED1_MASK     ((TPMA_MODES) 0xfffffffe)

/*-------------------------------------------------------------------*/
/* Part 2, section 9.2: TPMI_YES_NO                                  */
/*-------------------------------------------------------------------*/
/*! TPMI_YES_NO -  0 = NO; 1 = YES */
typedef ubyte  TPMI_YES_NO; 
#define NO ((TPMI_YES_NO)0)
#define YES ((TPMI_YES_NO)1)

/*-------------------------------------------------------------------*/
/* Part 2, section 9.3: TPMI_DH_OBJECT                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_DH_OBJECT
 * @details Handle that references a loaded object.  The handles in this set are used to refer to either transient or persistent objects. Valid values include:
<p> TRANSIENT_FIRST:TRANSIENT_LAST = allowed range for transient objects
<p> PERSISTENT_FIRST:PERSISTENT_LAST = allowed range for persistent objects
 */
typedef TPM2_HANDLE  TPMI_DH_OBJECT;


/*-------------------------------------------------------------------*/
/* Part 2, section 9.4: TPMI_DH_PARENT                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_DH_PARENT
 * @details Handle that references an object that can be the parent of another object.  The handles in this set may refer to either transient or persistent objects, or to Primary Seeds.  Valid values include:
<p> TRANSIENT_FIRST:TRANSIENT_LAST = allowed range for transient objects
<p> PERSISTENT_FIRST:PERSISTENT_LAST = allowed range for persistent objects
<p> TPM2_RH_OWNER - Storage hierarchy
<p> TPM2_RH_PLATFORM - Platform hierarchy
<p> TPM2_RH_ENDORSEMENT - Endorsement hierarchy
<p> TPM2_RH_NULL - No hierarchy
 */
typedef TPM2_HANDLE  TPMI_DH_PARENT;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.5: TPMI_DH_PERSISTENT                           */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_DH_PERSISTENT
 * @details Handle that references a location fora  transient object.  This type is used in TPM2_EvictControl() to indicate the handle to be assigned to the persistent object.  Valid values include:
<p> PERSISTENT_FIRST:PERSISTENT_LAST = allowed range for persistent objects
 */
typedef TPM2_HANDLE  TPMI_DH_PERSISTENT;


/*-------------------------------------------------------------------*/
/* Part 2, section 9.6: TPMI_DH_ENTITY                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_DH_ENTITY
 * @details TPM-defined values that are used to indicate that the handle refers to an authValue. Value values include:
<p> TPM2_RH_OWNER
<p> TPM2_RH_ENDORSEMENT
<p> TPM2_RH_PLATFORM
<p> TPM2_RH_LOCKOUT
<p> TRANSIENT_FIRST:TRANSIENT_LAST = allowed range for transient objects
<p> PERSISTENT_FIRST:PERSISTENT_LAST = allowed range for persistent objects
<p> NV_INDEX_FIRST:NV_INDEX_LAST
<p> PCR_FIRST:PCR_LAST
<p> TPM2_RH_AUTH_00:TPM2_RH_AUTH_FF = range of vendor-specific authorization values
<p> TPM2_RH_NULL = conditional value
 */
typedef TPM2_HANDLE  TPMI_DH_ENTITY;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.7: TPMI_DH_PCR                                  */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_DH_PCR
 * @details Handles that may be used as PCR references.
 */
typedef TPM2_HANDLE  TPMI_DH_PCR;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.8: TPMI_SH_AUTH_SESSION                         */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_SH_AUTH_SESSION
 * @details TPM-defined values that are used to indicate that the handle refers to an authorization session.
 */
typedef TPM2_HANDLE  TPMI_SH_AUTH_SESSION;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.9: TPMI_SH_HMAC                                 */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_SH_HMAC
 * @details Handles used for an authorization handle when the authorization session uses an HMAC.
 */
typedef TPM2_HANDLE  TPMI_SH_HMAC;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.10: TPMI_SH_POLICY                              */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_SH_POLICY
 * @details Handles used for a policy handle when it appears in a policy command.
 */
typedef TPM2_HANDLE  TPMI_SH_POLICY;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.11: TPMI_DH_CONTEXT                             */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_DH_CONTEXT
 * @details Handle values that may be used in TPM2_ContextSave() or TPM2_Flush().
 */
typedef TPM2_HANDLE  TPMI_DH_CONTEXT;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.12: TPMI_RH_HIERARCHY                           */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_HIERARCY
 * @details Type of handle used in a command when the handle is required to be one of the hierarchy selectors. Valid values include:
<p> - #TPM2_RH_OWNER
<p> - #TPM2_RH_PLATFORM
<p> - #TPM2_RH_ENDORSEMENT
<p> - #TPM2_RH_NULL
 */
typedef TPM2_HANDLE  TPMI_RH_HIERARCHY;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.13: TPMI_RH_ENABLES                             */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_ENABLES
 * @details Type of handle used in a command when the handle is required to be one of the hierarchy or NV enables. Valid values include:
<p> - #TPM2_RH_OWNER
<p> - #TPM2_RH_PLATFORM
<p> - #TPM2_RH_ENDORSEMENT
<p> - #TPM2_RH_PLATFORM_NV
<p> - #TPM2_RH_NULL
 */
typedef TPM2_HANDLE  TPMI_RH_ENABLES;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.14: TPMI_RH_HIERARCHY_AUTH                      */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_HIERARCY_AUTH
 * @details Type of handle used in a command when the handle is required to be one of the hierarchy selectors or the Lockout Authorization. Valid values include:
<p> - #TPM2_RH_OWNER
<p> - #TPM2_RH_PLATFORM
<p> - #TPM2_RH_ENDORSEMENT
<p> - #TPM2_RH_LOCKOUT
 */
typedef TPM2_HANDLE  TPMI_RH_HIERARCHY_AUTH;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.15: TPMI_RH_PLATFORM                            */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_PLATFORM
 * @details Type of handle used in a command when the only allowed handle is #TPM2_RH_PLATFORM.
 */
typedef TPM2_HANDLE  TPMI_RH_PLATFORM;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.16: TPMI_RH_OWNER                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_OWNER
 * @details Type of handle used in a command when the only allowed handle is #TPM2_RH_OWNER, indicating that Owner Authorization is required.
 */
typedef TPM2_HANDLE TPMI_RH_OWNER;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.17: TPMI_RH_ENDORSEMENT                         */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_ENDORSEMENT
 * @details Type of handle used in a command when the only allowed handle is #TPM2_RH_ENDORSEMENT, indicating that Endorsement Authorization is required.
 */
typedef TPM2_HANDLE TPMI_RH_ENDORSEMENT;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.18: TPMI_RH_PROVISION                           */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_PROVISION
 * @details Type of handle used in a command when the only allowed handles are either #TPM2_RH_OWNER or #TPM2_RH_PLATFORM, indicating that either Platform Authorization or Owner Authorization is required.
 */
typedef TPM2_HANDLE TPMI_RH_PROVISION;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.19: TPMI_RH_CLEAR                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_CLEAR
 * @details Type of handle used in a command when the only allowed handles are either #TPM2_RH_LOCKOUT or #TPM2_RH_PLATFORM, indicating that either Platform Authorization or Lockout Authorization is required.
 */
typedef TPM2_HANDLE TPMI_RH_CLEAR;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.20: TPMI_RH_NV_AUTH                             */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_NV_AUTH
 * @details Used to identify the source of the authorization for access to an NV location.  The handle value indicates that the authorization value is either Platform Authorization, Owner Authorization, or the authValue.  This type is used in the commands that access an NV Index (TPM2_NV_xxx) other than TPM2_NV_DefineSpace() and TPM2_NV_UndefineSpace().
 <p> Valid values include #TPM2_RH_PLATFORM, #TPM2_RH_OWNER and values in the range NV_INDEX_FIRST:NV_INDEX_LAST.
 */
typedef TPM2_HANDLE TPMI_RH_NV_AUTH;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.21: TPMI_RH_LOCKOUT                             */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_LOCKOUT
 * @details Type of handle used in a command when the only allowed handle is #TPM2_RH_LOCKOUT, indicating that Lockout Authorization is required.
 */
typedef TPM2_HANDLE TPMI_RH_LOCKOUT;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.22: TPMI_RH_NV_INDEX                            */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_RH_NV_INDEX
 * @details Used to identify an NV location.  This type is used in the NV commands. 
 */
typedef TPM2_HANDLE TPMI_RH_NV_INDEX;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.23: TPMI_ALG_HASH                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_HASH
 * @details Interface type of all the hash algorithms implemented on a specific TPM.
 */
typedef TPM2_ALG_ID TPMI_ALG_HASH;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.24: TPMI_ALG_ASYM                               */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_ASYM
 * @details Interface type of all the asymmetric algorithms implemented on a specific TPM.
 */
typedef TPM2_ALG_ID TPMI_ALG_ASYM;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.25: TPMI_ALG_SYM                                */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_SYM
 * @details Interface type of all the symmetric algorithms implemented on a specific TPM.
 */
typedef TPM2_ALG_ID TPMI_ALG_SYM;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.26: TPMI_ALG_SYM_OBJECT                         */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_SYM_OBJECT
 * @details Interface type of all TCG-defined symmetric algorithms that may be used as companion symmetric encryption algorithm for an asymmetric object.  All algorithms in this list shall be block cipers usabel in Cipher Feedback (CFB).
 */
typedef TPM2_ALG_ID TPMI_ALG_SYM_OBJECT;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.27: TPMI_ALG_SYM_MODE                           */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_SYM_MODE
 * @details Interface type of all TCG-defined block-cipher modes of operation.
 */
typedef TPM2_ALG_ID TPMI_ALG_SYM_MODE;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.28: TPMI_ALG_KDF                                */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_KDF
 * @details Interface type of all the key derivation functions implemented on a specific TPM.
 */
typedef TPM2_ALG_ID TPMI_ALG_KDF;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.29: TPMI_ALG_SIG_SCHEME                         */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_SIG_SCHEME
 * @details Interface type of any signature scheme.
 */
typedef TPM2_ALG_ID TPMI_ALG_SIG_SCHEME;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.30: TPMI_ALG_KEY_EXCHANGE                       */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ALG_KEY_EXCHANGE
 * @details Interface type of an ECC key exchange scheme.
 */
typedef TPM2_ALG_ID TPMI_ECC_KEY_EXCHANGE;

/*-------------------------------------------------------------------*/
/* Part 2, section 9.31: TPMI_ST_COMMAND_TAG                         */
/*-------------------------------------------------------------------*/

/**
 * @ingroup tpm2_definitions
 * @brief TPMI_ST_COMMAND_TAG
 * @details Interface type used for the command tags.
 * <p> The response code for a bad command tag has the same value as the TPM 1.2 response code (TPM_BAD_TAG). This value is used in case the software is not compatible with the specification and an unexpected response code might have unexpected side effects.
 */
typedef TPM2_ST TPMI_ST_COMMAND_TAG;


/*-------------------------------------------------------------------*/
/* Part 2, section 10: Structure Definitions                         */
/*-------------------------------------------------------------------*/

/* Section 10.1 - TPMS_EMPTY */

/**
 * @ingroup tpm2_definitions
 * @brief TPMS_EMPTY
 */
typedef struct
{
    /*! one-byte for compiling on different platforms */
    ubyte   empty[1];
} TPMS_EMPTY;

/* Section 10.2  */

/**
 * @ingroup tpm2_definitions
 * @brief Return value for a TPM2_GetCapability() that reads the installed algorithms.
 */
typedef struct
{
    /*! an algorithm */
    TPM2_ALG_ID alg;
    /*! the attributes of the algorithm */
    TPMA_ALGORITHM attributes;
} TPMS_ALGORITHM_DESCRIPTION;

#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SM3_256_DIGEST_SIZE 32

/* Section 10.3: Hash/Digest Structures */

/* Table 71 - Definition of TPMU_HA Union */

/**
 * @ingroup tpm2_definitions
 * @brief Union of all the hash algorithms implemented on a TPM.
 */
typedef union
{
    /*! SHA hash */
    sbyte       sha[TPM2_SHA_DIGEST_SIZE];          /* TPM2_ALG_SHA */
#ifdef TPM2_ALG_SHA1
    /*! SHA-1 hash */
    sbyte       sha1[TPM2_SHA1_DIGEST_SIZE];        /* TPM2_ALG_SHA1 */
#endif
#ifdef TPM2_ALG_SHA256
    /*! SHA-256 hash */
    sbyte       sha256[TPM2_SHA256_DIGEST_SIZE];    /* TPM2_ALG_SHA256 */
#endif
#ifdef TPM2_ALG_SHA384
    /*! SHA-384 hash */
    sbyte       sha384[TPM2_SHA384_DIGEST_SIZE];    /* TPM2_ALG_SHA384 */
#endif
#ifdef TPM2_ALG_SHA512
    /*! SHA-512 hash */
    sbyte       sha512[TPM2_SHA512_DIGEST_SIZE];    /* TPM2_ALG_SHA512 */
#endif
#ifdef TPM2_ALG_SM3_356
    /*! SM3-356 hash */
    sbyte       sm3_256[TPM2_SM3_256_DIGEST_SIZE];  /* TPM2_ALG_SM3_256 */
#endif
    /*! empty structure */
    TPMS_EMPTY  null;                                /* TPM2_ALG_NULL */
} TPMU_HA;

/* Table 72: TPMT_HA */

/**
 * @ingroup tpm2_definitions
 * @brief Hash-agile structure to accomodate any type of hash value.
 */
typedef struct
{
    /*! #TPMI_ALG_HASH - selector of the hash contained in the digest that implies the size of the digest */
    TPMI_ALG_HASH hashAlg;
    /*! #TPMU_HA - the digest data */
    TPMU_HA digest;
} TPMT_HA;

/* Section 10.4: Sized Buffers */


/* Table 73: TPM2B_DIGEST */

/**
 * @ingroup tpm2_definitions
 * @brief Structure used for a sized buffer that cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM.
 */
typedef struct
{
    /*! size in octects of the buffer field */
    ubyte2 size;
    /*! the buffer area that can be no larger than a digest */
    ubyte buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

/* Table 74: TPM2B_DATA */

/**
 * @ingroup tpm2_definitions
 * @brief Structure used for a data buffer that is required to be no larger than the size of the Name of an object.
 */
typedef struct
{
    /*! size in octects of the buffer field */
    ubyte2 size;
    /*! the buffer area */
    ubyte buffer[sizeof(TPMT_HA)];
} TPM2B_DATA;


/* Table 75: TPM2B_NONCE */

/*! Size limited to the same as the digest structure */
typedef TPM2B_DIGEST TPM2B_NONCE;

/* Table 76: TPM2B_AUTH */

/*! Size limited to the same as the digest structure */
typedef TPM2B_DIGEST TPM2B_AUTH;

/* Table 77: TPM2B_OPERAND */

/*! Size limited to the same as the digest structure */
typedef TPM2B_DIGEST TPM2B_OPERAND;

/* Table 78: TPM2B_EVENT */

/**
 * @ingroup tpm2_definitions
 * @brief A sized buffer that can hold event data.
 */
typedef struct
{
    /*! size in octects of the buffer field */
    ubyte2 size;
    /*! the buffer area */
    ubyte buffer[1024];
} TPM2B_EVENT;


/* Table 79: TPM2B_MAX_BUFFER */

/**
 * @ingroup tpm2_definitions
 * @brief A sized buffer that can hold a maximally sized buffer for commands that use a large data buffer such as TPM2_Hash(), TPM2_SequenceUpdate(), or TPM2_FieldUpgradeData().
 * @note TPM2_MAX_DIGEST_BUFFER is TPM-dependent, but is required to be at least 1024.
 */
typedef struct
{
    /*! size of the buffer field */
    ubyte2 size;
    /*! the buffer area */
    ubyte buffer[TPM2_MAX_DIGEST_BUFFER];
} TPM2B_MAX_BUFFER;


/* Table 80: TPM2B_MAX_NV_BUFFER */

/**
 * @ingroup tpm2_definitions
 * @brief A sized buffer that can hold a maximally sized buffer for NV data commands such as TPM2_NV_Read(), TPM2_NV_Write(), or TPM2_NV_Certify().
 * @note TPM2_MAX_DIGEST_BUFFER is TPM-dependent, but is required to be at least 1024.
 */
typedef struct
{
    /*! size of the buffer field */
    ubyte2 size;
    /*! the buffer area */
    ubyte buffer[TPM2_MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;

/* Table 81: TPM2B_TIMEOUT */

/**
 * @ingroup tpm2_definitions
 * @brief TPM-dependent structure used to provide the timeout value for an authorization.
 */
typedef TPM2B_DIGEST  TPM2B_TIMEOUT;

/* Table 82: TPM2B_IV */

/**
 * @ingroup tpm2_definitions
 * @brief This structure is used for passing an initial value for a symmetric block cipher to or from the TPM. The size is set to be the largest block size of any implemented symmetric cipher implemented on the TPM.
 */
typedef struct
{
    /*! size of the IV value */
    ubyte2 size;
    /*! The IV value */
    ubyte buffer[TPM2_MAX_SYM_BLOCK_SIZE];
} TPM2B_IV;


/* Section 10.5: Names */

/* Table 83: TPMU_NAME Union */

/**
 * @ingroup tpm2_definitions
 * @brief TPMU_NAME Union
 * @details Union to handle a Name as either a digest or a handle.
 */
typedef union
{
    /*! present when the Name is a digest */
    TPMT_HA    digest;
    /*! present when the Name is a handle */
    TPM2_HANDLE handle; 
} TPMU_NAME;

/* Table 84: TPM2B_NAME Struct */

/**
 * @ingroup tpm2_definitions
 * @brief TPM2B_NAME
 * @details This buffer holds a Name for any entity type.  They type of Name is determined by context and the size parameter.
 * <p> - If size is 4, then the Name is a handle.
 * <p> - If size is 0, then no Name is present.
 * <p> - else size is the size of a #TPM2_ALG_ID plus the size of the digest produced by the indicated hash algorithm.
 */
typedef struct
{
    /*! size of the Name structure */
    ubyte2 size;
    /*! the Name structure */
    ubyte name[sizeof(TPMU_NAME)];
} TPM2B_NAME;

/* Section 10.6: PCR Structures */

/* Table 85: TPMS_PCR_SELECT Struct */


/**
 * @ingroup tpm2_definitions
 * @brief Structure used to select one or more PCRs.
 * @details This structure provides a standard method of specifying a list of PCRs.  PCR numbering starts at zero.
 */
typedef struct
{
    /*! Number of octets (bytes) in pcrSelect.  The maximum value if (number of PCRS supported by platform + 7) / 8 */
    ubyte   sizeofSelect;
    /*! Array of octets.  The bit in the octet associated with a PCR is the remainder after dividing the PCR number by 8. */
    ubyte   pcrSelect[TPM2_PCR_SELECT_MAX];
    /* Or do we want the following, as in TPM 1.2?
    SIZEIS(sizeOfSelect) ubyte *pcrSelect;  // bit map of selected PCR
     */
} TPMS_PCR_SELECT;

/* Table 86: TPMS_PCR_SELECTION Struct */

/**
 * @ingroup tpm2_definitions
 * @brief Structure used to select one or more PCRs with an associated hash algorithm.
 * @details This structure provides a standard method of specifying a list of PCRs.  PCR numbering starts at zero.
 */
typedef struct
{
    /*! the hash algorithm associated with the selection */
    TPMI_ALG_HASH   hash;
    /*! the size in octets of the pcrSelect array */
    ubyte           sizeofSelect;
    /*! the bit map of the selected PCR */
    ubyte           pcrSelect[TPM2_PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;


/* Section 10.7: Tickets */

/* Table 89: TPMT_TK_CREATION Struct */

/**
 * @ingroup tpm2_definitions
 * @brief Ticked produced by TPM2_Create() or TPM2_CreatePrimary().
 * @details This structure is used to bind the creation data to the object to which is applies.
 */
typedef struct
{
    /*! ticket structure tag #TPM2_ST_CREATION */
    TPM2_ST            tag;
    /*! hierarchy containing name */
    TPMI_RH_HIERARCHY hierarchy;
    /*! HMAC produced using a proof value of hierarchy */
    TPM2B_DIGEST      digest;
} TPMT_TK_CREATION;

/* Table 90: TPMT_TK_VERIFIED Struct */

/**
 * @ingroup tpm2_definitions
 * @brief Ticked produced by TPM2_VerifySignature().
 * @details This formulation is used for multiple ticket uses.  The ticket provides evidence that the TPM has validated that a digest was signed by a key with the Name of keyName.
 */
typedef struct
{
    /*! ticket structure tag #TPM2_ST_VERIFIED */
    TPM2_ST            tag;
    /*! hierarchy containing keyName */
    TPMI_RH_HIERARCHY hierarchy;
    /*! HMAC produced using a proof value of hierarchy */
    TPM2B_DIGEST      digest;
} TPMT_TK_VERIFIED;

/* Table 91: TPMT_TK_AUTH Struct */

/**
 * @ingroup tpm2_definitions
 * @brief Ticked produced by TPM2_PolicySigned() and TPM2_PolicySecret() when the authorization has an expiration time.
 */
typedef struct
{
    /*! ticket structure tag #TPM2_ST_AUTH_SIGNED or #TPM2_ST_AUTH_SECRET */
    TPM2_ST            tag;
    /*! hierarchy of the object used to produce the ticket */
    TPMI_RH_HIERARCHY hierarchy;
    /*! HMAC produced using a proof value of hierarchy */
    TPM2B_DIGEST      digest;
} TPMT_TK_AUTH;

/* Section 10.8: Property Structures */

/* Table 92: TPMT_TK_HASHCHECK Struct */

/**
 * @ingroup tpm2_definitions
 * @details Ticked produced by TPM2_SequenceComplete() when the message that was digested did not start with #TPM2_GENERATED_VALUE.
 */
typedef struct
{
    /*! ticket structure tag #TPM2_ST_HASHCHECK */
    TPM2_ST            tag;
    /*! the hierarchy */
    TPMI_RH_HIERARCHY hierarchy;
    /*! HMAC produced using a proof value of hierarchy */
    TPM2B_DIGEST      digest;
} TPMT_TK_HASHCHECK;

/* Table 93: TPMS_ALG_PROPERTY Struct */

/**
 * @ingroup tpm2_definitions
 * @details Structure used to report the properties of an algorithm identifier.  It is returned in response to a TPM2_GetCapability() with capability = #TPM2_CAP_ALG.
 */
typedef struct
{
    /*! algoithm identifier */
    TPM2_ALG_ID      alg;
    /*! attributes of the algorithm */
    TPMA_ALGORITHM  algProperties;
} TPMS_ALG_PROPERTY;

/* Table 94: TPMS_TAGGED_PROPERTY Struct */

/**
 * @ingroup tpm2_definitions
 * @details Structure used to report the properties that are ubyte4 values.  It is returned in response to a TPM2_GetCapability().
 */
typedef struct
{
    /*! property identifier */
    TPM2_PT   property;
    /*! value of the property */
    ubyte4   value;
} TPMS_TAGGED_PROPERTY;

/* Table 95: TPMS_TAGGED_PCR_SELECT Struct */

/**
 * @ingroup tpm2_definitions
 * @details Structure used in TPM2_GetCapability() to return the attributes of the PCR.
 */
typedef struct
{
    /*! the property identifier */
    TPM2_PT   tag;
    /*! size in octets of the pcrSelect array */
    ubyte     sizeOfSelect;
    /*! the bit map of PCR with the identified property */
    ubyte     pcrSelect[TPM2_PCR_SELECT_MAX];
} TPMS_TAGGED_PCR_SELECT;


/* Table 96 - Definition of TPMS_TAGGED_POLICY Structure */

/**
 * @ingroup tpm2_definitions
 * @details Structure used in TPM2_GetCapability() to return the policy associated with a permanent handle.
 */
typedef struct
{
    /*! a permanent handle */
    TPM2_HANDLE     handle;
    /*! the policy algorithm and hash */
    TPMT_HA         policyHash;
} TPMS_TAGGED_POLICY;

/* Section 10.9: Lists */

/* Table 97: TPML_CC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief Command code list
 * @details A list of command codes that may be input to the TPM or returned by the TPM depending on the command.
 */
typedef struct
{
    /*! number of commands in commandCode list */
    ubyte4   count;
    /*! list of command codes */
    TPM2_CC     commandCodes[TPM2_MAX_CAP_CC];
} TPML_CC;

/* Table 98: TPML_CCA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief This list is only used in TPM2_GetCapability when capability = #TPM2_CAP_COMMANDS.
 * @details The values in teh list are returned in TPMA_CC->commandIndex order with vendor-specific commands returned after other commands.  The commands may not be returned in strict numerical order.
 */
typedef struct
{
    /*! number of values in commandAttributes list */
    ubyte4   count;
    /*! list of command codes attributes */
    TPMA_CC  commandAttributes[TPM2_MAX_CAP_CC];
} TPML_CCA;

/* Table 99: TPML_ALG Struct */

/**
 * @ingroup tpm2_definitions
 * @brief List of supported algorithms.
 * @details This list is returned by TPM2_IncrementalSelfTest()
 */
typedef struct
{
    /*! number of algorithms in algorithms list */
    ubyte4   count;
    /*! list of algorithm IDs */
    TPM2_ALG_ID     algorithms[TPM2_MAX_ALG_LIST_SIZE];
} TPML_ALG;

/* Table 100: TPML_HANDLE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list of handles
 * @details This structure is used when the TPM returns a list of loaded handles when the capability in TPM2_GetCapability() is #TPM2_CAP_HANDLE.
 */
typedef struct
{
    /*! number of algorithms in algorithms list */
    ubyte4       count;
    /*! list of handles */
    TPM2_HANDLE  handle[ TPM2_MAX_CAP_HANDLES];
} TPML_HANDLE;

/* Table 101: TPML_DIGEST Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to convey a list of digest values
 * @details This type is used in TPM2_PolicyOR() and in TPM2_PCR_Read().
 */
typedef struct
{
    /*! number of digests in the list; minimum is 2 for TPM2_PolicyOR() */
    ubyte4        count;
    /*! list of digests  (see #TPM2B_DIGEST)
        <p> For TPM2_PolicyOR(), all digests will have been computed using the digest of the policy session.
        <p> For TPM2_PCR_Read(), each digests will be the size of the digest for the bank containing the PCR.
     */
    TPM2B_DIGEST  digests[8];
} TPML_DIGEST;

/* Table 102: TPML_DIGEST_VALUES Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to convey a list of digest values
 * @details This type is returned by TPM2_Event() and TPM2_SequenceComplete() and is an input for TPM2_PCR_Extend().
 */
typedef struct
{
    /*! number of digest in the list */
    ubyte4   count;
    /*! list of tagged digests */
    TPMT_HA     digests[TPM2_NUM_PCR_BANKS];
} TPML_DIGEST_VALUES;


/* Table 103: TPML_PCR_SELECTION Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to indicate the PCR(s) that are included in a selection when more than one PCR value may be selected.
 * @details This structure is an input parameter to TPM2_PolicyPCR() to indicate the PCR that will be included in the digest of PCR for the authorization.
<p> The structure is used in TPM2_PCR_Read() command to indicate the PCR values to be returned and in the response to indicate which PCR are included in the list of returned digests.
<p> The structure is an output parameter from TPM2_Create() and indicates the PCR used in the digest of the PCR state when the object was created.
<p> The structure is also contained in the attestation structure of TPM2_Quote().
 */
typedef struct
{
    /*! number of selection structures (zero is allowed) */
    ubyte4   count;
    /*! list of selections */
    TPMS_PCR_SELECTION  pcrSelections[TPM2_NUM_PCR_BANKS];
} TPML_PCR_SELECTION;

/* Table 104: TPML_ALG_PROPERTY Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to report on a list of algorithm attributes
 * @details This type is returned by TPM2_GetCapability().
 */
typedef struct
{
    /*! number of algorithm property structures (zero is allowed) */
    ubyte4   count;
    /*! list of properties - see #TPMS_ALG_PROPERTY */
    TPMS_ALG_PROPERTY   algProperties[TPM2_MAX_CAP_ALGS];
} TPML_ALG_PROPERTY;

/* Table 105: TPML_TAGGED_TPM_PROPERTY Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to report on a list of properties that are #TPMS_TAGGED_PROPERTY values.
 * @details This is returned by TPM2_GetCapability().
 */
typedef struct
{
    /*! number of properties (zero is allowed) */
    ubyte4   count;
    /*! array of tagged properties */
    TPMS_TAGGED_PROPERTY    tpmProperty[TPM2_MAX_TPM_PROPERTIES];
} TPML_TAGGED_TPM_PROPERTY;

/* Table 106: TPML_TAGGED_PCR_PROPERTY Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to report on a list of properties that are #TPMS_PCR_SELECT values.
 * @details This is returned by TPM2_GetCapability().
 */
typedef struct
{
    /*! number of properties (zero is allowed) */
    ubyte4   count;           /* number of properties */
    /*! a tagged PCR selection */
    TPMS_TAGGED_PCR_SELECT  pcrProperty[TPM2_MAX_PCR_PROPERTIES];
} TPML_TAGGED_PCR_PROPERTY;

/* Table 107: TPML_ECC_CURVE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to report the ECC curve ID values supported by the TPM.
 * @details This is returned by TPM2_GetCapability().
 */
typedef struct
{
    /*! number of curves */
    ubyte4   count;
    /*! array of ECC curve identifiers */
    TPM2_ECC_CURVE  eccCurves[TPM2_MAX_ECC_CURVES];
} TPML_ECC_CURVE;

/* Table 108 - Definition of TPML_TAGGED_POLICY Structure */

/**
 * @ingroup tpm2_definitions
 * @brief   list used to report the authorization policy values for permanent handles.
 * @details This list may be generated by TPM2_GetCapability(). A permanent handle that cannot have a policy is not included in the list.
 */
typedef struct
{
    /*! number of tagged policies (zero is allowed) */
    ubyte4              count;
    /*! array of tagged policies */
    TPMS_TAGGED_POLICY  policies[TPM2_MAX_TAGGED_POLICIES];
} TPML_TAGGED_POLICY;


/* Section 10.10: Capability Structures */


/* Table 109: TPMU_CAPABILITIES Union */

/**
 * @ingroup tpm2_definitions
 * @brief TPMU_CAPABILITIES Union
 * @details It is required that each parameter in this union be a list (TPML_xxx).
<p> The number of returned elements in each list is determined by the size of each list element and the maximum size set by the vendor as the capability buffer (MAX_CAP_BUFFER in #TPM2_PT_MAX_CAP_BUFFER).
 */
typedef union
{
    /*! selector = TPM2_CAP_ALGS */
    TPML_ALG_PROPERTY         algorithms;
    /*! selector = TPM2_CAP_HANDLES */
    TPML_HANDLE               handles;
    /*! selector = TPM2_CAP_COMMANDS */
    TPML_CCA                  command;
    /*! selector = TPM2_CAP_PP_COMMANDS */
    TPML_CC                   ppCommands;
    /*! selector = TPM2_CAP_AUDIT_COMMANDS */
    TPML_CC                   auditCommands;
    /*! selector = TPM2_CAP_PCRS */
    TPML_PCR_SELECTION        assignedPCR;
    /*! selector = TPM2_CAP_TPM_PROPERTIES */
    TPML_TAGGED_TPM_PROPERTY  tpmProperties;
    /*! selector = TPM2_CAP_PCR_PROPERTIES */
    TPML_TAGGED_PCR_PROPERTY  pcrProperties;
    /*! selector = TPM2_CAP_ECC_CURVES; #TPM2_ALG_ECC */
    TPML_ECC_CURVE            eccCurves;
} TPMU_CAPABILITIES;

/* Table 110: TPMS_CAPABILITY_DATA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Capability data structure
 * @details This data area is returned in response to a TPM2_GetCapability().
 */
typedef struct
{
    /*! the capability */
    TPM2_CAP          capability;
    /*! the capability data */
    TPMU_CAPABILITIES  data;
} TPMS_CAPABILITY_DATA;

/* Table 111: TPMS_CLOCK_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Clock information
 * @details This structure is used in each of the attestation commands.
 */
typedef struct
{
    /*! time in ms during which TPM has been powered */
    ubyte8       clock;
    /*! number of occurrences of TPM Reset since last TPM2_Clear() */
    ubyte4       resetCount;
    /*! number of times TPM2_Shutdown() or _TPM2_Hash_Start have occurred since the last TPM Reset or TPM2_Clear() */
    ubyte4       restartCount;
    /*! no value of Clock greater than the current value of Clock has been previously reported by TPM.  Set to YES on TPM2_Clear() */
    TPMI_YES_NO  safe;
} TPMS_CLOCK_INFO;

/* Table 112: TPMS_TIME_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Structure used in the TPM2_GetTime() attestation.
 * @details The Time value reported in this structure is reset whenever the TPM is reset. An implementation may reset the value of Time any time after _TPM_Init and before the TPM returns after TPM2_Startup(). The value of Time shall increment continuously while power is applied to the TPM.
 */
typedef struct
{
    /*! time in ms since last _TPM2_Init() or TPM2_Startup() - used to report on the TPM's Time value. */
    ubyte8           time;
    /*! structure containing clock information */
    TPMS_CLOCK_INFO  clockinfo;
} TPMS_TIME_INFO;

/* Table 113: TPMS_TIME_ATTEST_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details Structure used when the TPM performs TPM2_GetTime.
 */
typedef struct
{
    /*! the Time, Clock, resetCount, restartCount,and Safe indicator */
    TPMS_TIME_INFO  time;
    /*! TPM vendor-specific value indicating the version number of the firmware */
    ubyte8          firmwareVersion;
} TPMS_TIME_ATTEST_INFO;

/* Table 114: TPMS_CERTIFY_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details The attested data for TPM2_Certify().
 */
typedef struct
{
    /*! Name of the certified object */
    TPM2B_NAME  name;
    /*! Qualified Name of the certified object */
    TPM2B_NAME  qualifiedName;
} TPMS_CERTIFY_INFO;

/* Table 115: TPMS_QUOTE_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details The attested data for TPM2_Quote().
 */
typedef struct
{
    /*! info on algID, PCR selected and digest */
    TPML_PCR_SELECTION pcrSelect;
    /*! digest of the selected PCR using the hash of the signing key */
    TPM2B_NAME         pcrDigest;
} TPMS_QUOTE_INFO;

/* Table 116: TPMS_COMMAND_AUDIT_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details The attested data for TPM2_GetCommandAuditDigest().
 */
typedef struct
{
    /*! the monotonic audit counter */
    ubyte8        auditCounter;
    /*! hash algorithm used for the command audit */
    TPM2_ALG_ID    digestAlg;
    /*! current value of the audit digest */
    TPM2B_DIGEST  auditDigest;
    /*! digest of the command codes being audited using digestAlg */
    TPM2B_DIGEST  commandDigest;
} TPMS_COMMAND_AUDIT_INFO;

/* Table 117: TPMS_SESSION_AUDIT_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details The attested data for TPM2_GetSessionAuditDigest().
 */
typedef struct
{
    /*! current exclusive state of the session
     <p> TRUE if all of the commands recorded in the sessionDigest were executed without any intervening TPM command that did not use this audit session.
     */
    TPMI_YES_NO   exclusiveSession;
    /*! current value of the session audit digest */
    TPM2B_DIGEST  sessionDigest;
} TPMS_SESSION_AUDIT_INFO;

/* Table 118: TPMS_CREATION_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details The attested data for TPM2_CertifyCreation().
 */
typedef struct
{
    /*! name of the object */
    TPM2B_NAME    objectName;
    /*! creationHash */
    TPM2B_DIGEST  creationHash;
} TPMS_CREATION_INFO;

/* Table 119: TPMS_NV_CERTIFY_INFO Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   NV certification structure.
 * @details This structure contains the Name and contents of the selected NV Index that is cerfified by  TPM2_NV_Certify().
 */
typedef struct
{
    /* name of the NV Index */
    TPM2B_NAME           indexName;
    /* offset parameter of TPM2_NV_Certify() */
    ubyte2               offset;
    /* contents of the NV Index */
    TPM2B_MAX_NV_BUFFER  nvContents;
} TPMS_NV_CERTIFY_INFO;

/* Table 120 - Definition of (TPM2_ST) TPMI_ST_ATTEST Type */

/*! TPMI_ST_ATTEST is one of the #TPM2_ST_ATTEST_xxx defined values */
typedef TPM2_ST  TPMI_ST_ATTEST;


/* Table 121: TPMU_ATTEST Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation union structure.
 */
typedef union
{
    /*! selector = #TPM2_ST_ATTEST_CERTIFY */
    TPMS_CERTIFY_INFO        certify;
    /*! selector = #TPM2_ST_ATTEST_CREATION */
    TPMS_CREATION_INFO       creation;
    /*! selector = #TPM2_ST_ATTEST_QUOTE */
    TPMS_QUOTE_INFO          quote;
    /*! selector = #TPM2_ST_ATTEST_COMMAND_AUDIT */
    TPMS_COMMAND_AUDIT_INFO  commandAudit;
    /*! selector = #TPM2_ST_ATTEST_SESSION_AUDIT */
    TPMS_SESSION_AUDIT_INFO  sessionAudit;
    /*! selector = #TPM2_ST_ATTEST_TIME */
    TPMS_TIME_ATTEST_INFO    time;
    /*! selector = #TPM2_ST_ATTEST_NV */
    TPMS_NV_CERTIFY_INFO     nv;
} TPMU_ATTEST;

/* Table 122: TPMS_ATTEST Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Attestation structure.
 * @details This structure is used on each TPM-generated signed structure. The signature is over this structure.
 */
typedef struct
{
    /*! indication that this structure was created by a TPM (always #TPM2_GENERATED_VALUE) */
    TPM2_GENERATED   magic;
    /*! type of the attestation structure */
    TPMI_ST_ATTEST  type;
    /*! Qualified Name of the signing key */
    TPM2B_NAME      qualifiedSigner;
    /*! external information supplied by caller */
    TPM2B_DATA      extraData;
    /*! Clock, resetCount, restartCount, and Safe */
    TPMS_CLOCK_INFO clockInfo;
    /*! TPM vendor-specific value identifying the version number of the firmware */
    ubyte8          firmwareVersion;
    /*! the type-specific attestation information */
    TPMU_ATTEST     attested;
} TPMS_ATTEST;

/* Table 123: TPM2B_ATTEST Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   sized buffer to contain the signed structure
 * @details The attestionData is the signed portion of the structure. The size parameter is not signed.
 */
typedef struct
{
    /*! size of the attestationData structure */
    ubyte2 size;
    /*! the signed structure */
    ubyte  attestationData[sizeof(TPMS_ATTEST)];
} TPM2B_ATTEST;

/* Table 124:  TPMS_AUTH_COMMAND Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   command authorization structure
 * @details The format used for each of the authorizations in the session area of a command.
 */
typedef struct
{
    /* the session handle */
    TPMI_SH_AUTH_SESSION sessionHandle;
    /* the session nonce, may be empty */
    TPM2B_NONCE          nonce;
    /* the session attributes */
    TPMA_SESSION         sessionAttributes;
    /* either an HMAC, a password, or an EmptyAuth */
    TPM2B_AUTH           hmac;
}  TPMS_AUTH_COMMAND;

/* Table 125:  TPMS_AUTH_RESPONSE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   response authorization structure
 * @details The format used for each of the authorizations in the session area of the response.  If the TPM returns #TPM2_RC_SUCCESS, then the session area of the response contains the same number of authorizations as the command and the authorizations are in the same order.
 */
typedef struct
{
    /*! the session nonce; may be empty */
    TPM2B_NONCE          nonce;
    /*! the session attributes */
    TPMA_SESSION         sessionAttributes;
    /*! either an HMAC or an EmptyAuth */
    TPM2B_AUTH           hmac;
}  TPMS_AUTH_RESPONSE;



/* Section 11.1: Symmetric Algorithm Parameters and Structures */


/* Table 126 - Definition of { !ALG.S} (TPM2_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type */

/*! supported key sizes for an AES symmetric key */
typedef TPM2_KEY_BITS  TPMI_AES_KEY_BITS;
/*! supported key sizes for an SM4 symmetric key */
typedef TPM2_KEY_BITS  TPMI_SM4_KEY_BITS;
/*! supported key sizes for a CAMELLIA symmetric key */
typedef TPM2_KEY_BITS  TPMI_CAMELLIA_KEY_BITS;

/* Table 127: TPMU_SYM_KEY_BITS Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Union used to collect the summetric encryption key sizes.
 * @details The xor entry is a hash algorithms selector and not a key size in bits. This overload is used in order to avoid an additional level of indirection with another union and another set of selectors.
<p>The xor entry is only selected in a #TPMT_SYM_DEF, which is used to select the parameter encryption value.
 */
typedef union
{
#ifdef TPM2_ALG_AES
    /*! Selector = TPM2_ALG_AES */
    TPMI_AES_KEY_BITS       aes;
#endif
#ifdef TPM2_ALG_SM4
    /*! Selector = TPM2_ALG_SM4 */
    TPMI_SM4_KEY_BITS       sm4;
#endif
#ifdef TPM2_ALG_CAMELLIA
    /*! Selector = TPM2_ALG_CAMELLIA */
    TPMI_CAMELLIA_KEY_BITS  camellia;
#endif
    /*! when selector may be any of the symmetric block ciphers */
    TPM2_KEY_BITS            sym;
#ifdef TPM2_ALG_XOR
    /*! Selector = TPM2_ALG_XOR; overload for using xor */
    TPMI_ALG_HASH           xor;
#endif
    /*! null/empty selector */
    TPMS_EMPTY              null; 
} TPMU_SYM_KEY_BITS;

/* Table 128: TPMU_SYM_MODE Union */

/**
 * @ingroup tpm2_definitions
 * @brief   symmetric union structure
 * @details This allows the mode value in #TPMT_SYM_DEF or #TPMT_SYM_DEF_OBJECT to be empty.
 */
typedef union
{
#ifdef TPM2_ALG_AES
    /*! Selector = TPM2_ALG_AES */
    TPMI_ALG_SYM_MODE  aes;
#endif
#ifdef TPM2_ALG_SM4
    /*! Selector = TPM2_ALG_SM4 */
    TPMI_ALG_SYM_MODE  sm4;
#endif
#ifdef TPM2_ALG_CAMELLIA
    /*! Selector = TPM2_ALG_CAMELLIA */
    TPMI_ALG_SYM_MODE  camellia;
#endif
    /*! when selector may be any of the symmetric block ciphers */
    TPMI_ALG_SYM_MODE  sym;
#ifdef TPM2_ALG_XOR
    /*! null/empty selector */
    TPMS_EMPTY         xor;
#endif
    /*! null/empty selector */
    TPMS_EMPTY         null; 
} TPMU_SYM_MODE;

/* Table 129: TPMU_SYM_DETAILS Union - not yet supported/defined */

/**
 * @private
 * @internal
 *
 * @ingroup tpm2_definitions
 * @brief   symmetric union structure
 * @details This allows additional parameters to be added for a symmetric cipher.  Currently, no additional parameters are required for any of the symmetric algorithms.
 */
typedef union
{
    /*! null/empty selector */
    TPMS_EMPTY         xor;
    /*! null/empty selector */
    TPMS_EMPTY         null; 
} TPMU_SYM_DETAILS;


/* Table 130: TPMT_SYM_DEF Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   symmetric algorithm structure
 * @details Structure used to select an algorithm to be used for parameter encryption in those cases when different symmetric algorithms may be selected.
 */
typedef struct
{
    /*! indicates a symmetric algorithm */
    TPMI_ALG_SYM       algorithim;
    /*! a supported key size */
    TPMU_SYM_KEY_BITS  keyBits;
    /*! the mode for the key */
    TPMU_SYM_MODE      mode;
} TPMT_SYM_DEF;

/* Table 131: TPMT_SYM_DEF_OBJECT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   symmetric block cipher algorithm structure
 * @details Structure used when different symmetric block cipher (not XOR) algorithms may be selected. If the Object can be an ordinary parent (not a derivation parent), this must be the first field in the Object's parameter field.
 */
typedef struct
{
    /*! selects a symmetric block cipher
     <p> When used in the parameter area of a parent object, this shall be a supported block cipher and not #TPM2_ALG_NULL.
     */
    TPMI_ALG_SYM_OBJECT algorithm;
    /*! the key size */
    TPMU_SYM_KEY_BITS   keyBits;
    /*! default mode
     <p> When used in the parameter area of a parent object, this shall be #TPM2_ALG_CFB.
     */
    TPMU_SYM_MODE       mode;
} TPMT_SYM_DEF_OBJECT;

/* Table 132:  TPM2B_SYM_KEY Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   structure used to hold a symmetric key in the sensitive area of an asymmetric object
 * @details The number of bits in the key is in keyBits in the public area. When keyBits is not an even multiple of 8 bits, the unused bits of buffer will be the most significant bits of buffer[0] and size will be rounded up to the number of octets required to hold all bits of the key.
 */
typedef struct
{
    /*! size, in octets, of the buffer containing the key (may be zero) */
    ubyte2  size;
    /*! the key */
    ubyte   buffer[TPM2_MAX_SYM_KEY_BYTES];
} TPM2B_SYM_KEY;

/* Table 133: TPMS_SYMCIPHER_PARMS Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   symmetric block cipher structure
 * @details This structure contains the parameters for a symmetric block cipher object.
 */
typedef struct
{
    /*! a symmetric block cipher */
    TPMT_SYM_DEF_OBJECT  sym;
} TPMS_SYMCIPHER_PARMS;

/* Table 134 - Definition of TPM2B_LABEL Structure */

/**
 * @ingroup tpm2_definitions
 * @brief   buffer to hold a label or context value
 * @details For interoperability and backwards compatibility, #TPM2_LABEL_MAX_BUFFER is the minimum of the largest digest on the device and the largest ECC parameter (#TPM2_MAX_ECC_KEY_BYTES) but no more than 32 bytes.
 */
typedef struct
{
    /*! size of the data in buffer */
    ubyte2  size;
    /*! symmetric data for a created object or the label and context for a derived object */
    ubyte   buffer[TPM2_LABEL_MAX_BUFFER];
} TPM2B_LABEL;

/* Table 135 - Definition of TPMS_DERIVE Structure */

/**
 * @ingroup tpm2_definitions
 * @brief   structure containing the label and context fields for a derived object
 * @details These values are used in the derivation KDF. The values in the unique field of inPublic area template take precedence over the values in the inSensitive parameter.
 */
typedef struct
{
    /*! label for a derived object */
    TPM2B_LABEL     label;
    /*! context for a derived object */
    TPM2B_LABEL     context;
} TPMS_DERIVE;

/* Table 136 - Definition of TPM2B_DERIVE Structure */

/**
 * @ingroup tpm2_definitions
 * @brief   structure containing the data for a derived object
 */
typedef struct
{
    /*! size of the data in buffer */
    ubyte2  size;
    /*! symmetic data for a created object or the label and context for a derived object */
    ubyte   buffer[ sizeof(TPMS_DERIVE)];
} TPM2B_DERIVE;

/* Table 137 - Definition of TPMU_SENSITIVE_CREATE Union */

/**
 * @ingroup tpm2_definitions
 * @brief   union for sensitive data
 */
typedef union
{
    /*! sensitive data for a created symmetric Object */
    ubyte           create[TPM2_MAX_SYM_DATA];
    /*! label and context for a derived Object */
    TPMS_DERIVE     derive;
} TPMU_SENSITIVE_CREATE;


/* Table 138:  TPM2B_SENSITIVE_DATA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   buffer that wraps the #TPMU_SENSITIVE_CREATE structure
 */
typedef struct
{
    /*! size, in octets */
    ubyte2  size;
    /*! symmetic data for a created object or the label and context for a derived object */
    ubyte   buffer[ sizeof(TPMU_SENSITIVE_CREATE)];
} TPM2B_SENSITIVE_DATA;

/* Table 139: TPMS_SENSITIVE_CREATE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Structure that defines the values to be placed in the sensitive area of a created object.
 * @details This structure is only used within a TPM2B_SENSITIVE_CREATE structure.
 */
typedef struct
{
    /*! the USER auth secret value */
    TPM2B_AUTH           userAuth;
    /*! data to be sealed, a key, or derivation values */
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

/* Table 140: TPM2B_SENSITIVE_CREATE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Structure that contains the sensitive creation data in a sized buffer
 * @details This structure is defined so that both the userAuth and data values of the TPMS_SENSITIVE_CREATE may be passed as a single parameter for parameter encryption purposes.
 */
typedef struct
{
    /* size of sensitive in octets (may NOT be zero) */
    ubyte2                size;
    /* data to be sealed or a symmetric key value */
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

/* Table 141: TPMS_SCHEME_HASH Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   The scheme data for schemes that only require a hash to complete their definition.
 */
typedef struct
{
    /*! the hash algorithm used to digest the message */
    TPMI_ALG_HASH hashAlg;
} TPMS_SCHEME_HASH;

/* Table 142: TPMS_SCHEME_ECDAA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief  This definition is for split signing schemes that require a commit count.
 */
typedef struct
{
    /*! the hash algorithm used to digest the message */
    TPMI_ALG_HASH hashAlg;
    /*! the counter value that is used between TPM2_Commit() and the sign operation */
    ubyte2        count;
} TPMS_SCHEME_ECDAA;

/* Table 143: TPMI_ALG_KEYEDHASH_SCHEME Type */

/**
 * @ingroup tpm2_definitions
 * @brief   The list of values that may appear in a keyedHash as the scheme parameter.
 */
typedef TPM2_ALG_ID  TPMI_ALG_KEYEDHASH_SCHEME;

/* Table 144: HMAC_SIG_SCHEME Type */

/**
 * @ingroup tpm2_definitions
 * @brief   The list of signature scheme values.
 */
typedef TPMS_SCHEME_HASH  TPMS_SCHEME_HMAC;

/* Table 145: TPMS_SCHEME_XOR */

/**
 * @ingroup tpm2_definitions
 * @brief   Stucture for the XOR encryption scheme.
 */
typedef struct
{
    /*! the hash algoritm used to digest the message */
    TPMI_ALG_HASH  hashAlg;
    /*! the key derivation function */
    TPMI_ALG_KDF   kdf;
} TPMS_SCHEME_XOR;

/* Table 146: TPMU_SCHEME_KEYEDHASH Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Union structure for keyed hash algorithms
 */
typedef union
{
    /*! the "signing" scheme */
    TPMS_SCHEME_HMAC  hmac;
    /*! the "obfuscation" scheme */
    TPMS_SCHEME_XOR   xor;
} TPMU_SCHEME_KEYEDHASH;

/* Table 147: TPMT_KEYEDHASH_SCHEME Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   This structure is used for a hash signing object.
 */
typedef struct
{
    /*! selects the scheme */
    TPMI_ALG_KEYEDHASH_SCHEME scheme;  /* selects the scheme */
    /*! the scheme parameters */
    TPMU_SCHEME_KEYEDHASH     details; /* the scheme parameters */
} TPMT_KEYEDHASH_SCHEME;



/* Section 11.2: Asymmetric Algorithm Parameters and Structures */

/* Table 148: RSA Signature Schemes */

/*! RSA SSA Signature Scheme */
typedef TPMS_SCHEME_HASH    TPMS_SIG_SCHEME_RSASSA;
/*! RSA PPS Signature Scheme */
typedef TPMS_SCHEME_HASH    TPMS_SIG_SCHEME_RSAPSS;

/* Table 149: ECC Signature Schemes */

/*! ECC ECDSA Signature Scheme */
typedef TPMS_SCHEME_HASH    TPMS_SIG_SCHEME_ECDSA;
/*! ECC SM2 Signature Scheme */
typedef TPMS_SCHEME_HASH    TPMS_SIG_SCHEME_SM2;
/*! ECC ECSCHNORR Signature Scheme */
typedef TPMS_SCHEME_HASH    TPMS_SIG_SCHEME_ECSCHNORR;
/*! ECC ECDAA Signature Scheme */
typedef TPMS_SCHEME_ECDAA   TPMS_SIG_SCHEME_ECDAA;

/* Table 150: TPMU_SIG_SCHEME Union */

/**
 * @ingroup tpm2_definitions
 * @brief   The union of all signature schemes. 
 */
typedef union
{
    /*! TPM2_ALG_RSASSA */
    TPMS_SIG_SCHEME_RSASSA       rsassa;
    /*! TPM2_ALG_RSAPSS */
    TPMS_SIG_SCHEME_RSAPSS       rsapss;
    /*! TPM2_ALG_ECDSA */
    TPMS_SIG_SCHEME_ECDSA        ecdsa;
    /*! TPM2_ALG_ECDAA */
    TPMS_SIG_SCHEME_ECDAA        ecdaa;
    /*! TPM2_ALG_SM2 */
    TPMS_SIG_SCHEME_SM2          sm2;
    /*! TPM2_ALG_ECSHNORR */
    TPMS_SIG_SCHEME_ECSCHNORR    eschnorr;
    /*! TPM2_ALG_HMAC */
    TPMS_SCHEME_HMAC             hmac;
    /*! selector that allows access to digest for any signing scheme */
    TPMS_SCHEME_HASH             any;
    /*! TPM2_ALG_NULL */
    TPMS_EMPTY                  null;
} TPMU_SIG_SCHEME;

/* Table 151: TPMT_SIG_SCHEME Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   signature scheme structure
 */
typedef struct
{
    /*! scheme selector */
    TPMI_ALG_SIG_SCHEME  scheme;
    /*! scheme parameters */
    TPMU_SIG_SCHEME      details;
} TPMT_SIG_SCHEME;

/* Table 152: RSA Encryption Schemes */

/*! TPMS_ENC_SCHEME_OAEP - schemes that only need a hash */
typedef TPMS_SCHEME_HASH    TPMS_ENC_SCHEME_OAEP;
/*! TPMS_ENC_SCHEME_RSAES - schemes that need nothing */
typedef TPMS_EMPTY          TPMS_ENC_SCHEME_RSAES;

/* Table 153: ECC Key Exchange */

/**
 * @ingroup tpm2_definitions
 * @brief   signature scheme structure
 */
/*! TPMS_KEY_SCHEME_ECDH - scheme that needs a hash */
typedef TPMS_SCHEME_HASH    TPMS_KEY_SCHEME_ECDH;
/*! TPMS_KEY_SCHEME_ECMQV - scheme that needs a hash */
typedef TPMS_SCHEME_HASH    TPMS_KEY_SCHEME_ECMQV;

/* Table 154: KDF Schemes */

/*! TPMS_SCHEME_MGF1 */
typedef TPMS_SCHEME_HASH    TPMS_SCHEME_MGF1;
/*! TPMS_SCHEME_KDF1_SP800_56A */
typedef TPMS_SCHEME_HASH    TPMS_SCHEME_KDF1_SP800_56A;
/*! TPMS_SCHEME_KDF2 */
typedef TPMS_SCHEME_HASH    TPMS_SCHEME_KDF2;
/*! TPMS_SCHEME_KDF1_SP800_108 */
typedef TPMS_SCHEME_HASH    TPMS_SCHEME_KDF1_SP800_108;

/* Table 155: TPMU_KDF_SCHEME Union */

/**
 * @ingroup tpm2_definitions
 * @brief   union of KDF schemes
 */
typedef union
{
    /*! TPM2_ALG_MGF1 */
    TPMS_SCHEME_MGF1            mgf1;
    /*! TPM2_ALG_KDF1_SP800_56A */
    TPMS_SCHEME_KDF1_SP800_56A  kdf1_sp800_56a;
    /*! TPM2_ALG_KDF2 */
    TPMS_SCHEME_KDF2            kdf2;
    /*! TPM2_ALG_KDF1_SP800_108 */
    TPMS_SCHEME_KDF1_SP800_108  kdf1_sp800_108;
} TPMU_KDF_SCHEME;

/* Table 156: TPMT_KDF_SCHEME */

/**
 * @ingroup tpm2_definitions
 * @brief   Key Derivation Function (KDF) structure
 */
typedef struct
{
    /* scheme selector */
    TPMI_ALG_KDF     scheme;
    /* scheme parameters */
    TPMU_KDF_SCHEME  details;
} TPMT_KDF_SCHEME;

/* Table 157: TPMI_ALG_ASYM_SCHEME Type */

/*! Asymmetric algorithm scheme type */
typedef TPM2_ALG_ID              TPMI_ALG_ASYM_SCHEME;

/* Table 158: TPMU_ASYM_SCHEME Union */

/**
 * @ingroup tpm2_definitions
 * @brief   This union of all asymmetric schemes is used in each of the asymmetric scheme structures.
 * @details The actual scheme structure is defined by the interface type used for the selector (#TPMI_ALG_ASYM_SCHEME).
 */
typedef union
{
    /*! TPM2_ALG_ECDH key scheme */
    TPMS_KEY_SCHEME_ECDH        ecdh;
    /*! TPM2_ALG_ECMQV key scheme */
    TPMS_KEY_SCHEME_ECMQV       ecmqvh;
    /*! TPM2_ALG_RSASSA signature scheme */
    TPMS_SIG_SCHEME_RSASSA      rsassa;
    /*! TPM2_ALG_RSAPSS signature scheme */
    TPMS_SIG_SCHEME_RSAPSS      rsapss;
    /*! TPM2_ALG_ECDSA signature scheme */
    TPMS_SIG_SCHEME_ECDSA       ecdsa;
    /*! TPM2_ALG_ECDAA signature scheme */
    TPMS_SIG_SCHEME_ECDAA       ecdaa;
    /*! TPM2_ALG_SM2 signature scheme */
    TPMS_SIG_SCHEME_SM2         sm2;
    /*! TPM2_ALG_ECSCHNORR signature scheme */
    TPMS_SIG_SCHEME_ECSCHNORR   ecSchnorr;
    /*! TPM2_ALG_RSAES encryption scheme */
    TPMS_ENC_SCHEME_RSAES       rsaes;
    /*! TPM2_ALG_OAEP encryption scheme */
    TPMS_ENC_SCHEME_OAEP        oaep;
    /*! any scheme */
    TPMS_SCHEME_HASH            anySig;
    /*! TPM2_ALG_NULL - no scheme or default.  This select the NULL Signature. */
    TPMS_EMPTY                  null;
} TPMU_ASYM_SCHEME;

/* Table 159: TPMT_ASYM_SCHEME Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Structure defined to allow overlay of all of the schemes for any asymmetric object.
 * @details This structure is not sent on the interface. It is defined so that common functions may operate on any similar scheme structure. 
 */
typedef struct
{
    /*! scheme selector */
    TPMI_ALG_ASYM_SCHEME  scheme;
    /*! scheme parameters */
    TPMU_ASYM_SCHEME      details;
} TPMT_ASYM_SCHEME;

/* Table 160: TPMI_ALG_RSA_SCHEME Type */

/*! TPMI_ALG_RSA_SCHEME - encrypting and signing algorithms */
typedef TPM2_ALG_ID TPMI_ALG_RSA_SCHEME;

/* Table 161: TPMT_RSA_SCHEME Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   RSA scheme structure
 */
typedef struct
{
    /*! scheme selector */
    TPMI_ALG_RSA_SCHEME scheme;
    /*! scheme parameters */
    TPMU_ASYM_SCHEME    details;
} TPMT_RSA_SCHEME;

/* Table 162: TPMI_ALG_RSA_DECRYPT Type */

/*! TPMI_ALG_RSA_DECRYPT - list of values that are allowed in a decryption scheme selection as used in TPM2_RSA_Encrypt() and TPM2_RSA_Decrypt(). */
typedef TPM2_ALG_ID TPMI_ALG_RSA_DECRYPT;

/* Table 163: TPMT_RSA_DECRYPT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   RSA decrypt structure
 */
typedef struct
{
    /*! scheme selector */
    TPMI_ALG_RSA_DECRYPT        scheme;
    /*! scheme parameters */
    TPMU_ASYM_SCHEME            details;
} TPMT_RSA_DECRYPT;

/* Table 164: TPM2B_PUBLIC_KEY_RSA Struct */

typedef struct
{
    /*! size of the buffer.  The value of zero is only valid for create. */
    ubyte2      size;
    /*! value - up to #TPM2_MAX_RSA_KEY_BYTES in size */
    ubyte       buffer[TPM2_MAX_RSA_KEY_BYTES];
} TPM2B_PUBLIC_KEY_RSA;

/* Table 165: TPMI_RSA_KEY_BITS Type */

/*! TPMI_RSA_KEY_BITS - holds the value that is the maximum size allowed for an RSA key */
typedef TPM2_KEY_BITS TPMI_RSA_KEY_BITS;

/* Table 166: TPM2B_PRIVATE_KEY_RSA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Sized buffer that holds the largest RSA prime number supported by the TPM.
 */
typedef struct
{
    /*! size of the buffer */
    ubyte2      size;
    /* value - up to #TPM2_MAX_RSA_KEY_BYTES/2 in size */
    ubyte       buffer[TPM2_MAX_RSA_KEY_BYTES/2];
} TPM2B_PRIVATE_KEY_RSA;

/* Table 167: TPM2B_ECC_PARAMETER Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Sized buffer that holds the largest ECC parameter (coordinate) supported by the TPM.
 */
typedef struct
{
    /*! size of the data in buffer */
    ubyte2      size;
    /*! the parameter data - up to #TPM2_MAX_ECC_KEY_BYTES in size */
    ubyte       buffer[TPM2_MAX_ECC_KEY_BYTES];
} TPM2B_ECC_PARAMETER;

/* Table 168: TPMS_ECC_POINT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   ECC point structure
 * @details This structure holds two ECC coordinates that, together, make up an ECC point.
 */
typedef struct
{
    /*! X coordinate */
    TPM2B_ECC_PARAMETER x;
    /*! Y coordinate */
    TPM2B_ECC_PARAMETER y;
} TPMS_ECC_POINT;

/* Table 169: TPM2B_ECC_POINT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   ECC point structure
 * @details This structure is defined to allow a point to be a single sized paramter so that it may be encrypted.
 */
typedef struct
{
    /*! size of the remainder of this structure */
    ubyte2              size;   /* size of the remainder of this structure */
    /*! coordinates */
    TPMS_ECC_POINT      point;  /* coordinates */
} TPM2B_ECC_POINT;

/* Table 170: TPMI_ALG_ECC_SCHEME Type */

/*! TPMI_ALG_ECC_SCHEME type */
typedef TPM2_ALG_ID TPMI_ALG_ECC_SCHEME;

/* Table 171: TPMI_ECC_CURVE Type */

/*! TPMI_ECC_CURVE type */
typedef TPM2_ECC_CURVE TPMI_ECC_CURVE;

/* Table 172: TPMT_ECC_SCHEME Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   ECC scheme structure
 */
typedef struct
{
    /*! scheme selector */
    TPMI_ALG_ECC_SCHEME  scheme;
    /*! scheme parameters */
    TPMU_ASYM_SCHEME     details;
} TPMT_ECC_SCHEME;

/* Table 173: TPMS_ALGORITHM_DETAIL_ECC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   ECC curve detail structure
 * @details This structure is used to report on the curve parameters of an ECC curve.  It is returned by TPM2_ECC_Parameters().
 */
typedef struct
{
    /*! identifier for the curve */
    TPM2_ECC_CURVE       curveID;
    /*! Size in bits of the key */
    ubyte2              keySize;
    /*! If not #TPM2_ALG_NULL, the required KDF and hash algorithm used in secret sharing operations */
    TPMT_KDF_SCHEME     kdf;
    /*! If not #TPM2_ALG_NULL, this is the mandatory signature scheme that is required to be used with this curve. */
    TPMT_ECC_SCHEME     sign;
    /*! Fp (the modulus) */
    TPM2B_ECC_PARAMETER p;
    /*! coefficient of the linear term in the curve equation */
    TPM2B_ECC_PARAMETER a;
    /*! constant term for curve equation */
    TPM2B_ECC_PARAMETER b;
    /*! x coordinate of base point G */
    TPM2B_ECC_PARAMETER gX;
    /*! y coordinate of base point G */
    TPM2B_ECC_PARAMETER gY;
    /*! order of G */
    TPM2B_ECC_PARAMETER n;
    /*! cofactor (a size of zero indicates a cofactor of 1) */
    TPM2B_ECC_PARAMETER h;
} TPMS_ALGORITHM_DETAIL_ECC;


/* Section 11.3: Signatures */


/* Table 174: TPMS_SIGNATURE_RSA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   RSA signature structure
 */
typedef struct
{
    /*! the hash algorithm used to digest the message (#TPM2_ALG_NULL not allowed.) */
    TPMI_ALG_HASH         hash;
    /*! The signature is the size of a public key. */
    TPM2B_PUBLIC_KEY_RSA  sig;
} TPMS_SIGNATURE_RSA;

/* Table 175: Types for RSA Signature */

/*! TPMS_SIGNATURE_RSASSA signature definition */
typedef TPMS_SIGNATURE_RSA      TPMS_SIGNATURE_RSASSA;
/*! TPMS_SIGNATURE_RSAPSS signature definition */
typedef TPMS_SIGNATURE_RSA      TPMS_SIGNATURE_RSAPSS;

/* Table 176: TPMS_SIGNATURE_ECC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   ECC signature structure
 */
typedef struct
{
    /*! the hash algorithm used in the signature process. (#TPM2_ALG_NULL not allowed.) */
    TPMI_ALG_HASH       hash;
    /*! r output */
    TPM2B_ECC_PARAMETER signatureR;
    /*! s output */
    TPM2B_ECC_PARAMETER signatureS;
} TPMS_SIGNATURE_ECC;

/* Table 177: Types for TPMS_SIGNATURE_ECC */

/*! TPMS_SIGNATURE_ECDSA definition */
typedef TPMS_SIGNATURE_ECC      TPMS_SIGNATURE_ECDSA;
/*! TPMS_SIGNATURE_ECDAA definition */
typedef TPMS_SIGNATURE_ECC      TPMS_SIGNATURE_ECDAA;
/*! TPMS_SIGNATURE_SM2 definition */
typedef TPMS_SIGNATURE_ECC      TPMS_SIGNATURE_SM2;
/*! TPMS_SIGNATURE_ECSCHNORR definition */
typedef TPMS_SIGNATURE_ECC      TPMS_SIGNATURE_ECSCHNORR;

/* Table 178: TPMU_SIGNATURE Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Signature union structure
 * @details A TPMU_SIGNATURE_COMPOSITE is a union of the various signatures that are supported by a particular TPM implementation. The union allows substitution of any signature algorithm wherever a signature is required in a structure.
 <p> When a symmetric algorithm is used for signing, the signing algorithm is assumed to be an HMAC based on the indicated hash algorithm.
 */
typedef union
{
    /*! TPM2_ALG_RSASSA asymmetric signature */
    TPMS_SIGNATURE_RSASSA       rsassa;
    /*! TPM2_ALG_RSAPSS asymmetric signature */
    TPMS_SIGNATURE_RSAPSS       rsapss;
    /*! TPM2_ALG_ECDSA asymmetric signature */
    TPMS_SIGNATURE_ECDSA        ecdsa;
    /*! TPM2_ALG_ECDAA asymmetric signature */
    TPMS_SIGNATURE_ECDAA        ecdaa;
    /*! TPM2_ALG_SM2 asymmetric signature */
    TPMS_SIGNATURE_SM2          sm2;
    /*! TPM2_ALG_ECSCHNORR asymmetric signature */
    TPMS_SIGNATURE_ECSCHNORR    ecschnorr;
    /*! TPM2_ALG_HMAC HMAC signature */
    TPMT_HA                     hmac;
    /*! used to access the hash */
    TPMS_SCHEME_HASH            any;
    /*! TPM2_ALG_NULL - the NULL signature */
    TPMS_EMPTY                  null;
} TPMU_SIGNATURE;

/* Table 179: TPMT_SIGNATURE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   basic algorithm-agile signature structure
 * @details This structure can be used when a symmetric or asymmetric signature is indicated. The sigAlg parameter indicates the algorithm used for the signature. This structure is output from the attestation commands and is an input to TPM2_VerifySignature(), TPM2_PolicySigned(), and TPM2_FieldUpgradeStart().
 */
typedef struct
{
    /*! selector of the algorithm used to construct the signature */
    TPMI_ALG_SIG_SCHEME sigAlg;
    /*! the actual signature information */
    TPMU_SIGNATURE      signature;
} TPMT_SIGNATURE;


/* Section 11.4: Key/Secret Exchange */


/* Table 180: TPMU_ENCRYPTED_SECRET Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Encrypted secret union definition
 */
typedef union
{
    /*! TPM2_ALG_ECC */
    ubyte ecc[sizeof(TPMS_ECC_POINT)];
    /*! TPM2_ALG_RSA */
    ubyte rsa[TPM2_MAX_RSA_KEY_BYTES];
    /*! TPM2_ALG_SYMCIPHER */
    ubyte symmetric[sizeof(TPM2B_DIGEST)];
    /*! TPM2_ALG_KEYEDHASH */
    ubyte keyedHash[sizeof(TPM2B_DIGEST)];
} TPMU_ENCRYPTED_SECRET;

/* Table 181: TPM2B_ENCRYPTED_SECRET Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Encrypted secret stucture definition
 * @details This structure is used to hold either an ephemeral public point for ECDH, an OAEP-encrypted block for RSA, or a symmetrically encrypted value. This structure is defined for the limited purpose of determining the size of a TPM2B_ENCRYPTED_SECRET.
 */
typedef struct
{
    /*! size of the secret value */
    ubyte2 size;
    /*! secret - up to max size of #TPMU_ENCRYPTED_SECRET */
    ubyte   secret[sizeof(TPMU_ENCRYPTED_SECRET)];
} TPM2B_ENCRYPTED_SECRET;


/* Section 12: Key/Object Complex */

/* Section 12.2: Public Area Structures */

/* Table 182: TPMI_ALG_PUBLIC Type */

/*! TPMI_ALG_PUBLIC */
typedef TPM2_ALG_ID TPMI_ALG_PUBLIC;

/* Table 183: TPMU_PUBLIC_ID Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Union of all values allowed in the unique field of a TPMT_PUBLIC
 */
typedef union
{
    /*! selector = #TPM2_ALG_KEYEDHASH */
    TPM2B_DIGEST            keyedHash;
    /*! selector = #TPM2_ALG_SYMCIPHER */
    TPM2B_DIGEST            sym;
    /*! selector = #TPM2_ALG_RSA */
    TPM2B_PUBLIC_KEY_RSA    rsa;
    /*! selector = #TPM2_ALG_ECC */
    TPMS_ECC_POINT          ecc;
    /*! Only allowed for TPM2_CreateLoaded() when parentHandle is a Derivation Parent. */
    TPMS_DERIVE             derive;
} TPMU_PUBLIC_ID;

/* Table 184: TPMS_KEYEDHASH_PARMS Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   This structure describes the parameters that would appear in the public area of a KEYEDHASH object.
 */
typedef struct
{
    /*! Indicates the signing method used for a keyedHash signing object. This field also determines the size of the data field for a data object created TPM2_CreatePrimary(). */
    TPMT_KEYEDHASH_SCHEME scheme;
} TPMS_KEYEDHASH_PARMS;

/* Table 185: TPMS_ASYM_PARMS Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   This structure contains the common public area parameters for an asymmetric key.
 */
typedef struct
{
    /*! the companion symmetric algorithm for a restricted decryption key; shall be set to a supported symmetric algorithm.
     <p> This field is optional for keys that are not decryption keys and shall be set to #TPM2_ALG_NULL if not used.
     */
    TPMT_SYM_DEF_OBJECT symmetric;
    /*! for a key with the sign attribute SET, a valid signing scheme for the key type
    <p> for a key with the decrypt attribute SET, a valid key exchange protocol
    <p> for a key with the sign and decrypt attributes SET, shall be #TPM2_ALG_NULL
     */
    TPMT_ASYM_SCHEME    scheme;
} TPMS_ASYM_PARMS;

/* Table 186: TPMS_RSA_PARMS Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   RSA parameter structure
 * @details A TPM compatible with the TPM 2.0 specification and supporting RSA shall support two primes and an exponent of zero. Support for other values is optional.
 */
typedef struct
{
    /*! for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode.
      <p> if the key is not a restricted decryption key, this field shall be set to #TPM2_ALG_NULL.
     */
    TPMT_SYM_DEF_OBJECT symmetric;
    /*! for an unrestricted signing key, shall be #TPM2_ALG_RSAPSS, #TPM2_ALG_RSASSA or #TPM2_ALG_NULL
     <p> for a restricted signing key, shall be #TPM2_ALG_RSAPSS or #TPM2_ALG_RSASSA
     <p> for an unrestricted decryption key, shall be #TPM2_ALG_RSAES, #TPM2_ALG_OAEP, or #TPM2_ALG_NULL unless the object also has the sign attribute
     <p> for a restricted decryption key, shall be #TPM2_ALG_NULL
     */
    TPMT_RSA_SCHEME     scheme;
    /*! number of bits in the public modulus */
    TPMI_RSA_KEY_BITS   keyBits;
    /*! the public exponent; a prime number greater than 2.  When zero, indicates that the exponent is the default of 2^16 + 1. */
    ubyte4              exponent;
} TPMS_RSA_PARMS;

/* Table 187: TPMS_ECC_PARMS Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   ECC parameter structure
 * @details This structure contains the parameters for prime modulus ECC.
 */
typedef struct
{
    /*! for a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode.
     <p> If the key is not a restricted decryption key, this field shall be set to #TPM2_ALG_NULL.
     */
    TPMT_SYM_DEF_OBJECT symmetric;
    /*! If the sign attribute of the key is SET, then this shall be a valid signing scheme.
     <p> If the decrypt attribute of the key is SET, then this shall be a valid key exchange scheme or #TPM2_ALG_NULL.
     <p> If the key is a Storage Key, then this field shall be #TPM2_ALG_NULL.
     */
    TPMT_ECC_SCHEME     scheme;
    /* ECC curve ID */
    TPMI_ECC_CURVE      curveID;
    /*! an optional key derivation scheme for generating a symmetric key from a Z value */
    TPMT_KDF_SCHEME     kdf;
} TPMS_ECC_PARMS;

/* Table 188: TPMU_PUBLIC_PARMS Union */

/**
 * @ingroup tpm2_definitions
 * @brief   Union of public key parameters
 * @details This union defines the possible parameter definition structures that may be contained in the public portion of a key. If the Object can be a parent, the first field must be a TPMT_SYM_DEF_OBJECT.
 */
typedef union
{
    /*! selector = #TPM2_ALG_KEYEDHASH; sign|decrypt|neither */
    TPMS_KEYEDHASH_PARMS    keyedHashDetail;
    /*! selector = #TPM2_ALG_SYMCIPHER; symmetric block cipher */
    TPMS_SYMCIPHER_PARMS    symDetail;
    /*! selector = #TPM2_ALG_RSA, decrypt & sign */
    TPMS_RSA_PARMS          rsaDetail;
    /*! selector = #TPM2_ALG_ECC, decrypt & sign */
    TPMS_ECC_PARMS          eccDetail;
    /*! common scheme structure for RSA and ECC keys */
    TPMS_ASYM_PARMS         asymDetail;
} TPMU_PUBLIC_PARMS;

/* Table 189: TPMT_PUBLIC_PARMS Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   public key parameters
 * @details This structure is used in TPM2_TestParms() to validate that a set of algorithm parameters is supported by the TPM.
 */
typedef struct
{
    /*! the algorithm to be tested */
    TPMI_ALG_PUBLIC     type;
    /*! the algorithm details */
    TPMU_PUBLIC_PARMS   parameters;
} TPMT_PUBLIC_PARMS;

/* Table 190: TPMT_PUBLIC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   public area structure
 * @details  This structure defines the public area. The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg.
 */
typedef struct
{
    /*! algorithm associated with this object */
    TPMI_ALG_PUBLIC     type;
    /*! hash algorithm used for computing the Name of the object.
        <p> Must be TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA512. 
     */
    TPMI_ALG_HASH       nameAlg;
    /*! attributes that, along with type, determine the manipulations of this object */
    TPMA_OBJECT         objectAttributes;
    /*! optional policy for using this key */
    TPM2B_DIGEST        authPolicy;
    /*! the algorithm or structure details */
    TPMU_PUBLIC_PARMS   parameters;
    /*! the unique identifier of the structure */
    TPMU_PUBLIC_ID      unique;
} TPMT_PUBLIC;

/* Table 191: TPM2B_PUBLIC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   sized buffer used for a public structure
 * @details This sized buffer is used to embed a #TPMT_PUBLIC in a load command and in any response that returns a public area.
 */
typedef struct
{
    /*! size of publicArea */
    ubyte2      size;
    /*! the public area  */
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

/* Table 192: TPM2B_TEMPLATE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   sized buffer used for a template structure
 * @details This sized buffer is used to embed a #TPMT_TEMPLATE for TPM2_CreateLoaded().
 */
typedef struct
{
    /*! size of buffer */
    ubyte2      size;
    /*! the buffer  */
    ubyte   buffer[sizeof(TPMT_PUBLIC)];
} TPM2B_TEMPLATE;


typedef struct 
{
    /*! size of buffer */
    ubyte2      size;
    /*! the buffer  */
    ubyte   buffer[sizeof(TPM2B_PUBLIC)];
}TPM2B_PUBLIC_BLOB;

/* Section 12.3: Private Area Structures */

/* Table 193: TPM2B_PRIVATE_VENDOR_SPECIFIC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   vendor-specific private data structure
 * @details The value for RSA_VENDOR_SPECIFIC is determined by the vendor.
 */
typedef struct
{
    /*! size of buffer */
    ubyte2      size;
    /*! vendor-specific data; max size is #TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES */
    ubyte   buffer[TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES];
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

/* Table 194: TPMU_SENSITIVE_COMPOSITE Union */

/**
 * @ingroup tpm2_definitions
 * @brief   union for the sensitive area data types
 */
typedef union
{
    /*! TPM2_ALG_RSA; a prime factor of the public key */
    TPM2B_PRIVATE_KEY_RSA           rsa;
    /*! TPM2_ALG_ECC; the integer private key */
    TPM2B_ECC_PARAMETER             ecc;
    /*! TPM2_ALG_KEYEDHASH; the private data */
    TPM2B_SENSITIVE_DATA            bits;
    /*! TPM2_ALG_SYMCIPHER; the symmetric key */
    TPM2B_SYM_KEY                   sym;
    /*! vendor-specific size for key storage */
    TPM2B_PRIVATE_VENDOR_SPECIFIC   any;
} TPMU_SENSITIVE_COMPOSITE;

/* Table 195: TPMT_SENSITIVE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   structure for sensitive area data
 */
typedef struct
{
    /*! identifier for the sensitive area.  This shall be the same as the type parameter of the associated public area.  */
    TPMI_ALG_PUBLIC             sensitiveType;
    /*! user authorization data. The authValue may be a zero-length string. */
    TPM2B_AUTH                  authValue;
    /*! for a parent object, the optional protection seed; for other objects, the obfuscation value */
    TPM2B_DIGEST                seedValue;
    /*! the type-specific private data */
    TPMU_SENSITIVE_COMPOSITE    sensitive;
} TPMT_SENSITIVE;

/* Table 196: TPM2B_SENSITIVE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   sensitive data structure
 * @details This structure is used as a parameter in TPM2_LoadExternal().  It is an unencrypted sensitive area but it may be encrypted using parameter encryption.
 */
typedef struct
{
    /*! size of the private structure */
    ubyte2          size;
    /*! an unencrypted sensitive area */
    TPMT_SENSITIVE  sensitiveArea;
} TPM2B_SENSITIVE;

/* Table 197: _PRIVATE Struct */

/**
 * @private
 * @internal
 *
 * @ingroup tpm2_definitions
 * @brief   internal structure
 * @details This structure is defined to size the contents of TPM2B_PRIVATE.
 */
typedef struct
{
    TPM2B_DIGEST        integrityOuter;
    /*! could also be a TPM2B_IV */
    TPM2B_DIGEST        integrityInner;
    /*! the sensitive area */
    TPM2B_SENSITIVE     sensitive;
} _PRIVATE;

/* Table 198: TPM2B_PRIVATE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Structure for the sensitive area of an object
 * @details This structure is used as a paremeter in multiple commands that create, load, and modify the sensitive area of an object.
 */
typedef struct
{
    /*! size of the private structure */
    ubyte2      size;
    /*! an encrypted private area */
    ubyte       buffer[sizeof(_PRIVATE)];
} TPM2B_PRIVATE;

/* Section 12.4: Identity Object */

/* Table 199: _ID_OBJECT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Structure used for sizing the TPM2B_ID_OBJECT.
 */
typedef struct
{
    /*! HMAC using the nameAlg of the storage key on the target TPM */
    TPM2B_DIGEST  integrityHMAC;
    /*! credential protector information returned if name matches the referenced object.  All of the encIdentity is encrypted, including the size field. */
    TPM2B_DIGEST  encIdentity;
} TPMS_ID_OBJECT;

/* Table 200: TPM2B_ID_OBJECT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   Identity object definiton
 * @details An identity object is used to convey credential protection value (CV) to a TPM that can load the object associated with the object. The CV is encrypted to a storage key on the target TPM, and if the credential integrity checks and the proper object is loaded in the TPM, then the TPM will return the CV.
 <p> This structure is an output from TPM2_MakeCredential() and is an input to TPM2_ActivateCredential().
 */
typedef struct
{
    /* size of the credential structure */
    ubyte2  size;
    /* an encrypted credential area */
    ubyte   credential[sizeof(TPMS_ID_OBJECT)];
} TPM2B_ID_OBJECT;


/* Section 13: NV Storage Structures */

/* Section 13.1: TPM2_NV_INDEX */

/* Table 201 - Definition of (ubyte4) TPM2_NV_INDEX Bits */

/*! TPM2_NV_INDEX_INDEX_MASK - bit mask to get the index of the NV location */
#define TPM2_NV_INDEX_INDEX_MASK      ((TPM2_NV_INDEX) 0x00ffffff)
/*! TPM2_NV_INDEX_RH_NV_SHIFT - number of bits to shift to get the NV index value */
#define TPM2_NV_INDEX_INDEX_SHIFT     (0)
/*! TPM2_NV_INDEX_RH_NV_MASK - bit mask to get the value of #TPM2_HT_NV_INDEX indicating the NV index range */
#define TPM2_NV_INDEX_RH_NV_MASK      ((TPM2_NV_INDEX) 0xff000000)
/*! TPM2_NV_INDEX_RH_NV_SHIFT - number of bits to shift to get the RH_NV value */
#define TPM2_NV_INDEX_RH_NV_SHIFT     (24)


/* Section 13.2: TPMA_NV (NV Index Attributes) */

/* Table 202: TPM2_NT Constants */

/*! Ordinary - contains data that is opaque to the TPM that can only be modified using TPM2_NV_Write(). */
#define TPM2_NT_ORDINARY    (0x0)
/*! Counter - contains an 8-octet value that is to be used as a counter and can only be modified with TPM2_NV_Increment() */
#define TPM2_NT_COUNTER     (0x1)
/*! Bit Field - contains an 8-octet value to be used as a bit field and can only be modified with TPM2_NV_SetBits(). */
#define TPM2_NT_BITS        (0x2)
/*! Extend - contains a digest-sized value used like a PCR. The Index can only be modified using TPM2_NV_Extend(). The extend will use the nameAlg of the Index. */
#define TPM2_NT_EXTEND      (0x4)
/*! PIN Fail - contains a PIN limit and a PIN count that increments on a PIN authorization failure and a pinLimit */
#define TPM2_NT_PIN_FAIL    (0x8)
/*! PIN Pass - contains a PIN limit and a PIN count that increments on a PIN authorization success and a pinLimit */
#define TPM2_NT_PIN_PASS    (0x9)



/* Table 203 - Definition of TPMS_NV_PIN_COUNTER_PARAMETERS Structure */

/**
 * @ingroup tpm2_definitions
 * @brief   NV Pin Counter Parameters
 * @details This is the data that can be written to and read from a #TPM2_NT_PIN_PASS or #TPM2_NT_PIN_FAIL non-volatile index. pinCount is the most significant octets. pinLimit is the least significant octets.
 */
typedef struct
{
    /*! This counter shows the current number of successful authValue authorization attempts to access a TPM_NT_PIN_PASS index or the current number of unsuccessful authValue authorization attempts to access a TPM_NT_PIN_FAIL index. */
    ubyte4  pinCount;
    /*! This threshold is the value of pinCount at which the authValue authorization of the host TPM_NT_PIN_PASS or TPM_NT_PIN_FAIL index is locked out. */
    ubyte4  pinLimit;
} TPMS_NV_PIN_COUNTER_PARAMETERS;


/* Table 204: TPMA_NV Bits (ubyte4) */

/**
 * @ingroup tpm2_definitions
 * @brief This structure allows the TPM to keep track of the data and permissions to manipulate an NV Index.
 * @details The platform controls (#TPMA_NV_PPWRITE and #TPMA_NV_PPREAD) and owner controls (#TPMA_NV_OWNERWRITE and #TPMA_NV_OWNERREAD) give the platform and owner access to NV Indexes using Platform Authorization or Owner Authorization rather than the authValue or authPolicy of the Index.
<p> If access to an NV Index is to be restricted based on PCR, then an appropriate authPolicy shall be provided.
 * <p> The following bit masks are defined for #TPMA_NV:
 *    - #TPMA_NV_PPWRITE
 *    - #TPMA_NV_OWNERWRITE
 *    - #TPMA_NV_AUTHWRITE
 *    - #TPMA_NV_POLICYWRITE
 *    - #TPMA_NV_POLICY_DELETE
 *    - #TPMA_NV_WRITELOCKED
 *    - #TPMA_NV_WRITEALL
 *    - #TPMA_NV_WRITEDEFINE
 *    - #TPMA_NV_WRITE_STCLEAR
 *    - #TPMA_NV_GLOBALLOCK
 *    - #TPMA_NV_PPREAD
 *    - #TPMA_NV_OWNERREAD
 *    - #TPMA_NV_AUTHREAD
 *    - #TPMA_NV_POLICYREAD
 *    - #TPMA_NV_NO_DA
 *    - #TPMA_NV_ORDERLY
 *    - #TPMA_NV_CLEAR_STCLEAR
 *    - #TPMA_NV_READLOCKED
 *    - #TPMA_NV_WRITTEN
 *    - #TPMA_NV_PLATFORMCREATE
 *    - #TPMA_NV_READ_STCLEAR
 */
typedef ubyte4 TPMA_NV;

/*! if SET: The Index data can be written if Platform Authorization is provided. 
 <p> if CLEAR: Writing of the Index data cannot be authorized with Platform Authorization.
*/
#define TPMA_NV_PPWRITE           ((TPMA_NV) 0x00000001)
/*! if SET: The Index data can be written if Owner Authorization is provided.
 <p> if CLEAR: Writing of the Index data cannot be authorized with Owner Authorization.
*/
#define TPMA_NV_OWNERWRITE        ((TPMA_NV) 0x00000002)
/*! if SET: Authorizations to change the Index contents that require USER role may be provided with an HMAC session or password.
 <p> if CLEAR: Authorizations to change the Index contents that require USER role may not be provided with an HMAC session or password.
*/
#define TPMA_NV_AUTHWRITE         ((TPMA_NV) 0x00000004)
/*! if SET: Authorizations to change the Index contents that require USER role may be provided with a policy session.
 <p> if CLEAR: Authorizations to change the Index contents that require
USER role may not be provided with a policy session.
*/
#define TPMA_NV_POLICYWRITE       ((TPMA_NV) 0x00000008)
/*! Bit mask to get the type of index. */
#define TPMA_NV_TPM2_NT_MASK      ((TPMA_NV) 0x000000f0)
/*! Number of bits to shift to get the type of index. */
#define TPMA_NV_TPM2_NT_SHIFT     (4)
/*! TPMA_NV_RESERVED1_MASK: bits 9:8 reserved and shall be zero */
#define TPMA_NV_RESERVED1_MASK    ((TPMA_NV) 0x00000300)
/*! if SET: Index may not be deleted unless the authPolicy is satisfied using TPM2_NV_UndefineSpaceSpecial().
 <p> if CLEAR: Index may be deleted with proper platform or owner authorization using TPM2_NV_UndefineSpace().
*/
#define TPMA_NV_POLICY_DELETE     ((TPMA_NV) 0x00000400)
/*! if SET: Index cannot be written.
 <p> if CLEAR: Index can be written.
*/
#define TPMA_NV_WRITELOCKED       ((TPMA_NV) 0x00000800)
/*! if SET: A partial write of the Index data is not allowed. The write size shall match the defined space size.
 <p> if CLEAR: Partial writes are allowed. This setting is required if the .dataSize of the Index is larger than #TPM2_NV_MAX_BUFFER_SIZE for the implementation.
*/
#define TPMA_NV_WRITEALL          ((TPMA_NV) 0x00001000)
/*! if SET: TPM2_NV_WriteLock() may be used to prevent further writes to this location.
 <p> if CLEAR: TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITE_STCLEAR is also CLEAR.
*/
#define TPMA_NV_WRITEDEFINE       ((TPMA_NV) 0x00002000)
/*! if SET: TPM2_NV_WriteLock() may be used to prevent further writes to this location until the next TPM Reset or TPM Restart.
 <p> if CLEAR: TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITEDEFINE is also CLEAR.
*/
#define TPMA_NV_WRITE_STCLEAR     ((TPMA_NV) 0x00004000)
/*! if SET: If TPM2_NV_GlobalWriteLock() is successful, then further writes to this location are not permitted until the next TPM Reset or TPM Restart.
 <p> if CLEAR: TPM2_NV_GlobalWriteLock() has no effect on the writing of the data at this Index.
*/
#define TPMA_NV_GLOBALLOCK        ((TPMA_NV) 0x00008000)
/*! if SET: The Index data can be read if Platform Authorization is provided.
 <p> if CLEAR: Reading of the Index data cannot be authorized with Platform Authorization.
*/
#define TPMA_NV_PPREAD            ((TPMA_NV) 0x00010000)
/*! if SET: The Index data can be read if Owner Authorization is provided.
 <p> if CLEAR: Reading of the Index data cannot be authorized with Owner Authorization.
*/
#define TPMA_NV_OWNERREAD         ((TPMA_NV) 0x00020000)
/*! if SET: The Index data may be read if the authValue is provided.
 <p> if CLEAR: Reading of the Index data cannot be authorized with the Index authValue.
*/
#define TPMA_NV_AUTHREAD          ((TPMA_NV) 0x00040000)
/*! if SET: The Index data may be read if the authPolicy is satisfied.
 <p> if CLEAR: Reading of the Index data cannot be authorized with the Index authPolicy.
*/
#define TPMA_NV_POLICYREAD        ((TPMA_NV) 0x00080000)
/*! TPMA_NV_RESERVED2_MASK: bits 24:20 reserved and shall be zero */
#define TPMA_NV_RESERVED2_MASK    ((TPMA_NV) 0x01f00000)
/*! if SET: Authorization failures of the Index do not affect the DA logic and authorization of the Index is not blocked when the TPM is in Lockout mode.
 <p> if CLEAR: Authorization failures of the Index will increment the authorization failure counter and authorizations of this Index are not allowed when the TPM is in Lockout mode.
*/
#define TPMA_NV_NO_DA             ((TPMA_NV) 0x02000000)
/*! if SET: NV Index state is only required to be saved when the TPM performs an orderly shutdown (TPM2_Shutdown()).
 <p> if CLEAR: NV Index state is required to be persistent after the command to update the Index completes successfully (that is, the NV update is synchronous with the update command).
*/
#define TPMA_NV_ORDERLY           ((TPMA_NV) 0x04000000)
/*! if SET: TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart.
 <p> if CLEAR: TPMA_NV_WRITTEN is not changed by TPM Restart.
*/
#define TPMA_NV_CLEAR_STCLEAR     ((TPMA_NV) 0x08000000)
/*! if SET: Reads of the Index are blocked until the next TPM Reset or TPM Restart.
 <p> if CLEAR: Reads of the Index are allowed if proper authorization is provided.
*/
#define TPMA_NV_READLOCKED        ((TPMA_NV) 0x10000000)
/*! if SET: Index has been written.
 <p> if CLEAR: Index has not been written.
*/
#define TPMA_NV_WRITTEN           ((TPMA_NV) 0x20000000)
/*! if SET: This Index may be undefined with Platform Authorization but not with Owner Authorization.
 <p> if CLEAR: This Index may be undefined using Owner Authorization but not with Platform Authorization.
*/
#define TPMA_NV_PLATFORMCREATE    ((TPMA_NV) 0x40000000)
/*! if SET: TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index.
 <p> if CLEAR: TPM2_NV_ReadLock() has no effect on this Index.
*/
#define TPMA_NV_READ_STCLEAR      ((TPMA_NV) 0x80000000)



/* Table 205: TPMS_NV_PUBLIC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   NV Index Structure
 */
typedef struct
{
    /*! the handle of the data area */
    TPMI_RH_NV_INDEX    nvIndex;
    /*! hash algorithm used to compute the name of the Index and used for the authPolicy. For an extend index, the hash algorithm is used for the extend. */
    TPMI_ALG_HASH       nameAlg;
    /*! the Index attributes */
    TPMA_NV             attributes;
    /*! optional access policy for the Index */
    TPM2B_DIGEST        authPolicy;
    /*! the size of the data area */
    ubyte2              dataSize;
} TPMS_NV_PUBLIC;

/* Table 206: TPM2B_NV_PUBLIC Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   NV Public Structure
 * @details This structure is used when a TPMS_NV_PUBLIC is sent on the TPM interface.
 */
typedef struct
{
    /*! size of nvPublic */
    ubyte2              size;
    /*! the public area */
    TPMS_NV_PUBLIC      nvPublic;
} TPM2B_NV_PUBLIC;


/* Section 14: Context Data */


/* Table 207: TPM2B_CONTEXT_SENSITIVE Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   structure for sensitive context data
 * @details This structure holds the object or session context data. When saved, the full structure is encrypted.
 */
typedef struct
{
    /*! size of sensitive data in buffer */
    ubyte2      size;
    /*! the sensitive data - max size is #TPM2_MAX_CONTENT_SIZE */
    ubyte   buffer[TPM2_MAX_CONTEXT_SIZE];

} TPM2B_CONTEXT_SENSITIVE;

/* Table 208: TPMS_CONTEXT_DATA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   structure for context data
 * @details This structure holds the integrity value and the encrypted data for a context.
 */
typedef struct
{
    /*! the integrity value */
    TPM2B_DIGEST                integrity;
    /*! the sensitive area */
    TPM2B_CONTEXT_SENSITIVE     encrypted;
} TPMS_CONTEXT_DATA;

/* Table 209: TPM2B_CONTEXT_DATA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   structure for context data
 * @details This structure is used in a TPMS_CONTEXT.
 */
typedef struct
{
    /*! the size of the data in buffer */
    ubyte2  size;
    /*! the buffer */
    ubyte   buffer[sizeof(TPMS_CONTEXT_DATA)];
} TPM2B_CONTEXT_DATA;

/* Table 210: TPMS_CONTEXT Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   context structure
 * @details This structure is used in TPM2_ContextLoad() and TPM2_ContextSave(). If the values of the TPMS_CONTEXT structure in TPM2_ContextLoad() are not the same as the values when the context was saved (TPM2_ContextSave()), then the TPM shall not load the context.
<p> Saved object contexts shall not be loaded as long as the associated hierarchy is disabled.
<p> Saved object contexts are invalidated when the Primary Seed of their hierarchy changes. Objects in the Endorsement hierarchy are invalidated when either the EPS or SPS is changed.
<p> When an object has the stClear attribute, it shall not be possible to reload the context or any descendant object after a TPM Reset or TPM Restart.
 */
typedef struct
{
    /*! the sequence number of the context */
    ubyte8              sequence;
    /*! the handle of the session, object or sequence */
    TPMI_DH_CONTEXT     savedHandle;
    /*! the hierarchy of the context */
    TPMI_RH_HIERARCHY   hierarchy;
    /*! the context data and integrity HMAC */
    TPM2B_CONTEXT_DATA  contextBlob;
} TPMS_CONTEXT;

/* Table 211: Context Handle Values */

/*! bit mask for an HMAC session context */
#define TPM2_CONTEXT_HANDLE_HMAC_MASK            0x02FFFFFF
/*! bit mask for a policy session context */
#define TPM2_CONTEXT_HANDLE_POLICY_SESSION_MASK  0x03FFFFFF
/*! bit mask for an ordinary transient object */
#define TPM2_CONTEXT_HANDLE_TRANSIENT_MASK       0x80000000
/*! bit mask for a sequence object */
#define TPM2_CONTEXT_HANDLE_SEQUENCE_MASK        0x80000001
/*! bit mask for a transient object with the stClear attribute SET */
#define TPM2_CONTEXT_HANDLE_STCLEAR_MASK         0x80000002


/* Table 212: TPMS_CREATION_DATA Struct */

/**
 * @ingroup tpm2_definitions
 * @brief   creation data structure
 * @details This structure provides information relating to the creation environment for the object. The creation data includes the parent Name, parent Qualified Name, and the digest of selected PCR. These values represent the environment in which the object was created. Creation data allows a relying party to determine if an object was created when some appropriate protections were present.
<p> When the object is created, this structure is generated and a ticket is computed over this data.
<p> If the parent is a permanent handle (TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, or TPM_RH_NULL), then parentName and parentQualifiedName will be set to the parent handle value and parentNameAlg will be TPM_ALG_NULL.
 */
typedef struct
{
    /*! list indicating the PCR included in pcrDigest */
    TPML_PCR_SELECTION  pcrSelect;
    /*! digest of the selected PCR using nameAlg of the object for which this structure is being created */
    TPM2B_DIGEST        pcrDigest;
    /*! the locality at which the object was created */
    TPMA_LOCALITY       locality;
    /*! nameAlg of the parent */
    TPM2_ALG_ID          parentNameAlg;
    /*! Name of the parent at time of creation */
    TPM2B_NAME          parentName;
    /*! Qualified Name of the parent at the time of creation */
    TPM2B_NAME          parentQualifiedName;
    /*! association with additional information added by the key creator */
    TPM2B_DATA          outsideInfo;
} TPMS_CREATION_DATA;

/* Table 213: TPM2B_CREATION_DATA Struct */


/**
 * @ingroup tpm2_definitions
 * @brief   creation data structure
 * @details This structure is created by TPM2_Create() and TPM2_CreatePrimary(). It is never entered into the TPM and never has a size of zero.
 */
typedef struct
{
    /*! size of the creation data */
    ubyte2              size;
    /*! the creation data */
    TPMS_CREATION_DATA  creationData;
} TPM2B_CREATION_DATA;

/* Digicert specific structures */
typedef struct
{
	TPMI_ST_COMMAND_TAG tag;
	ubyte4 commandSize;
	TPM2_CC commandCode;
} TPM2_COMMAND_HEADER;

typedef struct
{
	TPM2_ST tag;
	ubyte4 responseSize;
	TPM2_RC responseCode;
} TPM2_RESPONSE_HEADER;

/* TPM2_StartAuthSession Command/Response Handles and Parameter areas */
typedef struct {
	TPMI_DH_OBJECT tpmKey;
	TPMI_DH_ENTITY bind;
}TPM2_START_AUTH_SESSION_CMD_HANDLES;

typedef struct {
	TPM2B_NONCE nonceCaller;
	TPM2B_ENCRYPTED_SECRET encryptedSalt;
	TPM2_SE sessionType;
	TPMT_SYM_DEF symmetric;
	TPMI_ALG_HASH authHash;
} TPM2_START_AUTH_SESSION_CMD_PARAMS;

typedef struct {
	TPMI_SH_AUTH_SESSION sessionHandle;
} TPM2_START_AUTH_SESSION_RSP_HANDLES;

typedef struct {
	TPM2B_NONCE nonceTPM;
} TPM2_START_AUTH_SESSION_RSP_PARAMS;

typedef struct {
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} TPM2_CREATE_PRIMARY_CMD_PARAMS;

typedef struct {
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
} TPM2_CREATE_PRIMARY_RSP_PARAMS;

typedef struct {
    TPM2_CAP capability;
    ubyte4 property;
    ubyte4 propertyCount;
} TPM2_GET_CAPABILITY_CMD_PARAMS;

typedef struct {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
} TPM2_GET_CAPABILITY_RSP_PARAMS;

/* TPM2_CreatePrimary and TPM2_Create have the same command parameters */
typedef TPM2_CREATE_PRIMARY_CMD_PARAMS TPM2_CREATE_CMD_PARAMS;

typedef struct {
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} TPM2_CREATE_RSP_PARAMS;

typedef struct {
    TPM2B_DATA encryptKeyIn;
    TPMT_SYM_DEF_OBJECT symmetricAlg;
} TPM2_DUPLICATE_CMD_PARAMS;

typedef struct {
    TPM2B_DATA			encryptionKeyOut;
    TPM2B_PRIVATE		duplicate;
    TPM2B_ENCRYPTED_SECRET	outSymSeed;
} TPM2_DUPLICATE_RSP_PARAMS;

typedef struct {
    TPMI_DH_OBJECT    objectHandle;
    TPMI_DH_OBJECT    newParentHandle;
} TPM2_DUPLICATE_CMD_HANDLES;

typedef struct {
    TPM2B_DATA			encryptionKey;
    TPM2B_PUBLIC		objectPublic;
    TPM2B_PRIVATE		duplicate;
    TPM2B_ENCRYPTED_SECRET	inSymSeed;
    TPMT_SYM_DEF_OBJECT		symmetricAlg;
} TPM2_IMPORT_CMD_PARAMS;

typedef struct {
    TPM2B_PRIVATE	outPrivate;
} TPM2_IMPORT_RSP_PARAMS;

typedef struct {
    TPM2B_PRIVATE inPrivate;
    TPM2B_PUBLIC inPublic;
} TPM2_LOAD_CMD_PARAMS;

typedef struct {
    TPM2B_NAME name;
} TPM2_LOAD_RSP_PARAMS;

typedef struct {
    TPMI_DH_CONTEXT flushHandle;
} TPM2_FLUSH_CONTEXT_CMD_PARAMS;

typedef struct {
    TPM2B_AUTH auth;
    TPM2B_NV_PUBLIC publicInfo;
} TPM2_NV_DEFINE_SPACE_CMD_PARAMS;

typedef struct {
    TPMI_RH_PROVISION authHandle;
    TPMI_RH_NV_INDEX nvIndex;
} TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES;

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
} TPM2_NV_WRITE_CMD_HANDLES;

typedef struct {
    TPM2B_MAX_NV_BUFFER data;
    ubyte2 offset;
} TPM2_NV_WRITE_CMD_PARAMS;

typedef TPM2_NV_WRITE_CMD_HANDLES TPM2_NV_READ_CMD_HANDLES;
typedef TPM2_NV_WRITE_CMD_HANDLES TPM2_NV_INCREMENT_CMD_HANDLES;
typedef TPM2_NV_WRITE_CMD_HANDLES TPM2_NV_EXTEND_CMD_HANDLES;
typedef TPM2_NV_WRITE_CMD_HANDLES TPM2_NV_SET_BITS_CMD_HANDLES;
typedef TPM2_NV_WRITE_CMD_HANDLES TPM2_NV_WRITE_LOCK_CMD_HANDLES;
typedef TPM2_NV_WRITE_CMD_HANDLES TPM2_NV_READ_LOCK_CMD_HANDLES;

typedef struct {
    ubyte2 size;
    ubyte2 offset;
} TPM2_NV_READ_CMD_PARAMS;

typedef struct {
    TPM2B_MAX_NV_BUFFER data;
} TPM2_NV_READ_RSP_PARAMS;

typedef struct {
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;
} TPM2_NV_READ_PUBLIC_RSP_PARAMS;

typedef struct {
    ubyte4 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;
    TPML_DIGEST pcrValues;
} TPM2_PCR_READ_RSP_PARAMS;

typedef struct {
    TPM2B_MAX_BUFFER outData;
    TPM2_RC testResult;
} TPM2_GET_TEST_RESULT_RSP_PARAMS;

typedef struct {
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
    TPM2B_NAME qualifiedName;
} TPM2_READ_PUBLIC_RSP_PARAMS;

typedef struct {
    TPM2B_PUBLIC_KEY_RSA message;
    TPMT_RSA_DECRYPT scheme;
    TPM2B_DATA label;
} TPM2_RSA_ENCRYPT_CMD_PARAMS;

typedef struct {
    TPM2B_PUBLIC_KEY_RSA cipherText;
    TPMT_RSA_DECRYPT scheme;
    TPM2B_DATA label;
} TPM2_RSA_DECRYPT_CMD_PARAMS;

typedef struct {
    TPM2B_DIGEST digest;
    TPMT_SIG_SCHEME inScheme;
    TPMT_TK_HASHCHECK validation;
} TPM2_SIGN_CMD_PARAMS;

typedef struct {
    TPM2B_DIGEST digest;
    TPMT_SIGNATURE signature;
} TPM2_VERIFY_SIGNATURE_CMD_PARAMS;

typedef struct {
    TPMI_YES_NO decrypt;
    TPMI_ALG_SYM_MODE mode;
    TPM2B_IV ivIn;
    TPM2B_MAX_BUFFER inData;
} TPM2_ENCRYPT_DECRYPT_CMD_PARAMS;

typedef struct {
    TPM2B_MAX_BUFFER inData;
    TPMI_YES_NO decrypt;
    TPMI_ALG_SYM_MODE mode;
    TPM2B_IV ivIn;
} TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS;

typedef struct {
    TPM2B_MAX_BUFFER outData;
    TPM2B_IV ivOut;
} TPM2_ENCRYPT_DECRYPT_RSP_PARAMS;

typedef struct {
    TPMI_RH_ENABLES enable;
    TPMI_YES_NO state;
} TPM2_HIERARCHY_CONTROL_CMD_PARAMS;

typedef struct {
    TPMI_RH_PROVISION authHandle;
    TPMI_DH_OBJECT objectHandle;
} TPM2_EVICT_CONTROL_CMD_HANDLES;

typedef struct {
    TPM2B_SENSITIVE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPMI_RH_HIERARCHY hierarchy;
} TPM2_LOAD_EXTERNAL_CMD_PARAMS;

/*
 * This is a special case structure. For TPM2_LoadExternal, the
 * TPM2B_SENSITIVE parameter is an optional parameter. We use
 * the below structure, in case inSensitive is not going to be
 * used. We have an alternate structure since TPM2B_SENSITIVE is
 * a TPM2B containing a structure. These structures have their
 * size field back filled after serializing the enclosed structure.
 * The TPM however, uses the size field as an indication of intent
 * to use TPM2B_SENSITIVE. Our serialization code, back fills the
 * size, which means, the TPM2B_SENSITIVE structure will have a
 * size of 8 at a minimum, since TPMT_SENSITIVE contains 4 fields,
 * of which 3 are TPM2B's, and the TPMI_ALG_PUBLIC, which gives it
 * a minimum size of 8. Instead of changing the serialization code,
 * we will use this structure when TPMT_SENSITIVE is not going to
 * be used.
 */
typedef struct {
    ubyte2 size0;
    TPM2B_PUBLIC inPublic;
    TPMI_RH_HIERARCHY hierarchy;
} TPM2_LOAD_EXTERNAL_CMD_PARAMS2;

typedef struct {
    TPMI_DH_OBJECT objectHandle;
    TPMI_DH_OBJECT parentHandle;
} TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES;

typedef struct {
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
} TPM2_HASH_SEQUENCE_START_CMD_PARAMS;

typedef struct {
    TPM2B_MAX_BUFFER buffer;
    TPMI_RH_HIERARCHY hierarchy;
} TPM2_SEQUENCE_COMPLETE_CMD_PARAMS;

typedef struct {
    TPM2B_DIGEST digest;
    TPMT_TK_HASHCHECK validation;
} TPM2_SEQUENCE_COMPLETE_RSP_PARAMS;

typedef struct {
    TPM2B_DIGEST credential;
    TPM2B_NAME name;
} TPM2_MAKE_CREDENTIAL_CMD_PARAMS;

typedef struct {
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
} TPM2_MAKE_CREDENTIAL_RSP_PARAMS;

typedef struct {
    TPMI_DH_OBJECT activateHandle;
    TPMI_DH_OBJECT keyHandle;
} TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES;

typedef TPM2_MAKE_CREDENTIAL_RSP_PARAMS TPM2_ACTIVATE_CREDENTIAL_CMD_PARAMS;

typedef struct {
    TPM2B_DATA qualifyingData;
    TPMT_SIG_SCHEME inScheme;
    TPML_PCR_SELECTION PCRSelect;
} TPM2_QUOTE_CMD_PARAMS;

typedef struct {
    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature;
} TPM2_QUOTE_RSP_PARAMS;

typedef struct {
    TPMA_OBJECT ekObjectAttributes;
    TPM2_ALG_ID ekNameAlg;
    TPMT_PUBLIC akPublicArea;
} TPM2_AK_CSR_INFO;

typedef struct {
    TPM2B_DIGEST approvedPolicy;
    TPM2B_NONCE policyRef;
    TPM2B_NAME keySign;
    TPMT_TK_VERIFIED checkTicket;
} TPM2_POLICY_AUTHORIZE_CMD_PARAMS;

typedef struct {
    TPM2B_DIGEST pcrDigest;
    TPML_PCR_SELECTION pcrs;
} TPM2_POLICY_PCR_CMD_PARAMS;

typedef struct {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_SH_POLICY policySession;
} TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES;

typedef struct {
    TPMI_DH_ENTITY authHandle;
    TPMI_SH_POLICY policySession;
} TPM2_POLICY_SECRET_CMD_HANDLES;

typedef struct {
    TPM2B_NONCE nonceTPM;
    TPM2B_DIGEST cpHashA;
    TPM2B_NONCE policyRef;
    ubyte4 expiration;
} TPM2_POLICY_SECRET_CMD_PARAMS;

typedef struct {
    TPM2B_TIMEOUT timeout;
    TPMT_TK_AUTH policyTicket;
} TPM2_POLICY_SECRET_RSP_PARAMS;

typedef struct {
    TPMI_DH_ENTITY authObject;
    TPMI_SH_POLICY policySession;
} TPM2_POLICY_SIGNED_CMD_HANDLES;

typedef struct {
    TPM2B_NONCE nonceTPM;
    TPM2B_DIGEST cpHashA;
    TPM2B_NONCE policyRef;
    ubyte4 expiration;
    TPMT_SIGNATURE auth;
} TPM2_POLICY_SIGNED_CMD_PARAMS;

typedef struct {
    TPM2B_TIMEOUT timeout;
    TPMT_TK_AUTH policyTicket;
} TPM2_POLICY_SIGNED_RSP_PARAMS;

typedef struct {
    TPM2B_NAME		objectName;
    TPM2B_NAME		newParentName;
    TPMI_YES_NO		includeObject;
} TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS;

typedef struct {
    TPM2_CC code ;
} TPM2_POLICY_COMMANDCODE_CMD_PARAMS;

typedef struct {
    /* Count of authorization failures before the lockout is imposed */
    TPM2_PARAMETER_SIZE newMaxTries;
    /* Time in seconds before the authorization failure count is 
       automatically decremented. A value of zero indicates that DA 
       protection is disabled. */
    TPM2_PARAMETER_SIZE newRecoveryTime;
    /* Time in seconds after a lockoutAuth failure before use of 
       lockoutAuth is allowed. A value of zero indicates that a 
       reboot is required. */
    TPM2_PARAMETER_SIZE lockoutRecovery;
} TPM2_DA_LOCKOUT_PARAMETERS;

/* TPM2 HMAC Command parameters */
typedef struct {
    TPM2B_MAX_BUFFER buffer;
    TPMI_ALG_HASH hashAlg;
} TPM2_HMAC_CMD_PARAMS;

/* TPM2 HMAC response values */
typedef struct {
    TPM2B_DIGEST outHMAC;
} TPM2_HMAC_RSP_PARAMS;

#endif /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __TPM2_TYPES_H__ */
