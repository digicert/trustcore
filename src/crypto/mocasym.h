/*
 * mocasym.h
 *
 * Declarations and definitions for the Mocana Asymmetric Key
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

#ifndef __MOCANA_ASYMMETRIC_HEADER__
#define __MOCANA_ASYMMETRIC_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/hw_accel.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/ecc.h"
#include "../crypto/primeec_priv.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../cap/capasym.h"
#include "../crypto/mocsym.h"
#include "../crypto/malgo_id.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Define the local types of supported operators */

#define MOC_LOCAL_KEY_RSA_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_RSA)
#define MOC_LOCAL_KEY_RSA_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_RSA | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_DSA_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_DSA)
#define MOC_LOCAL_KEY_DSA_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_DSA | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_DH_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_DH)
#define MOC_LOCAL_KEY_DH_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_DH | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P192_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P192 )
#define MOC_LOCAL_KEY_ECC_P192_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P192 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P224_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P224 )
#define MOC_LOCAL_KEY_ECC_P224_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P224 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P256_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P256 )
#define MOC_LOCAL_KEY_ECC_P256_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P256 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P384_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P384 )
#define MOC_LOCAL_KEY_ECC_P384_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P384 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P521_PUB_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P521 )
#define MOC_LOCAL_KEY_ECC_P521_PRI_SW \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P521 | MOC_LOCAL_KEY_PRI )

#define MOC_LOCAL_KEY_RSA_PUB_TAP \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_KEY_ASYM | MOC_LOCAL_KEY_RSA)
#define MOC_LOCAL_KEY_RSA_PRI_TAP \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_KEY_ASYM | MOC_LOCAL_KEY_RSA | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_PUB_TAP \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_KEY_ASYM | MOC_LOCAL_KEY_ECC )
#define MOC_LOCAL_KEY_ECC_PRI_TAP \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_KEY_ASYM | MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_PRI )

#define MOC_LOCAL_TYPE_SS_TAP \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_TAP)

#define MOC_LOCAL_KEY_RSA_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_RSA )
#define MOC_LOCAL_KEY_RSA_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_RSA | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_DH_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_DH )
#define MOC_LOCAL_KEY_DH_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_DH | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P192_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P192 )
#define MOC_LOCAL_KEY_ECC_P192_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P192 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P224_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P224 )
#define MOC_LOCAL_KEY_ECC_P224_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P224 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P256_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P256 )
#define MOC_LOCAL_KEY_ECC_P256_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P256 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P384_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P384 )
#define MOC_LOCAL_KEY_ECC_P384_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P384 | MOC_LOCAL_KEY_PRI )
#define MOC_LOCAL_KEY_ECC_P521_PUB_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P521 )
#define MOC_LOCAL_KEY_ECC_P521_PRI_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_ECC | MOC_LOCAL_KEY_P521 | MOC_LOCAL_KEY_PRI )

/* Operator local types still use oqs-0.9.0 terminology, kyber, dilithium
   etc. When OQS is updated we can change these to mlkem, mldsa, etc. */
#define MOC_LOCAL_KEY_KEM_QS_KYBER_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_QS_KEM | MOC_LOCAL_KEY_QS | MOC_LOCAL_KEY_PQC_MLKEM )

#define MOC_LOCAL_KEY_SIG_QS_DILITHIUM_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_QS_SIG | MOC_LOCAL_KEY_QS | MOC_LOCAL_KEY_PQC_MLDSA )
#define MOC_LOCAL_KEY_SIG_QS_FALCON_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_QS_SIG | MOC_LOCAL_KEY_QS | MOC_LOCAL_KEY_PQC_FNDSA )
#define MOC_LOCAL_KEY_SIG_QS_SPHINCS_OPERATOR \
    (MOC_LOCAL_KEY_MOCANA | MOC_LOCAL_KEY_SW | MOC_LOCAL_KEY_ASYM | \
    MOC_LOCAL_KEY_QS_SIG | MOC_LOCAL_KEY_QS | MOC_LOCAL_KEY_PQC_SLHDSA )

/*----------------------------------------------------------------------------*/
/* Declaration for each supported operator */

/** Implements MKeyOperator.
 * This is an Operator that performs RSA private key operations through TAP. You can
 * use this to build a MocAsymKey and use it with the MocAsymKey API.
 * <p>If you use this operator to generate a new keypair with
 * CRYPTO_generateKeyPair, it will yield you two MocAsymKey objects, the
 * private key will contain the RSA TAP key. This key can be used for all
 * private key operations, which will end as calls to the TAP server. The public
 * key will contain a RSA software backed key. This key can be used for all public
 * key operations, which will be performed in software as it is more efficient
 * than using the TAP interface.
 * <p>The info to accompany this Operator in a call to CRYPTO_generateKeyPair is
 * a MRsaTapKeyGenArgs structure.
 * <p>The info to accompany this Operator in a call to createMocAsymKey is
 * a MRsaTapCreateArgs structure. Note to perform private key operations a TAP
 * key must be instantiated with CRYPTO_deserializeMocAsymKey.  This operator
 * will deserialize a PEM blob, DER blob, or a Mocana blob, however it will not
 * perform the TAP_loadKey operation to associate it with a TAP context. This
 * is the callers responsibility.
 * <p>This operator supports a Callback function. The associated info will be
 * a MRsaTapKeyData structure, see rsatap.h for definitions.
 * <p>Do not call this function, use it only as an argument to the functions
 * CRYPTO_generateKeyPair or CRYPTO_createMocAsymKey, or in an array of
 * Operators passed to functions that take an array of Operators.
 * <pre>
 * <code>
 *     TAP_CONTEXT *pTapContext = NULL;
 *     MocAsymKey pPubKey = NULL;
 *     MocAsymKey pPriKey = NULL;
 *     MRsaTapKeyGenArgs genArgs = {0}; // must initialize all fields to zero
 *
 *     // TAP_CONTEXT is initialized and setup
 *
 *     genArgs.pTapCtx = pTapContext;
 *     genArgs.keyUsage = TAP_KEY_USAGE_GENERAL;
 *     genArgs.algKeyInfo.rsaInfo.keySize = TAP_KEY_SIZE_2048;
 *     genArgs.algKeyInfo.rsaInfo.exponent = 65537;
 *     genArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_OAEP_SHA1;
 *     genArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PSS_SHA256;
 *     status = CRYPTO_generateKeyPair (
 *         KeyOperatorRsaTap, (void *)&genArgs, pMocCtx, g_pRandomContext,
 *         &pPubKey, &pPriKey, NULL);
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS KeyOperatorRsaTap (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/** Implements MKeyOperator.
 * This is an Operator that performs ECC private key operations through TAP. You can
 * use this to build a MocAsymKey and use it with the MocAsymKey API.
 * <p>If you use this operator to generate a new keypair with
 * CRYPTO_generateKeyPair, it will yield you two MocAsymKey objects, the
 * private key will contain the ECC TAP key. This key can be used for all
 * private key operations, which will end as calls to the TAP server. The public
 * key will contain a ECC software backed key. This key can be used for all public
 * key operations, which will be performed in software as it is more efficient
 * than using the TAP interface.
 * <p>The info to accompany this Operator in a call to CRYPTO_generateKeyPair is
 * a MEccTapKeyGenArgs structure. Note that public key functionality will only
 * be available if the StandardParams for the curve are available.
 * <p>The info to accompany this Operator in a call to createMocAsymKey is
 * a MEccTapCreateArgs structure. Note to perform private key operations a TAP
 * key must be instantiated with CRYPTO_deserializeMocAsymKey.  This operator
 * will deserialize a PEM blob, DER blob, or a Mocana blob, however it will not
 * perform the TAP_loadKey operation to associate it with a TAP context. This
 * is the callers responsibility.
 * <p>This operator supports a Callback function. The associated info will be
 * a MEccTapKeyData structure, see ecctap.h for definitions.
 * <p>Do not call this function, use it only as an argument to the functions
 * CRYPTO_generateKeyPair or CRYPTO_createMocAsymKey, or in an array of
 * Operators passed to functions that take an array of Operators.
 * <pre>
 * <code>
 *     TAP_CONTEXT *pTapContext = NULL;
 *     MocAsymKey pPubKey = NULL;
 *     MocAsymKey pPriKey = NULL;
 *     MEccTapKeyGenArgs genArgs = {0}; // must initialize all fields to zero
 *
 *     // TAP_CONTEXT is initialized and setup
 *
 *     genArgs.pTapCtx = pTapContext;
 *     genArgs.keyUsage = TAP_KEY_USAGE_GENERAL;
 *     genArgs.algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NIST_P256;
 *     genArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
 *     genArgs.standardParams = EccParamsNistP256r1;
 *     status = CRYPTO_generateKeyPair (
 *         KeyOperatorEccTap, (void *)&genArgs, pMocCtx, g_pRandomContext,
 *         &pPubKey, &pPriKey, NULL);
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS KeyOperatorEccTap (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/** Implements MKeyOperator.
 * This is an Operator that performs serialization of objects (usually private keys) to be
 * obtained or written to secure storage through the TAP layer.
 */
MOC_EXTERN MSTATUS KeyOperatorSSTap (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

/** These are the values that will be passed to a StandardParams function,
 * indicating what that function is supposed to do.
 */
typedef enum stdParamOperation
{
  /** Return the params as a pointer. There is a standard way to return params
   * based on algorithm.
   * <p>The caller declares a variable to be of type StandardParamStruct, sets
   * the algorithm field to either MOC_STD_PARAMS_ALG_DH or
   * MOC_STD_PARAMS_ALG_ECC, and passes the address. The implementation will
   * verify that the algorithm matches, then create the parameters and return
   * them in the pParams field.
   * <p>For DH, the format of the parameters returns is a pointer to MDhParams.
   * <p>For ECC, the format of the parameters is PEllipticCurvePtr.
   * <p>When getting params, the StandardParams implementation must return a copy
   * of the params (not a reference) that the caller can use.
   * <p>Later on, the caller will ask the StandardParams implementation to free
   * up any memory by using paramOpFree.
   */
  paramOpGet     = 1,

  /** Free the params.
   * <p>The caller originally got the params, which the implementation returned
   * as a pointer to a copy of the params. When the caller wants to delete the
   * params, it will call the function again with this op, the implementation
   * will know how to free them.
   * <p>The caller passes the StandardParamStruct. The implementation goes to the
   * pParams field and frees them, then sets that field to NULL.
   */
  paramOpFree    = 2

} stdParamOperation;

typedef struct
{
  ubyte4     algorithm;
  void      *pParams;
} StandardParamStruct;

#define MOC_STD_PARAMS_ALG_DH   1
#define MOC_STD_PARAMS_ALG_ECC  2

/* This is how a standard parameter set is represented.
 * <p>This will be the format of a parameter set whther Diffie-Hellman or ECC.
 */
typedef MSTATUS (*StandardParams) (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>ECC params secp192r1 defined in NIST document 186-4 (see also RFC 5480).
 * <p>Although this is a function, do not call it directly. Use it only as the
 * associated info for an ECC operator (CRYPTO_generateKeyPair,
 * CRYPTO_createMocAsymKey, MKeyOperatorAndInfo array).
 */
MOC_EXTERN MSTATUS EccParamsNistP192r1 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>ECC params secp224r1 defined in NIST document 186-4 (see also RFC 5480).
 * <p>Although this is a function, do not call it directly. Use it only as the
 * associated info for an ECC operator (CRYPTO_generateKeyPair,
 * CRYPTO_createMocAsymKey, MKeyOperatorAndInfo array).
 */
MOC_EXTERN MSTATUS EccParamsNistP224r1 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>ECC params secp256r1 defined in NIST document 186-4 (see also RFC 5480).
 * <p>Although this is a function, do not call it directly. Use it only as the
 * associated info for an ECC operator (CRYPTO_generateKeyPair,
 * CRYPTO_createMocAsymKey, MKeyOperatorAndInfo array).
 */
MOC_EXTERN MSTATUS EccParamsNistP256r1 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>ECC params secp384r1 defined in NIST document 186-4 (see also RFC 5480).
 * <p>Although this is a function, do not call it directly. Use it only as the
 * associated info for an ECC operator (CRYPTO_generateKeyPair,
 * CRYPTO_createMocAsymKey, MKeyOperatorAndInfo array).
 */
MOC_EXTERN MSTATUS EccParamsNistP384r1 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>ECC params secp521r1 defined in NIST document 186-4 (see also RFC 5480).
 * <p>Although this is a function, do not call it directly. Use it only as the
 * associated info for an ECC operator (CRYPTO_generateKeyPair,
 * CRYPTO_createMocAsymKey, MKeyOperatorAndInfo array).
 */
MOC_EXTERN MSTATUS EccParamsNistP521r1 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 1 DH params defined in 2409. The security size is 768 (note that this
 * should not be used, the security size is too small, but it is provided for
 * backwards compatibility).
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup1 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 2 DH params defined in 2409. The security size is 1024.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup2 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 5 DH params defined in 3526. The security size is 1536.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup5 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 14 DH params defined in 3526. The security size is 2048.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup14 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 15 DH params defined in 3526. The security size is 3072.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup15 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 16 DH params defined in 3526. The security size is 4096.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup16 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 17 DH params defined in 3526. The security size is 6144.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup17 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 18 DH params defined in 3526. The security size is 8192.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup18 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** Implements StandardParams.
 * <p>Group 24 DH params defined in 5114. The security size is 2048.
 * <p>Although this is a function, do not call it directly. Use it only in the
 * StandardParams field of the MDhParams struct.
 */
MOC_EXTERN MSTATUS DhParamsGroup24 (
  MocAsymKey pMocAsymKey,
  stdParamOperation paramOp,
  StandardParamStruct *pParamStruct
  );

/** This is the data to accompany a DSA operator when generating a key pair.
 * <p>If you want to build a key pair using the params (p, q, and g, from an
 * existing public key, set the pPublicKey field to that object and the
 * implementation will ignore the rest of the fields.)
 * <p>If you want to generate a new parameter set of a given securitySize, set
 * the securitySize field to the size desired (make sure the pPublicKey field is
 * NULL), and the implementation will ignore the rest of the fields.
 * <p>If you want to generate a key pair from an existing parameter set, make
 * sure pPublicKey and securitySize are NULL/0, the set the pPrime, pSubprime,
 * and pBase fields to byte arrays containing the canonical versions of the
 * existing param set. Note that the primeLen, subprimeLen, and baseLen are the
 * lengths of the values in bytes.
 * <p>You can also pass in a prime and subprime, leaving pBase NULL, in which
 * case the Operator will generate a new base (the g, aka generator).
 * <p>If you specify a securitySize, note that the implementation supports only
 * 1024, 2048, and 3072. Furthermore, the subprime will be 160, 224, and 256 bits
 * respectively.
 */
typedef struct
{
  MocAsymKey         pPublicKey;
  ubyte4             securitySize;
  ubyte             *pPrime;
  ubyte4             primeLen;
  ubyte             *pSubprime;
  ubyte4             subprimeLen;
  ubyte             *pBase;
  ubyte4             baseLen;
} MDsaParams;

/* This is the data to accompany an ECC operator when generating a key pair.
 * <p>Check the Operator to determine what it supports. Some Operators might
 * support only certain sizes or even certain standard params. Some might support
 * generating random params, others might not.
 * <p>You can pass in either a public key or a standard param set.
 * <p>If there is a public key, the Operator will extract the params and use
 * them. This is used when you are performing ECDH from the correspondent's
 * public key. If there is a public key, the Operator will ignore the
 * standardParams field.
 * <p>If pPublicKey is NULL, the Operator will look for standardParams. If that
 * is not NULL, it will load up the params described by the value.
 */
typedef struct
{
  MocAsymKey         pPublicKey;
  StandardParams     standardParams;
} MEccParams;

/* This is the data to accompany a DH operator when generating a key pair.
 * <p>Check the Operator to determine what it supports. Some Operators might
 * support only certain sizes or even certain standard params. Some might support
 * generating random params, others might not.
 * <p>You can pass in either a public key, a set of standard params, or a p, q,
 * and g from another source.
 * <p>If there is a public key, the Operator will extract the params and use
 * them. This is used when you are performing DH from the correspondent's public
 * key. If there is a public key, the Operator will ignore the other fields.
 * <p>If pPublicKey is NULL, the Operator will look for StandardParams. If that
 * is not NULL, it will load up the params described by the value and ignore the
 * rest of the fields.
 * <p>If pPublicKey and StandardParams are NULL, the Operator will look for a
 * prime, subprime, and base. Most operators will also allow passing in only a
 * prime and base.
 * <p>The priValLen is generally the same length as the subprime. If there is no
 * subprime, you must specify the length. If there is a subprime, you can leave
 * the priValLen blank and Operators will generate private keys the same size as
 * the subprime. Note that the priValLen is the length in bytes, not the bit
 * length.
 */
typedef struct
{
  MocAsymKey         pPublicKey;
  StandardParams     standardParams;
  ubyte             *pPrime;
  ubyte4             primeLen;
  ubyte             *pSubprime;
  ubyte4             subprimeLen;
  ubyte             *pBase;
  ubyte4             baseLen;
  ubyte4             priValLen;
} MDhParams;

/*----------------------------------------------------------------------------*/

/** Generic Operators
 */

MOC_EXTERN MSTATUS KeyOperatorDh (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorRsa (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorEccNistP192(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorEccNistP224(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorEccNistP256 (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorEccNistP384 (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorEccNistP521 (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSMcEliece(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSKyber(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSNtru(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSSaber(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSSike(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSFrodokem(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSSidh(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorKemQSNewhope(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorSigQSDilithium(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorSigQSFalcon(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorSigQSRainbow(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorSigQSQTesla(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorSigQSMqdss(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

MOC_EXTERN MSTATUS KeyOperatorSigQSSphincs(
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  );

#ifdef __cplusplus
}
#endif

#endif /* __MOCANA_ASYMMETRIC_HEADER__ */
