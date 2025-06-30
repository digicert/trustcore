/*
 * mocsym.h
 *
 * Symmetric algorithm definitions and declarations.
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
@file       mocsym.h
@filedoc    mocsym.h
*/

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
#include "../crypto/crypto.h"
#include "../cap/capsym.h"

#ifndef __MOC_SYM_HEADER__
#define __MOC_SYM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* Define the local types of supported operators */

#define MOC_LOCAL_TYPE_SHA1_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA1)
#define MOC_LOCAL_TYPE_SHA224_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA224)
#define MOC_LOCAL_TYPE_SHA256_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA256)
#define MOC_LOCAL_TYPE_SHA384_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA384)
#define MOC_LOCAL_TYPE_SHA512_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA512)
#define MOC_LOCAL_TYPE_SHA3_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA3)
#define MOC_LOCAL_TYPE_MD4_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_MD4)
#define MOC_LOCAL_TYPE_MD5_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_MD5)
#define MOC_LOCAL_TYPE_HMAC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_HMAC)
#define MOC_LOCAL_TYPE_NIST_KDF_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_KDF | MOC_LOCAL_TYPE_NIST_KDF_CTR)
#define MOC_LOCAL_TYPE_ANSI_X9_63_KDF_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_KDF | MOC_LOCAL_TYPE_ANSI_X9_63)
#define MOC_LOCAL_TYPE_PKCS5_PBE_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_PKCS5_PBE)
#define MOC_LOCAL_TYPE_AES_CMAC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES_MAC | MOC_LOCAL_TYPE_CMAC)
#define MOC_LOCAL_TYPE_AES_ECB_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_ECB)
#define MOC_LOCAL_TYPE_AES_CBC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_AES_OFB_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_OFB)
#define MOC_LOCAL_TYPE_AES_CFB_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CFB)
#define MOC_LOCAL_TYPE_AES_CFB1_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CFB1)
#define MOC_LOCAL_TYPE_AES_CTR_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CTR)
#define MOC_LOCAL_TYPE_RC5_CBC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_RC5 | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_AES_GCM_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_GCM)

#define MOC_LOCAL_TYPE_AES_ECB_HW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_ECB)
#define MOC_LOCAL_TYPE_AES_CBC_HW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_AES_CTR_HW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CTR)
#define MOC_LOCAL_TYPE_AES_GCM_HW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_GCM)

#define MOC_LOCAL_TYPE_AES_ECB_NI \
    (MOC_LOCAL_TYPE_AES_ECB_HW | MOC_LOCAL_TYPE_INTEL_NI)
#define MOC_LOCAL_TYPE_AES_CBC_NI \
    (MOC_LOCAL_TYPE_AES_CBC_HW | MOC_LOCAL_TYPE_INTEL_NI)
#define MOC_LOCAL_TYPE_AES_CTR_NI \
    (MOC_LOCAL_TYPE_AES_CTR_HW | MOC_LOCAL_TYPE_INTEL_NI)
#define MOC_LOCAL_TYPE_AES_GCM_NI \
    (MOC_LOCAL_TYPE_AES_GCM_HW | MOC_LOCAL_TYPE_INTEL_NI)

#define MOC_LOCAL_TYPE_DES_CBC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_DES | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_TDES_CBC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_TDES | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_ARC2_CBC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_ARC2 | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_ARC4_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_ARC4)
#define MOC_LOCAL_TYPE_RC5_CBC_SW \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_RC5 | MOC_LOCAL_TYPE_CBC)

#define MOC_LOCAL_TYPE_MD4_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_MD4)
#define MOC_LOCAL_TYPE_MD5_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_MD5)
#define MOC_LOCAL_TYPE_SHA1_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA1)
#define MOC_LOCAL_TYPE_SHA224_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA224)
#define MOC_LOCAL_TYPE_SHA256_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA256)
#define MOC_LOCAL_TYPE_SHA384_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA384)
#define MOC_LOCAL_TYPE_SHA512_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_SHA512)

#define MOC_LOCAL_TYPE_HMAC_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_HMAC)
#define MOC_LOCAL_TYPE_HMAC_KDF_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_KDF | MOC_LOCAL_TYPE_HMAC_KDF)

#define MOC_LOCAL_TYPE_POLY1305_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_POLY1305)

#define MOC_LOCAL_TYPE_AES_ECB_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_ECB)
#define MOC_LOCAL_TYPE_AES_CFB_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CFB)
#define MOC_LOCAL_TYPE_AES_CFB1_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CFB1)
#define MOC_LOCAL_TYPE_AES_OFB_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_OFB)
#define MOC_LOCAL_TYPE_AES_CTR_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CTR)
#define MOC_LOCAL_TYPE_AES_CBC_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_AES_GCM_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_GCM)
#define MOC_LOCAL_TYPE_AES_CMAC_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES_MAC | MOC_LOCAL_TYPE_CMAC)
#define MOC_LOCAL_TYPE_AES_XTS_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_XTS)
#define MOC_LOCAL_TYPE_DES_ECB_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_DES | MOC_LOCAL_TYPE_ECB)
#define MOC_LOCAL_TYPE_DES_CBC_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_DES | MOC_LOCAL_TYPE_CBC)
#define MOC_LOCAL_TYPE_TDES_ECB_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_TDES | MOC_LOCAL_TYPE_ECB)
#define MOC_LOCAL_TYPE_TDES_CBC_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_TDES | MOC_LOCAL_TYPE_CBC)

#define MOC_LOCAL_TYPE_ARC4_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
    MOC_LOCAL_TYPE_ARC4)

#define MOC_LOCAL_TYPE_CHACHA20_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_CHACHA20)
#define MOC_LOCAL_TYPE_CHACHAPOLY_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_CHACHA20 | MOC_LOCAL_TYPE_POLY1305)

#define MOC_LOCAL_TYPE_BLOWFISH_CBC_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
     MOC_LOCAL_TYPE_CBC | MOC_LOCAL_TYPE_BLOWFISH)

#define MOC_LOCAL_TYPE_CTR_DRBG_AES_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
     MOC_LOCAL_TYPE_CTR_DRBG | MOC_LOCAL_TYPE_AES)

#define MOC_LOCAL_TYPE_AES_TAP \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES )

#define MOC_LOCAL_TYPE_DES_TAP \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_DES )

#define MOC_LOCAL_TYPE_TDES_TAP \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_TDES )

#define MOC_LOCAL_TYPE_AES_GCM_TAP \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_GCM)

#define MOC_LOCAL_TYPE_HMAC_TAP \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_TAP | \
    MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_HMAC )
    
#define MOC_LOCAL_TYPE_PKCS5_PBE_OPERATOR \
    (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM | \
     MOC_LOCAL_TYPE_PKCS5_PBE)

/*----------------------------------------------------------------------------*/

/* Structures for operator use */

/** This is the data to accompany an RC5 operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>The round count must be either 20, 32, or 64.
 * <p>The blockSizeBits can be 64 or 128 bits (64 is the same size as DES and
 * Triple-DES, 128 is the same size as AES).
 * <p>If the padding field is TRUE, the Operator will pad following the rules
 * defined in PKCS 5. If FALSE, the Operator will not pad and will expect a total
 * input length a multiple of the block size.
 * <p>The initVector must be either 0 bytes long or 16 bytes long. RC5 as defined
 * in RFC 2040 allows for no IV. If you pass NULL for the pInitVector or 0 as the
 * initVectorLen, the Operator will follow RFC 2040 and simply use a block of 00
 * bytes as the IV.
 */
typedef struct
{
  ubyte4       roundCount;
  ubyte4       blockSizeBits;
  intBoolean   padding;
  ubyte       *pInitVector;
  ubyte4       initVectorLen;
} MRc5CbcOperatorData;

/* Minimum key length in bytes.
 */
#define MOC_RC5_MIN_KEY_LEN         5
/* Maximum key length in bytes.
 */
#define MOC_RC5_MAX_KEY_LEN         255
/* Minimum round count.
 */
#define MOC_RC5_MIN_ROUND_COUNT     8
/* Maximum round count according to RFC 2040.
 */
#define MOC_RC5_MAX_ROUND_COUNT     127

/* Maximum round count according to RC5 definition (not RFC 2040).
 */
#define MOC_RC5_FULL_MAX_ROUND_COUNT   255

#define MOC_RC5_256_KEY_LEN     32
#define MOC_RC5_192_KEY_LEN     24
#define MOC_RC5_128_KEY_LEN     16


/** This is the data to accompany RC2 CBC operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>If the padding field is TRUE, the Operator will pad following the rules
 * defined in PKCS 5. If FALSE, the Operator will not pad and will expect a total
 * input length a multiple of the block size.
 * <p>The effective key bits field is the number of effective key bits to use
 * for the ARC2 operation, must be between 1-1024 with a default of 32 mostly
 * for legacy support. If zero is recieved the default will be used. The
 * recommended value is 128.
 * <p>The initialization vector is mandatory and must be 8 bytes.
 */
typedef struct
{
  intBoolean padding;
  ubyte4     effectiveKeyBits;
  ubyte     *pInitVector;
  ubyte4     initVectorLen;
} MArc2CbcOperatorData;

/* This is the data to accompany an AnsiX963Kdf Operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>pHashCtx is a pointer to an already instantiated hash object. Specify
 * either pHashCtx OR hashCtxInfo but NOT BOTH. If this is specified it is
 * the callers responsibility to free this object.
 * <p>The hash operator and its associated info to use for construction. Specify
 * either pHashCtx OR hashCtxInfo but NOT BOTH. If this is specified, the
 * constructed hash object will be freed when the containing KDF object is freed.
 * <p>The secret is the secret info to use in the KDF, secretLen is the length
 * of the data in bytes.
 * <p>The shared info is optional, however if not specifying it then the
 * pSharedInfo pointer MUST be NULL. sharedInfoLen is the length in bytes
 * of the shared info.
 * <p>derivedKeyLen is the length of the key to be derived in bytes.
 */
typedef struct
{
  MocSymCtx             pHashCtx;
  MSymOperatorAndInfo   hashCtxInfo;
  ubyte                *pSecret;
  ubyte4                secretLen;
  ubyte                *pSharedInfo;
  ubyte4                sharedInfoLen;
  ubyte4                derivedKeyLen;
} MAnsiX963KdfOperatorData;


/* This is the data to accompany a Nist KDF Operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>pHmacCtx is an instantiated HMAC MocSym Context. The key must be
 * loaded with the input key from which the new key is to be derived from.
 * Specify either pHmacCtx OR hmacCtxInfo but NOT BOTH. If this is specified
 * then it is the callers responsibility to free the provided HMAC object.
 * <p>hmacCtxInfo contains a HMAC operator and its associated info to use for
 * construction. Specify either pHmacCtx OR hmacCtxInfo but NOT BOTH. If this is
 * specified then the HMAC object will be created internally and freed when the
 * containing KDF object is freed.
 * <p>The key data and its length, this must be specified when specifying
 * hmacCtxInfo and must be empty when specifying pHmacCtx.
 * <p>The label input into the KDF.
 * <p>The context input into the KDF.
 * <p>The initialization vector input to the KDF, note this is only used
 * for feedback mode.
 * <p>The length in bytes of the key to be derived.
 */
typedef struct
{
  MocSymCtx             pHmacCtx;
  MSymOperatorAndInfo   hmacCtxInfo;
  ubyte                *pKeyData;
  ubyte4                keyDataLen;
  ubyte                *pLabel;
  ubyte4                labelLen;
  ubyte                *pContext;
  ubyte4                contextLen;
  ubyte                *pIv;
  ubyte4                ivLen;
  ubyte4                derivedKeyLen;
} MNistKdfOperatorData;

#define MOC_SYM_HMAC_KDF_EXTRACT 0
#define MOC_SYM_HMAC_KDF_EXPAND 1

/* This is the data to accompany MHmacKdf in a call to
 * CRYPTO_deriveKey.
 * <p>flag should be one of MOC_SYM_HMAC_KDF_EXTRACT or MOC_SYM_HMAC_KDF_EXPAND
 * and will indicate to the operator which of those operations to perform.
 * For MOC_SYM_HMAC_KDF_EXTRACT your instance may include the fields pSalt, saltLen,
 * pInputKeyMaterial, and inputKeyMaterialLen. For MOC_SYM_HMAC_KDF_EXPAND
 * your instance must include pPseudoRandomKey, pseudoRandomKeyLen, and may contain
 * pContext and contextLen.
 * <p> pSalt               The salt input to an HMAC-KDF extraction method.
 * <p> saltLen             The length of pSalt in bytes.
 * <p> pInputKeyMaterial   The key material input to an HMAC-KDF extraction method.
 * <p> inputKeyMaterialLen The length of pInputKeyMaterial in bytes.
 * <p> pPseudoRandomKey    The pPseudoRandomKey input to an HMAC-KDF expansion method.
 *                         This is typically the output of the extraction method.
 * <p> pseudoRandomKeyLen  The length of pPseudoRandomKey in bytes
 * <p> pContext            The optional pContext input to an HMAC-KDF expansion method.
 * <p> contextLen          The length of pContext in bytes.
 */
typedef struct
{
    ubyte flag;
    ubyte *pSalt;
    ubyte4 saltLen;
    ubyte *pInputKeyMaterial;
    ubyte4 inputKeyMaterialLen;
    ubyte *pPseudoRandomKey;
    ubyte4 pseudoRandomKeyLen;
    ubyte *pContext;
    ubyte4 contextLen;
    ubyte *pIv;
    ubyte4 ivLen;

} MHmacKdfOperatorData;

/** This is the data to accompany a Pkcs5Pbe Operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>The pPassword field points to the buffer with the password bytes, the
 * passwordLen indicates the length in bytes of the password data.
 * <p>The pSalt field points to the buffer with the salt bytes, the
 * saltLen indicates the length in bytes of the salt data.
 * <p>The iteration count is the number of iterations to perform when deriving
 * a key, higher numbers result in greater security and increased key derivation
 * time. RFC 2898 recommends at least 1000 to be secure.
 * <p>The derivedKeyLength is the length in bytes of the key to be derived. A
 * derived key can be no longer than the output size of the underlying hash
 * function used by the HMAC operator.
 * <p>pHashCtx is a pointer to an already instantiated MocSymCtx, HMAC for
 * PBE V2 and some SHA operator (likely SHA1) for PBE V1. Specify either
 * pHmacCtx OR hmacCtxInfo but NOT BOTH. If this is specified it is the callers
 * responsibility to free this object.
 * <p>hmacCtxInfo is a structure containing an HMAC operator and its associated
 * info. Specify either pHmacCtx OR hmacCtxInfo but NOT BOTH. If this is
 * specified, the library will create the objects for you which will be freed
 * when the containing PBE object is freed.
 * <p>pSymAlgoCtx is a pointer to an already instantiated MocSymCtx,
 * ARC2 for PBE V1, anything for PBE V2. Specify either pSymAlgoCtx OR symCtxInfo
 * but NOT BOTH. If this is specified it is the callers responsibility to
 * free this object.
 * <p>symCtxInfo is a structure containing an sym operator and its associated
 * info. Specify either pSymAlgoCtx OR symCtxInfo but NOT BOTH. If this is
 * specified, the library will create the objects for you which will be freed
 * when the containing PBE object is freed.
 */
typedef struct
{
  ubyte                *pPassword;
  ubyte4                passwordLen;
  ubyte                *pSalt;
  ubyte4                saltLen;
  ubyte4                iterationCount;
  ubyte4                derivedKeyLen;
  MocSymCtx             pHmacCtx;
  MSymOperatorAndInfo   hmacCtxInfo;
  MocSymCtx             pSymAlgoCtx;
  MSymOperatorAndInfo   symCtxInfo;
} MPkcs5PbeOperatorData;


#define MOC_SYM_OP_PKCS5_KDF 0
#define MOC_SYM_OP_PKCS5_ENCRYPT 1
#define MOC_SYM_OP_PKCS5_DECRYPT 2

/** This is the data to accompany a Pkcs5Pbe Operator in a call to
 * <p>operation field is one of \c MOC_SYM_OP_PKCS5_KDF, \c MOC_SYM_OP_PKCS5_ENCRYPT,
 * or \c MOC_SYM_OP_PKCS5_DECRYPT.
 * <p>The pPassword field points to the buffer with the password bytes, the
 * passwordLen indicates the length in bytes of the password data.
 * <p>The pSalt field points to the buffer with the salt bytes, the
 * saltLen indicates the length in bytes of the salt data.
 * <p>The iteration count is the number of iterations to perform when deriving
 * a key, higher numbers result in greater security and increased key derivation
 * time. RFC 2898 recommends at least 1000 to be secure.
 * <p>The digestAlg is one of the following enum values from
 * src/crypto/crypto.h:
 * \c ht_md2 (not valid in FIPS mode)
 * \c ht_md4 (not valid in FIPS mode)
 * \c ht_md5 (not valid in FIPS mode)
 * \c ht_sha1
 * \c ht_sha224
 * \c ht_sha256
 * \c ht_sha384
 * \c ht_sha512
 * <p> The encAlg is one of the following enum values
 * \c nilEncryption
 * \c tdesEncryption
 * \c twoKeyTdesEncryption
 * \c desEncryption
 * \c rc4Encryption
 * \c rc2Encryption
 * \c rc2EkbEncryption
 * \c bfEncryption
 * \c aesEncryption
 * \c aesCtrEncryption
 * <p> keyLen is the length of the key to be generated for encryption op.
 * <p> effectiveKeyBits is the effictive key bits for rc2.
 * <p> pIv is the initial vector for CBC encryption schemes
 * <p> pPBEInfo is a raw buffer containing much of the above parameters in an
 * asn1 form. This may be used in place of those parameters. Its length in bytes is pbeLen.
 */
typedef struct
{
    ubyte                 operation;
    ubyte                *pPassword;
    ubyte4                passwordLen;
    ubyte                *pSalt;
    ubyte4                saltLen;
    ubyte4                iterationCount;
    ubyte                 digestAlg;
    ubyte                 encAlg;
    ubyte4                keyLen;
    sbyte4                effectiveKeyBits;
    ubyte                *pIv;
    ubyte                *pPBEInfo;
    ubyte4                pbeLen;
    
} MPkcs5OperatorData;

/** This is the data to accompany DES CBC operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>If the padding field is TRUE, the Operator will pad following the rules
 * defined in PKCS 5. If FALSE, the Operator will not pad and will expect a total
 * input length a multiple of the block size.
 * <p>The initialization vector is mandatory and must be 8 bytes.
 */
typedef struct
{
  ubyte     *pInitVector;
  ubyte4     initVectorLen;
  intBoolean padding;
} MDesCbcOperatorData;

/**
 * struct for Triple Des, same as that for DES, please see the MDesCbcOperatorData
 * description.
 */
typedef MDesCbcOperatorData MTDesCbcOperatorData;

/** This is the data to accompany a DES ECB operator in a call to
 * CRYPTO_createMocSymCtx.
 * <p>If the padding field is TRUE, the Operator will pad following the rules
 * defined in PKCS 5. If FALSE, the Operator will not pad and will expect a total
 * input length a multiple of the block size.
 */
typedef struct
{
    intBoolean padding;
} MDesEcbOperatorData;

/**
 * struct for Triple Des, same as that for DES, please see the MDesEcbOperatorData
 * description.
 */
typedef MDesEcbOperatorData MTDesEcbOperatorData;

/*----------------------------------------------------------------------------*/

/* Declaration for each supported operator */

MOC_EXTERN MSTATUS SymOperatorMd4(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorMd5(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorSha1(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorSha224(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorSha256(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorSha384(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorSha512(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorSha3(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorHmac(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorPoly1305 (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorArc4 (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorDesEcb (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorDesCbc (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorTDesEcb (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorTDesCbc (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesEcb(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesCbc(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesCfb128(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesCfb1(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesOfb(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesCtr(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesGcm(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesCmac(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorAesXts(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorChaCha20(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorChaChaPoly(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorBlowfish(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorHmacKdf(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

MOC_EXTERN MSTATUS SymOperatorPkcs5Pbe(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

/** This operator implements the NIST CTR-DRBG using AES-256 as the
 * underlying block cipher. This operator requires a function pointer to
 * collect entropy, it does not support direct entropy injection. The key
 * size is fixed at 256 bits and this implementation always uses a derivation
 * function. Requests to instantiate this operator without these options
 * will result in an error. */
MOC_EXTERN MSTATUS SymOperatorCtrDrbgAes(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

/**
 * TAP operator (shell) for AES */
MOC_EXTERN MSTATUS MAesTapOperator(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

/**
 * TAP operator (shell) for DES */
MOC_EXTERN MSTATUS MDesTapOperator(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

/**
 * TAP operator (shell) for TDES */
MOC_EXTERN MSTATUS MTDesTapOperator(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

/**
 * TAP operator (shell) for HMAC */
MOC_EXTERN MSTATUS MHmacTapOperator(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

#ifdef __cplusplus
}
#endif

#endif /* __MOC_SYM_HEADER__ */
