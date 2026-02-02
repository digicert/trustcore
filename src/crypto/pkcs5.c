/*
 * pkcs5.c
 *
 * PKCS #5 Factory
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
@file       pkcs5.c
@brief      SoT Platform convenience API to support PKCS&nbsp;\#5.
@details    This file contains the SoT Platform convenience API functions that
              support PKCS&nbsp;\#5 v2.0, as defined in RFC&nbsp;2898.

@flags
To enable the SoT Platform PKCS&nbsp;\#5 convenience API functions, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@filedoc    pkcs5.c
*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5_INTERNAL__

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_PKCS5__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mudp.h"
#include "../common/debug_console.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/oiddefs.h"
#include "../asn1/mocasn1.h"
#include "../crypto/crypto.h"
#include "../common/base64.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/md5.h"
#include "../crypto/md4.h"
#include "../crypto/md2.h"
#ifdef __ENABLE_BLOWFISH_CIPHERS__
#include "../crypto/blowfish.h"
#endif
#include "../crypto/hmac.h"
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#include "../crypto/des.h"
#include "../crypto/aes.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs5.h"

const ubyte pkcs5_root_OID[] = /* 1.2.840.113549.1.5 */
    { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05 };

const ubyte pkcs5_PBKDF2_OID[] =  /* 1.2.840.113549.1.5.12 */
    { 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };

const ubyte pkcs5_PBES2_OID[] =   /* 1.2.840.113549.1.5.13 */
    { 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };

enum pkcs5Types
{
    PKCS5_PBES2 = 13
};

/*------------------------------------------------------------------*/

extern MSTATUS
PKCS5_CreateKey_PBKDF1(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt,
                       ubyte4 saltLen, ubyte4 iterationCount,
                       enum hashFunc hashingFunction,
                       const ubyte* pPassword, ubyte4 passwordLen,
                       ubyte4 dkLen, ubyte* pRetDerivedKey)
{
    MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx)
                              const ubyte *pData, ubyte4 dataLen,
                              ubyte *pDigestOutput);
    ubyte*  pDigest = NULL;
    ubyte4  digestLen, allocLen;
    ubyte4  count;
    MSTATUS status;

    if ((NULL == pSalt) || (NULL == pPassword) || (NULL == pRetDerivedKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == iterationCount)
    {
        /* we should enforce a minimal number of rounds, atleast one round, otherwise we are only doing a memcpy */
        status = ERR_PKCS5_BAD_ITERATION_COUNT;
        goto exit;
    }

    switch (hashingFunction)
    {
        case(sha1Encryption):
            completeDigest = SHA1_completeDigest;
            digestLen = SHA1_RESULT_SIZE;
            break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case(sha224Encryption):
            completeDigest = SHA224_completeDigest;
            digestLen = SHA224_RESULT_SIZE;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case(sha256Encryption):
            completeDigest = SHA256_completeDigest;
            digestLen = SHA256_RESULT_SIZE;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case(sha384Encryption):
            completeDigest = SHA384_completeDigest;
            digestLen = SHA384_RESULT_SIZE;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case(sha512Encryption):
            completeDigest = SHA512_completeDigest;
            digestLen = SHA512_RESULT_SIZE;
            break;
#endif

#ifdef __ENABLE_DIGICERT_MD2__
        case(md2Encryption):
            completeDigest = MD2_completeDigest;
            digestLen = MD2_RESULT_SIZE;
            break;
#endif

#ifdef __ENABLE_DIGICERT_MD4__
        case(md4Encryption):
            completeDigest = MD4_completeDigest;
            digestLen = MD4_RESULT_SIZE;
            break;
#endif

        case(md5Encryption):
            completeDigest = MD5_completeDigest;
            digestLen = MD5_RESULT_SIZE;
            break;

        default:
            status = ERR_PKCS5_INVALID_HASH_FUNCTION;
            goto exit;
    }

    /* make sure we're not trying to generate more key than possible */
    if (dkLen > digestLen)
    {
        status = ERR_PKCS5_DKLEN_TOO_LONG;
        goto exit;
    }

    /* allocate enough space for the digest and the initial input */
    allocLen = passwordLen + saltLen;
    if (allocLen < digestLen)
    {
        allocLen = digestLen;
    }

    if (NULL == (pDigest = MALLOC(allocLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pDigest, pPassword, passwordLen);
    DIGI_MEMCPY(pDigest + passwordLen, pSalt, saltLen);

    /* first round digest entire pPassword + pSalt */
    if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pDigest, passwordLen + saltLen, pDigest)))
        goto exit;

    /* subsequent rounds digest the digest */
    for (count = 1; count < iterationCount; count++)
    {
        if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pDigest, digestLen, pDigest)))
            goto exit;
    }

    /* dup the results */
    status = DIGI_MEMCPY(pRetDerivedKey, pDigest, dkLen);

exit:
    if (pDigest)
        FREE(pDigest);

    return status;

} /* PKCS5_CreateKey_PBKDF1 */


/*------------------------------------------------------------------*/

extern MSTATUS PKCS5_CreateKey_PBKDF2 (
  MOC_HASH(hwAccelDescr hwAccelCtx)
  const ubyte *pSalt,
  ubyte4 saltLen,
  ubyte4 iterationCount,
  ubyte digestAlg,
  const ubyte *pPassword,
  ubyte4 passwordLen,
  ubyte4 dkLen,
  ubyte *pRetDerivedKey
  )
{
    ubyte4  hLen;
    ubyte   digest[CERT_MAXDIGESTSIZE];
    ubyte4  len;
    ubyte4  i,j,k;
    ubyte   blockCount[4];
    MSTATUS status = OK;
    const BulkHashAlgo* pHashAlgo;
    HMAC_CTX *ctx = NULL;

    if ((NULL == pSalt) || (NULL == pPassword) || (NULL == pRetDerivedKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    /* In order to be FIPS-compliant, the salt and key lengths
     * must be >= to defined minimums.
     * For the iteration count, there is no required minimum, but SP 800-132
     * recommends at least 1,000. We'll enforce that.
     */
    status = ERR_FIPS_INVALID_INPUT;
    if ( (MOC_MIN_800_132_SALT_LEN > saltLen) ||
         (MOC_MIN_800_132_KEY_LEN > dkLen) ||
         (MOC_MIN_800_132_ITERATION_COUNT > iterationCount) )
      goto exit;

    /* In order to be FIPS-compliant, we must use only approved
     * Digest algorithms.
     */
    if ( (digestAlg != ht_sha1) && (digestAlg != ht_sha224) &&
         (digestAlg != ht_sha256) && (digestAlg != ht_sha384) &&
         (digestAlg != ht_sha512) )
      goto exit;
#endif

    if (OK > ( status = CRYPTO_getRSAHashAlgo (digestAlg, &pHashAlgo)))
    {
        goto exit;
    }

    if (OK > (status = HmacCreate(MOC_HASH(hwAccelCtx) &ctx, pHashAlgo)))
    {
        goto exit;
    }
    /* since dkLen is ubyte4, it's in the correct range */

    hLen = pHashAlgo->digestSize;

    /* each block will be hlen in length.  Determine number of blocks needed to
    generate key of length dklen */
    len = (dkLen + hLen - 1 )/ hLen;

    blockCount[0] = blockCount[1] = blockCount[2] = 0;
    blockCount[3] = 1;

    for (i = 0; i < len; ++i)
    {
        ubyte4 toCopy = (dkLen < hLen) ? dkLen : hLen;

        /* first one is PRF(P, S || INT(i)) */
        if (OK > (status = HmacQuickEx(MOC_HASH(hwAccelCtx) pPassword,
                                       passwordLen, pSalt, saltLen, blockCount,
                                       4, digest, pHashAlgo)))
        {
            goto exit;
        }

        DIGI_MEMCPY( pRetDerivedKey, digest, toCopy);

        /* do the rest */
        for (j = 1; j < iterationCount; ++j)
        {
            if (OK > ( status = HmacQuicker(MOC_HASH(hwAccelCtx) pPassword,
                                            passwordLen, digest, hLen, digest,
                                            pHashAlgo, ctx)))
            {
                goto exit;
            }
            for (k = 0; k < toCopy; ++k)
            {
                pRetDerivedKey[k] ^= digest[k];
            }
        }

        /* increment/decrement */
        dkLen -= toCopy;
        pRetDerivedKey += toCopy;

        /* increment the block count */
        blockCount[3]++;
        if (0 == blockCount[3])
        {
            blockCount[2]++;
            if (0 == blockCount[2])
            {
                blockCount[1]++;
                if (0 == blockCount[1])
                {
                    blockCount[0]++;
                }
            }
        }
    }

exit:

    if (ctx) HmacDelete(MOC_HASH(hwAccelCtx) &ctx);
    return status;

} /* PKCS5_CreateKey_PBKDF2 */

/*-----------------------------------------------------------------------------*/

static MSTATUS
PKCS5_GetV1Algos( ubyte pkcs5SubType, enum hashFunc* pHashingFunction,
                const BulkEncryptionAlgo** ppBulkAlgo)
{
    switch (pkcs5SubType)
    {
#ifdef __ENABLE_DES_CIPHER__

#ifdef __ENABLE_DIGICERT_MD2__
    case 1:  /* MD2-DES */
        *pHashingFunction = md2Encryption;
        *ppBulkAlgo = &CRYPTO_DESSuite;
        break;
#endif

    case 3:  /* MD5-DES */
        *pHashingFunction = md5Encryption;
        *ppBulkAlgo = &CRYPTO_DESSuite;
        break;
#endif

#ifdef __ENABLE_ARC2_CIPHERS__
#ifdef __ENABLE_DIGICERT_MD2__
    case 4:  /* MD2-RC2 */
        *pHashingFunction = md2Encryption;
        *ppBulkAlgo = &CRYPTO_RC2Suite;
        break;
#endif

    case 6:  /* MD5-RC2 */
        *pHashingFunction = md5Encryption;
        *ppBulkAlgo = &CRYPTO_RC2Suite;
        break;
#endif


#ifdef __ENABLE_DES_CIPHER__
    case 10: /* SHA1-DES */
        *pHashingFunction = sha1Encryption;
        *ppBulkAlgo = &CRYPTO_DESSuite;
        break;
#endif

#ifdef __ENABLE_ARC2_CIPHERS__
    case 11: /* SHA1-RC2 */
        *pHashingFunction = sha1Encryption;
        *ppBulkAlgo = &CRYPTO_RC2Suite;
        break;
#endif

    default:
        return ERR_RSA_UNKNOWN_PKCS5_ALGO;
        break;
    }
    return OK;
 }


/*-----------------------------------------------------------------------------*/

static MSTATUS
PKCS5_decryptV1_internal( MOC_SYM(hwAccelDescr hwAccelCtx)
                          ubyte pkcs5SubType, CStream cs,
                          ASN1_ITEMPTR pPBEParam, ASN1_ITEMPTR pEncrypted,
                          const ubyte* password, ubyte4 passwordLen,
                          ubyte** decryptedInfo, sbyte4* decryptedInfoLen)
{
    MSTATUS status;
    const ubyte* salt = 0;
    ASN1_ITEMPTR pSalt, pIterationCount;
    enum hashFunc hashingFunction;
    ubyte keyMaterial[16+8] = {0}; /* For version one the key and iv are 8 bytes each but
                                      PKCS_BulkDecrypt doesn't know that, so include 8 bytes padding too */
    const BulkEncryptionAlgo* pBulkAlgo = NULL;
    BulkCtx ctx = 0;

    /* some sanity checks */
    if (OK > ASN1_VerifyType( pPBEParam, SEQUENCE) ||
        OK > ASN1_VerifyType( pEncrypted, OCTETSTRING))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }
    pSalt = ASN1_FIRST_CHILD( pPBEParam);
    if ( OK > ASN1_VerifyType( pSalt, OCTETSTRING) ||
         pSalt->length != 8)
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }
    pIterationCount = ASN1_NEXT_SIBLING(pSalt);
    if ( OK > ASN1_VerifyType( pIterationCount, INTEGER))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }

    salt = CS_memaccess( cs, pSalt->dataOffset, 8);

    if (OK > (status = PKCS5_GetV1Algos( pkcs5SubType,
                                        &hashingFunction,
                                        &pBulkAlgo)))
    {
        goto exit;
    }

    if (OK > (status = PKCS5_CreateKey_PBKDF1(MOC_HASH(hwAccelCtx) salt, 8,
                                    pIterationCount->data.m_intVal,
                                    hashingFunction,
                                    password, passwordLen, 16, keyMaterial)))
    {
        goto exit;
    }

    ctx = pBulkAlgo->createFunc( MOC_SYM(hwAccelCtx) keyMaterial, 8, 0);
    if (!ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = PKCS_BulkDecrypt(MOC_SYM(hwAccelCtx) pEncrypted,
                                cs, ctx, pBulkAlgo, keyMaterial+8,
                                decryptedInfo, decryptedInfoLen)))
    {
        goto exit;
    }

exit:

    CS_stopaccess( cs, salt);
    if (pBulkAlgo && ctx)
    {
        pBulkAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &ctx);
    }

    return status;
}


/*-----------------------------------------------------------------------------*/

static MSTATUS
PKCS5_decryptV2_internal( MOC_SYM(hwAccelDescr hwAccelCtx) CStream cs,
                          ASN1_ITEMPTR pPBEParam, ASN1_ITEMPTR pEncrypted,
                          const ubyte* password, ubyte4 passwordLen,
                          ubyte** decryptedInfo, sbyte4* decryptedInfoLen)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pPKDF2Params, pSalt, pIterationCount;
    ASN1_ITEMPTR pOptional;
    ASN1_ITEMPTR pEncAlgoOID;
    sbyte4 keyLength = -1;
    sbyte4 effectiveKeyBits = -1;
    ubyte subType;
    ubyte iv[16 /* MAX_IV_SIZE */];
    const ubyte* salt = 0;
    ubyte* derivedKey = 0;
    const BulkEncryptionAlgo* pBulkAlgo = 0;
    BulkCtx ctx = 0;
    ubyte rsaAlgoId = 0;

    static WalkerStep pbeParamToPkdf2Params[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},          /* OID */
        { VerifyOID, 0, (ubyte*) pkcs5_PBKDF2_OID },
        { GoNextSibling, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { Complete, 0, 0}
    };

    static WalkerStep pbeParamToEncryptionOID[] =
    {
        { GoFirstChild, 0, 0},
        { GoNextSibling, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},          /* OID */
        { VerifyType, OID, 0 },
        { Complete, 0, 0}
    };

    /* some sanity checks */
    if (OK > ASN1_VerifyType( pPBEParam, SEQUENCE) ||
        OK > ASN1_VerifyType( pEncrypted, OCTETSTRING))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }

    /* the pPBEParam is a sequence of 2 sequences */
    /* the first one describes the PBKDF2 */
    if ( OK >  ASN1_WalkTree( pPBEParam, cs, pbeParamToPkdf2Params,
                                &pPKDF2Params))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }
    pSalt = ASN1_FIRST_CHILD( pPKDF2Params);
    if ( OK > ASN1_VerifyType( pSalt, OCTETSTRING))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }
    pIterationCount = ASN1_NEXT_SIBLING(pSalt);
    if ( OK > ASN1_VerifyType( pIterationCount, INTEGER))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }

    /* optional keyLength */
    pOptional = ASN1_NEXT_SIBLING( pIterationCount);
    /* if type integer, this is keylength */
    if (OK <= ASN1_VerifyType( pOptional, INTEGER))
    {
        keyLength = pOptional->data.m_intVal;
        pOptional = ASN1_NEXT_SIBLING( pOptional); /* advance */
    }

    /* optional prf */
    rsaAlgoId = sha1withRSAEncryption; /* default */
    if (OK <= ASN1_VerifyType( pOptional, SEQUENCE))
    {
        ASN1_ITEMPTR pPrfAlgoOID = ASN1_FIRST_CHILD(pOptional);

        if (OK <= ASN1_VerifyOIDRoot( pPrfAlgoOID, cs, rsaDSI_OID, &subType))
        {
            switch (subType)
            {
            case hmacSHA1Digest:
                rsaAlgoId = sha1withRSAEncryption;
                break;

#ifndef __DISABLE_DIGICERT_SHA224__
            case hmacSHA224Digest:
                rsaAlgoId = sha224withRSAEncryption;
                break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
            case hmacSHA256Digest:
                rsaAlgoId = sha256withRSAEncryption;
                break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
            case hmacSHA384Digest:
                rsaAlgoId = sha384withRSAEncryption;
                break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
            case hmacSHA512Digest:
                rsaAlgoId = sha512withRSAEncryption;
                break;
#endif

            default:
                status = ERR_RSA_UNKNOWN_PKCS5_ALGO;
                break;
            }
            if (OK != status)
                goto exit;
        }
        else
        {
            status = ERR_RSA_INVALID_PKCS8;
            goto exit;
        }
    }

    /* not what is the algorithm used for encryption */
    if ( OK >  ASN1_WalkTree( pPBEParam, cs, pbeParamToEncryptionOID,
                                &pEncAlgoOID))
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }


    if (OK <= ASN1_VerifyOID( pEncAlgoOID, cs, desCBC_OID))
    {
#ifdef __ENABLE_DES_CIPHER__
        if (OK > (status = PKCS_GetCBCParams(pEncAlgoOID, cs,
                                                DES_BLOCK_SIZE, iv)))
        {
            goto exit;
        }

        pBulkAlgo = &CRYPTO_DESSuite;
        if (keyLength < 0)
        {
            keyLength = 8;
        }
#endif
    }
    else if (OK <= ASN1_VerifyOIDRoot( pEncAlgoOID, cs,
                                    rsaEncryptionAlgoRoot_OID, &subType))
    {
        switch (subType)
        {
#ifdef __ENABLE_ARC2_CIPHERS__
        case 2: /* RC2CBC*/
            if (OK > ( status = PKCS_GetRC2CBCParams( pEncAlgoOID, cs,
                                            &effectiveKeyBits, iv)))
            {
                goto exit;
            }
            pBulkAlgo = &CRYPTO_RC2EffectiveBitsSuite;
            if (keyLength < 0)
            {
                keyLength = 16;
            }
            break;
#endif

#ifndef __DISABLE_ARC4_CIPHERS__
        case 4: /* rc4 -- not in the standard */
            pBulkAlgo = &CRYPTO_RC4Suite;
            if (keyLength < 0)
            {
                keyLength = 16;
            }
            break;
#endif

#ifndef __DISABLE_3DES_CIPHERS__
        case 7: /* desEDE3CBC */
            if (OK > (status = PKCS_GetCBCParams(pEncAlgoOID, cs,
                                                    DES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            pBulkAlgo = &CRYPTO_TripleDESSuite;
            if (keyLength < 0)
            {
                keyLength = 24;
            }
            break;
#endif
        }
    }
#ifndef __DISABLE_AES_CIPHERS__
    else if (OK <= ASN1_VerifyOIDRoot( pEncAlgoOID, cs, aes_OID, &subType))
    {
        switch (subType)
        {
#ifndef __DISABLE_AES128_CIPHER__
        case 2: /* AES128 */
            if (OK > (status = PKCS_GetCBCParams(pEncAlgoOID, cs,
                                                 AES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            pBulkAlgo = &CRYPTO_AESSuite;
            if (keyLength < 0)
            {
                keyLength = 16;
            }
            break;
#endif

#ifndef __DISABLE_AES192_CIPHER__
        case 22: /* AES192 */
            if (OK > (status = PKCS_GetCBCParams(pEncAlgoOID, cs,
                                                 AES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            pBulkAlgo = &CRYPTO_AESSuite;
            if (keyLength < 0)
            {
                keyLength = 24;
            }
            break;
#endif

#ifndef __DISABLE_AES256_CIPHER__
        case 42: /* AES256 */
            if (OK > (status = PKCS_GetCBCParams(pEncAlgoOID, cs,
                                                 AES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            pBulkAlgo = &CRYPTO_AESSuite;
            if (keyLength < 0)
            {
                keyLength = 32;
            }
            break;
#endif
        }
    }
#endif

    if (!pBulkAlgo)
    {
        status = ERR_RSA_UNKNOWN_PKCS5_ALGO;
        goto exit;
    }

    salt = CS_memaccess(cs, pSalt->dataOffset, pSalt->length);
    derivedKey = MALLOC( keyLength);
    if (!salt || !derivedKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* generate the key now using the PBKDF2 */
    if (OK > (status = PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx) salt, pSalt->length,
                                          pIterationCount->data.m_intVal,
                                          rsaAlgoId,
                                          password, passwordLen,
                                          keyLength, derivedKey)))
    {
        goto exit;
    }

    if (effectiveKeyBits < 0)
    {
        effectiveKeyBits = 0; /* decrypt */
    }

    ctx = pBulkAlgo->createFunc( MOC_SYM(hwAccelCtx) derivedKey, keyLength, effectiveKeyBits);
    if (!ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > ( status = PKCS_BulkDecrypt(MOC_SYM(hwAccelCtx)
                                pEncrypted, cs, ctx,
                                pBulkAlgo, iv,
                                decryptedInfo, decryptedInfoLen)))
    {
        goto exit;
    }

exit:

    if (pBulkAlgo && ctx)
    {
        pBulkAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &ctx);
    }

    if (salt)
    {
        CS_stopaccess( cs, salt);
    }

    if (derivedKey)
    {
        FREE( derivedKey);
    }

    return status;
}


/*--------------------------------------------------------------------------*/
/**
@todo_64
@ingroup    pkcs_functions
*/
extern MSTATUS
PKCS5_decrypt( MOC_SYM(hwAccelDescr hwAccelCtx)
                ubyte subType, CStream cs,
                ASN1_ITEMPTR pPBEParam, ASN1_ITEMPTR pEncrypted,
                const ubyte* password, sbyte4 passwordLen,
                ubyte** privateKeyInfo, sbyte4* privateKeyInfoLen)
{
    if (!pPBEParam || !pEncrypted || !password || !privateKeyInfo ||
        !privateKeyInfoLen)
    {
        return ERR_NULL_POINTER;
    }

    if ( PKCS5_PBES2 == subType)
    {
        return PKCS5_decryptV2_internal( MOC_SYM(hwAccelCtx) cs, pPBEParam,
                                         pEncrypted, password, passwordLen,
                                         privateKeyInfo, privateKeyInfoLen);
    }
    else
    {
        return PKCS5_decryptV1_internal( MOC_SYM(hwAccelCtx) subType, cs,
                                         pPBEParam, pEncrypted, password, passwordLen,
                                         privateKeyInfo, privateKeyInfoLen);

    }
}

/*-----------------------------------------------------------------------------*/

extern MSTATUS PKCS5_decryptV2( MOC_SYM(hwAccelDescr hwAccelCtx)
                                const ubyte *pAsn1PBE, ubyte4 pbeLen,
                                ubyte *pData, ubyte4 dataLen,
                                const ubyte* pPassword, sbyte4 passwordLen,
                                ubyte *pPrivateKeyInfo, ubyte4 privKeyInfoBufferLen,
                                ubyte4 *pPrivKeyInfoLen)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
    ubyte *pRecovered = NULL;
    sbyte4 recoveredLen = 0; 
    ASN1_ITEMPTR pRoot = NULL;
    ASN1_ITEMPTR pPBEParam = NULL;
    ASN1_ITEMPTR pEncrypted = NULL;
    CStream cs = {0};
    MemFile mf = {0}; 
    ubyte *pFullAsn1 = NULL;
    ubyte *pEnd = NULL;
    ubyte4 fullLen = 0;

    if (NULL == pPrivKeyInfoLen)
        goto exit;
    
    /* We need to combine the pAsn1PBE with the encrypted data after it 
      SEQ
        pAsn1PBE
        OCTET STRING pData
    */

    /* Allocate a buffer at least big enough, might have 2 tag and lengths of up to 4 bytes each */
    status = DIGI_MALLOC((void **) &pFullAsn1, pbeLen + dataLen + 8);
    if (OK != status)
        goto exit;

    /* We'll work backwards, fill in the data first at the end */
    pEnd = pFullAsn1 + pbeLen + 8;

    status = DIGI_MEMCPY(pEnd, pData, dataLen);
    if (OK != status)
        goto exit;
    
    fullLen += dataLen;

    /* length */
    if (dataLen < 128)
    {
        pEnd--;
        *pEnd = (ubyte) (dataLen & 0xff);
        fullLen++;
    }
    else if (dataLen < 256)
    {
        pEnd--;
        *pEnd = (ubyte) (dataLen & 0xff);
        pEnd--;
        *pEnd = 0x81; /* 1 byte length */
        fullLen += 2;
    }
    else if (dataLen < 0x8000)
    {
        pEnd--;
        *pEnd = (ubyte) (dataLen & 0xff);
        pEnd--;
        *pEnd = (ubyte) ((dataLen >> 8) & 0xff);
        pEnd--;
        *pEnd = 0x82; /* 2 byte length */
        fullLen += 3;
    }
    else
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    
    /* tag */
    pEnd--;
    *pEnd = 0x04; /* octet string */
    fullLen++;

    pEnd -= pbeLen;

    /* copy the pbe info */
    status = DIGI_MEMCPY(pEnd, pAsn1PBE, pbeLen);
    if (OK != status)
        goto exit;

    fullLen += pbeLen;

    /* wrap both in a sequence */

    /* length */
    if (fullLen < 128)
    {
        pEnd--;
        *pEnd = (ubyte) (fullLen & 0xff);
        fullLen++;
    }
    else if (fullLen < 256)
    {
        pEnd--;
        *pEnd = (ubyte) (fullLen & 0xff);
        pEnd--;
        *pEnd = 0x81; /* 1 byte length */
        fullLen += 2;
    }
    else if (fullLen < 0x8000)
    {
        pEnd--;
        *pEnd = (ubyte) (fullLen & 0xff);
        pEnd--;
        *pEnd = (ubyte) ((fullLen >> 8) & 0xff);
        pEnd--;
        *pEnd = 0x82; /* 2 byte length */
        fullLen += 3;
    }
    else
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    
    /* tag */
    pEnd--;
    *pEnd = 0x30; /* sequence */
    fullLen++;

    (void) MF_attach(&mf, (sbyte4) fullLen, pEnd);
    (void) CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRoot);
    if (OK != status)
        goto exit;

    /* first child is the initial top level sequence, so go to the child after that */
    pPBEParam = ASN1_FIRST_CHILD( pRoot);
    pPBEParam = ASN1_FIRST_CHILD( pPBEParam);

    /* next sibling is the encrypted key that we need to decrypt */
    pEncrypted = ASN1_NEXT_SIBLING( pPBEParam);
  
    status = PKCS5_decryptV2_internal(MOC_SYM(hwAccelCtx) cs, pPBEParam, pEncrypted, pPassword, passwordLen, &pRecovered, &recoveredLen);
    if (OK != status)
        goto exit;

    *pPrivKeyInfoLen = (ubyte4) recoveredLen;
    status = ERR_BUFFER_TOO_SMALL;
    if (NULL == pPrivateKeyInfo || privKeyInfoBufferLen < (ubyte4) recoveredLen)
        goto exit;

    status = DIGI_MEMCPY(pPrivateKeyInfo, pRecovered, recoveredLen);

exit:
    
    if (NULL != pRoot)
    {
        fstatus = TREE_DeleteTreeItem( (TreeItem*) pRoot);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pFullAsn1)
    {
        fstatus = DIGI_MEMSET_FREE(&pFullAsn1, pbeLen + dataLen + 8);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pRecovered)
    {
        fstatus = DIGI_MEMSET_FREE(&pRecovered, recoveredLen);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

/*-----------------------------------------------------------------------------*/

extern MSTATUS
PKCS5_encryptV1( MOC_SYM(hwAccelDescr hwAccelCtx)
                      ubyte pkcs5SubType,
                      const ubyte* password, ubyte4 passwordLen,
                      const ubyte* salt, ubyte4 saltLen,
                      ubyte4 iterCount,
                      ubyte* plainText, ubyte4 ptLen)
{
    MSTATUS status;
    enum hashFunc hashingFunction;
    ubyte keyMaterial[16];
    const BulkEncryptionAlgo* pBulkAlgo;

    if (OK > ( status = PKCS5_GetV1Algos( pkcs5SubType, &hashingFunction, &pBulkAlgo)))
    {
        goto exit;
    }

    if (OK > (status = PKCS5_CreateKey_PBKDF1(MOC_HASH(hwAccelCtx) salt, saltLen,
                                    iterCount, hashingFunction,
                                    password, passwordLen, 16, keyMaterial)))
    {
        goto exit;
    }


    if (OK > ( status = CRYPTO_Process( MOC_SYM(hwAccelCtx) pBulkAlgo,
                                        keyMaterial, 8, keyMaterial + 8,
                                        plainText, ptLen, 1)))
    {
        goto exit;
    }

exit:

    return status;
}


/*-----------------------------------------------------------------------------*/

extern MSTATUS
PKCS5_encryptV2( MOC_SYM(hwAccelDescr hwAccelCtx)
                  const BulkEncryptionAlgo* pAlgo, ubyte rsaAlgoId,
                  ubyte4 keyLength, sbyte4 effectiveKeyBits,
                  const ubyte* password, ubyte4 passwordLen,
                  const ubyte* salt, ubyte4 saltLen,
                  ubyte4 iterCount, const ubyte* iv,
                  ubyte* plainText, ubyte4 ptLen)
{
    MSTATUS status;
    ubyte* derivedKey = 0;

    if (!pAlgo || !password || !salt || !plainText)
        return ERR_NULL_POINTER;

    derivedKey = MALLOC( keyLength + pAlgo->blockSize);
    if (!derivedKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* generate the key now using the PBKDF2 */
    if (OK > (status = PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx) salt, saltLen,
                                    iterCount, rsaAlgoId,
                                    password, passwordLen,
                                    keyLength, derivedKey)))
    {
        goto exit;
    }

    if (effectiveKeyBits < 0)
    {
        effectiveKeyBits = 1; /* encrypt */
    }

    /* copy the iv since CRYPTO_Process will modify it */
    DIGI_MEMCPY( derivedKey + keyLength, iv, pAlgo->blockSize);

    if (OK > (status = CRYPTO_Process( MOC_SYM(hwAccelCtx) pAlgo,
                                        derivedKey, keyLength,
                                        derivedKey + keyLength, /* iv copy */
                                        plainText, ptLen,
                                        effectiveKeyBits)))
    {
        goto exit;
    }

exit:

    if (derivedKey)
    {
        FREE( derivedKey);
    }

    return status;
}

MOC_EXTERN MSTATUS PKCS5_encryptV2_Alt(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte encryptionAlgo, ubyte digestAlg,
    ubyte4 keyLength, sbyte4 effectiveKeyBits,
    const ubyte *pPassword, ubyte4 passwordLen,
    const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterCount, const ubyte *pIv,
    ubyte *pPlainText, ubyte4 ptLen,
    ubyte *pCipherText, ubyte4 ctBufferLen,
    ubyte4 *pCtLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    const BulkEncryptionAlgo *pBulkAlgo = NULL;
    ubyte4 padLen = 0;
    ubyte4 padValue = 0;

    if (NULL == pCtLen)
        goto exit;

    switch (encryptionAlgo)
    {
#ifdef __ENABLE_NIL_CIPHER__
        case nilEncryption:
            pBulkAlgo = &CRYPTO_NilSuite;
            padLen = 0;
            break;
#endif
#ifndef __DISABLE_3DES_CIPHERS__
        case tdesEncryption:
            pBulkAlgo = &CRYPTO_TripleDESSuite;
            padLen = DES_BLOCK_SIZE;
            break;

        case twoKeyTdesEncryption:
            pBulkAlgo = &CRYPTO_TwoKeyTripleDESSuite;
            padLen = DES_BLOCK_SIZE;
            break;
#endif
#ifdef __ENABLE_DES_CIPHER__
        case desEncryption:
            pBulkAlgo = &CRYPTO_DESSuite;
            padLen = DES_BLOCK_SIZE;
            break;
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
        case rc4Encryption:
            pBulkAlgo = &CRYPTO_RC4Suite;
            padLen = 0;
            break;
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
        case rc2Encryption:
            pBulkAlgo = &CRYPTO_RC2Suite;
            padLen = RC2_BLOCK_SIZE;
            break;

        case rc2EkbEncryption:
            pBulkAlgo = &CRYPTO_RC2EffectiveBitsSuite;
            padLen = RC2_BLOCK_SIZE;
            break;
#endif
#ifdef __ENABLE_BLOWFISH_CIPHERS__
        case bfEncryption:
            pBulkAlgo = &CRYPTO_BlowfishSuite;
            padLen = BLOWFISH_BLOCK_SIZE;
            break;
#endif
#ifndef __DISABLE_AES_CIPHERS__
        case aesEncryption:
            pBulkAlgo = &CRYPTO_AESSuite;
            padLen = AES_BLOCK_SIZE;
            break;

        case aesCtrEncryption:
            pBulkAlgo = &CRYPTO_AESCtrSuite;
            padLen = 0;
            break;
#endif
        default:
            status = ERR_PKCS5_INVALID_ENC_FUNCTION;
            goto exit;
    }
    
    if (padLen > 0)
    {
        padValue = padLen - (ptLen % padLen);
    }
    
    /* make sure buffer is big enough */
    *pCtLen = (ptLen + padValue);
    status = ERR_BUFFER_TOO_SMALL;
    if (NULL == pCipherText || ctBufferLen < ptLen + padValue)
        goto exit;

    /* We manually pad and store in the pCipherText buffer */
    status = DIGI_MEMCPY(pCipherText, pPlainText, ptLen);
    if (OK != status)
        goto exit;

    if (padLen > 0)
    {
        status = DIGI_MEMSET(pCipherText + ptLen, (ubyte) padValue, padValue);
        if (OK != status)
            goto exit;
    }

    /* now call the usual in place encryption */
    status = PKCS5_encryptV2(MOC_SYM(hwAccelCtx) pBulkAlgo, digestAlg, keyLength, effectiveKeyBits, pPassword, passwordLen,
                             pSalt, saltLen, iterCount, pIv, pCipherText, ptLen + padValue);

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_PKCS5__ */
