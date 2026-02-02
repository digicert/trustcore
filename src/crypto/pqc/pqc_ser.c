/*
 * pqc_ser.c
 *
 * PQC key serialization methods
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

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../crypto/pqc/pqc_ser.h" /* includes mldsa.h etc... */

#define PQC_SER_OCTET_STR_TAG 0x04
#define PQC_SER_SEQ_TAG 0x30
#define PQC_SER_ZERO_TAG 0x80
#define PQC_SER_TWO_BYTE_LEN_TAG 0x82

#ifdef __ENABLE_DIGICERT_PQC_KEM__

/* Sizes from Table 3. */
static size_t MLKEM_getPrivKeyLen(MLKEMType type)
{
    switch (type) {
        case MLKEM_TYPE_512:
            return 1632;
        case MLKEM_TYPE_768:
            return 2400;
        case MLKEM_TYPE_1024:
            return 3168;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */

/* Sizes from Table 3. */
static size_t MLKEM_getPubKeyLen(MLKEMType type)
{
    switch (type) {
        case MLKEM_TYPE_512:
            return 800;
        case MLKEM_TYPE_768:
            return 1184;
        case MLKEM_TYPE_1024:
            return 1568;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */

static MSTATUS MLKEM_serialize(MLKEMCtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen)
{
    uint8_t *ser = NULL;
    uint8_t *serPtr = NULL;
    size_t serLen = 0;

    serLen = 4 + ctx->encKeyLen; // Always prepend the size in 4 bytes.
    bool copyPrivate = false;
    if (pubOnly == false && ctx->decKey != NULL)
    {
        copyPrivate = true;
        serLen += 4 + ctx->decKeyLen;
    }

    MSTATUS status = DIGI_MALLOC((void **) &ser, serLen);
    if (OK != status)
        goto exit;

    ser[0] = (ubyte)((ctx->encKeyLen >> 24) & 0xFF);
    ser[1] = (ubyte)((ctx->encKeyLen >> 16) & 0xFF);
    ser[2] = (ubyte)((ctx->encKeyLen >> 8) & 0xFF);
    ser[3] = (ubyte)(ctx->encKeyLen & 0xFF);
    serPtr = ser + 4;

    /* already checked pointers not NULL */
    moc_memcpy(serPtr, ctx->encKey, ctx->encKeyLen);

    if (copyPrivate == true) {
        serPtr += ctx->encKeyLen;

        serPtr[0] = (ubyte)((ctx->decKeyLen >> 24) & 0xFF);
        serPtr[1] = (ubyte)((ctx->decKeyLen >> 16) & 0xFF);
        serPtr[2] = (ubyte)((ctx->decKeyLen >> 8) & 0xFF);
        serPtr[3] = (ubyte)(ctx->decKeyLen & 0xFF);
        serPtr = serPtr + 4;

        moc_memcpy(serPtr, ctx->decKey, ctx->decKeyLen);
    }

    *serKey = ser; ser = NULL;
    *serKeyLen = serLen;

exit:

    /* no goto exit after ser allocation, defensive code, but no need to zero */
    if (NULL != ser)
    {
        (void) DIGI_FREE((void **) &ser);
    }

    return status;
}


/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLKEM_serializeKeyAlloc(MLKEMCtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen)
{
    if (ctx == NULL || serKey == NULL || serKeyLen == NULL) {
        return ERR_NULL_POINTER;
    }

    if (ctx->encKey == NULL) {
        return ERR_UNINITIALIZED_CONTEXT;
    }

    if (*serKey != NULL) {
        return ERR_INVALID_INPUT;
    }

    return MLKEM_serialize(ctx, pubOnly, serKey, serKeyLen);
}

/* ------------------------------------------------------------------- */

/* Note this API expects we already allocated the MlkemKey for the proper size
   Future, we could make this an allocKey API and work for any enabled size */
MOC_EXTERN MSTATUS MLKEM_deserializeKey(MLKEMCtx *ctx, bool pubOnly, ubyte *serKey, ubyte4 serKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pDataPtr = NULL;
    ubyte *pPub = NULL;
    ubyte *pPriv = NULL;
    byteBoolean isPrivate = FALSE;
    ubyte4 keyLen = 0;

    if (ctx == NULL || serKey == NULL)
        goto exit;

    if (ctx->encKey != NULL || ctx->decKey != NULL) {
        return ERR_PREVIOUSLY_EXISTING_ITEM;
    }

    /* validate the public keyLen */
    keyLen = ((ubyte4) serKey[0] << 24) | ((ubyte4) serKey[1] << 16) |
             ((ubyte4) serKey[2] << 8) | (ubyte4) serKey[3];

    if (keyLen > 0)
    {
        /* validate the length, private serialization contains both keys and two 4 byte lengths */
        if (keyLen != (ubyte4) MLKEM_getPubKeyLen(ctx->type))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* Is there also a private key */
        if (serKeyLen > keyLen + 8) /* if bigger than just a public key assume it's private, validate later... */
        {
            isPrivate = TRUE;
        }
    }
    else
    {
        isPrivate = TRUE;
    }

    pDataPtr = serKey + 4;
    if (keyLen > 0)
    {
        status = DIGI_MALLOC_MEMCPY((void **) &pPub, keyLen, (void *) pDataPtr, keyLen);
        if (OK != status)
            goto exit;

        ctx->encKeyLen = keyLen;
        ctx->encKey = pPub; pPub = NULL;
    }

    if (isPrivate && !pubOnly)
    {
        /* skip over to the private key, we don't validate the pub and pri match */
        pDataPtr += keyLen;

        /* validate the private key len */
        keyLen = ((ubyte4) pDataPtr[0] << 24) | ((ubyte4) pDataPtr[1] << 16) |
                 ((ubyte4) pDataPtr[2] << 8) | (ubyte4) pDataPtr[3];
        pDataPtr += 4;

        if (keyLen != MLKEM_getPrivKeyLen(ctx->type)) 
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* copy the private key */
        status = DIGI_MALLOC_MEMCPY((void **) &pPriv, keyLen, (void *) pDataPtr, keyLen);
        if (OK != status)
            goto exit;

        ctx->decKey = pPriv; pPriv = NULL;
        ctx->decKeyLen = keyLen;
    }

exit:

    if (NULL != pPriv)
    {
        (void) DIGI_MEMSET_FREE(&pPriv, ctx->decKeyLen);
    }

    if (NULL != pPub)
    {
        (void) DIGI_MEMSET_FREE(&pPub, ctx->encKeyLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC_KEM__ */

/* ------------------------------------------------------------------- */

#ifdef __ENABLE_DIGICERT_PQC_SIG__
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
/* Note this flag and method is NOT thread safe
   If being toggled to TRUE it should be done once on startup */
static byteBoolean gIsLongFormPrivateKeyFormat = FALSE;
extern void MLDSA_setLongFormPrivKeyFormat(byteBoolean format)
{
    gIsLongFormPrivateKeyFormat = format;
}
#endif /* __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__ */

/* ------------------------------------------------------------------- */

/* Sizes from Table 2. */
static size_t MLDSA_getPrivKeyLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return 2560;
        case MLDSA_TYPE_65:
            return 4032;
        case MLDSA_TYPE_87:
            return 4896;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */

/* Sizes from Table 2. */
static size_t MLDSA_getPubKeyLen(MLDSAType type)
{
    switch (type) {
        case MLDSA_TYPE_44:
            return 1312;
        case MLDSA_TYPE_65:
            return 1952;
        case MLDSA_TYPE_87:
            return 2592;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */

/* Sizes from Table 2. */
static size_t SLHDSA_getPrivKeyLen(SLHDSAType type)
{
    switch (type) {
        case SLHDSA_TYPE_SHA2_128S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_128F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128F:
            return 2*32;
        case SLHDSA_TYPE_SHA2_192S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_192F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192F:
            return 2*48;
        case SLHDSA_TYPE_SHA2_256S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_256F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256F:
            return 2*64;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */

/* Sizes from Table 2. */
static size_t SLHDSA_getPubKeyLen(SLHDSAType type)
{
    switch (type) {
        case SLHDSA_TYPE_SHA2_128S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_128F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_128F:
            return 32;
        case SLHDSA_TYPE_SHA2_192S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_192F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_192F:
            return 48;
        case SLHDSA_TYPE_SHA2_256S: /* fallthrough */
        case SLHDSA_TYPE_SHA2_256F: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256S: /* fallthrough */
        case SLHDSA_TYPE_SHAKE_256F:
            return 64;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------- */

static MSTATUS MLDSA_serialize(MLDSACtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen)
{
    uint8_t *ser = NULL;
    uint8_t *serPtr = NULL;
    size_t serLen = 0;

    if (NULL != ctx->pubKey && ctx->pubKeyLen)
    {
        serLen = 4 + ctx->pubKeyLen; /* Always prepend the size in 4 bytes. */
    }
    else
    {
        serLen = 4; /* prepend 4 byte length of 0, then private key ser only */
    }
    bool copyPrivate = false;
    if (pubOnly == false && ctx->privKey != NULL)
    {
        copyPrivate = true;
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
        if (gIsLongFormPrivateKeyFormat)
        {
            serLen += 8 + ctx->privKeyLen; /* expanded private key in an octet string */
        }
        else
#endif
        {
            serLen += 6 + MLDSA_SEED_LEN; /* [0] tag plus seed only */
        }
    }

    MSTATUS status = DIGI_MALLOC((void **) &ser, serLen);
    if (OK != status)
        goto exit;

    ser[0] = (ubyte)((ctx->pubKeyLen >> 24) & 0xFF);
    ser[1] = (ubyte)((ctx->pubKeyLen >> 16) & 0xFF);
    ser[2] = (ubyte)((ctx->pubKeyLen >> 8) & 0xFF);
    ser[3] = (ubyte)(ctx->pubKeyLen & 0xFF);
    serPtr = ser + 4;

    /* already checked pointers not NULL */
    if (NULL != ctx->pubKey && ctx->pubKeyLen)
    {
        moc_memcpy(serPtr, ctx->pubKey, ctx->pubKeyLen);
        serPtr += ctx->pubKeyLen;
    }
    
    if (copyPrivate == true) 
    {
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
        if (gIsLongFormPrivateKeyFormat)
        {
            /* We serialize an raw priv key in an octet string asn1 format
               We need 4 extra bytes for the 0x04 tag and the 3 byte length */
            serPtr[0] = (ubyte)(((ctx->privKeyLen + 4) >> 24) & 0xFF);
            serPtr[1] = (ubyte)(((ctx->privKeyLen + 4) >> 16) & 0xFF);
            serPtr[2] = (ubyte)(((ctx->privKeyLen + 4) >> 8) & 0xFF);
            serPtr[3] = (ubyte)((ctx->privKeyLen + 4) & 0xFF);

            serPtr[4] = PQC_SER_OCTET_STR_TAG;
            serPtr[5] = PQC_SER_TWO_BYTE_LEN_TAG;
            serPtr[6] = (ubyte)((ctx->privKeyLen >> 8) & 0xFF);
            serPtr[7] = (ubyte)(ctx->privKeyLen & 0xFF);
            serPtr += 8;

            moc_memcpy(serPtr, ctx->privKey, ctx->privKeyLen); /* expanded key */
        }
        else
#endif
        {
            serPtr[0] = 0;
            serPtr[1] = 0;
            serPtr[2] = 0;
            serPtr[3] = (ubyte) (MLDSA_SEED_LEN + 2);
            serPtr[4] = PQC_SER_ZERO_TAG; /* [0] tag */
            serPtr[5] = (ubyte) MLDSA_SEED_LEN;
            serPtr = serPtr + 6;
            moc_memcpy(serPtr, ctx->privKeySeed, MLDSA_SEED_LEN); /* seed */
        }
    }

    *serKey = ser; ser = NULL;
    *serKeyLen = serLen;

exit:

    /* no goto exit after ser allocation, defensive code, but no need to zero */
    if (NULL != ser)
    {
        (void) DIGI_FREE((void **) &ser);
    }

    return status;
}

/* ------------------------------------------------------------------- */

static MSTATUS SLHDSA_serialize(SLHDSACtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen)
{
    uint8_t *ser = NULL;
    uint8_t *serPtr = NULL;
    size_t serLen = 0;

    serLen = 4 + ctx->pubKeyLen; /* Always prepend the size in 4 bytes. */
    bool copyPrivate = false;
    if (pubOnly == false && ctx->privKey != NULL)
    {
        copyPrivate = true;
        serLen += 4 + ctx->privKeyLen;
    }

    MSTATUS status = DIGI_MALLOC((void **) &ser, serLen);
    if (OK != status)
        goto exit;

    ser[0] = (ubyte)((ctx->pubKeyLen >> 24) & 0xFF);
    ser[1] = (ubyte)((ctx->pubKeyLen >> 16) & 0xFF);
    ser[2] = (ubyte)((ctx->pubKeyLen >> 8) & 0xFF);
    ser[3] = (ubyte)(ctx->pubKeyLen & 0xFF);
    serPtr = ser + 4;

    /* already checked pointers not NULL */
    moc_memcpy(serPtr, ctx->pubKey, ctx->pubKeyLen);

    if (copyPrivate == true) {
        serPtr += ctx->pubKeyLen;

        serPtr[0] = (ubyte)((ctx->privKeyLen >> 24) & 0xFF);
        serPtr[1] = (ubyte)((ctx->privKeyLen >> 16) & 0xFF);
        serPtr[2] = (ubyte)((ctx->privKeyLen >> 8) & 0xFF);
        serPtr[3] = (ubyte)(ctx->privKeyLen & 0xFF);
        serPtr = serPtr + 4;

        moc_memcpy(serPtr, ctx->privKey, ctx->privKeyLen);
    }

    *serKey = ser; ser = NULL;
    *serKeyLen = serLen;

exit:

    /* no goto exit after ser allocation, defensive code, but no need to zero */
    if (NULL != ser)
    {
        (void) DIGI_FREE((void **) &ser);
    }

    return status;
}

/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MLDSA_serializeKeyAlloc(MLDSACtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen)
{
    if (ctx == NULL || serKey == NULL || serKeyLen == NULL) {
        return ERR_NULL_POINTER;
    }

    if (*serKey != NULL) {
        return ERR_INVALID_INPUT;
    }

    return MLDSA_serialize(ctx, pubOnly, serKey, serKeyLen);
}

/* ------------------------------------------------------------------- */

/* Note this API expects we already allocated the MldsaKey for the proper size
   Future, we could make this an allocKey API and work for any enabled size */
MOC_EXTERN MSTATUS MLDSA_deserializeKey(MLDSACtx *ctx, bool pubOnly, ubyte *serKey, ubyte4 serKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    byteBoolean isPrivate = FALSE;
    ubyte4 pubKeyLen = 0;
    ubyte4 privKeyLen = 0;
    ubyte *pPubKeyPtr = NULL;

    if (ctx == NULL || serKey == NULL)
        goto exit;

    if (ctx->pubKey != NULL || ctx->privKey != NULL) {
        return ERR_PREVIOUSLY_EXISTING_ITEM;
    }

    /* is there a public key? */
    pubKeyLen = ((ubyte4) serKey[0] << 24) | ((ubyte4) serKey[1] << 16) |
                ((ubyte4) serKey[2] << 8) | (ubyte4) serKey[3];

    if (0 != pubKeyLen)
    {
        /* validate the length */
        if (pubKeyLen != (ubyte4) MLDSA_getPubKeyLen(ctx->type))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* Is there also a private key */
        if (serKeyLen > pubKeyLen + 4) /* if bigger than just a public key assume it's private, validate later... */
        {
            isPrivate = TRUE;
        }
    }
    else /* assume it's just a private key */
    {
        isPrivate = TRUE;
    }

    pPubKeyPtr = serKey + 4;

    if (isPrivate && !pubOnly)
    {
        /* skip over the public key for now */
        ubyte *pDataPtr = pPubKeyPtr + pubKeyLen;

#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
        /* We can deserialize three types of serializations, 1) seed only 2) expanded key only 3) both
           For expanded key only we can't recover the seed, so it can't be re-serialized in short format */

        /* get expected length of expanded priv key */
        ubyte4 expPrivLen = (ubyte4) MLDSA_getPrivKeyLen(ctx->type);
#endif
    
        /* validate the private key len */
        privKeyLen = ((ubyte4) pDataPtr[0] << 24) | ((ubyte4) pDataPtr[1] << 16) |
                     ((ubyte4) pDataPtr[2] << 8) | (ubyte4) pDataPtr[3];
        pDataPtr += 4;

        if ((ubyte4)(2 + MLDSA_SEED_LEN) == privKeyLen) /* we have just the [0] tag and seed, call method that will set and expand */
        {
            status = ERR_INVALID_INPUT;
            if (PQC_SER_ZERO_TAG != *pDataPtr) /* 0x80 meaning [0] */
                goto exit;

            pDataPtr++;
            if ((ubyte) MLDSA_SEED_LEN != *pDataPtr)
                goto exit;

            pDataPtr++;
            status = MLDSA_setPrivateKey(pDataPtr, MLDSA_SEED_LEN, ctx); /* we don't validate the pub and pri match */
        }
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
        else if(4 + expPrivLen == privKeyLen) /* extra octet string tag and 3 byte length */
        {
            ubyte4 tempLen;

            status = ERR_INVALID_INPUT;
            if (PQC_SER_OCTET_STR_TAG != *pDataPtr)  /* 0x04 octet string */
                goto exit;

            pDataPtr++;
            if (PQC_SER_TWO_BYTE_LEN_TAG != *pDataPtr) /* 0x82 two byte length tag */
                goto exit;

            pDataPtr++;
            tempLen = ((ubyte4)(*pDataPtr)) << 8;
            pDataPtr++;
            tempLen |= (ubyte4) (*pDataPtr);
            pDataPtr++;

            if (tempLen != expPrivLen)
                goto exit;

            status = DIGI_MALLOC_MEMCPY((void **) &ctx->privKey, privKeyLen, (void *) pDataPtr, privKeyLen);
            if (OK != status)
                goto exit;

            ctx->privKeyLen = expPrivLen;
            (void) DIGI_MEMSET(ctx->privKeySeed, 0x00, MLDSA_SEED_LEN); /* can't recover the seed */

            /* set the public key too if there was one */
            if (pubKeyLen > 0)
            {
                status = MLDSA_setPublicKey(pPubKeyPtr, pubKeyLen, ctx);
            }
        }
        else if (expPrivLen + MLDSA_SEED_LEN + 10 == privKeyLen) /* both format, 3 tags and 7 len bytes account for the extra 10 */
        {
            ubyte4 tempLen;
            ubyte *pSeedPtr;

            status = ERR_INVALID_INPUT;
            if (PQC_SER_SEQ_TAG != *pDataPtr) /* 0x30 sequence tag */
                goto exit;

            pDataPtr++;
            if (PQC_SER_TWO_BYTE_LEN_TAG != *pDataPtr) /* 0x82 two byte length tag */
                goto exit;

            pDataPtr++;
            tempLen = ((ubyte4)(*pDataPtr)) << 8;
            pDataPtr++;
            tempLen |= (ubyte4) (*pDataPtr);
            pDataPtr++;

            if (expPrivLen + MLDSA_SEED_LEN + 6 != tempLen) /* 2 tags and 4 len bytes */
                goto exit;

            if (PQC_SER_OCTET_STR_TAG != *pDataPtr) /* 0x04 octet string */
                goto exit;

            pDataPtr++;
            if ((ubyte) MLDSA_SEED_LEN != *pDataPtr)
                goto exit;
            
            pDataPtr++;
            
            /* We are at the seed, and will set the private key from that, but first validate the rest of the serialization */
            pSeedPtr = pDataPtr;
            pDataPtr += MLDSA_SEED_LEN;

            if (PQC_SER_OCTET_STR_TAG != *pDataPtr) /* 0x04 octet string */
                goto exit;

            pDataPtr++;
            if (PQC_SER_TWO_BYTE_LEN_TAG != *pDataPtr) /* 0x82 two byte length tag */
                goto exit;

            pDataPtr++;
            tempLen = ((ubyte4)(*pDataPtr)) << 8;
            pDataPtr++;
            tempLen |= (ubyte4) (*pDataPtr);

            if (expPrivLen != tempLen)
                goto exit;

            status = MLDSA_setPrivateKey(pSeedPtr, MLDSA_SEED_LEN, ctx); /* we don't validate the seed matches the priv */
        }
#endif
        else
        {
            status = ERR_INVALID_INPUT;
        }
    }
    else if (pubKeyLen > 0)
    {
        status = MLDSA_setPublicKey(pPubKeyPtr, pubKeyLen, ctx);
    }

exit:

    return status;
}
/* ------------------------------------------------------------------- */

MOC_EXTERN MSTATUS SLHDSA_serializeKeyAlloc(SLHDSACtx *ctx, bool pubOnly, uint8_t **serKey, size_t *serKeyLen)
{
    if (ctx == NULL || serKey == NULL || serKeyLen == NULL) {
        return ERR_NULL_POINTER;
    }

    if (ctx->pubKey == NULL) {
        return ERR_UNINITIALIZED_CONTEXT;
    }

    if (*serKey != NULL) {
        return ERR_INVALID_INPUT;
    }

    return SLHDSA_serialize(ctx, pubOnly, serKey, serKeyLen);
}

/* ------------------------------------------------------------------- */

/* Note this API expects we already allocated the SlhdsaKey for the proper size
   Future, we could make this an allocKey API and work for any enabled size */
MOC_EXTERN MSTATUS SLHDSA_deserializeKey(SLHDSACtx *ctx, bool pubOnly, uint8_t *serKey, size_t serKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pDataPtr = NULL;
    ubyte *pPub = NULL;
    ubyte *pPriv = NULL;
    byteBoolean isPrivate = FALSE;
    ubyte4 keyLen = 0;

    if (ctx == NULL || serKey == NULL)
        goto exit;

    if (ctx->pubKey != NULL || ctx->privKey != NULL) {
        return ERR_PREVIOUSLY_EXISTING_ITEM;
    }

    /* validate the public keyLen */
    keyLen = ((ubyte4) serKey[0] << 24) | ((ubyte4) serKey[1] << 16) |
             ((ubyte4) serKey[2] << 8) | (ubyte4) serKey[3];

    if (keyLen > 0)
    {
        /* validate the length, private serialization contains both keys and two 4 byte lengths */
        if (keyLen != (ubyte4) SLHDSA_getPubKeyLen(ctx->type))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* Is there also a private key */
        if (serKeyLen > keyLen + 8) /* if bigger than just a public key assume it's private, validate later... */
        {
            isPrivate = TRUE;
        }
    }
    else
    {
        isPrivate = TRUE;
    }

    pDataPtr = serKey + 4;
    if (keyLen > 0)
    {
        status = DIGI_MALLOC_MEMCPY((void **) &pPub, keyLen, (void *) pDataPtr, keyLen);
        if (OK != status)
            goto exit;

        ctx->pubKeyLen = keyLen;
        ctx->pubKey = pPub; pPub = NULL;
    }

    if (isPrivate && !pubOnly)
    {
        /* skip over to the private key, we don't validate the pub and pri match */
        pDataPtr += keyLen;

        /* validate the private key len */
        keyLen = ((ubyte4) pDataPtr[0] << 24) | ((ubyte4) pDataPtr[1] << 16) |
                 ((ubyte4) pDataPtr[2] << 8) | (ubyte4) pDataPtr[3];
        pDataPtr += 4;

        if (keyLen != SLHDSA_getPrivKeyLen(ctx->type)) 
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* copy the private key */
        status = DIGI_MALLOC_MEMCPY((void **) &pPriv, keyLen, (void *) pDataPtr, keyLen);
        if (OK != status)
            goto exit;

        ctx->privKey = pPriv; pPriv = NULL;
        ctx->privKeyLen = keyLen;
    }

exit:

    if (NULL != pPriv)
    {
        (void) DIGI_MEMSET_FREE(&pPriv, ctx->privKeyLen);
    }

    if (NULL != pPub)
    {
        (void) DIGI_MEMSET_FREE(&pPub, ctx->pubKeyLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC_SIG__ */
