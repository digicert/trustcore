/*
 * smp_nanoroot_device_protect.c
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

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__))

#include "smp_nanoroot_device_protect.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"

#include "crypto/hw_accel.h"
#include "crypto/crypto.h"

#include "crypto/hmac_kdf.h"
#include "crypto_interface/crypto_interface_hmac_kdf.h"

#include "crypto/aes.h"
#include "crypto_interface/crypto_interface_aes.h"

#include "crypto/aes_ctr.h"
#include "crypto_interface/crypto_interface_aes_ctr.h"

#include "crypto/chacha20.h"
#include "crypto_interface/crypto_interface_chacha20.h"

#include "crypto/md5.h"
#include "crypto_interface/crypto_interface_md5.h"

#include "crypto/sha1.h"
#include "crypto_interface/crypto_interface_sha1.h"

#include "crypto/sha256.h"
#include "crypto_interface/crypto_interface_sha256.h"

#include "crypto/sha512.h"
#include "crypto_interface/crypto_interface_sha512.h"

#include "crypto/hmac.h"
#include "crypto_interface/crypto_interface_hmac.h"

#include "crypto/poly1305.h"
#include "crypto_interface/crypto_interface_poly1305.h"

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
/* no crypto interface implemenation yet for nist_kdf or ansix9_63_kdf or blake2 */
#include "crypto/nist_prf.h"
#include "crypto/nist_kdf.h"
#include "crypto/ansix9_63_kdf.h"
#include "crypto/blake2.h"
#include "crypto_interface/crypto_interface_blake2.h"

#endif

#define NanoROOTCTX_UNINITIALIZED 0
#define NanoROOTCTX_INITIALIZED   1
#define NanoROOTCTX_PROTECT_READY 2

static MSTATUS NanoROOTapplyKDF(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte kdfAlgo, const ubyte *pLabel, ubyte4 labelLen,
                                const ubyte *pValue, ubyte4 valueLen, ubyte *pRunningSeed, ubyte4 seedLen)
{
    MSTATUS status;
    const BulkHashAlgo *pBHA;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    HMAC_CTX *pHmacCtx = NULL;
#endif
    ubyte pPseudoKey[NanoROOTMAX_SEED_LEN] = {0};

    /* internal method, NULL checks already done */

    status = CRYPTO_getRSAHashAlgo(ht_sha256, &pBHA);
    if (OK != status)
        goto exit;

    switch (kdfAlgo)
    {
        case NanoROOTKDF_NIST_CTR:
        case NanoROOTKDF_NIST_FB:
        case NanoROOTKDF_NIST_DP:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
            status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#else
            status = CRYPTO_INTERFACE_HmacCreate(MOC_HASH(hwAccelCtx) &pHmacCtx, pBHA);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_HmacKey(MOC_HASH(hwAccelCtx) pHmacCtx, pRunningSeed, NanoROOTMAX_SEED_LEN);
            if (OK != status)
                goto exit;

            if (NanoROOTKDF_NIST_CTR == kdfAlgo)
                status = KDF_NIST_CounterMode(MOC_SYM(hwAccelCtx) 4, pHmacCtx, &NIST_PRF_Hmac, pLabel, labelLen,
                                                pValue, valueLen, 4, 1, pRunningSeed, seedLen);
            else if (NanoROOTKDF_NIST_FB == kdfAlgo)
                status = KDF_NIST_FeedbackMode(MOC_SYM(hwAccelCtx) 4, pHmacCtx, &NIST_PRF_Hmac, NULL, 0, pLabel,
                                                labelLen, pValue, valueLen, 4, 1, pRunningSeed, seedLen);
            else /* NanoROOTKDF_NIST_DP == kdfAlgo */
                status = KDF_NIST_DoublePipelineMode(MOC_SYM(hwAccelCtx) 4, pHmacCtx, &NIST_PRF_Hmac, pLabel, labelLen,
                                                pValue, valueLen, 4, 1, pRunningSeed, seedLen);
#endif
            break;

        case NanoROOTKDF_HMAC:

            status = CRYPTO_INTERFACE_HmacKdfExtract(MOC_HASH(hwAccelCtx) pBHA, (ubyte *) pValue, valueLen,
                                (ubyte *) pRunningSeed, NanoROOTMAX_SEED_LEN, pPseudoKey, NanoROOTMAX_SEED_LEN);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_HmacKdfExpand(MOC_HASH(hwAccelCtx) pBHA, pPseudoKey, NanoROOTMAX_SEED_LEN,
                                (ubyte *) pLabel, labelLen, NULL, 0, pRunningSeed, seedLen);

            /* zero out the pseudo key, ok to ignore return code */
            DIGI_MEMSET(pPseudoKey, 0x00, NanoROOTMAX_SEED_LEN);

            break;

        case NanoROOTKDF_ANSI_X963:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
            status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#else
            status = ANSIX963KDF_generate(MOC_HASH(hwAccelCtx) pBHA, pRunningSeed, NanoROOTMAX_SEED_LEN,
                                            pValue, valueLen, seedLen, pRunningSeed);
#endif
            break;

        default:
            status = ERR_TDP_INVALID_KDF_ALGO;
            break;
    }

exit:

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    if (NULL != pHmacCtx)
    {
        MSTATUS fstatus = CRYPTO_INTERFACE_HmacDelete(MOC_HASH(hwAccelCtx) &pHmacCtx);
        if (OK == status)
            status = fstatus;
    }
#endif

    return status;
}


static MSTATUS NanoROOTapplySymAlg(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte symAlgo, ubyte *pKeyMaterial,
                                    ubyte *pData, ubyte4 dataLen, ubyte4 *pOutLen, byteBoolean encrypt)
{
    MSTATUS status = ERR_TDP_INVALID_DATA_LEN;
    MSTATUS fstatus = OK;
    BulkCtx pCtx = NULL;
    ubyte4 keyLen = 0;
    ubyte pIv[16] = {0}; /* mutable copy for AES-CBC */

    /* internal API, NULL checks not needed. dataLen checked below based on symAlgo */

    switch (symAlgo)
    {
        case NanoROOTAES_128_CTR:

            keyLen = 32;  /* 16 byte key and 16 byte initial nonce and ctr */
            /* fall through */

        case NanoROOTAES_192_CTR:

            if (!keyLen)
                keyLen = 40; /* 24 byte key and 16 byte initial nonce and ctr */
            /* fall through */

        case NanoROOTAES_256_CTR:

            if (!keyLen)
                keyLen = 48; /* 32 byte key and 16 byte initial nonce and ctr */
            /* fall through */

            if (!dataLen)  /* only restriction for AES-CTR is non-zero */
                goto exit;

            status = ERR_TDP;
            pCtx = CRYPTO_INTERFACE_CreateAESCTRCtx(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLen, encrypt);
            if (NULL == pCtx)
                goto exit;

            /*
             use the next 16 bytes of pKey as the IV
             (NOTE: this overwrites the IV part of the key material passed in above)
             */
            status = CRYPTO_INTERFACE_DoAESCTR(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pKeyMaterial + keyLen);
            *pOutLen = dataLen;

            /* delete the ctx regardless of status */
            fstatus = CRYPTO_INTERFACE_DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) &pCtx);
            if (OK == status)
                status = fstatus;

            break;

        case NanoROOTAES_128_CBC:

            keyLen = 16;  /* 16 byte key */
            /* fall through */

        case NanoROOTAES_192_CBC:

            if (!keyLen)
                keyLen = 24; /* 24 byte key */
            /* fall through */

        case NanoROOTAES_256_CBC:

            if (!keyLen)
                keyLen = 32; /* 32 byte key */
            /* fall through */

            /* cbc requires dataLen to be a multiple of the AES block size of 16 */
            if (!dataLen || dataLen & 0x0f) /* 0 != dataLen mod 16 */
                goto exit;

            status = ERR_TDP;
            pCtx = CRYPTO_INTERFACE_CreateAESCtx(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLen, encrypt);
            if (NULL == pCtx)
                goto exit;

            /* make a mutable copy of the iv*/
            DIGI_MEMCPY(pIv, pKeyMaterial + keyLen, 16);

            status = CRYPTO_INTERFACE_DoAES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pIv);
            *pOutLen = dataLen;

            /* zero the mutable copy of the pIv */
            DIGI_MEMSET(pIv, 0x00, 16);

            /* delete the ctx regardless of status */
            fstatus = CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(hwAccelCtx) &pCtx);
            if (OK == status)
                status = fstatus;

            break;
#ifdef __ENABLE_DIGICERT_CHACHA20__
        case NanoROOTCHACHA20:

            /* chacha20 keys contain a 16 byte AES key, a 16 byte nonce, and 16 byte r */
            status = ERR_TDP;
            pCtx = CRYPTO_INTERFACE_CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) (const ubyte *) pKeyMaterial, 48, encrypt);
            if (NULL == pCtx)
                goto exit;

            status = CRYPTO_INTERFACE_DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, NULL);
            *pOutLen = dataLen;

            /* delete the ctx regardless of status */
            fstatus = CRYPTO_INTERFACE_DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) &pCtx);
            if (OK == status)
                status = fstatus;

            break;
#endif
        default:

            status = ERR_TDP_INVALID_SYM_ALGO;
            break;
    }

exit:

    return status;
}


MSTATUS NanoROOT_initFingerprintCtx(NROOT_FP_CTX **ppCtx, ubyte4 numUses, ubyte additionalProtectionMode)
{
    MSTATUS status = OK;
    byteBoolean reusableKey = FALSE;
    hwAccelDescr hwAccelCtx = 0;

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)

    /* initialize and get the hwAccelDesc */
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
        goto exit;

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_DEVICE_PROTECT, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    MOC_UNUSED(additionalProtectionMode);

    if (NULL == ppCtx)
        return ERR_NULL_POINTER;

    if (numUses > NanoROOTMAX_NUM_USES)
        return ERR_TDP_INVALID_NUM_USES;

    if (NanoROOTSINGLE_REUSABLE_KEY == numUses)
    {
        numUses = 1;
        reusableKey = TRUE;
    }

    /* allocate all the memory we'll need in a single shot */
    status = DIGI_CALLOC((void **) ppCtx, 1, sizeof(_NROOT_FP_CTX) + NanoROOTMAX_SEED_LEN * numUses);
    if (OK != status)
        goto exit;

    (*ppCtx)->pKeyMaterial = (*ppCtx)->pRunningSeed = ((ubyte *) (*ppCtx)) + sizeof(_NROOT_FP_CTX);
    (*ppCtx)->numUses = numUses;
    (*ppCtx)->state = NanoROOTCTX_INITIALIZED;
    (*ppCtx)->reusableKey = reusableKey;
    (*ppCtx)->hwAccelCtx = hwAccelCtx;
    /* usesSoFar is already zero via the CALLOC */

exit:

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
    if(OK != status)
    {
        (void) HARDWARE_ACCEL_UNINIT();

        if(ppCtx && *ppCtx)
        {
            (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_DEVICE_PROTECT, &(*ppCtx)->hwAccelCtx);
        }
    }
#endif
    return status;
}


MSTATUS NanoROOT_FingerprintDevice(NROOT_FP_CTX *pCtx, ubyte kdfAlgo, NROOTKdfElement *pElements, ubyte4 numElements,
                                         ubyte *pInitialSeed, ubyte4 initialSeedLen, void *pAdditionalProtection)
{
    MSTATUS status = OK;
    ubyte4 labelLen = 0;
    ubyte4 seedLen = NanoROOTMAX_SEED_LEN; /* 64 */
    ubyte4 i = 0;

    MOC_UNUSED(pAdditionalProtection);

    if (NULL == pCtx || NULL == pElements || NULL == pInitialSeed)
        return ERR_NULL_POINTER;

    if (NanoROOTCTX_INITIALIZED != pCtx->state)
        return ERR_TDP_UNINITIALIZED_CTX;

    if (kdfAlgo > NanoROOTKDF_ANSI_X963)
        return ERR_TDP_INVALID_KDF_ALGO;

    if (!numElements)
        return ERR_TDP_INVALID_NUM_FP_ELEMENTS;

    if (initialSeedLen > NanoROOTMAX_SEED_LEN || initialSeedLen < NanoROOTMIN_SEED_LEN)
        return ERR_TDP_INVALID_SEED_LEN;

    /* begin with the initial seed, which is zero padded on the right via init */
    status = DIGI_MEMCPY(pCtx->pRunningSeed, pInitialSeed, initialSeedLen);
    if (OK != status)
        goto exit;

    for (; i < numElements; ++i)
    {
        if (pElements[i].valueLen > NanoROOT_MAX_VALUE_LEN)
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        /* if last element, we'll generate pCtx->numUses * NanoROOTMAX_SEED_LEN bytes of key material */
        if ( i == (numElements - 1) )
            seedLen = pCtx->numUses * NanoROOTMAX_SEED_LEN;

        labelLen = DIGI_STRLEN((const sbyte *) pElements[i].pLabel);

        status = NanoROOTapplyKDF(MOC_HASH(pCtx->hwAccelCtx) kdfAlgo, (const ubyte *) pElements[i].pLabel,
                                 labelLen, (const ubyte *) pElements[i].pValue, pElements[i].valueLen,
                                 pCtx->pRunningSeed, seedLen);
        if (OK != status)
            goto exit;
    }

    pCtx->state = NanoROOTCTX_PROTECT_READY;

exit:

    if (OK != status)  /* zero the running seed, rest of pCtx can remain unchanged */
        DIGI_MEMSET((ubyte *) pCtx->pRunningSeed, 0x00, pCtx->numUses * NanoROOTMAX_SEED_LEN);  /* here on error only, ignore return code */

    return status;
}


MSTATUS NanoROOT_Encrypt(NROOT_FP_CTX *pCtx, ubyte symAlgo, ubyte *pCredData, ubyte4 credLen,
            ubyte *pDataIn, ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pOutLen)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte keyData[NanoROOTMAX_SEED_LEN] = {0};

    if (NULL == pCtx || NULL == pDataIn || NULL == pDataOut || NULL == pOutLen)
        return ERR_NULL_POINTER;

    if(dataLen > *pOutLen)
    {
        return ERR_BUFFER_OVERFLOW;
    }
    *pOutLen = 0;

    if (NanoROOTCTX_PROTECT_READY != pCtx->state)
        return ERR_TDP_CTX_NOT_READY;

    if (symAlgo > NanoROOTCHACHA20)
        return ERR_TDP_INVALID_SYM_ALGO;

    if (!pCtx->reusableKey && (pCtx->usesSoFar >= pCtx->numUses))
        return ERR_TDP_NUM_USES_EXCEEDED;

    if (pDataIn != pDataOut)
    {
        /* not in-place, copy over to pDataOut which we'll encrypt in-place. ok to ignore return code */
        DIGI_MEMCPY(pDataOut, pDataIn, dataLen);
    }

    if(NULL != pCredData)
    {
        if(NanoROOTMAX_SEED_LEN != credLen)
        {
            return ERR_INTERNAL_ERROR;
        }
        for(i = 0; i < credLen; i++)
        {
            keyData[i] = pCtx->pKeyMaterial[i] ^ pCredData[i];
        }
        status = NanoROOTapplySymAlg(MOC_SYM(pCtx->hwAccelCtx) symAlgo, keyData, pDataOut, dataLen, pOutLen, TRUE);

        /* zero out the keyData, ok to ignore return code */
        DIGI_MEMSET(keyData, 0x00, NanoROOTMAX_SEED_LEN);
    }
    else
    {
        status = NanoROOTapplySymAlg(MOC_SYM(pCtx->hwAccelCtx) symAlgo, pCtx->pKeyMaterial, pDataOut, dataLen, pOutLen, TRUE);
    }

    if (!pCtx->reusableKey && OK == status)  /* move to the next key position and increment usesSoFar */
    {
        pCtx->pKeyMaterial += NanoROOTMAX_SEED_LEN;
        pCtx->usesSoFar++;
    }

    return status;
}


MSTATUS NanoROOT_Decrypt(NROOT_FP_CTX *pCtx, ubyte symAlgo, ubyte *pCredData, ubyte4 credLen,
                        ubyte *pDataIn, ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pOutLen)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte keyData[NanoROOTMAX_SEED_LEN] = {0};

    if (NULL == pCtx || NULL == pDataIn || NULL == pDataOut || NULL == pOutLen)
        return ERR_NULL_POINTER;

    if(dataLen > *pOutLen)
    {
        return ERR_INTERNAL_ERROR;
    }
    *pOutLen = 0;

    if (NanoROOTCTX_PROTECT_READY != pCtx->state)
        return ERR_TDP_CTX_NOT_READY;

    if (symAlgo > NanoROOTCHACHA20)
        return ERR_TDP_INVALID_SYM_ALGO;

    if (!pCtx->reusableKey && (pCtx->usesSoFar >= pCtx->numUses))
        return ERR_TDP_NUM_USES_EXCEEDED;

    if (pDataIn != pDataOut)
    {
        /* not in-place, copy over to pDataOut which we'll encrypt in-place. ok to ignore return code */
        DIGI_MEMCPY(pDataOut, pDataIn, dataLen);
    }

    if(NULL != pCredData)
    {
        if(NanoROOTMAX_SEED_LEN != credLen)
        {
            return ERR_INTERNAL_ERROR;
        }
        for(i = 0; i < credLen; i++)
        {
            keyData[i] = pCtx->pKeyMaterial[i] ^ pCredData[i];
        }
        status = NanoROOTapplySymAlg(MOC_SYM(pCtx->hwAccelCtx) symAlgo, keyData, pDataOut, dataLen, pOutLen, FALSE);

        /* zero out the keyData, ok to ignore return code */
        DIGI_MEMSET(keyData, 0x00, NanoROOTMAX_SEED_LEN);
    }
    else
    {
        status = NanoROOTapplySymAlg(MOC_SYM(pCtx->hwAccelCtx) symAlgo, pCtx->pKeyMaterial, pDataOut, dataLen, pOutLen, FALSE);
    }

    if (!pCtx->reusableKey && OK == status)  /* move to the next key position and increment usesSoFar */
    {
        pCtx->pKeyMaterial += NanoROOTMAX_SEED_LEN;
        pCtx->usesSoFar++;
    }

    return status;
}

MSTATUS NanoROOT_freeFingerprintCtx(NROOT_FP_CTX **ppCtx)
{
    MSTATUS status = OK, fstatus = OK;

    if (NULL == ppCtx)
        return ERR_NULL_POINTER;

    if (NULL == *ppCtx)
        return OK;

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
    /* initialize and get the hwAccelDesc */
    status = (MSTATUS) HARDWARE_ACCEL_UNINIT();

    fstatus = (MSTATUS) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_DEVICE_PROTECT, &(*ppCtx)->hwAccelCtx);
    if (OK == status)
        status = fstatus;
#endif

    /* ok to ignore DIGI_MEMSET return code */
    (void) DIGI_MEMSET((ubyte *) *ppCtx, 0x00, sizeof(_NROOT_FP_CTX) + NanoROOTMAX_SEED_LEN * ((*ppCtx)->numUses));

    fstatus = DIGI_FREE((void **) ppCtx);
    if (OK == status)
        status = fstatus;

    return status;
}

#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_SMP_NANOROOT__ */
