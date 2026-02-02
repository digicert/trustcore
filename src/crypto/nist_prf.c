/*
 * nist_prf.c
 *
 * PRF used by NIST 800 108 implementation of KDF
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"

#ifndef __DISABLE_DIGICERT_SHA256__
#include "../crypto/sha256.h"
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
#include "../crypto/sha512.h"
#endif

#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/aes.h"
#include "../crypto/aes_cmac.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_hmac.h"
#include "../crypto_interface/crypto_interface_aes_cmac.h"
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#endif
#include "../harness/harness.h"
#include "../crypto/nist_prf.h"


/*---------------------------------------------------------------------*/

static MSTATUS
NIST_PRF_HmacOutputSize(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx,
                           ubyte4 * size)
{

    if (!size || !ctx)
    {
        return ERR_NULL_POINTER;
    }
    /* figure out the bulk hash algo underneath */

    /* CRYPTO_INTERFACE_HmacCreate does set the pBHalgo so this should work in all cases */
    *size = ((HMAC_CTX*)ctx)->pBHAlgo->digestSize;
    return OK;
}


/*---------------------------------------------------------------------*/

static MSTATUS
NIST_PRF_HmacUpdate(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx,
                    const ubyte *data, ubyte4 dataLen)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_HmacUpdate(MOC_HASH(hwAccelCtx) (HMAC_CTX*) ctx, data, dataLen);
#else
    return HmacUpdate(MOC_HASH(hwAccelCtx) (HMAC_CTX*) ctx, data, dataLen);
#endif
}


/*---------------------------------------------------------------------*/

static MSTATUS
NIST_PRF_HmacFinal(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx,
                    ubyte* result)
{
    MSTATUS status;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > ( status = CRYPTO_INTERFACE_HmacFinal(MOC_HASH(hwAccelCtx) (HMAC_CTX*) ctx, result)))
#else
    if (OK > ( status = HmacFinal(MOC_HASH(hwAccelCtx) (HMAC_CTX*) ctx, result)))
#endif
    {
        return status;
    }
    /* also do a reset so that client can redo a PRF */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_HmacReset(MOC_HASH(hwAccelCtx) (HMAC_CTX*) ctx);
#else
    return HmacReset(MOC_HASH(hwAccelCtx) (HMAC_CTX*) ctx);
#endif
}


/*---------------------------------------------------------------------*/

MOC_EXTERN_DATA_DEF const PRF_NIST_108 NIST_PRF_Hmac =
{
    NIST_PRF_HmacOutputSize,
    NIST_PRF_HmacUpdate,
    NIST_PRF_HmacFinal
};

/*---------------------------------------------------------------------*/

#if (!defined(__DISABLE_AES_CMAC__))

static MSTATUS
NIST_PRF_AesCmacOutputSize(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx,
                           ubyte4 * size)
{
    MOC_UNUSED(ctx);
    
    if (!size)
    {
        return ERR_NULL_POINTER;
    }
    *size = CMAC_RESULT_SIZE;
    return OK;
}

/*---------------------------------------------------------------------*/

static MSTATUS
NIST_PRF_AesCmacUpdate(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx,
                    const ubyte *data, ubyte4 dataLen)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_AESCMAC_update(MOC_SYM(hwAccelCtx) data, dataLen,
                                           (AESCMAC_Ctx*) ctx);
#else
    return AESCMAC_update(MOC_SYM(hwAccelCtx) data, dataLen,
                            (AESCMAC_Ctx*) ctx);
#endif
}

/*---------------------------------------------------------------------*/

static MSTATUS
NIST_PRF_AesCmacFinal(MOC_SYM(hwAccelDescr hwAccelCtx) void *ctx,
                    ubyte* result)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_AESCMAC_finalAndReset(MOC_SYM(hwAccelCtx) result, (AESCMAC_Ctx*) ctx);
#else
    /* not resetting the context severly limits the use of NKDF with CMAC. 
       When we get a chance to modify FIPS boundary we can also update this 
       to an API that will finalize and reset */
    return AESCMAC_final(MOC_SYM(hwAccelCtx) result,
                         (AESCMAC_Ctx*) ctx);
#endif
}

/*---------------------------------------------------------------------*/

const PRF_NIST_108 NIST_PRF_AesCmac =
{
    NIST_PRF_AesCmacOutputSize,
    NIST_PRF_AesCmacUpdate,
    NIST_PRF_AesCmacFinal
};

#endif /* if (!defined(__DISABLE_AES_CMAC__)) */
