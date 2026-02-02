/*
 * aes_eax.c
 *
 * AES-EAX Implementation
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_EAX_INTERNAL__

#include "../common/moptions.h"

#ifndef __DISABLE_AES_EAX__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_eax.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#if (!defined(__DISABLE_AES_CIPHERS__))

#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*----------------------------------------------------------------------------*/

static MSTATUS
AES_EAX_initOMAC( MOC_SYM(hwAccelDescr hwAccelCtx) aesCipherContext* pAESCtx,
                 AES_OMAC_Ctx* pOMACCtx,
                 ubyte tweak)
{
    MSTATUS status;
    ubyte tweakBlock[AES_BLOCK_SIZE] = {0};

    if ( OK > ( status = AES_OMAC_init( pOMACCtx)))
        return status;

    tweakBlock[AES_BLOCK_SIZE-1] = tweak;

    return AES_OMAC_update( MOC_SYM(hwAccelCtx) pAESCtx, pOMACCtx, tweakBlock, AES_BLOCK_SIZE);
}


/*----------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_init(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial,
             ubyte4 keyLength, const ubyte* nonce, ubyte4 nonceLength,
             AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS         status;
    ubyte4 bufLen;
    AES_OMAC_Ctx    nonceOMAC;
    BulkCtx pCtrCtx = NULL;
    ubyte *pBuf = NULL;

    bufLen = 0;

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    	return ERR_AES_NO_AESNI_SUPPORT;
#endif

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,keyLength);

    status = ERR_NULL_POINTER;
    if ( !pCtx || !keyMaterial)
        goto exit;
    /* NOTE: nonce can be NULL */

    DIGI_MEMSET ((void *)pCtx, 0, sizeof (AES_EAX_Ctx));

    bufLen = keyLength + 16;
    status = DIGI_MALLOC ((void **)&pBuf, bufLen);
    if (OK != status)
        goto exit;

    DIGI_MEMCPY ((void *)pBuf, (void *)keyMaterial, keyLength);
    DIGI_MEMSET ((void *)(pBuf + keyLength), 0, 16);

    /* initialize the AES context */
    /* The CTR code requires the key + IV. We're going to change the IV later, so
     * for now the IV is irrelevant. We can simply pass in 00 ... 00.
     * But we need to pass it in as a single block.
     * We have only the key, so we had to build a new buffer.
     */
    status = ERR_AES;
    pCtrCtx = CreateAESCTRCtx (
      MOC_SYM(hwAccelCtx) pBuf, keyLength + 16, 1);
    if (NULL == pCtrCtx)
        goto exit;

    pCtx->pAesCTRCtx = (AES_CTR_Ctx *)pCtrCtx;

    /* do a complete OMAC with the nonce and tweak = 0 */
    if ( OK > ( status = AES_EAX_initOMAC( MOC_SYM(hwAccelCtx)
                              pCtx->pAesCTRCtx->pCtx, &nonceOMAC, 0)))
    {
        goto exit;
    }
    if ( nonce && nonceLength > 0)
    {
        if ( OK > ( status = AES_OMAC_update( MOC_SYM(hwAccelCtx)
                                            pCtx->pAesCTRCtx->pCtx,
                                            &nonceOMAC, nonce, nonceLength)))
        {
            goto exit;
        }
    }
    if ( OK > ( status = AES_OMAC_final( MOC_SYM(hwAccelCtx)
                                        pCtx->pAesCTRCtx->pCtx,
                                        &nonceOMAC, pCtx->N)))
    {
        goto exit;
    }

    /* use the result of the OMAC of the Nonce as the block for
    the AES Counter context */
    DIGI_MEMCPY( pCtx->pAesCTRCtx->u.counterBlock, pCtx->N, AES_BLOCK_SIZE);
    pCtx->pAesCTRCtx->offset = 0;
    /* at this point the Counter Ctx has been initialized */

    /* initialize the rest = headerOMAC and cipherOMAC */
    if ( OK > ( status = AES_EAX_initOMAC( MOC_SYM(hwAccelCtx)
                              pCtx->pAesCTRCtx->pCtx, &pCtx->headerOMAC, 1)))
    {
        goto exit;
    }

    if ( OK > ( status = AES_EAX_initOMAC( MOC_SYM(hwAccelCtx)
                              pCtx->pAesCTRCtx->pCtx, &pCtx->cipherOMAC, 2)))
    {
        goto exit;
    }
    /* we can now proceed header and messages as they come */

    pCtrCtx = NULL;

exit:

    if (NULL != pBuf)
    {
        DIGI_MEMSET ((void *)pBuf, 0, bufLen);
        DIGI_FREE ((void **)&pBuf);
    }
    if (NULL != pCtrCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) &pCtrCtx);
    }

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,keyLength);
    return status;
}

extern MSTATUS AES_EAX_clear(MOC_SYM(hwAccelDescr hwAccelCtx) AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK, fstatus;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    if (NULL != pCtx)
    {
        if (NULL != pCtx->pAesCTRCtx)
        {
            status = DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pAesCTRCtx));
        }

        fstatus = DIGI_MEMSET ((void *)pCtx, 0, sizeof (AES_EAX_Ctx));
        if (OK == status)
            status = fstatus;
    }

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_updateHeader(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* headerData,
                     sbyte4 dataLength, AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    if ( !headerData || !  pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    status = AES_OMAC_update( MOC_SYM(hwAccelCtx) pCtx->pAesCTRCtx->pCtx,
                            &pCtx->headerOMAC, headerData, dataLength);

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_getPlainText(  MOC_SYM(hwAccelDescr hwAccelCtx)
                        ubyte* cipherText, sbyte4 cipherLen,
                        AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    if ( !cipherText || !pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    status = DoAESCTR( MOC_SYM(hwAccelCtx) pCtx->pAesCTRCtx,
                        cipherText, cipherLen, 1, NULL);

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_encryptMessage(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* msgData,
                       sbyte4 msgLen, AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    if ( !msgData || !pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    if ( OK > (status = DoAESCTR( MOC_SYM(hwAccelCtx) pCtx->pAesCTRCtx,
                                    msgData, msgLen, 1, NULL)))
    {
        goto exit;
    }

    /* add the cipher to the OMAC */
    status = AES_OMAC_update(MOC_SYM(hwAccelCtx)
                           pCtx->pAesCTRCtx->pCtx, &pCtx->cipherOMAC,
                            msgData, msgLen);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_decryptMessage(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* msgData,
                       sbyte4 msgLen, AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    if ( !msgData || !pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    /* add the cipher to the OMAC */
    if ( OK > (status = AES_OMAC_update(MOC_SYM(hwAccelCtx)
                                        pCtx->pAesCTRCtx->pCtx, &pCtx->cipherOMAC,
                                        msgData, msgLen)))
    {
        goto exit;
    }

    status = DoAESCTR( MOC_SYM(hwAccelCtx) pCtx->pAesCTRCtx,
                    msgData, msgLen, 1, NULL);

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_final( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte tag[/*tagLen*/],
              sbyte4 tagLen, AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte omacRes[ CMAC_RESULT_SIZE];
    sbyte4 i;

    if (!tag || !pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    /* tag is the first tagLen byte of
        OMAC(nonce) ^ OMAC(cipher) ^ OMAC(header) */

    if ( tagLen > AES_BLOCK_SIZE || tagLen < 0)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* complete the two OMAC */
    if ( OK > ( status = AES_OMAC_final( MOC_SYM(hwAccelCtx)
                                        pCtx->pAesCTRCtx->pCtx,
                                        &pCtx->cipherOMAC,
                                        omacRes)))
    {
        goto exit;
    }
    for ( i = 0; i < tagLen; ++i)
    {
        tag[i] = (omacRes[i] ^ (pCtx->N[i]));
    }
    if ( OK > ( status = AES_OMAC_final( MOC_SYM(hwAccelCtx)
                                        pCtx->pAesCTRCtx->pCtx,
                                        &pCtx->headerOMAC,
                                        omacRes)))
    {
        goto exit;
    }

    for ( i = 0; i < tagLen; ++i)
    {
        tag[i] ^= omacRes[i];
    }

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_EAX_generateTag( MOC_SYM(hwAccelDescr hwAccelCtx)
                   const ubyte* cipherText, sbyte4 cipherLen,
                   const ubyte* header, sbyte4 headerLen,
                   ubyte tag[/*tagLen*/], sbyte4 tagLen,
                   AES_EAX_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte omacRes[ CMAC_RESULT_SIZE];
    sbyte4 i;

    if (!cipherText || !tag || !pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_EAX,0);

    /* header can be NULL */

    /* tag is the first tagLen byte of
        OMAC(nonce) ^ OMAC(cipher) ^ OMAC(header) */
    if ( tagLen > AES_BLOCK_SIZE || tagLen < 0)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* do the two complete OMAC operation */
    if ( OK > ( status = AES_OMAC_update( MOC_SYM(hwAccelCtx)
                                            pCtx->pAesCTRCtx->pCtx,
                                            &pCtx->cipherOMAC,
                                            cipherText, cipherLen)))
    {
        goto exit;
    }

    if ( OK > ( status = AES_OMAC_final( MOC_SYM(hwAccelCtx)
                                        pCtx->pAesCTRCtx->pCtx,
                                        &pCtx->cipherOMAC,
                                        omacRes)))
    {
        goto exit;
    }
    for ( i = 0; i < tagLen; ++i)
    {
        tag[i] = (omacRes[i] ^ (pCtx->N[i]));
    }

    if ( header)
    {
        if ( OK > ( status = AES_OMAC_update( MOC_SYM(hwAccelCtx)
                                            pCtx->pAesCTRCtx->pCtx,
                                            &pCtx->headerOMAC,
                                            header, headerLen)))
        {
            goto exit;
        }

        if ( OK > ( status = AES_OMAC_final( MOC_SYM(hwAccelCtx)
                                        pCtx->pAesCTRCtx->pCtx,
                                        &pCtx->headerOMAC,
                                        omacRes)))
        {
            goto exit;
        }

        for ( i = 0; i < tagLen; ++i)
        {
            tag[i] ^= omacRes[i];
        }
    }

exit:
    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_EAX,0);
    return status;
}


#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
#endif /* ifndef __DISABLE_AES_EAX__ */
