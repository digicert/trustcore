/*
 * ios_sync.c
 *
 * iOS Core Crypto Synchronous Adapter
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

#include "../../common/moptions.h"


#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_IOS_CORECRYPTO_HARDWARE_ACCEL__))



#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/merrors.h"
#include "../../common/int64.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md45.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/aes.h"

#include "../../harness/harness.h"


#ifdef __SHA1_HARDWARE_HASH__

/*------------------------------------------------------------------*/

extern MSTATUS SHA1_initDigest(shaDescr *p_shaContext)
{
    MSTATUS status;
    status = OK;
    if (CC_SHA1_Init(&(p_shaContext->c)))
        status = OK;
    else status = ERR_GENERAL; 
    
exit:
    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_ALLOC(hwAccelCtx, sizeof(shaDescr), TRUE, pp_context);
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return CRYPTO_FREE(hwAccelCtx, TRUE, pp_context);
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status;
    status = OK;
    
    CC_SHA1(pData, dataLen, pShaOutput);
    
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_updateDigest(shaDescr *p_shaContext,
                  const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status;
    status = OK;
    
    if(!(CC_SHA1_Update(&(p_shaContext->c), pData, dataLen)))
        status = ERR_GENERAL;
    
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_finalDigest(shaDescr *p_shaContext, ubyte *pOutput)
{
    MSTATUS status;
    status = OK;
    
    if(!(CC_SHA1_Final(pOutput, &(p_shaContext->c))))
        status = ERR_GENERAL;
    
exit:
    return status;
    
}

#endif /* __SHA1_HARDWARE_HASH__ */

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))

/*------------------------------------------------------------------*/
/*xts mode*/



MOC_EXTERN BulkCtx
CreateAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial,
                sbyte4 keyLength, sbyte4 encrypt)
{
    iosCryptorDescr * pCtx;
    
    
    pCtx = NULL;
    if (NULL == (pCtx = MALLOC(sizeof(iosCryptorDescr))))
        goto exit;
    
    DIGI_MEMSET(pCtx, 0, sizeof(iosCryptorDescr) );
    DIGI_MEMCPY(pCtx->pKeyMaterial[0], keyMaterial, keyLength);
    pCtx->encrypt = encrypt;
    
exit:
    return pCtx;
    
    
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DeleteAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }
    return OK;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DoAESXTS(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
         sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;
    iosCryptorDescr *pTempDescr;
    CCOperation op;
    CCCryptorStatus ccStatus;
    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    pTempDescr = (iosCryptorDescr *) ctx;
    
    if (encrypt) {
        op = kCCEncrypt;
    }
    else
        op = kCCDecrypt;
    
    /*we know it is the first time calling this*/
    if(0 == pTempDescr->tweakLength)
    {
        pTempDescr->tweakLength = MAX_TWEAK_LENGTH;
        DIGI_MEMCPY((void *)pTempDescr->pTweak, iv, MAX_TWEAK_LENGTH);
        
        
        CCCryptorCreateWithMode(op, kCCModeXTS, kCCAlgorithmAES128, ccNoPadding, NULL /* iv */, pTempDescr->pKeyMaterial, pTempDescr->keyLength, pTempDescr->pTweak, pTempDescr->tweakLength, 0 /* rounds 0 = default */, 0 /* options */, &(pTempDescr->cccRef));
        
        
    }
    CCCryptorEncryptDataBlock(pTempDescr->cccRef, NULL /* no iv - only tweak */, data, dataLength, data);
    //ccStatus = CCCryptorUpdate( 
    
    
    
exit:
    return status;
}

/*------------------------------------------------------------------*/
/*CBC mode with PKCS7 style padding*/
extern BulkCtx
CreateAESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    
    
    
}

/*------------------------------------------------------------------*/

#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))*/

#endif

