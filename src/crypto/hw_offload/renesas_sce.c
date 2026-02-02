/*
 * renesas_sce.c
 *
 * Renaissance Hardware Acceleration
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
#if (defined(__ENABLE_SYNERGY_HARDWARE_ACCEL__) && defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__))
#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/mocana.h"
#include "common/merrors.h"
#include "common/mstdlib.h"
#include "crypto/hw_accel.h"
#include "common/int64.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "renesas_sce.h"


static volatile int cryptoInit = 0;

crypto_ctrl_t crypto_ctrl;
crypto_cfg_t crypto_cfg;

/*
 * Originally intended for convering ubyte array to ubyte4 array for SHA,
 * this function adds padding to SHA blocks which are not multples of 4, and
 * returns the amount of pdding added in the pRetPaddingAdded param. It can
 * also be used in general to convert a ubyte array to a ubyte4 array
 */
void byteArrayToWordArray(const ubyte* source, ubyte4* dest, ubyte4 byteCount, ubyte* pRetPaddedAdded)
{
    ubyte4 i = 0;
    if (NULL != pRetPaddedAdded)
        *pRetPaddedAdded = 0;
    ubyte* curWord = source;
    ubyte4 wordCount = byteCount / 4; //swap in place?
    for (i = 0; i < wordCount; i++)
    {
        dest[i] = ((ubyte4) (*curWord++) << 24);
        dest[i] |= ((ubyte4) (*curWord++) << 16);
        dest[i] |= ((ubyte4) (*curWord++) << 8);
        dest[i] |= ((ubyte4) (*curWord++));
    }
    /* if the bytes won't make a complete word, start padding them */
    if (byteCount % 4)
    {
        if (1 == (byteCount % 4))
        {
            dest[wordCount] = ((ubyte4) (*curWord++) << 24);
            dest[wordCount] |= ((ubyte4) (0x800000));
            if (NULL != pRetPaddedAdded)
                *pRetPaddedAdded = 3;
        }
        else if (2 == byteCount % 4)
        {
            dest[wordCount] = ((ubyte4) (*curWord++) << 24);
            dest[wordCount] |= ((ubyte4) (*curWord++) << 16);
            dest[wordCount] |= ((ubyte8) (0x8000));
            if (NULL != pRetPaddedAdded)
                *pRetPaddedAdded = 2;
        }
        else
        {
            dest[wordCount] = ((ubyte4) (*curWord++) << 24);
            dest[wordCount] |= ((ubyte4) (*curWord++) << 16);
            dest[wordCount] |= ((ubyte4) (*curWord++) << 8);
            dest[wordCount] |= ((ubyte4) (0x80));
            if (NULL != pRetPaddedAdded)
                *pRetPaddedAdded = 1;
        }
    }
}

/* Initialize the SCE module */
void ssp_crypto_initialize(void)
{
    ssp_err_t iret;

    /* nothing to configure for SCE driver */
    DIGI_MEMSET((ubyte*)&crypto_cfg, 0, sizeof(crypto_cfg));

    iret = g_sce_crypto_api.open (&crypto_ctrl, &crypto_cfg);
    if (iret != SSP_SUCCESS)
    {
        while (1)
        {
        }
    }
    cryptoInit = 1;
}


/**
 * Initialization is done automatically in generated code
 * @return
 */
extern sbyte4 SYNERGY_init(void)
{
    return OK;
}
extern sbyte4 SYNERGY_uninit(void)
{
    return OK;
}

/**
 * Open channels to SHA1 and SHA256. We don't open channels to all the AES
 * contexts because we share the control and config structures between them
 * during AES operations, and so we open and close them individually when
 * we use them.
 */
extern sbyte4 SYNERGY_openChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie)
{
    MOC_UNUSED(moduleId);
    MOC_UNUSED(pHwAccelCookie);

    if (!cryptoInit)
    {
        ssp_crypto_initialize ();
        ssp_err_t iret;
        iret = g_sha1_hash_on_sce.open (&sha1_ctrl, &sha1_cfg);
        if (iret != SSP_SUCCESS)
        {
            return ERR_GENERAL;
        }
        iret = g_sha256_hash_on_sce.open (&sha256_ctrl, &sha256_cfg);
        if (iret != SSP_SUCCESS)
        {
            return ERR_GENERAL;
        }
    }
    return OK;
}

extern sbyte4 SYNERGY_closeChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie)
{
    MOC_UNUSED(moduleId);
    MOC_UNUSED(pHwAccelCookie);
    g_sce_crypto_api.close (&crypto_ctrl);
    return OK;
}

/***************************************/
/*********** SHA 1 HW ******************/
/***************************************/

uint32_t sha1InitialValue[5] = /* sha1 initial value */
{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

extern MSTATUS
SHA1_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_MALLOC(pp_context,sizeof(shaDescr));
}

extern MSTATUS
SHA1_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{   return DIGI_FREE(pp_context);
}

extern MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    MSTATUS status = OK;
    shaDescr shaContext;
    if(OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) &shaContext)))
    {
        goto exit;
    }
    if(OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,pData,dataLen)))
    {
        goto exit;
    }

    status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) &shaContext,pShaOutput);
    exit:
    return status;
}


extern MSTATUS SHA1_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;
    ubyte   paddingAdded; /* Treated as boolean ********/
    ubyte4  numToCopy;
    if((NULL == p_shaContext ) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    p_shaContext->mesgLength += dataLen;
    /* If our index is > 0, then we have data to potentially transform */
    if(p_shaContext->hashBufferIndex > 0)
    {

        /* Since we will hash any full blocks, we will never have more than one
         * block's worth of data waiting in the hashBuffer.
         */
        numToCopy = SHA1_BLOCK_SIZE - p_shaContext->hashBufferIndex;

        if( dataLen < numToCopy)
        {
            numToCopy = dataLen;
        }
        DIGI_MEMCPY(p_shaContext->hashBuffer + p_shaContext->hashBufferIndex,pData, (sbyte4)numToCopy);
        pData += numToCopy;
        dataLen -= numToCopy;
        p_shaContext->hashBufferIndex += (sbyte4)numToCopy;
        if(SHA1_BLOCK_SIZE == p_shaContext->hashBufferIndex)
        {
            /* We have a full block to transform */
            byteArrayToWordArray(p_shaContext->hashBuffer,p_shaContext->W,SHA1_BLOCK_SIZE,&paddingAdded);
            g_sha1_hash_on_sce.updateHash(p_shaContext->W, SHA1_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
            p_shaContext->hashBufferIndex = 0;
        }
    }
    while(SHA1_BLOCK_SIZE <= dataLen)
    {
        byteArrayToWordArray(pData,p_shaContext->W,SHA1_BLOCK_SIZE,&paddingAdded);
        g_sha1_hash_on_sce.updateHash(p_shaContext->W, SHA1_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
        dataLen -= SHA1_BLOCK_SIZE;
        pData += SHA1_BLOCK_SIZE;
    }
    if(dataLen > 0)
    {
        DIGI_MEMCPY(p_shaContext->hashBuffer + p_shaContext->hashBufferIndex, pData, (sbyte4)dataLen);
        p_shaContext->hashBufferIndex += (sbyte4)dataLen;
    }
    exit:
    return status;
}

extern MSTATUS
SHA1_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, ubyte *pOutput)
{
    MSTATUS status = OK;
    sbyte4 i;
    ubyte paddingAdded;
    if((NULL == p_shaContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    byteArrayToWordArray(p_shaContext->hashBuffer,p_shaContext->W,p_shaContext->hashBufferIndex,&paddingAdded);
    p_shaContext->hashBufferIndex += paddingAdded;

    /*
     * If no padding was added, then the input was on a word boundary. We append 0x80
     * to the next byte. Since our hashBuffer is processed when it is longer than
     * SHA1_BLOCK_SIZE, we know we have room for at least one byte (the 0x80).
     */
    if(0 == paddingAdded)
    {
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = ((ubyte4) 0x80 << 24);
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x80000000;
        p_shaContext->hashBufferIndex +=4;
    }
    p_shaContext->hashBuffer[p_shaContext->hashBufferIndex] = 0x80;
    p_shaContext->hashBufferIndex++;

    /*
     *  The last 64 bits of the last message is reserved, so if we don't
     * have enough room for it, we pad out the current block with zeros.
     */
    if(p_shaContext->hashBufferIndex > SHA1_BLOCK_SIZE - 8)
    {
        while(p_shaContext->hashBufferIndex < SHA1_BLOCK_SIZE)
        {
            p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x00000000;
            p_shaContext->hashBufferIndex +=4;
        }
        g_sha1_hash_on_sce.updateHash(p_shaContext->W, SHA1_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
        p_shaContext->hashBufferIndex = 0;
    }

    /* Pad the remainder of the input block */
    /* Use the hash buffer index to track our position in the W array */
    while(p_shaContext->hashBufferIndex < SHA1_BLOCK_SIZE - 8)
    {
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x00000000;
        p_shaContext->hashBufferIndex += 4;
    }
    p_shaContext->mesgLength = u8_Shl(p_shaContext->mesgLength,3);
    p_shaContext->W[(SHA1_BLOCK_SIZE/4)-2] = HI_U8(p_shaContext->mesgLength);
    p_shaContext->W[(SHA1_BLOCK_SIZE/4)-1] = LOW_U8(p_shaContext->mesgLength);

    BIGEND32(p_shaContext->hashBuffer+SHA1_BLOCK_SIZE-8,HI_U8(p_shaContext->mesgLength));
    BIGEND32(p_shaContext->hashBuffer+SHA1_BLOCK_SIZE-4, LOW_U8(p_shaContext->mesgLength));
    g_sha1_hash_on_sce.updateHash(p_shaContext->W, SHA1_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
    for(i = 0; i < SHA1_RESULT_SIZE/4;i++)
    {
        BIGEND32(pOutput,p_shaContext->hashBlocks[i]);
        pOutput +=4;
    }
    exit:
    return status;
}

extern MSTATUS
SHA1_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext)
{

    DIGI_MEMCPY(p_shaContext->hashBuffer, sha1InitialValue, SHA1_BLOCK_SIZE);
    MSTATUS status;

    if (NULL == p_shaContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        p_shaContext->hashBlocks[0] = 0x67452301L;
        p_shaContext->hashBlocks[1] = 0xefcdab89L;
        p_shaContext->hashBlocks[2] = 0x98badcfeL;
        p_shaContext->hashBlocks[3] = 0x10325476L;
        p_shaContext->hashBlocks[4] = 0xc3d2e1f0L;

        p_shaContext->mesgLength = 0;
        p_shaContext->hashBufferIndex = 0;

        status = OK;
    }
    return status;
}

/*****************************************/
/*********** SHA 224 HW ******************/
/*****************************************/

MOC_EXTERN MSTATUS SHA224_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen,
        ubyte *pShaOutput)
{
    SHA224_CTX context;
    MSTATUS status;

    if (OK > (status = SHA224_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;

    if (OK > (status = SHA224_updateDigest(MOC_HASH(hwAccelCtx) &context, pData, dataLen)))
        goto exit;

    status = SHA224_finalDigest(MOC_HASH(hwAccelCtx) &context, pShaOutput);

    exit:
    return status;
}

extern MSTATUS
SHA224_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *p_shaContext,
        ubyte *pOutput)
{
    MSTATUS status = OK;
    sbyte4 i;
    ubyte paddingAdded;

    if ((NULL == p_shaContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    byteArrayToWordArray(p_shaContext->hashBuffer,p_shaContext->W,p_shaContext->hashBufferIndex,&paddingAdded);
    p_shaContext->hashBufferIndex += paddingAdded;

    if(0 == paddingAdded)
    {
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x80000000;
        p_shaContext->hashBufferIndex +=4;
    }
    /* less than 8 bytes available -> extra round */
    if ( p_shaContext->hashBufferIndex > SHA224_BLOCK_SIZE - 8)
    {
        while ( p_shaContext->hashBufferIndex < SHA224_BLOCK_SIZE)
        {
            p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x00000000;
            p_shaContext->hashBufferIndex +=4;
        }
        g_sha256_hash_on_sce.updateHash(p_shaContext->W, SHA224_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
        p_shaContext->hashBufferIndex = 0;
    }

    /*last round */
    while ( p_shaContext->hashBufferIndex < SHA224_BLOCK_SIZE - 8)
    {
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x00000000;
        p_shaContext->hashBufferIndex += 4;
    }

    /* fill in message bit length */
    /* bytes to bits */
    p_shaContext->mesgLength = u8_Shl( p_shaContext->mesgLength, 3);
    p_shaContext->W[(SHA224_BLOCK_SIZE/4)-2] = HI_U8(p_shaContext->mesgLength);
    p_shaContext->W[(SHA224_BLOCK_SIZE/4)-1] = LOW_U8(p_shaContext->mesgLength);

    g_sha256_hash_on_sce.updateHash(p_shaContext->W, SHA224_BLOCK_SIZE / 4, p_shaContext->hashBlocks);

    /* return the output */
    for (i = 0; i < SHA224_RESULT_SIZE/4; ++i)
    {
        BIGEND32( pOutput, p_shaContext->hashBlocks[i]);
        pOutput += 4;
    }

    exit:

    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((ubyte *)p_shaContext, 0x00, sizeof(SHA224_CTX));

    return status;

} /* SHA224_finalDigest */

extern MSTATUS
SHA224_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pContext)
{
    MSTATUS status;

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        pContext->hashBlocks[0] = 0xc1059ed8;
        pContext->hashBlocks[1] = 0x367cd507;
        pContext->hashBlocks[2] = 0x3070dd17;
        pContext->hashBlocks[3] = 0xf70e5939;
        pContext->hashBlocks[4] = 0xffc00b31;
        pContext->hashBlocks[5] = 0x68581511;
        pContext->hashBlocks[6] = 0x64f98fa7;
        pContext->hashBlocks[7] = 0xbefa4fa4;

        ZERO_U8(pContext->mesgLength);

        pContext->hashBufferIndex = 0;

        status = OK;
    }

    return status;
}

/*****************************************/
/*********** SHA 256 HW ******************/
/*****************************************/


MOC_EXTERN MSTATUS SHA256_freeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext)
{
    return DIGI_FREE(pp_shaContext);
}

MOC_EXTERN MSTATUS SHA256_allocDigest(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext)
{
    return DIGI_MALLOC(pp_shaContext,sizeof(sha256Descr));
}

extern MSTATUS
SHA256_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *p_shaContext,
        const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;

    if ((NULL == p_shaContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    u8_Incr32(&p_shaContext->mesgLength, dataLen);

    /* some remaining from last time ?*/
    if (p_shaContext->hashBufferIndex > 0)
    {
        sbyte4 numToCopy = SHA256_BLOCK_SIZE - p_shaContext->hashBufferIndex;
        if ( (sbyte4)dataLen < numToCopy)
        {
            numToCopy = dataLen;
        }

        DIGI_MEMCPY( p_shaContext->hashBuffer + p_shaContext->hashBufferIndex, pData, numToCopy);
        pData += numToCopy;
        dataLen -= numToCopy;
        p_shaContext->hashBufferIndex += numToCopy;
        if (SHA256_BLOCK_SIZE == p_shaContext->hashBufferIndex)
        {
            /* We have a full block to transform */
            ubyte paddingAdded;
            byteArrayToWordArray(p_shaContext->hashBuffer,p_shaContext->W,SHA256_BLOCK_SIZE,&paddingAdded);
            g_sha256_hash_on_sce.updateHash(p_shaContext->W, SHA256_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
            p_shaContext->hashBufferIndex = 0;
        }
    }

    /* process as much as possible right now */
    while ( SHA256_BLOCK_SIZE <= dataLen)
    {

        ubyte paddingAdded;
        byteArrayToWordArray(pData,p_shaContext->W,SHA256_BLOCK_SIZE,&paddingAdded);
        g_sha256_hash_on_sce.updateHash(p_shaContext->W, SHA256_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
        dataLen -= SHA256_BLOCK_SIZE;
        pData += SHA256_BLOCK_SIZE;
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(p_shaContext->hashBuffer + p_shaContext->hashBufferIndex, pData, dataLen);
        p_shaContext->hashBufferIndex += dataLen;
    }

    exit:
    return status;
}
extern MSTATUS
SHA256_finalDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *p_shaContext,
        ubyte *pOutput)
{
    MSTATUS status = OK;
    sbyte4 i;
    ubyte paddingAdded;

    if ((NULL == p_shaContext) || (NULL == pOutput))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    byteArrayToWordArray(p_shaContext->hashBuffer,p_shaContext->W,p_shaContext->hashBufferIndex,&paddingAdded);
    p_shaContext->hashBufferIndex += paddingAdded;

    if(0 == paddingAdded)
    {
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x80000000;
        p_shaContext->hashBufferIndex +=4;
    }
    /* less than 8 bytes available -> extra round */
    if ( p_shaContext->hashBufferIndex > SHA256_BLOCK_SIZE - 8)
    {
        while ( p_shaContext->hashBufferIndex < SHA256_BLOCK_SIZE)
        {
            p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x00000000;
            p_shaContext->hashBufferIndex +=4;
        }
        g_sha256_hash_on_sce.updateHash(p_shaContext->W, SHA256_BLOCK_SIZE / 4, p_shaContext->hashBlocks);
        p_shaContext->hashBufferIndex = 0;
    }

    /*last round */
    while ( p_shaContext->hashBufferIndex < SHA256_BLOCK_SIZE - 8)
    {
        p_shaContext->W[p_shaContext->hashBufferIndex/4] = 0x00000000;
        p_shaContext->hashBufferIndex += 4;
    }

    /* fill in message bit length */
    /* bytes to bits */
    p_shaContext->mesgLength = u8_Shl( p_shaContext->mesgLength, 3);
    p_shaContext->W[(SHA256_BLOCK_SIZE/4)-2] = HI_U8(p_shaContext->mesgLength);
    p_shaContext->W[(SHA256_BLOCK_SIZE/4)-1] = LOW_U8(p_shaContext->mesgLength);

    g_sha256_hash_on_sce.updateHash(p_shaContext->W, SHA256_BLOCK_SIZE / 4, p_shaContext->hashBlocks);

    /* return the output */
    for (i = 0; i < SHA256_RESULT_SIZE/4; ++i)
    {
        BIGEND32( pOutput, p_shaContext->hashBlocks[i]);
        pOutput += 4;
    }

    exit:

    /* Zeroize the sensitive information before deleting the memory */
    DIGI_MEMSET((ubyte *)p_shaContext, 0x00, sizeof(SHA256_CTX));

    return status;

} /* SHA256_finalDigestAux */

extern MSTATUS
SHA256_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    SHA256_CTX context;
    MSTATUS status;

    if (OK > (status = SHA256_initDigest(MOC_HASH(hwAccelCtx) &context)))
        goto exit;

    if (OK > (status = SHA256_updateDigest(MOC_HASH(hwAccelCtx) &context, pData, dataLen)))
        goto exit;

    status = SHA256_finalDigest(MOC_HASH(hwAccelCtx) &context, pShaOutput);

    exit:
    return status;
}

extern MSTATUS
SHA256_initDigest(MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pContext)
{
    MSTATUS status;

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        pContext->hashBlocks[0] = 0x6a09e667;
        pContext->hashBlocks[1] = 0xbb67ae85;
        pContext->hashBlocks[2] = 0x3c6ef372;
        pContext->hashBlocks[3] = 0xa54ff53a;
        pContext->hashBlocks[4] = 0x510e527f;
        pContext->hashBlocks[5] = 0x9b05688c;
        pContext->hashBlocks[6] = 0x1f83d9ab;
        pContext->hashBlocks[7] = 0x5be0cd19;

        ZERO_U8(pContext->mesgLength);

        pContext->hashBufferIndex = 0;

        status = OK;
    }

    return status;
}
#endif
