/*
 * aes_ecb.c
 *
 * AES-ECB Implementation
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
@file       aes_ecb.c
@brief      C source code for the NanoCrypto AES-ECB API.

@details    This file contains the NanoCrypto AES-ECB API functions.

@copydoc    overview_aes_ecb

@flags
There are no flag dependencies to enable the functions in this API.

@filedoc    aes_ecb.c
*/


/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*------------------------------------------------------------------*/

extern BulkCtx
CreateAESECBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCipherContext* ctx = NULL;

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    {
        return NULL; /* returns NULL ctx */
    }
#endif

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_ECB); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_ECB,keyLength);

    ctx = (aesCipherContext*) MALLOC(sizeof(aesCipherContext));

    if (NULL != ctx)
    {
        DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(aesCipherContext));

        if (OK > AESALGO_makeAesKeyEx (
          MOC_SYM(hwAccelCtx) ctx, 8 * keyLength, keyMaterial, encrypt, MODE_ECB))
        {
            FREE(ctx);  ctx = NULL;
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_ECB,keyLength);
    return ctx;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DeleteAESECBCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_ECB); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_ECB,0);

    if (*ctx)
    {
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAES - Before Zeroization\n");
        for( counter = 0; counter < sizeof(aesCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*)*ctx, 0x00, sizeof(aesCipherContext));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAES - After Zeroization\n");
        for( counter = 0; counter < sizeof(aesCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        FREE(*ctx);
        *ctx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_ECB,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
DoAESECB(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    sbyte4              retLength;
    aesCipherContext*   pAesContext = (aesCipherContext *)ctx;
    MSTATUS             status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_ECB); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_ECB,0);

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
      status = AESALGO_blockEncryptEx (
        MOC_SYM(hwAccelCtx) pAesContext, NULL, data, 8 * dataLength, data, &retLength);
    else
      status = AESALGO_blockDecryptEx (
        MOC_SYM(hwAccelCtx) pAesContext, NULL, data, 8 * dataLength, data, &retLength);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
      DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"DoAESECB: cipher failed, error = ", status);
#endif

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_ECB,0);
    return status;
}

#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
