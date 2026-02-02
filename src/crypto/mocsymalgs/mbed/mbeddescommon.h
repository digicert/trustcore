/*
 * mbeddescommon.h
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

#ifndef MBED_DES_COMMON_H
#define MBED_DES_COMMON_H

#include "../../../crypto/mocsym.h"
#include "mbedtls/des.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_DES_BLOCK_SIZE 8
#define MBEDTLS_DES_IV_SIZE 8
#define MBEDTLS_DES_KEY_SIZE 8
#define MBEDTLS_TDES_TWO_KEY_SIZE 16
#define MBEDTLS_TDES_KEY_SIZE 24

typedef struct
{
    void *pDesCtx;
    ubyte pKey[MBEDTLS_TDES_KEY_SIZE]; /* big enough for des or tdes */
    ubyte4 keyLen;
    intBoolean hasKey;
    ubyte pLeftovers[MBEDTLS_DES_BLOCK_SIZE];
    ubyte4 leftoverLen;

    /* for cbc mode ops */
    ubyte pIv[MBEDTLS_DES_IV_SIZE];
    intBoolean hasIv;
} MbedDesInfo;

/* Function pointer types for DES or TDES methods */

typedef void (*MbedDesInitFree) (
    void *pCtx
    );

typedef int (*MbedDesSetKey) (
    void *pCtx,
    const unsigned char pKey[]
    );

typedef int (*MbedDesCrypt) (
    void *pCtx,
    int mode,
    unsigned int length,
    unsigned char *pIv,
    const unsigned char *pInput,
    unsigned char *pOutput
    );

/* Wrapper methods of mbed DES and TDES methods that fit the above definitions */

void mbedtls_des_init_wrap(void *pCtx);
void mbedtls_des_free_wrap(void *pCtx);
void mbedtls_des3_init_wrap(void *pCtx);
void mbedtls_des3_free_wrap(void *pCtx);

int mbedtls_des_setkey_enc_wrap( void *pCtx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] );
int mbedtls_des_setkey_dec_wrap( void *pCtx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] );
int mbedtls_des3_set3key_enc_wrap( void *pCtx, const unsigned char key[MBEDTLS_TDES_KEY_SIZE] );
int mbedtls_des3_set3key_dec_wrap( void *pCtx, const unsigned char key[MBEDTLS_TDES_KEY_SIZE] );

int mbedtls_des_crypt_ecb_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput);
int mbedtls_des3_crypt_ecb_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput);
int mbedtls_des_crypt_cbc_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput);
int mbedtls_des3_crypt_cbc_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput);

/* common methods whether doing ecb or cbc */
MOC_EXTERN MSTATUS MDesMbedCreate (MocSymCtx pCtx, void *pDesData, ubyte4 localType, MSymOperator symOperator);
MOC_EXTERN MSTATUS MDesMbedInit (MocSymCtx pCtx, MbedDesInitFree desInitFunc, MbedDesSetKey desSetKeyFunc);
MOC_EXTERN MSTATUS MDesMbedGenerateKey (MocSymCtx pCtx, MSymKeyGenInfo *pGenInfo, MSymOperatorBuffer *pOutput);
MOC_EXTERN MSTATUS MDesMbedLoadKey (MocSymCtx pCtx, MSymOperatorData *pKeyData);
MOC_EXTERN MSTATUS MDesMbedUpdate (MocSymCtx pCtx, ubyte4 cipherFlag, MSymOperatorData *pInput, MSymOperatorBuffer *pOutput, MbedDesCrypt desCryptFunc);
MOC_EXTERN MSTATUS MDesMbedFinal (MocSymCtx pCtx, ubyte4 cipherFlag, MSymOperatorData *pInput, MSymOperatorBuffer *pOutput, MbedDesCrypt desCryptFunc);
MOC_EXTERN MSTATUS MDesMbedFree (MocSymCtx pCtx, MbedDesInitFree desFreeFunc);
MOC_EXTERN MSTATUS MDesMbedUpdateOperatorData (MocSymCtx pCtx, MDesUpdateData *pDesData);
MOC_EXTERN MSTATUS MDesMbedGetOpData(MbedDesInfo *pCtx, MSymOperatorData *pOutput);
MOC_EXTERN MSTATUS MDesMbedClone(MocSymCtx pCtx, MocSymCtx pCopyCtx);

#ifdef __cplusplus
}
#endif

#endif /* MBED_DES_COMMON_H */
