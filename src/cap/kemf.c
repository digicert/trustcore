/*
 * kemf.c
 *
 * Key Encapsulation Mechanism Functions
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
@file       kemf.c
@brief      Key Encapsulation Mechanism Functions
@details    Add details here.

@filedoc    kemf.c
*/

#include "../cap/capasym.h"

#ifdef __ENABLE_DIGICERT_ASYM_KEY__

extern MSTATUS CRYPTO_keyEncapsulate (
    MocAsymKey pPublicKey,
    RNGFun rngFun,
    void *pRngFunArg,
    ubyte *pCipherText,
    ubyte4 cipherTextLen,
    ubyte *pSharedSecret,
    ubyte4 sharedSecretLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MKeyEncapsulationInfo outputInfo = {0};
    MRandomGenInfo inputInfo = {0};

    if (NULL == pPublicKey || NULL == pPublicKey->KeyOperator || NULL == pCipherText || NULL == pSharedSecret)
        goto exit;
    
    inputInfo.RngFun = rngFun;
    inputInfo.pRngFunArg = pRngFunArg;
    outputInfo.pCipherText = pCipherText;
    outputInfo.cipherTextLen = cipherTextLen;
    outputInfo.pSharedSecret = pSharedSecret;
    outputInfo.sharedSecretLen = sharedSecretLen;
    
    status = pPublicKey->KeyOperator(pPublicKey, pPublicKey->pMocCtx, MOC_ASYM_OP_ENCAPSULATE, (void *) &inputInfo, (void *) &outputInfo , NULL);
 
exit:
    
    return status;
}


extern MSTATUS CRYPTO_keyDecapsulate (
    MocAsymKey pSecretKey,
    ubyte *pCipherText,
    ubyte4 cipherTextLen,
    ubyte *pSharedSecret,
    ubyte4 sharedSecretLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MKeyEncapsulationInfo inputInfo = {0};
    MKeyEncapsulationInfo outputInfo = {0};
    
    if (NULL == pSecretKey || NULL == pSecretKey->KeyOperator || NULL == pCipherText || NULL == pSharedSecret)
        goto exit;
    
    inputInfo.pCipherText = pCipherText;
    inputInfo.cipherTextLen = cipherTextLen;
    outputInfo.pSharedSecret = pSharedSecret;
    outputInfo.sharedSecretLen = sharedSecretLen;
    
    status = pSecretKey->KeyOperator(pSecretKey, pSecretKey->pMocCtx, MOC_ASYM_OP_DECAPSULATE, (void *) &inputInfo, (void *) &outputInfo, NULL);

exit:
    
    return status;
}
#endif /* __ENABLE_DIGICERT_ASYM_KEY__ */
