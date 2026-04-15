/*
 * kemf.c
 *
 * Key Encapsulation Mechanism Functions
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
