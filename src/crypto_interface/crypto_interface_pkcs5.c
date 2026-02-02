/*
 * crypto_interface_pkcs5.c
 *
 * Cryptographic Interface for PKCS5 password
 * based encryption.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5_INTERNAL__

#include "../crypto/mocsym.h"
#include "../crypto/pkcs5.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5__

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_CREATEKEY_PBKDF1(_status, _pSalt, _saltLen, _iterationCount, _hashingFunction, _pPassword, _passwordLen, _dkLen, _pRetDerivedKey) \
    _status = PKCS5_CreateKey_PBKDF1(MOC_HASH(hwAccelCtx) _pSalt, _saltLen, _iterationCount, _hashingFunction, _pPassword, _passwordLen, _dkLen, _pRetDerivedKey)
#else
#define MOC_CREATEKEY_PBKDF1(_status, _pSalt, _saltLen, _iterationCount, _hashingFunction, _pPassword, _passwordLen, _dkLen, _pRetDerivedKey) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_CREATEKEY_PBKDF2(_status, _pSalt, _saltLen, _iterationCount, _rsaAlgoId, _pPassword, _passwordLen, _dkLen, _pRetDerivedKey) \
    _status = PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx) _pSalt, _saltLen, _iterationCount, _rsaAlgoId, _pPassword, _passwordLen, _dkLen, _pRetDerivedKey)
#else
#define MOC_CREATEKEY_PBKDF2(_status, _pSalt, _saltLen, _iterationCount, _rsaAlgoId, _pPassword, _passwordLen, _dkLen, _pRetDerivedKey) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_PKCS5_DECRYPT(_status, _subType, _cs, _pPBEParam, _pEncrypted, _pPassword, _passwordLen, _privateKeyInfo, _privateKeyInfoLen) \
    _status = PKCS5_decrypt(MOC_SYM(hwAccelCtx) _subType, _cs, _pPBEParam, _pEncrypted, _pPassword, _passwordLen, _privateKeyInfo, _privateKeyInfoLen)
#else
#define MOC_PKCS5_DECRYPT(_status, _subType, _cs, _pPBEParam, _pEncrypted, _pPassword, _passwordLen, _privateKeyInfo, _privateKeyInfoLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_PKCS5_DECRYPT_V2(_status, _pAsn1PBE, _pbeLen, _pData, _dataLen, _pPassword, _passwordLen, _pPrivateKeyInfo, _privKeyInfoBufferLen, _pPrivKeyInfoLen) \
    _status = PKCS5_decryptV2(MOC_SYM(hwAccelCtx) pAsn1PBE, _pbeLen, _pData, _dataLen, _pPassword, _passwordLen, _pPrivateKeyInfo, _privKeyInfoBufferLen, _pPrivKeyInfoLen)
#else
#define MOC_PKCS5_DECRYPT_V2(_status, _pAsn1PBE, _pbeLen, _pData, _dataLen, _pPassword, _passwordLen, _pPrivateKeyInfo, _privKeyInfoBufferLen, _pPrivKeyInfoLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_PKCS5_ENCRYPT_V1(_status, _pkcs5SubType, _pPassword, _passwordLen, _pSalt, _saltLen, _iterationCount, _plainText, _ptLen) \
    _status = PKCS5_encryptV1(MOC_SYM(hwAccelCtx) _pkcs5SubType, _pPassword, _passwordLen, _pSalt, _saltLen, _iterationCount, _plainText, _ptLen)
#else
#define MOC_PKCS5_ENCRYPT_V1(_status, _pkcs5SubType, _pPassword, _passwordLen, _pSalt, _saltLen, _iterationCount, _plainText, _ptLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_PKCS5_ENCRYPT_V2_ALT(_status, _encAlgo, _rsaAlgoId, _keyLength, _effKeyBits, _pPassword, _passwordLen, _pSalt, _saltLen, _iterationCount, _pIv, _plainText, _ptLen, _pCipher, _ctLen, _pBytesWritten) \
    _status = PKCS5_encryptV2_Alt(MOC_SYM(hwAccelCtx) _encAlgo, _rsaAlgoId, _keyLength, _effKeyBits, _pPassword, _passwordLen, _pSalt, _saltLen, _iterationCount, _pIv, _plainText, _ptLen, _pCipher, _ctLen, _pBytesWritten);
#else
#define MOC_PKCS5_ENCRYPT_V2_ALT(_status, _encAlgo, _rsaAlgoId, _keyLength, _effKeyBits, _pPassword, _passwordLen, _pSalt, _saltLen, _iterationCount, _pIv, _plainText, _ptLen, _pCipher, _ctLen, _pBytesWritten) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF1(
    MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterationCount, enum hashFunc hashingFunction,
    const ubyte *pPassword, ubyte4 passwordLen,
    ubyte4 dkLen, ubyte *pRetDerivedKey)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_pkcs5_pbe, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_CREATEKEY_PBKDF1(status, pSalt, saltLen, iterationCount, hashingFunction, pPassword, passwordLen, dkLen, pRetDerivedKey);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF2(
    MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterationCount, ubyte digestAlg,
    const ubyte *pPassword, ubyte4 passwordLen,
    ubyte4 dkLen, ubyte *pRetDerivedKey)
{
    MSTATUS status = OK, fstatus = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;
    MocSymCtx pNewSymCtx = NULL;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_pkcs5_pbe, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        MocCtx pMocCtx = NULL;
        MSymOperator pOperator = NULL;
        ubyte4 derivedOutLen;

        MPkcs5OperatorData pbkdfData = {0};

        pbkdfData.operation = MOC_SYM_OP_PKCS5_KDF;
        pbkdfData.pPassword = (ubyte *) pPassword;
        pbkdfData.passwordLen = passwordLen;
        pbkdfData.pSalt = (ubyte *) pSalt;
        pbkdfData.saltLen = saltLen;
        pbkdfData.iterationCount = iterationCount;
        pbkdfData.digestAlg = digestAlg;

        /* Get a reference to the MocCtx within the Crypto Interface Core */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;

        /* get the operator */
        status = CRYPTO_getSymOperatorAndInfoFromIndex(index, pMocCtx, &pOperator, NULL);
        if (OK != status)
            goto exit;

        /* create a new sym ctx */
        status = CRYPTO_createMocSymCtx (pOperator, (void *)&pbkdfData, pMocCtx, &pNewSymCtx);
        if (OK != status)
            goto exit;

        status = CRYPTO_deriveKey (pNewSymCtx, NULL, pRetDerivedKey, dkLen, &derivedOutLen);
    }
    else
    {
        MOC_CREATEKEY_PBKDF2(status, pSalt, saltLen, iterationCount, digestAlg, pPassword, passwordLen, dkLen, pRetDerivedKey);
    }

exit:

    if (NULL != pNewSymCtx)
    {
        fstatus = CRYPTO_freeMocSymCtx(&pNewSymCtx);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_decrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte subType, CStream cs,
    ASN1_ITEMPTR pPBEParam, ASN1_ITEMPTR pEncrypted,
    const ubyte *pPassword, sbyte4 passwordLen,
    ubyte **ppPrivateKeyInfo,
    sbyte4 *pPrivateKeyInfoLen)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_pkcs5_pbe, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_PKCS5_DECRYPT(status, subType, cs, pPBEParam, pEncrypted, pPassword, passwordLen, ppPrivateKeyInfo, pPrivateKeyInfoLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_decryptV2( 
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte *pAsn1PBE, ubyte4 pbeLen,
    ubyte *pData, ubyte4 dataLen,
    const ubyte* pPassword, sbyte4 passwordLen,
    ubyte *pPrivateKeyInfo, ubyte4 privKeyInfoBufferLen,
    ubyte4 *pPrivKeyInfoLen)
{
    MSTATUS status = OK, fstatus = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;
    MocSymCtx pNewSymCtx = NULL;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_pkcs5_pbe, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        MocCtx pMocCtx = NULL;
        MSymOperator pOperator = NULL;

        MPkcs5OperatorData pDecData = {0};

        status = ERR_NULL_POINTER;
        if (NULL == pPrivateKeyInfo)
            goto exit;

        pDecData.operation = MOC_SYM_OP_PKCS5_DECRYPT;
        pDecData.pPBEInfo = (ubyte *) pAsn1PBE;
        pDecData.pbeLen = pbeLen;
        pDecData.pPassword = (ubyte *) pPassword;
        pDecData.passwordLen = passwordLen;

        /* Get a reference to the MocCtx within the Crypto Interface Core */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;

        /* get the operator */
        status = CRYPTO_getSymOperatorAndInfoFromIndex(index, pMocCtx, &pOperator, NULL);
        if (OK != status)
            goto exit;

        /* create a new sym ctx */
        status = CRYPTO_createMocSymCtx (pOperator, (void *) &pDecData, pMocCtx, &pNewSymCtx);
        if (OK != status)
            goto exit;

        /* Initialize the cipher operation  */
        status = CRYPTO_cipherInit(pNewSymCtx, MOC_CIPHER_FLAG_DECRYPT);
        if (OK != status)
            goto exit;

        /* Update the cipher operation */
        status = CRYPTO_cipherUpdate(pNewSymCtx, MOC_CIPHER_FLAG_DECRYPT, pData, dataLen, pPrivateKeyInfo, privKeyInfoBufferLen, pPrivKeyInfoLen);
        if (OK != status)
            goto exit;

        /* No need to call CRYPTO_cipherFinal */
    }
    else
    {
        MOC_PKCS5_DECRYPT_V2(status, pAsn1PBE, pbeLen, pData, dataLen, pPassword, passwordLen, pPrivateKeyInfo, privKeyInfoBufferLen, pPrivKeyInfoLen);
    }

exit:

    if (NULL != pNewSymCtx)
    {
        fstatus = CRYPTO_freeMocSymCtx(&pNewSymCtx);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_encryptV1(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte pkcs5SubType,
    const ubyte *pPassword, ubyte4 passwordLen,
    const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterCount,
    ubyte *pPlainText, ubyte4 ptLen)
{
    MSTATUS status = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_pkcs5_pbe, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_PKCS5_ENCRYPT_V1(status, pkcs5SubType, pPassword, passwordLen, pSalt, saltLen, iterCount, pPlainText, ptLen);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_encryptV2_Alt(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte encryptionAlg, ubyte digestAlg,
    ubyte4 keyLength, sbyte4 effectiveKeyBits,
    const ubyte *pPassword, ubyte4 passwordLen,
    const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterCount, const ubyte *pIv,
    ubyte *pPlainText, ubyte4 ptLen,
    ubyte *pCipherText, ubyte4 ctBufferLen,
    ubyte4 *pCtLen)
{
    MSTATUS status = OK, fstatus = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;
    MocSymCtx pNewSymCtx = NULL;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_pkcs5_pbe, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        MocCtx pMocCtx = NULL;
        MSymOperator pOperator = NULL;

        MPkcs5OperatorData pEncData = {0};
        
        pEncData.operation = MOC_SYM_OP_PKCS5_ENCRYPT;
        pEncData.encAlg = encryptionAlg;
        pEncData.keyLen = keyLength;
        pEncData.effectiveKeyBits = effectiveKeyBits;
        pEncData.digestAlg = digestAlg;
        pEncData.pPassword = (ubyte *) pPassword;
        pEncData.passwordLen = passwordLen;
        pEncData.pSalt = (ubyte *) pSalt;
        pEncData.saltLen = saltLen;
        pEncData.iterationCount = iterCount;
        pEncData.pIv = (ubyte *) pIv;
        
        /* Get a reference to the MocCtx within the Crypto Interface Core */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;

        /* get the operator */
        status = CRYPTO_getSymOperatorAndInfoFromIndex(index, pMocCtx, &pOperator, NULL);
        if (OK != status)
            goto exit;

        /* create a new sym ctx */
        status = CRYPTO_createMocSymCtx (pOperator, (void *) &pEncData, pMocCtx, &pNewSymCtx);
        if (OK != status)
            goto exit;

        /* Initialize the cipher operation  */
        status = CRYPTO_cipherInit(pNewSymCtx, MOC_CIPHER_FLAG_ENCRYPT);
        if (OK != status)
            goto exit;

        /* Update the cipher operation, We'll assume pPlainText as out buffer has room for a block lengths of padding for any cipher */
        status = CRYPTO_cipherUpdate(pNewSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pPlainText, ptLen, pCipherText, ctBufferLen, pCtLen);
        if (OK != status)
            goto exit;
    
        /* No need to call CRYPTO_cipherFinal */
    }
    else
    {
        MOC_PKCS5_ENCRYPT_V2_ALT(status, encryptionAlg, digestAlg, keyLength, effectiveKeyBits, pPassword, passwordLen, 
                                 pSalt, saltLen, iterCount, pIv, pPlainText, ptLen, pCipherText, ctBufferLen, pCtLen);
    }

exit:

    if (NULL != pNewSymCtx)
    {
        fstatus = CRYPTO_freeMocSymCtx(&pNewSymCtx);
        if (OK == status)
            status = fstatus;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5__ */
