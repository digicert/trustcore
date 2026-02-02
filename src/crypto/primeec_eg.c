/*
 * primeec_eg.c
 *
 * Elliptic Curve El-Gamal Encryption/Decryption operations
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

/*
 Elliptic Curve El-Gamal Encryption and Decryption.

 ************************************************************************************

 Encryption: The input block size is 4 bytes less than the curve's coordinate
 size in bytes. We prefix the plaintext block with a 4 byte ctr 0,1,2...
 until the prefixed plaintext, considered as a Big Endian integer, is a valid
 X coordinate of a point on the curve M.

 Note there is no official standard for the 4 byte size of the counter, but all
 implementations I have seen use 4 bytes.

 Also an important note is that it is up to the user to ensure the message can be
 divided into an even number of blocks. They may pad the message however they want
 as their is no standard. We do not pad for them and return ERR_ECEG_INVALID_INPUT_LEN
 if it is not the correct length.

 Encryption happens as follows, we compute an ephemeral public key R by creating an
 ephemeral random nonce value r and compute R = r*G where G is the generator of the curve.

 We also create a "shared secret" S which is r*Q where Q is the decryptor's public key,
 and then encrpyt the message by computing the point P = S + M = r*Q + M.

 The ciphertext consists of the 2 coordinates or R together with the 2 coordinates of P,
 all in Big Endian, so four times the curve's coordinate size in bytes total.

 ************************************************************************************

 Decryption: The input block size is four times the curve's coordinate size in bytes.

 The first two coords are that of R and the second two are that of P. We can calculate
 our copy of the shared secret S as k * R where k is the private key, since of course

 k*R = k*r*G = r*k*G = r*Q.

 The all we need to do is subtract that from P to obtain M, ie M = P - r*Q. We output
 the entire x coordinate of M as the plaintext and do not remove the counter. It
 is up to the user to know what size counter was used on encryption and to remove
 the counter his or herself. The output block size is therefore equal to the curve's
 coordinate size and different from that of the input block size to encryption.
 */

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL_INTERNAL__

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__)

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

#include "../crypto/primeec_eg.h"

#define ECEG_MAX_NONCE_CTR 128
#define MOCANA_ECEG_PKCSV1P5_MIN_PADDING 11
#define MOCANA_ECEG_PKCS1_V1P5_BT 0x02

/*---------------------------------------------------------------------------*/

/* increments a big endian 4 byte ctr */
static MOC_INLINE void ECEG_increment_ctr(ubyte *pCtr)
{
    pCtr[3]++;
    if (!pCtr[3])
    {
        pCtr[2]++;
        if (!pCtr[2])
        {
            pCtr[1]++;
            if (!pCtr[1])
            {
                pCtr[0]++;
            }
        }
    }
}

/*
 Internal method that encrypts one block of plaintext.

 The calling method must insure pPlaintext must be the proper length based
 on the curve size (ie the curve byte size - MOCANA_ECEG_CTR_LEN).

 The calling method must insure pCipherText must be the proper length based
 on the curve size (ie 4*the curve byte size).
 */
static MSTATUS ECEG_update_encrypt_block(MOC_ECC(hwAccelDescr hwAccelCtx) PEllipticCurvePtr pCurve, PFEPtr pPubKeyX, PFEPtr pPubKeyY,
                                         RNGFun rngFun, void *pRngArg, ubyte *pPlaintext, ubyte *pCipherText)
{
    MSTATUS status;
    sbyte4 i = 0;
    ubyte *pCoordBuffer = NULL;
    ubyte zeroTest = 0x00;
    sbyte4 coordLen = (pCurve->pPF->numBits+7)/8;  /* in bytes */

    PFEPtr pX = NULL;
    PFEPtr pY = NULL;
    PFEPtr pNonce = NULL;
    PFEPtr pResultX = NULL;
    PFEPtr pResultY = NULL;

    /* Internal method, input validation already done */

    status = PRIMEFIELD_newElement(pCurve->pPF, &pX);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pY);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pNonce);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pResultX);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pResultY);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **) &pCoordBuffer, coordLen, 1);
    if (OK != status)
        goto exit;

    /* Encode the plaintext prefixed with a 4 byte counter as an X coordinate on the curve */
    status = DIGI_MEMCPY(pCoordBuffer + MOCANA_ECEG_CTR_LEN, pPlaintext, coordLen - MOCANA_ECEG_CTR_LEN);
    if (OK != status)
        goto exit;

    /* If X is not on the curve increment the counter. Each iteration has 50% chance of success */
    while(TRUE)
    {
        status = PRIMEFIELD_setToByteString(pCurve->pPF, pX, pCoordBuffer, coordLen);
        if (OK != status)
            goto exit;

        status = EC_computeYFromX(pCurve, pX, pY); /* note API has result in last param */
        if (ERR_NOT_FOUND == status)
        {
            ECEG_increment_ctr(pCoordBuffer);
        }
        else if (OK != status)
        {
            goto exit;
        }
        else /* OK == status */
        {
            break;
        }
    }

    /*
     Compute a random nonce times the generator, hence essentially an ephemeral public key,
     so ok to just use EC_generateKeyPair which will handle making sure the nonce is less than the
     curve order and not zero.
     */
    status = EC_generateKeyPair(pCurve, rngFun, pRngArg, pNonce, pResultX, pResultY);
    if (OK != status)
        goto exit;

    /* The result makes up the first half of the ciphertext */
    status = PRIMEFIELD_writeByteString(pCurve->pPF, pResultX, pCipherText, coordLen);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_writeByteString(pCurve->pPF, pResultY, pCipherText + coordLen, coordLen);
    if (OK != status)
        goto exit;

    /* Compute the nonce times the public key plus the message encoded as a point */
    status = EC_addMultiplyPoint(pCurve->pPF, pResultX, pResultY, pX, pY, pNonce, pPubKeyX, pPubKeyY);
    if (OK != status)
        goto exit;

    /* The result makes up the second half of the ciphertext */
    status = PRIMEFIELD_writeByteString(pCurve->pPF, pResultX, pCipherText + 2*coordLen, coordLen);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_writeByteString(pCurve->pPF, pResultY, pCipherText + 3*coordLen, coordLen);
    if (OK != status)
        goto exit;

    /* check that it is not all zeros (which is how the point at infinity was manifested). */
    for (i = 2*coordLen; i < 4*coordLen; ++i) /* re-use nonceCtr */
    {
        zeroTest |= pCipherText[i];
    }

    if (!zeroTest)
        status = ERR_EC_INFINITE_RESULT;

exit:

    if (NULL != pCoordBuffer)
    {
        DIGI_MEMSET(pCoordBuffer, 0x00, coordLen);
        DIGI_FREE((void **)& pCoordBuffer);
    }
    coordLen = 0;

    if (NULL != pX)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pX);
    }
    if (NULL != pY)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pY);
    }
    if (NULL != pNonce)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pNonce);
    }
    if (NULL != pResultX)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pResultX);
    }
    if (NULL != pResultY)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pResultY);
    }

    return status;
}

/*
 Internal method that decrypts one block of ciphertext.

 The calling method must insure pCiphertext must be the proper length based
 on the curve size (ie 4*the curve byte size).

 The calling method must insure pPlaintext must be the proper length based
 on the curve size (ie the curve byte size).
 */
static MSTATUS ECEG_update_decrypt_block(MOC_ECC(hwAccelDescr hwAccelCtx) PEllipticCurvePtr pCurve, PFEPtr pPrivateKey,
                                         ubyte *pCipherText, ubyte *pPlaintext)
{
    MSTATUS status;
    sbyte4 coordLen = (pCurve->pPF->numBits+7)/8;  /* in bytes */
    sbyte4 i;
    ubyte zeroTest = 0x00;

    PFEPtr pRx = NULL;
    PFEPtr pRy = NULL;
    PFEPtr pPx = NULL;
    PFEPtr pPy = NULL;
    PFEPtr pResultX = NULL;
    PFEPtr pResultY = NULL;

    /* Internal method, input validation already done */

    status = PRIMEFIELD_newElement(pCurve->pPF, &pRx);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pRy);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pPx);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pPy);
    if (OK != status)
        goto exit;

    /* Convert the ciphertext into the 2 points on the curve, R and P resp */

    status = PRIMEFIELD_setToByteString(pCurve->pPF, pRx, pCipherText, coordLen);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_setToByteString(pCurve->pPF, pRy, pCipherText + coordLen, coordLen);
    if (OK != status)
        goto exit;

    /* Very important: Validate R is on the curve */

    status = EC_verifyPoint(pCurve, pRx, pRy);
    if (ERR_FALSE == status)
    {
        status = ERR_EC_DIFFERENT_CURVE;
        goto exit;
    }
    else if (OK != status)
        goto exit;

    status = PRIMEFIELD_setToByteString(pCurve->pPF, pPx, pCipherText + 2*coordLen, coordLen);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_setToByteString(pCurve->pPF, pPy, pCipherText + 3*coordLen, coordLen);
    if (OK != status)
        goto exit;

    /* do not need to validate P is on the curve */

    status = PRIMEFIELD_newElement(pCurve->pPF, &pResultX);
    if (OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pCurve->pPF, &pResultY);
    if (OK != status)
        goto exit;

    /*
      Compute P - k*R which is = P - k*r*G = P - r*k*G = P - r*Q = M.

      Noting there is EC_subtract (or EC_add) method, and so to make use
      of EC_addMultiplyPoint (which may be more efficient anyway), we invert P
      and compute  k*R + (-P) (and then we don't need to invert again since we
      are just getting the x-coordinate).
    */

    status = PRIMEFIELD_additiveInvert(pCurve->pPF, pPy);
    if (OK != status)
        goto exit;

    status = EC_addMultiplyPoint(pCurve->pPF, pResultX, pResultY, pPx, pPy, pPrivateKey, pRx, pRy);
    if (OK != status)
        goto exit;

    /*
     We do have to check that the result is not the point at infinity,
     first check y for 0, use pPlaintext as a temp buffer
     */
    status = PRIMEFIELD_writeByteString(pCurve->pPF, pResultY, pPlaintext, coordLen);
    if (OK != status)
        goto exit;

    for (i = 0; i < coordLen; ++i)
    {
        zeroTest |= pPlaintext[i];
    }

    /* Now get x */
    status = PRIMEFIELD_writeByteString(pCurve->pPF, pResultX, pPlaintext, coordLen);
    if (OK != status)
        goto exit;

    /* check that y and x together were not all zeros. */
    for (i = 0; i < coordLen; ++i)
    {
        zeroTest |= pPlaintext[i];
    }

    if (!zeroTest)
        status = ERR_EC_INFINITE_RESULT;

    /*
     NOTE: we DO NOT remove the counter since 4 bytes is not a standard and we may be decrypting
     someone else's encryption using a different size counter.
     */

exit:

    coordLen = 0;

    if (NULL != pRx)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pRx);
    }
    if (NULL != pRy)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pRy);
    }
    if (NULL != pPx)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pPx);
    }
    if (NULL != pPy)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pPy);
    }
    if (NULL != pResultX)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pResultX);
    }
    if (NULL != pResultY)
    {
        PRIMEFIELD_deleteElement(pCurve->pPF, &pResultY);
    }

    return status;
}


MSTATUS ECEG_init(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, ECCKey *pKey, ubyte direction, RNGFun rngFun, void *pRngArg, void *pExtCtx)
{
    MSTATUS status;
    ubyte *pNewBuffer = NULL;

    MOC_UNUSED(pExtCtx);

    if (NULL == pCtx || NULL == pKey)
        return ERR_NULL_POINTER;

    if (direction > MOCANA_ECEG_DECRYPT)
        return ERR_INVALID_ARG;

    if (pCtx->isInitialized)
        return ERR_ECEG_ALREADY_INITIALIZED_CTX;

    if (MOCANA_ECEG_ENCRYPT == direction)
    {
        if(NULL == rngFun)
            return ERR_NULL_POINTER;

        if(pKey->privateKey)
            return ERR_ECEG_INVALID_KEY_TYPE;

        if (NULL == pKey->Qx || NULL == pKey->Qy || NULL == pKey->pCurve)
            return ERR_ECEG_UNALLOCATED_KEY;

        pCtx->rngFun = rngFun;
        pCtx->pRngArg = pRngArg;

        pCtx->isEncrypt = TRUE;

        pCtx->inputBlockLen = (pKey->pCurve->pPF->numBits+7)/8 - MOCANA_ECEG_CTR_LEN;
        pCtx->outputBlockLen = 4 * ((pKey->pCurve->pPF->numBits+7)/8);
    }
    else /* MOCANA_ECEG_DECRYPT == direction */
    {
        if( !(pKey->privateKey) )
            return ERR_ECEG_INVALID_KEY_TYPE;

        if (NULL == pKey->k || NULL == pKey->pCurve)
            return ERR_ECEG_UNALLOCATED_KEY;

        pCtx->rngFun = NULL;
        pCtx->pRngArg = NULL;

        pCtx->isEncrypt = FALSE;

        pCtx->inputBlockLen = 4 * ((pKey->pCurve->pPF->numBits+7)/8);
        pCtx->outputBlockLen = (pKey->pCurve->pPF->numBits+7)/8;
    }

    pCtx->pKey = pKey;
    pCtx->position = 0;
    status = DIGI_MALLOC((void **) &pNewBuffer, pCtx->inputBlockLen);

    if (OK == status)
    {
        pCtx->pBuffer = pNewBuffer;
        pCtx->isInitialized = TRUE;
    }
    else
    {   /* don't change status */
        DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(ECEG_CTX));
    }

    pNewBuffer = NULL;

    return status;
}


MSTATUS ECEG_update(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, ubyte *pInputData, ubyte4 inputDataLen, ubyte *pOutputData, ubyte4 outputDataBufferLen, ubyte4 *pBytesWritten, void *pExtCtx)
{
    MSTATUS status = OK;
    ubyte *pInputPtr = pInputData;
    ubyte4 bytesNeeded;
    ubyte4 bytesLeft = inputDataLen;

    ubyte *pOutputPtr = pOutputData;
    ubyte4 bytesWritten = 0;

    MOC_UNUSED(pExtCtx);

    if (NULL == pCtx || (NULL == pInputData && inputDataLen) || (NULL == pOutputData && outputDataBufferLen) || NULL == pBytesWritten)
        return ERR_NULL_POINTER;

    if ( !(pCtx->isInitialized) )
        return ERR_ECEG_UNINITIALIZED_CTX;

    if (!inputDataLen) /* No-op, return OK */
        goto exit;

    /* Make sure outputDataBufferLen has enough space */
    if (outputDataBufferLen < ( (pCtx->position + inputDataLen) / (pCtx->inputBlockLen) ) * pCtx->outputBlockLen)
        return ERR_BUFFER_TOO_SMALL;

    /* Process bytes leftover in pBuffer first */
    bytesNeeded = pCtx->inputBlockLen - pCtx->position;

    if (inputDataLen < bytesNeeded)
    {

        status = DIGI_MEMCPY( &(pCtx->pBuffer[pCtx->position]), pInputPtr, inputDataLen);
        if (OK != status)
            goto exit;

        pCtx->position += inputDataLen;
        goto exit;  /* no more data left anyway */

    }
    else
    {
        status = DIGI_MEMCPY( &(pCtx->pBuffer[pCtx->position]), pInputPtr, bytesNeeded);
        if (OK != status)
            goto exit;

        /* just process the one block in the buffer */
        if (pCtx->isEncrypt)
            status = ECEG_update_encrypt_block(MOC_ECC(hwAccelCtx) pCtx->pKey->pCurve, pCtx->pKey->Qx, pCtx->pKey->Qy, pCtx->rngFun, pCtx->pRngArg, pCtx->pBuffer, pOutputPtr);
        else
            status = ECEG_update_decrypt_block(MOC_ECC(hwAccelCtx) pCtx->pKey->pCurve, pCtx->pKey->k, pCtx->pBuffer, pOutputPtr);
        if (OK != status)
            goto exit;

        pInputPtr += bytesNeeded;
        bytesLeft -= bytesNeeded;

        pOutputPtr += pCtx->outputBlockLen;
        bytesWritten += pCtx->outputBlockLen;

        pCtx->position = 0;
    }

    /* Process as many more blocks as we can */
    while (bytesLeft >= pCtx->inputBlockLen)
    {
        if (pCtx->isEncrypt)
            status = ECEG_update_encrypt_block(MOC_ECC(hwAccelCtx) pCtx->pKey->pCurve, pCtx->pKey->Qx, pCtx->pKey->Qy, pCtx->rngFun, pCtx->pRngArg, pInputPtr, pOutputPtr);
        else
            status = ECEG_update_decrypt_block(MOC_ECC(hwAccelCtx) pCtx->pKey->pCurve, pCtx->pKey->k, pInputPtr, pOutputPtr);
        if (OK != status)
            goto exit;

        pInputPtr += pCtx->inputBlockLen;
        bytesLeft -= pCtx->inputBlockLen;

        pOutputPtr += pCtx->outputBlockLen;
        bytesWritten += pCtx->outputBlockLen;
    }

    /* Copy any leftovers to the buffer */
    if (bytesLeft)
    {
        status = DIGI_MEMCPY( pCtx->pBuffer, pInputPtr, bytesLeft);
        if (OK != status)
            goto exit;

        pCtx->position = bytesLeft;
    }

exit:

    *pBytesWritten = bytesWritten;

    pInputPtr = NULL;
    bytesNeeded = 0;
    bytesLeft = 0;
    pOutputPtr = NULL;
    bytesWritten = 0;

    return status;
}


MSTATUS ECEG_final(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, void *pExtCtx)
{
    MSTATUS status = OK;

    MOC_UNUSED(pExtCtx);

    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if ( !(pCtx->isInitialized) )
        return ERR_ECEG_UNINITIALIZED_CTX;

    if (pCtx->position)
        return ERR_ECEG_INVALID_INPUT_LEN;

    if (NULL != pCtx->pBuffer)
        status = DIGI_FREE((void **) &pCtx->pBuffer);

    /* keep status of the DIGI_FREE over that of the DIGI_MEMSET */
    DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(ECEG_CTX));

    return status;
}


/* Internal one shot method. Uses rngFun as a flag to handle Encrpyt instead of Decrypt */
static MSTATUS ECEG_one_shot_op(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, RNGFun rngFun, void *pRngArg, ubyte *pInput,
                                ubyte4 inputLen, ubyte **ppOutput, ubyte4 *pOutputLen, void *pExtCtx)
{
    MSTATUS status;
    ECEG_CTX ctx = {0};

    ubyte *pNewBuffer = NULL;
    ubyte4 newBufferLen = 0;
    ubyte4 bytesWritten = 0;

    /*
     Call ECEG_init in order to set the input/output block sizes.
     Validation of pKey handled by ECEG_init.
     */
    if (NULL != rngFun)
        status = ECEG_init(MOC_ECC(hwAccelCtx) &ctx, pKey, MOCANA_ECEG_ENCRYPT, rngFun, pRngArg, pExtCtx);
    else
        status = ECEG_init(MOC_ECC(hwAccelCtx) &ctx, pKey, MOCANA_ECEG_DECRYPT, NULL, NULL, pExtCtx);

    if (OK != status)
        goto exit;

    /* Now we can validate pInput, pinputLen etc */
    if ((NULL == pInput && inputLen) || NULL == ppOutput || NULL == pOutputLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* inputLen must be an non-zero multiple of the inputBlockLen */
    if (!inputLen || (inputLen % ctx.inputBlockLen) )
    {
        status = ERR_ECEG_INVALID_INPUT_LEN;
        goto exit;
    }

    /* output will be the number of blocks times the outputBlockLen */
    newBufferLen = (inputLen / ctx.inputBlockLen) * ctx.outputBlockLen;
    status = DIGI_MALLOC((void **) &pNewBuffer, newBufferLen);
    if (OK != status)
        goto exit;

    status = ECEG_update(MOC_ECC(hwAccelCtx) &ctx, pInput, inputLen, pNewBuffer, newBufferLen, &bytesWritten, pExtCtx);

exit:

    if (ctx.isInitialized)
    {   /* don't change status */
        ECEG_final(MOC_ECC(hwAccelCtx) &ctx, pExtCtx);
    }

    if (OK == status)
    {
        *ppOutput = pNewBuffer;
        *pOutputLen = bytesWritten;
        pNewBuffer = NULL;
    }
    else if (NULL != pNewBuffer)
    {   /* don't change status */
        DIGI_MEMSET(pNewBuffer, 0x00, newBufferLen);
        DIGI_FREE((void **) &pNewBuffer);
    }

    newBufferLen = 0;
    bytesWritten = 0;

    return status;
}


MSTATUS ECEG_encrypt(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPublicKey, RNGFun rngFun, void *pRngArg, ubyte *pPlaintext,
                     ubyte4 plaintextLen, ubyte **ppCiphertext, ubyte4 *pCiphertextLen, void *pExtCtx)
{
    /* Must have non-null rngFun. That will also serve as a flag for ECEG_one_shot_op to encrypt */
    if (NULL == rngFun)
        return ERR_NULL_POINTER;

    return ECEG_one_shot_op(MOC_ECC(hwAccelCtx) pPublicKey, rngFun, pRngArg, pPlaintext, plaintextLen, ppCiphertext, pCiphertextLen, pExtCtx);
}


MSTATUS ECEG_decrypt(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPrivateKey, ubyte *pCiphertext, ubyte4 ciphertextLen, ubyte **ppPlaintext, ubyte4 *pPlaintextLen, void *pExtCtx)
{
    return ECEG_one_shot_op(MOC_ECC(hwAccelCtx) pPrivateKey, NULL, NULL, pCiphertext, ciphertextLen, ppPlaintext, pPlaintextLen, pExtCtx);
}


MSTATUS ECEG_encryptPKCSv1p5(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPublicKey, RNGFun rngFun, void *pRngArg, ubyte *pPlaintext, ubyte4 plaintextLen, ubyte *pCiphertext, void *pExtCtx)
{
    MSTATUS status;
    ubyte4 inputBlockLen;
    ubyte4 numPaddingBytesNeeded;
    ubyte4 rngAttempts;
    sbyte4 rngStatus;
    ubyte *pPadded = NULL;
    ubyte *pPaddedPtr = NULL;

    MOC_UNUSED(pExtCtx);

    if (NULL == pPublicKey || NULL == rngFun || NULL == pPlaintext || NULL == pCiphertext)
        return ERR_NULL_POINTER;

    if (pPublicKey->privateKey)
        return ERR_ECEG_INVALID_KEY_TYPE;

    if (NULL == pPublicKey->Qx || NULL == pPublicKey->Qy || NULL == pPublicKey->pCurve)
        return ERR_ECEG_UNALLOCATED_KEY;

    inputBlockLen = (pPublicKey->pCurve->pPF->numBits+7)/8 - MOCANA_ECEG_CTR_LEN;

    if (!plaintextLen || plaintextLen > inputBlockLen - MOCANA_ECEG_PKCSV1P5_MIN_PADDING)
        return ERR_ECEG_INVALID_PLAINTEXT_LEN;

    /* allocate a buffer for the padded message */

    status = DIGI_CALLOC((void **)&pPadded, 1, inputBlockLen);
    if (OK != status)
        goto exit;

    /* first byte is already 0x00 */
    pPadded[1] = MOCANA_ECEG_PKCS1_V1P5_BT;

    pPaddedPtr = pPadded + 2; /* begin after the 0x00 and 0x02 Block types */
    numPaddingBytesNeeded = inputBlockLen - plaintextLen - 3;

    /* get numPaddingBytesNeeded nonzero random bytes */
    while (numPaddingBytesNeeded > 0)
    {
        rngAttempts = 0;
        do {
            /* Get one byte at a time and then check that it's non-zero */
            rngStatus = rngFun(pRngArg, 1, pPaddedPtr);
            rngAttempts++;
        }
        while (!(*pPaddedPtr) && !rngStatus && rngAttempts < ECEG_MAX_NONCE_CTR);

        if (rngStatus || rngAttempts >= ECEG_MAX_NONCE_CTR)
        {
            status = ERR_ECEG_INVALID_PRNG;
            goto exit;
        }

        pPaddedPtr++;
        numPaddingBytesNeeded--;
    }
    /* skip the next byte (which is already 0x00) */
    pPaddedPtr++;

    /* copy in the plaintext, no need to check return code */
    DIGI_MEMCPY(pPaddedPtr, pPlaintext, plaintextLen);

    status = ECEG_update_encrypt_block(MOC_ECC(hwAccelCtx) pPublicKey->pCurve, pPublicKey->Qx, pPublicKey->Qy, rngFun, pRngArg, pPadded, pCiphertext);

exit:

    if (NULL != pPadded)
    {
        /* don't change status, no need to check return codes */
        DIGI_MEMSET(pPadded, 0x00, inputBlockLen);
        DIGI_FREE((void **) &pPadded);
    }

    return status;
}


MOC_EXTERN MSTATUS ECEG_decryptPKCSv1p5(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPrivateKey, ubyte *pCiphertext, ubyte4 ciphertextLen, ubyte *pPlaintext, void *pExtCtx)
{
    MSTATUS status;
    ubyte4 paddingLen = 2; /* begin accounting for the 0x00 and 0x02 Block type bytes */
    ubyte4 coordLen;

    ubyte *pPadded = NULL;
    ubyte *pPaddedPtr = NULL;

    MOC_UNUSED(pExtCtx);

    if (NULL == pPrivateKey || NULL == pCiphertext || NULL == pPlaintext)
        return ERR_NULL_POINTER;

    if (!pPrivateKey->privateKey)
        return ERR_ECEG_INVALID_KEY_TYPE;

    if (NULL == pPrivateKey->pCurve || NULL == pPrivateKey->k)
        return ERR_ECEG_UNALLOCATED_KEY;

    coordLen = (pPrivateKey->pCurve->pPF->numBits+7)/8;

    if ( 4*coordLen != ciphertextLen )
        return ERR_ECEG_INVALID_CIPHERTEXT_LEN;

    /* Allocate memory for the recovered padded plaintext */
    status = DIGI_CALLOC((void **) &pPadded, 1, coordLen);
    if (OK != status)
        goto exit;

    status = ECEG_update_decrypt_block(MOC_ECC(hwAccelCtx) pPrivateKey->pCurve, pPrivateKey->k, pCiphertext, pPadded);
    if (OK != status)
        goto exit;

    /* Validate the pkcs v1.5 padding, try to remain constant time, begin after the 4 byte counter */
    pPaddedPtr = pPadded + MOCANA_ECEG_CTR_LEN;

    /* Validate pkcs v1.5 padding, don't go to exit on padding errors in order to remain constant time */
    if ( 0x00 != *pPaddedPtr)
        status = ERR_ECEG_INVALID_PKCS1_V1P5;

    pPaddedPtr++;
    if ( MOCANA_ECEG_PKCS1_V1P5_BT != *pPaddedPtr)
        status = ERR_ECEG_INVALID_PKCS1_V1P5;

    pPaddedPtr++;
    while (0x00 != (*pPaddedPtr) && paddingLen < coordLen - MOCANA_ECEG_CTR_LEN - 1)
    {
        pPaddedPtr++;
        paddingLen++;
    }

    /* Account for the single 0x00 padding byte */
    pPaddedPtr++;
    paddingLen++;

    if (paddingLen < MOCANA_ECEG_PKCSV1P5_MIN_PADDING)
        status = ERR_ECEG_INVALID_PKCS1_V1P5;

    if (paddingLen == coordLen - MOCANA_ECEG_CTR_LEN)
        status = ERR_ECEG_INVALID_PKCS1_V1P5;

    if ( status && (paddingLen < coordLen - MOCANA_ECEG_CTR_LEN) )
    {
        /* do a dummy copy */
        DIGI_MEMCPY(pPaddedPtr, pPaddedPtr, coordLen - MOCANA_ECEG_CTR_LEN - paddingLen);
    }
    else
    {
        /* We now point to the plain text, just copy to the output buffer */
        DIGI_MEMCPY(pPlaintext, pPaddedPtr, coordLen - MOCANA_ECEG_CTR_LEN - paddingLen);
    }

exit:

    if (NULL != pPadded)
    {
        /* don't change status, no need to check return codes */
        DIGI_MEMSET(pPadded, 0x00, coordLen);
        DIGI_FREE((void **) &pPadded);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ && __ENABLE_DIGICERT_ECC_ELGAMAL__ */
