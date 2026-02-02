/*
 * file scram_client.c
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"
#include "../common/initmocana.h"
#include "../common/base64.h"
#include "../crypto/mocasym.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/pkcs5.h"
#include "../crypto/hmac.h"
#include "../crypto/scram_client.h"
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_pkcs5.h"
#include "../crypto_interface/crypto_interface_hmac.h"
#endif

MOC_EXTERN MSTATUS digestData(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigestAlgo,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte **ppDigest,
    ubyte4 *pDigestLen
    );

static MSTATUS SCRAM_buildClientFinalEx(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    ScramCtx *pCtx,
    ubyte *pServerFirst,
    ubyte4 serverFirstLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte4 iterCount,
    ubyte hashType,
    ubyte **ppClientFinal,
    ubyte4 *pClientFinalLen);

#define SCRAM_MAX_HASH_LEN 64

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SCRAM_newCtx(ScramCtx **ppNewCtx)
{
    MSTATUS status;
    ScramCtx *pNewCtx = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == ppNewCtx)
        goto exit;

    status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(ScramCtx));
    if (OK != status)
        goto exit;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    return status;
}

MOC_EXTERN MSTATUS SCRAM_freeCtx(ScramCtx **ppScramCtx)
{
    MSTATUS status;
    ScramCtx *pCtx = NULL;

    if (NULL == ppScramCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = *ppScramCtx;
    if (NULL == pCtx)
    {
        status = OK;
        goto exit;
    }

    if (NULL != pCtx->pClientFirst)
    {
        DIGI_FREE((void **) &pCtx->pClientFirst);
    }
    if (NULL != pCtx->pAuthMsg)
    {
        DIGI_FREE((void **) &pCtx->pAuthMsg);
    }
    if (NULL != pCtx->pSalt)
    {
        DIGI_FREE((void **) &pCtx->pSalt);
    }

    DIGI_FREE((void **) ppScramCtx);

    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SCRAM_buildClientFirstData(
    ScramCtx *pCtx,
    char *pUsername,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte **ppClientFirst,
    ubyte4 *pClientFirstLen)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte *pBuf = NULL;
    ubyte4 bufLen = 0;
    ubyte *pIter = NULL;

    if (0 == nonceLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* n,,n=${user},r=${nonce} */
    bufLen = 5 + DIGI_STRLEN((const sbyte *) pUsername) + 3 + nonceLen;

    status = DIGI_MALLOC((void **)&pBuf, bufLen);
    if (OK != status)
        goto exit;

    pIter = pBuf;

    /* No channel binding, no authzid at this time */
    *pIter = 'n'; pIter++;
    *pIter = ','; pIter++;
    *pIter = ','; pIter++;
    *pIter = 'n'; pIter++;
    *pIter = '='; pIter++;

    status = DIGI_MEMCPY(pIter, pUsername, DIGI_STRLEN((const sbyte *) pUsername));
    if (OK != status)
        goto exit;

    pIter += DIGI_STRLEN((const sbyte *) pUsername);

    *pIter = ','; pIter++;
    *pIter = 'r'; pIter++;
    *pIter = '='; pIter++;

    if (NULL != pNonce)
    {
        /* Check for any invalid characters */
        for (i = 0; i < nonceLen; i++)
        {
            if (FALSE == DIGI_ISASCII(pNonce[i]) || pNonce[i] == ',')
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }
        }

        /* Use caller provided nonce */
        DIGI_MEMCPY(pIter, pNonce, nonceLen);
    }
    else
    {
        /* Generate our own nonce using the caller provided length */
        status = RANDOM_generateASCIIString(g_pRandomContext, pIter, nonceLen);
        if (OK != status)
            goto exit;

        /* Replace any invalid characters */
        for (i = 0; i < nonceLen; i++)
        {
            while (pIter[i] == ',')
            {
                status = RANDOM_generateASCIIString(g_pRandomContext, pIter + i, 1);
                if (OK != status)
                    goto exit;
            }
        }
    }

    /* Store clientfirst in ctx */
    pCtx->pClientFirst = pBuf;
    pCtx->clientFirstLen = bufLen;
    *ppClientFirst = pBuf;
    *pClientFirstLen = bufLen;
    pBuf = NULL;
    
exit:

    if (NULL != pBuf)
    {
        DIGI_FREE((void **)&pBuf);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS SCRAM_parseServerFirst (
    ubyte *pData, 
    ubyte4 dataLen, 
    ubyte **ppServerNonce, 
    ubyte4 *pServerNonceLen, 
    ubyte **ppSalt, 
    ubyte4 *pSaltLen, 
    ubyte4 *pIterCount)
{
    MSTATUS status;
    ubyte *pSalt = NULL;
    ubyte4 saltLen = 0;
    ubyte *pIter = pData;
    ubyte4 len = 0;
    ubyte4 iterCount = 0;
    MOC_UNUSED(dataLen);

    /* r=${nonce},s=${salt},i=${itercount} */
    status = ERR_INVALID_INPUT;
    if (*pIter != 'r')
        goto exit;

    pIter++;
    if (*pIter != '=')
        goto exit;

    pIter++;

    *ppServerNonce = pIter;
    while(TRUE)
    {
        if (',' == *pIter)
        {
            break;
        }

        pIter++;
        len++;
    }

    *pServerNonceLen = len;

    pIter++;
    if (*pIter != 's')
        goto exit;

    pIter++;
    if (*pIter != '=')
        goto exit;

    pIter++;

    len = 0;
    pSalt = pIter;
    while(TRUE)
    {
        if (',' == *pIter)
        {
            break;
        }

        pIter++;
        len++;
    }

    saltLen = len;

    status = BASE64_decodeMessage(pSalt, saltLen, ppSalt, pSaltLen);
    if (OK != status)
        goto exit;

    pIter++;
    if (*pIter != 'i')
        goto exit;

    pIter++;
    if (*pIter != '=')
        goto exit;

    pIter++;

    iterCount = (ubyte4)DIGI_ATOL((const sbyte *)pIter, NULL);
    *pIterCount = iterCount;
    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SCRAM_buildClientFinal(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    ScramCtx *pCtx,
    ubyte *pServerFirst,
    ubyte4 serverFirstLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    ubyte hashType,
    ubyte **ppClientFinal,
    ubyte4 *pClientFinalLen)
{
    MSTATUS status;
    ubyte *pNonce = NULL;
    ubyte4 nonceLen = 0;
    ubyte *pSalt = NULL;
    ubyte4 saltLen = 0;
    ubyte4 iterCount = 0;

    status = SCRAM_parseServerFirst(pServerFirst, serverFirstLen, &pNonce, &nonceLen,
        &pSalt, &saltLen, &iterCount);
    if (OK != status)
        goto exit;

    status = SCRAM_buildClientFinalEx (MOC_HASH(hwAccelCtx)
        pCtx, pServerFirst, serverFirstLen, pPassword, passwordLen, pNonce, nonceLen,
        pSalt, saltLen, iterCount, hashType, ppClientFinal, pClientFinalLen);

exit:
    if (pSalt != NULL) {
        DIGI_FREE((void **) &pSalt);
    }

    return status;
}

static MSTATUS SCRAM_buildClientFinalEx(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    ScramCtx *pCtx,
    ubyte *pServerFirst,
    ubyte4 serverFirstLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte4 iterCount,
    ubyte hashType,
    ubyte **ppClientFinal,
    ubyte4 *pClientFinalLen)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 hashLen = 0;
    ubyte *pBuf = NULL;
    ubyte4 bufLen = 0;
    ubyte *pStoredKey = NULL;
    ubyte4 storedKeyLen = 0;
    ubyte *pAuth = NULL;
    ubyte4 authLen = 0;
    ubyte *pBase64Proof = NULL;
    ubyte4 base64ProofLen = 0;
    ubyte *pIter = NULL;
    BulkHashAlgo *pHashAlgo = NULL;
    ubyte saltedPass[SCRAM_MAX_HASH_LEN];
    ubyte clientKey[SCRAM_MAX_HASH_LEN];
    ubyte clientSig[SCRAM_MAX_HASH_LEN];
    ubyte clientProof[SCRAM_MAX_HASH_LEN];

    switch(hashType)
    {
        case ht_sha1:
            hashLen = 20;
            break;
        
        case ht_sha224:
            hashLen = 28;
            break;

        case ht_sha256:
            hashLen = 32;
            break;

        case ht_sha384:
            hashLen = 48;
            break;

        case ht_sha512:
            hashLen = 64;
            break;

        default:
        {
            status = ERR_INVALID_INPUT;
            goto exit;   
        }     
    }

    /* Make a copy of the salt for the final verification of the server signature later */
    status = DIGI_MALLOC_MEMCPY((void **)&(pCtx->pSalt), saltLen, pSalt, saltLen);
    if (OK != status)
        goto exit;
    pCtx->saltLen = saltLen;

    pCtx->iterCount = iterCount;
    pCtx->hashType = hashType;
    pCtx->hashLen = hashLen;

    /* SaltedPassword  := Hi(Normalize(password), salt, i) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx)
        pSalt, saltLen, iterCount, hashType, pPassword, passwordLen,
        hashLen, (ubyte *)saltedPass);
    if (OK != status)
        goto exit;
#else
    status = PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx)
        pSalt, saltLen, iterCount, hashType, pPassword, passwordLen,
        hashLen, (ubyte *)saltedPass);
    if (OK != status)
        goto exit;
#endif

    status = CRYPTO_getRSAHashAlgo(hashType, (const BulkHashAlgo **)&pHashAlgo);
    if (OK != status)
        goto exit;

    /* ClientKey := HMAC(SaltedPassword, "Client Key") */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
   status = CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx)
        (ubyte *)saltedPass, hashLen, (const ubyte *) "Client Key", DIGI_STRLEN((const sbyte *) "Client Key"),
        (ubyte *)clientKey, pHashAlgo);
    if (OK != status)
        goto exit;
#else
    status = HmacQuick(MOC_HASH(hwAccelCtx)
        (ubyte *)saltedPass, hashLen, (const ubyte *) "Client Key", DIGI_STRLEN((const sbyte *) "Client Key"),
        (ubyte *)clientKey, pHashAlgo);
    if (OK != status)
        goto exit;
#endif

    /* StoredKey := H(ClientKey) */
    status = digestData(MOC_HASH(hwAccelCtx) pHashAlgo, (ubyte *)clientKey, hashLen, &pStoredKey, &storedKeyLen);
    if (OK != status)
        goto exit;

    /* AuthMessage := client-first-message-bare + "," +
                      server-first-message + "," +
                      client-final-message-without-proof */
    authLen = (pCtx->clientFirstLen - 3) + 1 + serverFirstLen + 1 + 9 + nonceLen;

    status = DIGI_MALLOC((void **)&pAuth, authLen);
    if (OK != status)
        goto exit;

    pIter = pAuth;

    /* This memcpy offset logic assumes no channel binding */
    status = DIGI_MEMCPY(pIter, (pCtx->pClientFirst + 3), pCtx->clientFirstLen - 3);
    if (OK != status)
        goto exit;

    pIter += pCtx->clientFirstLen - 3;

    *pIter = ','; pIter++;
    status = DIGI_MEMCPY(pIter, pServerFirst, serverFirstLen);
    if (OK != status)
        goto exit;

    pIter += serverFirstLen;
    *pIter = ','; pIter++;

    /* Default channel binding */
    *pIter = 'c'; pIter++;
    *pIter = '='; pIter++;
    *pIter = 'b'; pIter++;
    *pIter = 'i'; pIter++;
    *pIter = 'w'; pIter++;
    *pIter = 's'; pIter++;
    *pIter = ','; pIter++;

    /* nonce in client-final-message-without-proof */
    *pIter = 'r'; pIter++;
    *pIter = '='; pIter++;
    status = DIGI_MEMCPY(pIter, pNonce, nonceLen);
    if (OK != status)
        goto exit;

    /* ClientSignature := HMAC(StoredKey, AuthMessage) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx)
        pStoredKey, storedKeyLen, pAuth, authLen, (ubyte *)clientSig, pHashAlgo);
    if (OK != status)
        goto exit;
#else
    status = HmacQuick(MOC_HASH(hwAccelCtx)
        pStoredKey, storedKeyLen, pAuth, authLen, (ubyte *)clientSig, pHashAlgo);
    if (OK != status)
        goto exit;
#endif

    /* Transfer ownership to the context, we will need the auth message
     * to verify the final server data */
    pCtx->pAuthMsg = pAuth; pAuth = NULL;
    pCtx->authMsgLen = authLen;

    /* ClientProof := ClientKey XOR ClientSignature */
    for (i = 0; i < hashLen; i++)
    {
        clientProof[i] = clientKey[i] ^ clientSig[i];
    }

    status = BASE64_encodeMessage((ubyte *)clientProof, hashLen, &pBase64Proof, &base64ProofLen);
    if (OK != status)
        goto exit;

    /* c=biws,r=${nonce},p=${proof} */
    bufLen = 9 + nonceLen + 1 + 2 + base64ProofLen;

    status = DIGI_MALLOC((void **)&pBuf, bufLen);
    if (OK != status)
        goto exit;

    pIter = pBuf;
    *pIter = 'c'; pIter++;
    *pIter = '='; pIter++;
    *pIter = 'b'; pIter++;
    *pIter = 'i'; pIter++;
    *pIter = 'w'; pIter++;
    *pIter = 's'; pIter++;
    *pIter = ','; pIter++;
    *pIter = 'r'; pIter++;
    *pIter = '='; pIter++;
    status = DIGI_MEMCPY(pIter, pNonce, nonceLen);
    if (OK != status)
        goto exit;

    pIter += nonceLen;
    *pIter = ','; pIter++;
    *pIter = 'p'; pIter++;
    *pIter = '='; pIter++;
    status = DIGI_MEMCPY(pIter, pBase64Proof, base64ProofLen);
    if (OK != status)
        goto exit;

    *ppClientFinal = pBuf;
    *pClientFinalLen = bufLen;
    pBuf = NULL;
    pIter = NULL;
    
exit:

    if (NULL != pAuth)
    {
        DIGI_FREE((void **)&pAuth);
    }
    if (NULL != pBuf)
    {
        DIGI_FREE((void **)&pBuf);
    }
    if (NULL != pStoredKey)
    {
        DIGI_FREE((void **)&pStoredKey);
    }
    if (NULL != pBase64Proof)
    {
        DIGI_FREE((void **)&pBase64Proof);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SCRAM_verifyServerSignature(MOC_HASH(hwAccelDescr hwAccelCtx) ScramCtx *pCtx, ubyte *pPassword, ubyte4 passwordLen, ubyte *pServerFinal, ubyte4 serverFinalLen, byteBoolean *pVerify)
{
    MSTATUS status;
    ubyte saltedPass[SCRAM_MAX_HASH_LEN];
    ubyte serverKey[SCRAM_MAX_HASH_LEN];
    ubyte serverSig[SCRAM_MAX_HASH_LEN];
    ubyte *pIter = pServerFinal;
    ubyte *pServerSig = NULL;
    ubyte4 serverSigLen = 0;
    BulkHashAlgo *pHashAlgo = NULL;
    sbyte4 cmp = -1;
    
    if ( (NULL == pCtx) || (NULL == pServerFinal) || (NULL == pVerify) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pVerify = FALSE;

    /* v=${serversig} */
    status = ERR_INVALID_INPUT;
    if (*pIter != 'v')
        goto exit;

    pIter++;
    if (*pIter != '=')
        goto exit;

    pIter++;
    status = BASE64_decodeMessage(pIter, serverFinalLen - 2, &pServerSig, &serverSigLen);
    if (OK != status)
        goto exit;

    /* SaltedPassword  := Hi(Normalize(password), salt, i) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx)
        pCtx->pSalt, pCtx->saltLen, pCtx->iterCount, pCtx->hashType, pPassword, passwordLen,
        pCtx->hashLen, (ubyte *)saltedPass);
    if (OK != status)
        goto exit;
#else
    status = PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelCtx)
        pCtx->pSalt, pCtx->saltLen, pCtx->iterCount, pCtx->hashType, pPassword, passwordLen,
        pCtx->hashLen, (ubyte *)saltedPass);
    if (OK != status)
        goto exit;
#endif

    status = CRYPTO_getRSAHashAlgo(pCtx->hashType, (const BulkHashAlgo **)&pHashAlgo);
    if (OK != status)
        goto exit;

    /* ServerKey := HMAC(SaltedPassword, "Server Key") */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx)
        (ubyte *)saltedPass, pCtx->hashLen, (const ubyte *) "Server Key", DIGI_STRLEN((const sbyte *) "Server Key"),
        (ubyte *)serverKey, pHashAlgo);
    if (OK != status)
        goto exit;
#else
    status = HmacQuick(MOC_HASH(hwAccelCtx)
        (ubyte *)saltedPass, pCtx->hashLen, (const ubyte *) "Server Key", DIGI_STRLEN((const sbyte *) "Server Key"),
        (ubyte *)serverKey, pHashAlgo);
    if (OK != status)
        goto exit;
#endif

    /* ServerSignature := HMAC(ServerKey, AuthMessage) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx)
        serverKey, pCtx->hashLen, pCtx->pAuthMsg, pCtx->authMsgLen, (ubyte *)serverSig, pHashAlgo);
    if (OK != status)
        goto exit;
#else
    status = HmacQuick(MOC_HASH(hwAccelCtx)
        serverKey, pCtx->hashLen, pCtx->pAuthMsg, pCtx->authMsgLen, (ubyte *)serverSig, pHashAlgo);
    if (OK != status)
        goto exit;
#endif

    status = DIGI_MEMCMP(serverSig, pServerSig, serverSigLen, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        status = ERR_CMP;
        goto exit;
    }
    else
    {
        *pVerify = TRUE;
    }

exit:
    if (pServerSig != NULL) {
        DIGI_FREE((void **) &pServerSig);
    }
    return status;    
}
#endif
