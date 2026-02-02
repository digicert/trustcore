/*
 * crypto_interface_rsa_test.c
 *
 * test cases for crypto interface API in rsa.h and pkcs1.h
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
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/crypto.h"
#include "../../crypto/rsa.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto_interface/crypto_interface_random.h"
#include "../../crypto/test/nonrandop.h"
#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
/* headers needed for speed test */
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdio.h>

/* number of iterations for each test */
#define SIGN_ITERATIONS         1000
#define VERIFY_ITERATIONS       10000
#define SERIALIZE_ITERATIONS    1000
#define DESERIALIZE_ITERATIONS  10000

#endif

#include "rsa_pss_sign_vectors_long_inc.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static MSTATUS testRsaTwoEqual(RSAKey *, RSAKey *, ubyte4);

static MSTATUS testTwoRsa(
    RSAKey *pKey1,
    RSAKey *pKey2,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 keyLen,
    ubyte hashId
);

/*----------------------------------------------------------------------------*/

static MSTATUS performHash(
    ubyte hashId,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte **ppOutput,
    ubyte4 *pOutLen
    )
{
    MSTATUS status, fstatus;
	const BulkHashAlgo *pHashAlgo = NULL;
	BulkCtx pCtx = NULL;
	ubyte *pOutput = NULL;

	status = CRYPTO_getRSAHashAlgo( hashId, &pHashAlgo);
	if (OK != status)
		goto exit;

	status = DIGI_MALLOC((void **) &pOutput, pHashAlgo->digestSize);
	if (OK != status)
		goto exit;
	
	status = pHashAlgo->allocFunc(MOC_HASH(gpHwAccelCtx) &pCtx);
	if (OK != status)
		goto exit;
	
	status = pHashAlgo->initFunc(MOC_HASH(gpHwAccelCtx) pCtx);
	if (OK != status)
		goto exit;
	
	status = pHashAlgo->updateFunc(MOC_HASH(gpHwAccelCtx) pCtx, pData, dataLen);
	if (OK != status)
		goto exit;
	
	status = pHashAlgo->finalFunc(MOC_HASH(gpHwAccelCtx) pCtx, pOutput);
	if (OK != status)
		goto exit;
	
	*ppOutput = pOutput; pOutput = NULL;
	*pOutLen = pHashAlgo->digestSize;
	
exit:
	
	if (NULL != pHashAlgo && NULL != pCtx)
	{
	    fstatus = pHashAlgo->freeFunc(MOC_HASH(gpHwAccelCtx) &pCtx);
		if (OK == status)
			status = fstatus;
	}
	
	if (NULL != pOutput)
	{
		DIGI_FREE((void **) &pOutput); /* error only, no need to change status */
	}
	
	return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS keyFromByteTest(ubyte4 keyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    /* this key will beused to generate an rsa key */
    RSAKey *pKey1 = NULL;
    /* variable that we will use to store byte string generated key */
    RSAKey *pKey2 = NULL;

    /* variables for key byte string */
    ubyte * pKeyData1 = NULL;
    ubyte4 keyData1Len = 0;

    /* create shell for RSA key object */
    status = RSA_createKey(&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* generate key material */
    status = RSA_generateKey(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pKey1, keyLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get the length required for byte buffer */
    status = RSA_byteStringFromKey(MOC_RSA(gpHwAccelCtx) pKey1, pKeyData1, &keyData1Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Allocate memory for buffer */
    status = DIGI_MALLOC((void **) &pKeyData1, keyData1Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get the byte string from RSAKey object */
    status = RSA_byteStringFromKey(MOC_RSA(gpHwAccelCtx) pKey1, pKeyData1, &keyData1Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* generate a key using byte string from previous call */
    status = RSA_keyFromByteString(MOC_RSA(gpHwAccelCtx) &pKey2, pKeyData1, keyData1Len, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* check if key generated from byte string is same as original */
    status = testRsaTwoEqual(pKey1, pKey2, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pKeyData1)
    {
        DIGI_FREE((void **) &pKeyData1);
    }
    if (NULL != pKey1)
    {
        RSA_freeKey(&pKey1, NULL);
    }
    if (NULL != pKey2)
    {
        RSA_freeKey(&pKey2, NULL);
    }

    if (OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static MSTATUS getRsaPubsFromPris(
    RSAKey *pKey1,
    RSAKey *pKey2,
    RSAKey **ppNewPubKey1,
    RSAKey **ppNewPubKey2
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MRsaKeyTemplate template1;
    MRsaKeyTemplate template2;

    /* Get public key information */
    status = RSA_getKeyParametersAlloc(MOC_RSA(gpHwAccelCtx) pKey1, &template1,
                                       MOC_GET_PUBLIC_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_getKeyParametersAlloc(MOC_RSA(gpHwAccelCtx) pKey2, &template2,
                                       MOC_GET_PUBLIC_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* create RSAKey object with just public key information */
    status = RSA_createKey(ppNewPubKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) *ppNewPubKey1, template1.pE,
                                  template1.eLen,
                                  template1.pN, template1.nLen,
                                  NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_createKey(ppNewPubKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) *ppNewPubKey2, template2.pE,
                                  template2.eLen,
                                  template2.pN, template2.nLen,
                                  NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

exit:
    RSA_freeKeyTemplate(NULL, &template1);
    RSA_freeKeyTemplate(NULL, &template2);
    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS testRsaEncryptDecrypt(
    RSAKey *pDecryptKey,
    RSAKey *pEncryptKey,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pCipherText,
    ubyte4 cipherTextLen,
    ubyte hashId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPlainText = NULL;
    ubyte4 plainTextLen = 0;
    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;
    sbyte4 cmpRes = -1;

    /* take message, and return der encoded digestInfo object */
    status = performHash(hashId, pData, dataLen, &pDigest,
                        &digestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* will encrypt the digestInfo object with the public key of
     * the encrypt key */
    status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pEncryptKey, pDigest, digestLen, pCipherText,
        RANDOM_rngFun, g_pRandomContext, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /** buffer where result of decryption is stored.
     *  Has to be same size as cipher text buffer. */
    status = DIGI_MALLOC((void *) &pPlainText, cipherTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /** Decrypt cipher text and store result in pPlainText buffer.
     * Number of bytes written will be stored in plainTextLen. */
    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pDecryptKey, pCipherText, pPlainText, &plainTextLen,
        RANDOM_rngFun, g_pRandomContext, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* check if expected # of bytes were written */
    if (plainTextLen != digestLen)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCMP(pPlainText, pDigest, plainTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* clear plainText buffer for negative test */
    status = DIGI_MEMSET(pPlainText, 0, plainTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* alter the value of the cipher text to show decryption will fail */
    pCipherText[0]++;

    /* check that incorrect cipher text will fail */
    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pDecryptKey, pCipherText, pPlainText, &plainTextLen,
        RANDOM_rngFun, g_pRandomContext, NULL);
    /* crypto interface returns ERR_MBED_FAILURE on bad decrypt
     * and the other two runs return ERR_RSA_DECRYPTION */
    if ((ERR_RSA_DECRYPTION != status) && (ERR_MBED_FAILURE != status))
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    cmpRes = 0;
    status = DIGI_MEMCMP(pPlainText, pDigest, digestLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* The values should not have been the same */
    if (0 == cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pPlainText)
    {
        DIGI_FREE((void **) &pPlainText);
    }
    if (NULL != pDigest)
    {
        DIGI_FREE((void **) &pDigest);
    }
    if (NULL != pCipherText)
    {
        /* zero out buffer so we can re-use it */
        DIGI_MEMSET(pCipherText, 0, cipherTextLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS testRsaTwoEncyptDecrypt(
    RSAKey *pKey1,
    RSAKey *pKey2,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte * pCipherText = NULL;
    sbyte4 cipherTextLen = 0;

    RSAKey *pPubKey1 = NULL;
    RSAKey *pPubKey2 = NULL;
    /* This function gets the size of the cipher text buffer needed */
    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey1, &cipherTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Allocate memory for cipher text buffer */
    status = DIGI_MALLOC((void **) &pCipherText, cipherTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* decrypt with key1, encrypt with key2 */
    status = testRsaEncryptDecrypt(pKey1, pKey2, pData, dataLen,
        pCipherText, cipherTextLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* decrypt with key2, encrypt with key1 */
    status = testRsaEncryptDecrypt(pKey2, pKey1, pData, dataLen,
        pCipherText, cipherTextLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get key objects that only contain the public key so we can
     * test encryption/decryption seperate key objects. */
    status = getRsaPubsFromPris(pKey1, pKey2, &pPubKey1, &pPubKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaEncryptDecrypt(pKey1, pPubKey1, pData, dataLen, pCipherText,
                               cipherTextLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaEncryptDecrypt(pKey2, pPubKey2, pData, dataLen, pCipherText,
                               cipherTextLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaEncryptDecrypt(pKey1, pPubKey2, pData, dataLen, pCipherText,
                               cipherTextLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaEncryptDecrypt(pKey2, pPubKey1, pData, dataLen, pCipherText,
                               cipherTextLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pCipherText)
    {
        DIGI_FREE((void **) &pCipherText);
    }
    if (NULL != pPubKey1)
    {
        RSA_freeKey(&pPubKey1, NULL);
    }
    if (NULL != pPubKey2)
    {
        RSA_freeKey(&pPubKey2, NULL);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS testRsaSignVerify(
    RSAKey *pSignKey,
    RSAKey *pVerifyKey,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pSig,
    ubyte4 sigLen,
    ubyte hashId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPlainText = NULL;
    ubyte4 plainTextLen = 0;
    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;
    sbyte4 cmpRes = -1;

    /* take message, and return der encoded digestInfo object */
    status = performHash(hashId, pData, dataLen, &pDigest,
                        &digestLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* sign the digestInfo object */
    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pSignKey, pDigest, digestLen, pSig, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /** buffer where result of signature verification is stored.
     *  Has to be same size as signature buffer.
     * */
    status = DIGI_MALLOC((void *) &pPlainText, sigLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /** Compute value of result from applying public key to signature buffer.
     * */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pVerifyKey, pSig, pPlainText, &plainTextLen,
                                 NULL);

    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* compare result of verification with original digestInfo object signed */
    if (plainTextLen != digestLen)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCMP(pPlainText, pDigest, plainTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* clear plainText buffer for negative test */
    status = DIGI_MEMSET(pPlainText, 0, plainTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* alter the value of the signature to show verification will fail */
    pSig[0]++;

    /* check that bad signature will fail */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pVerifyKey, pSig, pPlainText, &plainTextLen,
        NULL);
    /* crypto interface returns ERR_MBED_FAILURE on bad decrypt
     * and the other two runs return ERR_RSA_DECRYPTION */
    if ((ERR_RSA_DECRYPTION != status) && (ERR_MBED_FAILURE != status))
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    cmpRes = 0;
    status = DIGI_MEMCMP(pPlainText, pDigest, digestLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* The values should not have been the same */
    if (0 == cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pPlainText)
    {
        DIGI_FREE((void **) &pPlainText);
    }
    if (NULL != pDigest)
    {
        DIGI_FREE((void **) &pDigest);
    }
    if (NULL != pSig)
    {
        /* zero out buffer so we can re-use it */
        DIGI_MEMSET(pSig, 0, sigLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS testRsaTwoSignVerify(
    RSAKey *pKey1,
    RSAKey *pKey2,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte * pSig = NULL;
    sbyte4 sigLen = 0;

    RSAKey *pPubKey1 = NULL;
    RSAKey *pPubKey2 = NULL;
    /* This function gets the size of the signature needed */
    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey1, &sigLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Allocate memory for signature buffer */
    status = DIGI_MALLOC((void **) &pSig, sigLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Sign with key1, verify with key2 */
    status = testRsaSignVerify(pKey1, pKey2, pData, dataLen, pSig, sigLen,
                               hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Sign with key2, verify with key1 */
    status = testRsaSignVerify(pKey2, pKey1, pData, dataLen, pSig, sigLen,
                               hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get public keys so we can test signature verification */
    status = getRsaPubsFromPris(pKey1, pKey2, &pPubKey1, &pPubKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaSignVerify(pKey1, pPubKey1, pData, dataLen, pSig,
                               sigLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaSignVerify(pKey2, pPubKey2, pData, dataLen, pSig,
                               sigLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaSignVerify(pKey1, pPubKey2, pData, dataLen, pSig,
                               sigLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaSignVerify(pKey2, pPubKey1, pData, dataLen, pSig,
                               sigLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **) &pSig);
    }
    if (NULL != pPubKey1)
    {
        RSA_freeKey(&pPubKey1, NULL);
    }
    if (NULL != pPubKey2)
    {
        RSA_freeKey(&pPubKey2, NULL);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS testRsaTwoEqual(
    RSAKey *pKey1,
    RSAKey *pKey2,
    ubyte4 keyLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    byteBoolean res = FALSE;
    RSAKey *pNewKey1 = NULL;
    RSAKey *pNewKey2 = NULL;

    status = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pKey1, pKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = RSA_cloneKey(MOC_RSA(gpHwAccelCtx) &pNewKey1, pKey1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_cloneKey(MOC_RSA(gpHwAccelCtx) &pNewKey2, pKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    res = FALSE;
    status = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pKey1, pNewKey1, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pKey2, pNewKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pKey1, pNewKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pKey2, pNewKey1, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    res = FALSE;
    status = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pNewKey1, pNewKey2, &res);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (FALSE == res)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = RSA_freeKey(&pNewKey1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (NULL != pNewKey1)
    {
        status = ERR_MEM_FREE_PTR;

    }

    status = RSA_freeKey(&pNewKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
exit:
    return status;
}

/*----------------------------------------------------------------------------*/

static int setKeyParameters(
    RSAKey *pKey1,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId,
    ubyte4 keyLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RSAKey *pKey2 = NULL;
    RSAKey *pPubKey1 = NULL;
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;
    MRsaKeyTemplate template1;
    ubyte4 pubExpo = 0;

    /* get key data  to use setAllKeyParameters with */
    status = RSA_getKeyParametersAlloc(MOC_RSA(gpHwAccelCtx) pKey1, &template1,
                                       MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* convert a bytestring representation of public exponent */
    if (template1.eLen == 4)
    {
        pubExpo = (pubExpo | template1.pE[0]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[1]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[2]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[3]);
    } else if (template1.eLen == 3)
    {
        pubExpo = (pubExpo | template1.pE[0]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[1]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[2]);

    } else if (template1.eLen == 2)
    {
        pubExpo = (pubExpo | template1.pE[0]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[1]);

    } else if (template1.eLen == 1)
    {
        pubExpo = (pubExpo | template1.pE[0]);
    }

    status = RSA_createKey(&pKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pKey2, pubExpo,
                                     template1.pN, template1.nLen,
                                     template1.pP,
                                     template1.pLen, template1.pQ,
                                     template1.qLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = testRsaTwoEqual(pKey1, pKey2, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = testTwoRsa(pKey1, pKey2, pData, dataLen, keyLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* free pKey2 so we can reuse it */
    status = RSA_freeKey(&pKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* free template so we can reuse it */
    status = RSA_freeKeyTemplate(pKey1, &template1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* get a template with just the public key */
    status = RSA_getKeyParametersAlloc(MOC_RSA(gpHwAccelCtx) pKey1, &template1,
                                       MOC_GET_PUBLIC_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = RSA_createKey(&pPubKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    pubExpo = 0;
    if (template1.eLen == 4)
    {
        pubExpo = (pubExpo | template1.pE[0]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[1]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[2]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[3]);
    } else if (template1.eLen == 3)
    {
        pubExpo = (pubExpo | template1.pE[0]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[1]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[2]);

    } else if (template1.eLen == 2)
    {
        pubExpo = (pubExpo | template1.pE[0]);
        pubExpo = (pubExpo << 8);
        pubExpo = (pubExpo | template1.pE[1]);

    } else if (template1.eLen == 1)
    {
        pubExpo = (pubExpo | template1.pE[0]);
    }

    /* populate public key object with exponent and modulus */
    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey1, pubExpo, template1.pN,
                                        template1.nLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* This function gets the size of the signature needed */
    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey1, (sbyte4*)&sigLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Allocate memory for signature buffer */
    status = DIGI_MALLOC((void **) &pSig, sigLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testRsaSignVerify(pKey1, pPubKey1, pData, dataLen, pSig,
                               sigLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

exit:

    RSA_freeKeyTemplate(NULL, &template1);

    if (NULL != pSig)
    {
        DIGI_FREE((void **) &pSig);
    }
    if (NULL != pPubKey1)
    {
        RSA_freeKey(&pPubKey1, NULL);
    }

    if (OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static MSTATUS testTwoRsa(
    RSAKey *pKey1,
    RSAKey *pKey2,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 keyLen,
    ubyte hashId
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    status = testRsaTwoEqual(pKey1, pKey2, keyLen);
    if (OK != status)
        goto exit;

    status = testRsaTwoSignVerify(pKey1, pKey2, pData, dataLen, hashId);
    if (OK != status)
        goto exit;

    status = testRsaTwoEncyptDecrypt(pKey1, pKey2, pData, dataLen, hashId);

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

static int rsaFunctionalTests(
    ubyte4 keyLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RSAKey *pKey1 = NULL;
    RSAKey *pKey2 = NULL;
    MRsaKeyTemplate template1;

    AsymmetricKey asymKey1;
    AsymmetricKey asymKey2;
    ubyte *pSerialData = NULL;
    ubyte4 serialLen = 0;
    MKeySerialize pSupported[1] = {
        KeySerializeRsa
    };

    /* generate key for testing */
    status = RSA_createKey(&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_generateKey(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pKey1, keyLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Clone pKey1 */
    status = RSA_cloneKey(MOC_RSA(gpHwAccelCtx) &pKey2, pKey1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* test the cloned key against original */
	status = testTwoRsa(pKey1, pKey2, pData, dataLen, keyLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_freeKey(&pKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Have to wait for RSA_getKeyParametersAlloc to be done */
    status = RSA_getKeyParametersAlloc(MOC_RSA(gpHwAccelCtx) pKey1, &template1,
                                       MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Create shell for other key */
    status = RSA_createKey(&pKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* set values of pKey2 using template we generated with pKey1 */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pKey2, template1.pE, template1.eLen,
                               template1.pN, template1.nLen,
                               template1.pP,
                               template1.pLen, template1.pQ,
                               template1.qLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* test the template generated key against original */
    status = testTwoRsa(pKey1, pKey2, pData, dataLen, keyLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = setKeyParameters(pKey1, pData, dataLen, hashId, keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    status = keyFromByteTest(keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
    {
        goto exit;
    }

    /* Test serialization */
    status = CRYPTO_initAsymmetricKey(&asymKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymKey1, akt_rsa, (void **)&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
        &asymKey1, pSupported, 1, privateKeyInfoDer, &pSerialData, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pSerialData, serialLen, pSupported, 1, &asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = testTwoRsa(asymKey1.key.pRSA, asymKey2.key.pRSA, pData,
        dataLen, keyLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* uniitialize key 2 so we can reuse it for seralizing as a digicert blob */
    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* Free blob so we can reuse it */
    status = DIGI_FREE((void **)&pSerialData);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* init asymKey2 for digicert blob */
    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
        &asymKey1, pSupported, 1, mocanaBlobVersion2, &pSerialData, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
        pSerialData, serialLen, pSupported, 1, &asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = testTwoRsa(asymKey1.key.pRSA, asymKey2.key.pRSA, pData,
        dataLen, keyLen, hashId);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_uninitAsymmetricKey(&asymKey1, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = DIGI_FREE((void **)&pSerialData);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

exit:

    RSA_freeKeyTemplate(NULL, &template1);

    if (NULL != pKey1)
    {
        RSA_freeKey(&pKey1, NULL);
    }
    if (NULL != pKey2)
    {
        RSA_freeKey(&pKey2, NULL);
    }

    if (OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int rsaTest()
{
    MSTATUS status = ERR_NULL_POINTER;

    unsigned char pRsaE[] = {
        0x01, 0x00, 0x01
    };
    unsigned int rsaELen = 3;

    unsigned char pRsaN[] = {
        0xc7, 0x7b, 0xfb, 0x18, 0x3f, 0x3b, 0x48, 0x63, 0x84, 0xbc, 0xbd, 0x6f,
        0x39, 0xec, 0x96, 0x3a, 0x55, 0x2c, 0x3f, 0x41, 0xcc, 0x28, 0x49, 0x37,
        0xf6, 0x6a, 0xcb, 0x43, 0xf4, 0x0e, 0x16, 0x95, 0x98, 0x5e, 0x58, 0xfc,
        0x39, 0x48, 0xfb, 0xee, 0x08, 0x49, 0x29, 0xe0, 0xd4, 0x9d, 0x21, 0x90,
        0x29, 0x36, 0x15, 0x13, 0x05, 0x20, 0x8a, 0xfd, 0x0d, 0x0d, 0x9a, 0x18,
        0xc4, 0x9d, 0x85, 0xa0, 0x73, 0xfd, 0x3d, 0xd0, 0x58, 0x5c, 0x5a, 0xeb,
        0xb9, 0x6f, 0xf6, 0x8c, 0x1a, 0x64, 0xf0, 0xee, 0x6e, 0x25, 0x15, 0xc7,
        0x49, 0x96, 0x0f, 0xef, 0x69, 0x8f, 0xcb, 0x54, 0x29, 0x72, 0xbf, 0x3d,
        0x55, 0x89, 0xf3, 0xa2, 0xcb, 0x21, 0x49, 0xfc, 0x81, 0x18, 0xeb, 0x58,
        0x9c, 0x54, 0x3d, 0x87, 0x0b, 0xd7, 0x95, 0xd5, 0xe3, 0xd7, 0xc4, 0x3a,
        0x57, 0x2a, 0x57, 0x4b, 0xb5, 0xef, 0x85, 0xc2, 0x7b, 0x48, 0xaf, 0x89,
        0x67, 0xdc, 0x77, 0xef, 0x70, 0x62, 0xe2, 0x0c, 0x55, 0xae, 0xde, 0x3e,
        0x6f, 0x4c, 0x7e, 0x62, 0x20, 0xf3, 0xee, 0x03, 0x68, 0xa5, 0x82, 0x66,
        0x23, 0x7a, 0x04, 0xbe, 0x46, 0xb1, 0xb7, 0x05, 0x05, 0x18, 0xf4, 0x16,
        0xbd, 0xeb, 0x72, 0x94, 0x2d, 0xb5, 0xbd, 0xbc, 0x7d, 0x27, 0xde, 0x91,
        0x7e, 0xbc, 0xbe, 0xda, 0xd1, 0x5c, 0x3f, 0xd0, 0x25, 0x6b, 0xa5, 0xc9,
        0x91, 0xb3, 0x4a, 0xe3, 0x1d, 0x56, 0xea, 0x2b, 0x8e, 0x77, 0x63, 0x41,
        0xc0, 0x74, 0x77, 0xe7, 0x61, 0x44, 0x56, 0x46, 0x54, 0xe3, 0xb6, 0x6d,
        0x6d, 0x1a, 0x47, 0xe9, 0x52, 0x4a, 0xc2, 0xf0, 0xda, 0x09, 0x65, 0x92,
        0x6a, 0xb6, 0xe2, 0xca, 0x24, 0x44, 0x98, 0xda, 0x41, 0xd1, 0xde, 0x24,
        0x82, 0x53, 0x63, 0xf5, 0xb6, 0xca, 0x34, 0xbf, 0x6c, 0xf5, 0x85, 0x02,
        0x75, 0xc1, 0xa2, 0xa7
    };
    unsigned int rsaNLen = 256;

    unsigned char pRsaP[] = {
        0xec, 0x69, 0x51, 0x72, 0xd3, 0x99, 0xc9, 0x7f, 0xc9, 0x0a, 0xf1, 0xd3,
        0xaa, 0xfc, 0x2d, 0x54, 0xcd, 0x8d, 0xc7, 0x79, 0x29, 0x60, 0x15, 0x1f,
        0x9a, 0xfa, 0x66, 0x22, 0x38, 0x7f, 0x1c, 0x7f, 0x7e, 0x68, 0x3f, 0x80,
        0xb8, 0x42, 0xfa, 0x65, 0x3b, 0xec, 0xfb, 0x04, 0x0c, 0x55, 0x72, 0x7f,
        0xb2, 0x81, 0x0d, 0x4d, 0x73, 0x85, 0xf1, 0x0d, 0xdf, 0x60, 0x69, 0x18,
        0x7d, 0x7c, 0x68, 0x6e, 0x5f, 0x46, 0x01, 0x6e, 0xdd, 0x61, 0x9a, 0x34,
        0x37, 0x8a, 0x1d, 0x7b, 0xb4, 0xb8, 0xa6, 0x9c, 0x98, 0x50, 0xbe, 0x66,
        0xd0, 0x54, 0xd8, 0x23, 0x5c, 0x14, 0xcf, 0x5a, 0x6b, 0xfd, 0x28, 0xa2,
        0xc2, 0x5d, 0xb0, 0x1f, 0x45, 0x9b, 0xfa, 0xdb, 0x03, 0x82, 0x74, 0x49,
        0x04, 0x5d, 0xf8, 0x99, 0x1f, 0x1e, 0xf1, 0x94, 0x62, 0x97, 0xa4, 0xc0,
        0xc2, 0x76, 0xd5, 0x10, 0x47, 0x90, 0xaa, 0xc3
    };
    unsigned int rsaPLen = 128;

    unsigned char pRsaQ[] = {
        0xd8, 0x03, 0x60, 0x86, 0x2e, 0x36, 0x9b, 0x23, 0x01, 0xb9, 0x9f, 0x48,
        0xcd, 0x5a, 0x66, 0x12, 0xc5, 0x5a, 0x95, 0x44, 0x4a, 0x3e, 0x0e, 0x0b,
        0x06, 0x0a, 0x15, 0xd9, 0x40, 0xb0, 0x83, 0x6f, 0xe8, 0x04, 0xe8, 0x1f,
        0xef, 0xf6, 0xe9, 0xb6, 0x09, 0x83, 0xa4, 0xec, 0x46, 0x8e, 0xd1, 0x50,
        0xa3, 0x3a, 0xf5, 0x3d, 0x44, 0xae, 0xab, 0xc3, 0x85, 0x7e, 0x2e, 0xa3,
        0xd0, 0x46, 0x3e, 0xe7, 0x93, 0x57, 0x7a, 0x1f, 0x1d, 0x30, 0x42, 0x4e,
        0xb8, 0xdb, 0xc5, 0xb8, 0x17, 0x8d, 0xff, 0x2b, 0x39, 0xf2, 0x7a, 0x46,
        0xe6, 0x4d, 0x68, 0xc7, 0xea, 0xa0, 0xd6, 0xa0, 0x8b, 0xd9, 0x5a, 0x8f,
        0xbf, 0x57, 0x3f, 0x8c, 0x44, 0x0e, 0x1d, 0xc1, 0x2b, 0xc7, 0xff, 0xaf,
        0x53, 0xe7, 0x50, 0xab, 0x5f, 0x09, 0xf6, 0x67, 0x4f, 0xd6, 0x84, 0xa8,
        0xe7, 0xd4, 0x75, 0x1e, 0x6c, 0x68, 0x42, 0x4d
    };
    unsigned int rsaQLen = 128;

    /* This is the digestinfo of a buffer with 50 zeros */
    unsigned char pMessage[] = {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xCC, 0x27, 0x86, 0xE1, 0xF9,
        0x91, 0x0A, 0x9D, 0x81, 0x14, 0x00, 0xED, 0xCD, 0xDA, 0xF7, 0x07, 0x51,
        0x95, 0xF7, 0xA1, 0x6B, 0x21, 0x6D, 0xCB, 0xEF, 0xBA, 0x3B, 0xC7, 0xC4,
        0xF2, 0xAE, 0x51
    };
    unsigned int messageLen = 51;

    /* the contents of the expected signature */
    unsigned char pExpectedSignature[] = {
        0x4B, 0x2B, 0x9F, 0xF4, 0xB5, 0xBC, 0xB8, 0x7D, 0xE5, 0xAD, 0x24, 0x52,
        0x03, 0xB4, 0x9A, 0x5F, 0x7B, 0x0D, 0xCD, 0xA4, 0x67, 0x52, 0xAA, 0x2F,
        0xBC, 0x6E, 0x25, 0x7E, 0x5B, 0x94, 0xAB, 0x2E, 0x24, 0xF2, 0x7F, 0x65,
        0xAC, 0x3A, 0x5E, 0xA0, 0xD5, 0xD3, 0x77, 0x9B, 0x83, 0xD3, 0xBE, 0xBB,
        0xD1, 0x35, 0x71, 0xA7, 0xD3, 0xF4, 0x7E, 0xAC, 0x3E, 0x71, 0x52, 0x89,
        0x77, 0x70, 0x06, 0x17, 0x1B, 0x50, 0x1E, 0x52, 0xEC, 0xB6, 0xB3, 0x49,
        0x12, 0x36, 0x3C, 0x89, 0xE3, 0x7D, 0x5C, 0xE4, 0x20, 0x01, 0x52, 0x95,
        0xD3, 0x00, 0x8C, 0xBB, 0x83, 0x6F, 0x4D, 0xFC, 0x2C, 0x7B, 0x03, 0x4E,
        0x5B, 0x76, 0x5C, 0x84, 0xA1, 0x11, 0xD2, 0xC4, 0x10, 0x63, 0xB4, 0x72,
        0xA9, 0x40, 0xFC, 0x4D, 0x1A, 0xA4, 0x9C, 0x3C, 0xEE, 0xBA, 0x2D, 0x75,
        0xD3, 0xDF, 0x01, 0xBE, 0x71, 0xCD, 0x70, 0x09, 0xC7, 0x23, 0x1F, 0x4C,
        0x92, 0x68, 0xCF, 0x8E, 0x47, 0xEA, 0xFF, 0xB2, 0x72, 0x8A, 0xFC, 0x02,
        0x34, 0x96, 0x7D, 0x3E, 0x87, 0x23, 0x63, 0xFD, 0xBD, 0xB6, 0x34, 0x0A,
        0x1A, 0x26, 0x06, 0xB3, 0x60, 0x60, 0x7D, 0x9B, 0x7D, 0xC2, 0x0A, 0x24,
        0x47, 0x5F, 0xDE, 0xEB, 0x95, 0x00, 0x8E, 0xCB, 0x8B, 0x79, 0xA1, 0x20,
        0x46, 0x14, 0x60, 0x4E, 0x75, 0x77, 0xB9, 0x39, 0x93, 0x19, 0x7E, 0x57,
        0x26, 0x0B, 0xF4, 0x62, 0xE6, 0x3C, 0x84, 0xEF, 0x05, 0x07, 0xE2, 0x3B,
        0x4B, 0x47, 0x31, 0xE2, 0x08, 0x2C, 0x26, 0xAB, 0x79, 0x36, 0x5E, 0x3F,
        0xE0, 0xEF, 0x07, 0x83, 0xE9, 0xA0, 0x24, 0x4A, 0x2D, 0x3C, 0x96, 0xED,
        0xB2, 0x41, 0x70, 0xAA, 0x38, 0x27, 0x71, 0xC9, 0x3C, 0xF8, 0xD1, 0x88,
        0xBC, 0xED, 0xEC, 0xB1, 0xCD, 0x7D, 0x44, 0x75, 0x75, 0xD3, 0x54, 0x37,
        0x9E, 0xFA, 0xC9, 0x5C
    };
    unsigned int expectedSignatureLen = 256;

    RSAKey *pKey = NULL;

    /* variables used for computing and comparing signatures */
    ubyte pSignature[256] = { 0 };

    /* buffer for verifySignature to write to */
    ubyte pVerify[256];
    /* variable used by verifySignature to store # of bytes written */
    ubyte4 verifyLen = 0;
    /* variable for comparing expected signature with computed signature */
    sbyte4 cmpRes = 667;

    /* getCipherTextLength will store result here */
    sbyte4 sigSize = 0;
    /* create shell for RSA key */
    status = RSA_createKey(&pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    /* set values of key for the known vector test */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pKey, pRsaE, rsaELen, pRsaN,
                               rsaNLen, pRsaP, rsaPLen, pRsaQ,
                               rsaQLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey, &sigSize);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pKey, pMessage, messageLen, pSignature, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;


    status = DIGI_MEMCMP(pSignature, pExpectedSignature, expectedSignatureLen,
                        &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        goto exit;
    }

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pKey, pSignature, pVerify, &verifyLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK > status)
    {
        goto exit;
    }

    cmpRes = 1;
    status = DIGI_MEMCMP(pVerify, pMessage, verifyLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
    {
        goto exit;
    }

    if (0 != cmpRes)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        goto exit;
    }

exit:

    if (NULL != pKey)
    {
        RSA_freeKey(&pKey, NULL);
    }

    if (OK > status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int testBadModulusErrorCases()
{
    int retVal = 0;
    MSTATUS status = OK;

    RSAKey *pPubKey = NULL;
    RSAKey *pPrivKey = NULL;

    ubyte pEvenModulus[256] = {
        0xb4, 0xf4, 0x89, 0xe8, 0x58, 0x38, 0x16, 0x3e, 0x4d, 0x9a, 0x7f, 0x4f,
        0x92, 0xb6, 0x28, 0xd2, 0x34, 0xe4, 0x7c, 0x2b, 0xf8, 0x4d, 0xf0, 0x3f,
        0xa5, 0xd3, 0xbf, 0x28, 0xba, 0x59, 0x6c, 0x93, 0x80, 0x12, 0xbd, 0x2c,
        0x23, 0xb0, 0x23, 0x68, 0xee, 0xc1, 0xd4, 0x6b, 0x8c, 0x50, 0x66, 0x5e,
        0x49, 0x3b, 0xa5, 0x6a, 0x63, 0x5f, 0x0b, 0x00, 0xdc, 0x0e, 0x46, 0x3a,
        0xdc, 0xf4, 0x16, 0x97, 0xe0, 0xc8, 0x2e, 0xce, 0xc6, 0xc5, 0x5c, 0x17,
        0xba, 0xb8, 0x58, 0x75, 0x99, 0x5a, 0x57, 0x98, 0x5c, 0x52, 0xa5, 0x40,
        0x72, 0x43, 0xef, 0x79, 0xd0, 0xc1, 0x73, 0xfd, 0xeb, 0xcf, 0x80, 0xff,
        0x7a, 0xc1, 0x5f, 0xb3, 0xe1, 0x3b, 0x40, 0xc1, 0x6d, 0x99, 0xdf, 0x8a,
        0xd3, 0x8b, 0x3e, 0x03, 0xc4, 0xc2, 0x34, 0xed, 0x76, 0x0d, 0x15, 0x41,
        0x0e, 0x96, 0xcf, 0xe0, 0x91, 0x43, 0xf6, 0x1b, 0x1c, 0xf2, 0x9a, 0xc3,
        0xb6, 0x91, 0xa6, 0x16, 0x4e, 0xeb, 0x77, 0x4a, 0xbc, 0x82, 0xa9, 0xe1,
        0xc4, 0x15, 0xb6, 0x45, 0x90, 0x1e, 0x2e, 0xac, 0xc9, 0x38, 0xc6, 0xb2,
        0x09, 0x0b, 0x70, 0xb3, 0x5a, 0xbb, 0x92, 0xd9, 0x0d, 0x05, 0x1d, 0xb0,
        0x65, 0x7e, 0x48, 0x0a, 0x37, 0x9c, 0x17, 0x56, 0x09, 0x16, 0x15, 0xf8,
        0x8e, 0xb9, 0xc7, 0xc2, 0x9f, 0xe2, 0x10, 0xb1, 0xaa, 0xa9, 0xa3, 0x57,
        0x77, 0x7f, 0xd8, 0xd2, 0x91, 0xbb, 0x40, 0x57, 0x9c, 0x37, 0xbf, 0x37,
        0xe8, 0x83, 0xcf, 0x75, 0xf4, 0xcc, 0x4a, 0x23, 0xd1, 0xfa, 0x97, 0x82,
        0xae, 0x12, 0x59, 0xc0, 0xb4, 0x9e, 0xc1, 0xb5, 0x97, 0x2c, 0x97, 0xb7,
        0x54, 0xcb, 0xdb, 0xbd, 0x08, 0xe8, 0x04, 0xca, 0x44, 0x62, 0x56, 0x89,
        0x05, 0x42, 0x0a, 0x90, 0xed, 0x73, 0x43, 0x53, 0xea, 0xf7, 0x49, 0xe3,
        0x96, 0xc2, 0x4b, 0x18
    };
    ubyte pP[64] =
    {
        0xdf,0xa5,0x76,0xd0,0x5c,0x2f,0x46,0x8b,0x04,0x30,0xa8,0x46,0x7e,0xcd,0x0b,0x4d,
        0xb4,0x92,0xac,0xb0,0x33,0x07,0x42,0x65,0xef,0x29,0xc1,0x44,0x3e,0xcc,0xa3,0xcc,
        0xc6,0x9d,0xd4,0x30,0xfa,0xc0,0xf3,0x5b,0x8b,0x98,0xde,0x0c,0xd0,0x8a,0xae,0x4f,
        0xd9,0xfe,0xfc,0xfe,0xb3,0x3e,0x64,0x1c,0xbb,0xa3,0xa5,0x44,0x93,0xc2,0x99,0x3d
    };
    ubyte pQ[64] =
    {
        0xc9,0xad,0xf2,0xff,0x9c,0x4f,0xe9,0x8d,0x24,0xa1,0x72,0xcf,0x33,0x18,0x83,0x94,
        0x29,0x8f,0xb0,0x22,0xc0,0x58,0x27,0x70,0x89,0xc9,0x40,0x5e,0x5b,0x74,0x85,0x14,
        0x13,0x40,0xe3,0xdd,0x89,0x9f,0xa9,0xca,0x2e,0x8f,0x61,0x1f,0xce,0x56,0x26,0x81,
        0x10,0x59,0x6c,0x9a,0x7f,0x2b,0xcb,0x11,0x20,0xef,0xd7,0x19,0x63,0xce,0x2a,0x87
    };
    ubyte pPub[3] = {0x01, 0x00, 0x01};

    status = RSA_createKey(&pPubKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, sizeof(pPub), pEvenModulus, sizeof(pEvenModulus), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_INVALID_MODULUS);
    if (OK != status)
        goto exit;

    status = RSA_createKey(&pPrivKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, sizeof(pPub), pEvenModulus, sizeof(pEvenModulus), pP, sizeof(pP), pQ, sizeof(pQ), NULL);
    retVal +=  UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_INVALID_MODULUS);
    if (OK != status)
        goto exit;

exit:
    if (NULL != pPrivKey)
    {
        RSA_freeKey(&pPrivKey, NULL);
    }
    if (NULL != pPubKey)
    {
        RSA_freeKey(&pPubKey, NULL);
    }
    return retVal;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PKCS1__

static MSTATUS getDeterministicRngCtx (
    randomContext **ppRandCtx
    )
{
    MSTATUS status;
    randomContext *pRandCtx = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == ppRandCtx)
        goto exit;

    status = CRYPTO_createMocSymRandom (
        NonRandomOperator, (void *)g_pRandomContext, NULL, &pRandCtx);
    if (OK != status)
        goto exit;

    *ppRandCtx = pRandCtx;
    pRandCtx = NULL;

exit:

    if (NULL != pRandCtx)
    {
        CRYPTO_freeMocSymRandom(&pRandCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static int rsaOaepTests(
    ubyte   *pMsg,
    ubyte4  msgLen,
    ubyte   *pLabel,
    ubyte4  labelLen,
    ubyte4  keyLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RSAKey* pKey1 = NULL;

    ubyte *pCipherText = NULL;
    ubyte4 cipherTextLen = 0;

    ubyte *pDecryptedText = NULL;
    ubyte4 decryptedTextLen = 0;

    int i;
    sbyte4 cmpRes = -1;

    /* generate key for testing */
    status = RSA_createKey(&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_generateKey(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pKey1, keyLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pKey1,
        sha256withRSAEncryption, MOC_PKCS1_ALG_MGF1, sha256withRSAEncryption,
        pMsg, msgLen, pLabel, labelLen, &pCipherText, &cipherTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pKey1, sha256withRSAEncryption,
        MOC_PKCS1_ALG_MGF1, sha256withRSAEncryption, pCipherText,
        cipherTextLen, pLabel, labelLen, &pDecryptedText, &decryptedTextLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pDecryptedText, pMsg, decryptedTextLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pKey1)
    {
        RSA_freeKey(&pKey1, NULL);
    }
    if (NULL != pCipherText)
    {
        DIGI_FREE((void **)&pCipherText);
    }
    if (NULL != pDecryptedText)
    {
        DIGI_FREE((void **)&pDecryptedText);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static int runRsaPssVectorManualPad (
    RSA_PSS_TestVector *pVector
    )
{
    MSTATUS status;
    ubyte4 hashAlg = 0;
    RSAKey *pKey = NULL;
    randomContext *pRandCtx = NULL;
    ubyte *pP = NULL;
    ubyte4 pLen = 0;
    ubyte *pQ = NULL;
    ubyte4 qLen = 0;
    ubyte *pN = NULL;
    ubyte4 nLen = 0;
    ubyte *pE = NULL;
    ubyte4 eLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pSalt = NULL;
    ubyte4 saltLen = 0;
    ubyte *pTestSig = NULL;
    ubyte4 testSigLen = 0;
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;
    ubyte4 expectedVerifyValue = 0;
    ubyte4 verify = 0;
    sbyte4 cmp = 0;
    ubyte4 expectedSaltLen = 0;
    ubyte *pEM = NULL;
    ubyte4 emLen = 0;

    hashAlg = pVector->hashAlg;
    pLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pP, &pP);
    qLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pQ, &pQ);
    nLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pN, &pN);
    eLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pE, &pE);
    msgLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pMsg, &pMsg);
    saltLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pSalt, &pSalt);
    testSigLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pSig, &pTestSig);
    expectedVerifyValue = pVector->verify;

    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRandCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Create a new RSA key */
    status = RSA_createKey(&pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Set the key data. Many of these vectors are negative tests with invalid
     * key data. The Mocana implementation does not perform key validation
     * upon load, so we simply expect the verify to fail. The Mbed operator
     * actually validates the key data upon load, so we need to catch that
     * valid rejection here. */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) 
        pKey, pE, eLen, pN, nLen, pP, pLen, pQ, qLen, NULL);
#ifdef __ENABLE_DIGICERT_RSA_MBED__
    if ( (0 != expectedVerifyValue) && (ERR_MBED_FAILURE == status) )
    {
        status = OK;
        goto exit;
    }
#endif
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Mbed will only allow a salt length equal to the hash output length
     * when performing PSS signing */
#ifdef __ENABLE_DIGICERT_RSA_MBED__
    status = ERR_INVALID_INPUT;
    switch(hashAlg)
    {
        case ht_sha1:
            expectedSaltLen = 20;
            break;

        case ht_sha224:
            expectedSaltLen = 28;
            break;

        case ht_sha256:
            expectedSaltLen = 32;
            break;

        case ht_sha384:
            expectedSaltLen = 48;
            break;

        case ht_sha512:
            expectedSaltLen = 64;
            break;

        default:
            goto exit;
    }
#endif

    /* If this signature is supposed to verify, ensure we can generate the
     * expected value. Mbed will only allow a salt length equal to the hash
     * output length when performing PSS signing. */
#ifdef __ENABLE_DIGICERT_RSA_MBED__
    if ( (0 == expectedVerifyValue) && (saltLen == expectedSaltLen) )
#else
    if ( (0 == expectedVerifyValue) )
#endif
    {
        if (0 < saltLen)
        {
            /* Set up the RNG to produce desired salt value */
            status = CRYPTO_seedRandomContext(pRandCtx, NULL, pSalt, saltLen);
            UNITTEST_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
        }

        status = CRYPTO_INTERFACE_PKCS1_rsaPssPad(MOC_RSA(gpHwAccelCtx) pKey, RANDOM_rngFun, pRandCtx, pMsg, msgLen,
                                                  saltLen, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, &pEM, &emLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;                                        

        status = CRYPTO_INTERFACE_RSA_applyPrivateKeyAux(MOC_RSA(gpHwAccelCtx) pKey, RANDOM_rngFun, g_pRandomContext, pEM, emLen,
                                                         &pSig, NULL);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        sigLen = testSigLen; /* not returned, known apriori */
    }

    /* Attempt to verify the vector */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) 
        pKey, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pMsg, msgLen, pTestSig,
        testSigLen, (sbyte4) saltLen, &verify);

    /* Note we do not check the status here. The Mocana implementation of
     * setKeyData will not validate the key at that time. If the key is
     * not valid we will fail with an actual error code. */
    if (0 == expectedVerifyValue)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (verify != expectedVerifyValue)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    else
    {
        if (0 == verify)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        status = OK;
    }

    /* verify again with saltLen calculated, pass -1 */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pKey, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pMsg, msgLen, pTestSig,
                                 testSigLen, -1, &verify);
    
    /* Note we do not check for status here. The Mocana implementation of
     * setKeyData will not validate the key at that time. If the key is
     * not valid we will fail with an actual error code. */
    if (0 == expectedVerifyValue)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        if (verify != expectedVerifyValue)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    else
    {
        /* we'll just make sure it's not ERR_INVALID_ARG */
        if (ERR_INVALID_ARG == status)
        {
            UNITTEST_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
        }
        
        if (0 == verify)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        
        status = OK;
    }
    
exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != pMsg)
    {
        DIGI_FREE((void **)&pMsg);
    }
    if (NULL != pSalt)
    {
        DIGI_FREE((void **)&pSalt);
    }
    if (NULL != pTestSig)
    {
        DIGI_FREE((void **)&pTestSig);
    }
    if (NULL != pN)
    {
        DIGI_FREE((void **)&pN);
    }
    if (NULL != pE)
    {
        DIGI_FREE((void **)&pE);
    }
    if (NULL != pP)
    {
        DIGI_FREE((void **)&pP);
    }
    if (NULL != pQ)
    {
        DIGI_FREE((void **)&pQ);
    }
    if (NULL != pKey)
    {
        RSA_freeKey(&pKey, NULL);
    }
    if (NULL != pRandCtx)
    {
        CRYPTO_freeMocSymRandom(&pRandCtx);
    }
    if (NULL != pEM)
    {
        DIGI_FREE((void **) &pEM);
    }

    if (OK != status)
        return 1;
    return 0;
}
#endif

/*----------------------------------------------------------------------------*/

static int runRsaPssVector (
    RSA_PSS_TestVector *pVector
    )
{
    MSTATUS status;
    ubyte4 hashAlg = 0;
    RSAKey *pKey = NULL;
    randomContext *pRandCtx = NULL;
    ubyte *pP = NULL;
    ubyte4 pLen = 0;
    ubyte *pQ = NULL;
    ubyte4 qLen = 0;
    ubyte *pN = NULL;
    ubyte4 nLen = 0;
    ubyte *pE = NULL;
    ubyte4 eLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pSalt = NULL;
    ubyte4 saltLen = 0;
    ubyte *pTestSig = NULL;
    ubyte4 testSigLen = 0;
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;
    ubyte4 expectedVerifyValue = 0;
    ubyte4 verify = 0;
    sbyte4 cmp = 0;
    ubyte4 expectedSaltLen = 0;

    hashAlg = pVector->hashAlg;
    pLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pP, &pP);
    qLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pQ, &pQ);
    nLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pN, &pN);
    eLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pE, &pE);
    msgLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pMsg, &pMsg);
    saltLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pSalt, &pSalt);
    testSigLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *)pVector->pSig, &pTestSig);
    expectedVerifyValue = pVector->verify;

    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRandCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Create a new RSA key */
    status = RSA_createKey(&pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Set the key data. Many of these vectors are negative tests with invalid
     * key data. The Mocana implementation does not perform key validation
     * upon load, so we simply expect the verify to fail. The Mbed operator
     * actually validates the key data upon load, so we need to catch that
     * valid rejection here. */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) 
        pKey, pE, eLen, pN, nLen, pP, pLen, pQ, qLen, NULL);
#ifdef __ENABLE_DIGICERT_RSA_MBED__
    if ( (0 != expectedVerifyValue) && (ERR_MBED_FAILURE == status) )
    {
        status = OK;
        goto exit;
    }
#endif
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Mbed will only allow a salt length equal to the hash output length
     * when performing PSS signing */
#ifdef __ENABLE_DIGICERT_RSA_MBED__
    status = ERR_INVALID_INPUT;
    switch(hashAlg)
    {
        case ht_sha1:
            expectedSaltLen = 20;
            break;

        case ht_sha224:
            expectedSaltLen = 28;
            break;

        case ht_sha256:
            expectedSaltLen = 32;
            break;

        case ht_sha384:
            expectedSaltLen = 48;
            break;

        case ht_sha512:
            expectedSaltLen = 64;
            break;

        default:
            goto exit;
    }
#endif

    /* If this signature is supposed to verify, ensure we can generate the
     * expected value. Mbed will only allow a salt length equal to the hash
     * output length when performing PSS signing. */
#ifdef __ENABLE_DIGICERT_RSA_MBED__
    if ( (0 == expectedVerifyValue) && (saltLen == expectedSaltLen) )
#else
    if ( (0 == expectedVerifyValue) )
#endif
    {
        if (0 < saltLen)
        {
            /* Set up the RNG to produce desired salt value */
            status = CRYPTO_seedRandomContext(pRandCtx, NULL, pSalt, saltLen);
            UNITTEST_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
        }

        /* Generate the signature */
        status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) 
            pRandCtx, pKey, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pMsg,
            msgLen, saltLen, &pSig, &sigLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        /* Ensure it matches the expected output */
        if (sigLen != testSigLen)
        {
            status = ERR_BAD_LENGTH;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        status = DIGI_MEMCMP(pSig, pTestSig, testSigLen, &cmp);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (0 != cmp)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    /* Attempt to verify the vector */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) 
        pKey, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pMsg, msgLen, pTestSig,
        testSigLen, (sbyte4) saltLen, &verify);

    /* Note we do not check the status here. The Mocana implementation of
     * setKeyData will not validate the key at that time. If the key is
     * not valid we will fail with an actual error code. */
    if (0 == expectedVerifyValue)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (verify != expectedVerifyValue)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    else
    {
        if (0 == verify)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        status = OK;
    }

    /* verify again with saltLen calculated, pass -1 */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pKey, hashAlg, MOC_PKCS1_ALG_MGF1, hashAlg, pMsg, msgLen, pTestSig,
                                 testSigLen, -1, &verify);
    
    /* Note we do not check for status here. The Mocana implementation of
     * setKeyData will not validate the key at that time. If the key is
     * not valid we will fail with an actual error code. */
    if (0 == expectedVerifyValue)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        if (verify != expectedVerifyValue)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    else
    {
        /* we'll just make sure it's not ERR_INVALID_ARG */
        if (ERR_INVALID_ARG == status)
        {
            UNITTEST_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
        }
        
        if (0 == verify)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        
        status = OK;
    }
    
exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != pMsg)
    {
        DIGI_FREE((void **)&pMsg);
    }
    if (NULL != pSalt)
    {
        DIGI_FREE((void **)&pSalt);
    }
    if (NULL != pTestSig)
    {
        DIGI_FREE((void **)&pTestSig);
    }
    if (NULL != pN)
    {
        DIGI_FREE((void **)&pN);
    }
    if (NULL != pE)
    {
        DIGI_FREE((void **)&pE);
    }
    if (NULL != pP)
    {
        DIGI_FREE((void **)&pP);
    }
    if (NULL != pQ)
    {
        DIGI_FREE((void **)&pQ);
    }
    
    if (NULL != pKey)
    {
        RSA_freeKey(&pKey, NULL);
    }
    if (NULL != pRandCtx)
    {
        CRYPTO_freeMocSymRandom(&pRandCtx);
    }
    
    if (OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int rsaPssVectorTests()
{
    int retVal = 0;
    ubyte4 i;

    for (i = 0; i < COUNTOF(g_RsaPssTestVectorsLong); i++)
    {
        retVal += runRsaPssVector(g_RsaPssTestVectorsLong + i);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        retVal += runRsaPssVectorManualPad(g_RsaPssTestVectorsLong + i);
#endif
    }

    return retVal;
}

static int testPKCS1ErrorCases()
{
    int retVal = 0;
    MSTATUS status = OK;
    
    RSAKey *pPrivKey = NULL;
    RSAKey *pPubKey = NULL;
    RSAKey *pNoKey = NULL;
    
    randomContext *pRandCtx = NULL;
    randomContext *pNoRand = NULL;
    
    /* need valid primes and modulus for mbed key creation */
    ubyte pModulus[128] =
    {
        0xb0,0x30,0xe1,0x64,0x9b,0xe0,0x5f,0x85,0xdf,0xc2,0x5d,0xbf,0x3d,0xc7,0x1f,0xc7,
        0x87,0x85,0xa7,0x31,0x50,0x50,0x10,0x3d,0x47,0x05,0xe5,0x3a,0x9e,0xe5,0xdb,0x78,
        0x25,0xe5,0x31,0x65,0x70,0x73,0x0c,0xf8,0xcb,0xc9,0xf7,0xb8,0x49,0xfa,0x26,0x1c,
        0xc6,0x5c,0x8e,0xba,0x30,0x0e,0x77,0xcd,0x08,0xc5,0x26,0xed,0x94,0xb1,0x86,0xa5,
        0xbf,0x46,0xc5,0x10,0xf3,0x44,0xaf,0xc5,0xfc,0x5b,0xf3,0x82,0x06,0xbd,0x45,0xdc,
        0xe6,0x47,0xd5,0x51,0xe3,0x0d,0x8b,0xae,0x86,0xd7,0xd1,0xcc,0x4c,0xcd,0x4c,0x0c,
        0xa6,0xdf,0x54,0xc9,0xeb,0x7a,0x42,0xf5,0xe4,0x1c,0x1c,0xf4,0x5a,0xd7,0x17,0xcd,
        0xe8,0x5a,0xbc,0x99,0x2d,0xf7,0x56,0x34,0xdb,0x62,0xc1,0x36,0xbe,0xd8,0xd1,0x2b
    };
    
    ubyte pP[64] =
    {
        0xdf,0xa5,0x76,0xd0,0x5c,0x2f,0x46,0x8b,0x04,0x30,0xa8,0x46,0x7e,0xcd,0x0b,0x4d,
        0xb4,0x92,0xac,0xb0,0x33,0x07,0x42,0x65,0xef,0x29,0xc1,0x44,0x3e,0xcc,0xa3,0xcc,
        0xc6,0x9d,0xd4,0x30,0xfa,0xc0,0xf3,0x5b,0x8b,0x98,0xde,0x0c,0xd0,0x8a,0xae,0x4f,
        0xd9,0xfe,0xfc,0xfe,0xb3,0x3e,0x64,0x1c,0xbb,0xa3,0xa5,0x44,0x93,0xc2,0x99,0x3d
    };
    ubyte pQ[64] =
    {
        0xc9,0xad,0xf2,0xff,0x9c,0x4f,0xe9,0x8d,0x24,0xa1,0x72,0xcf,0x33,0x18,0x83,0x94,
        0x29,0x8f,0xb0,0x22,0xc0,0x58,0x27,0x70,0x89,0xc9,0x40,0x5e,0x5b,0x74,0x85,0x14,
        0x13,0x40,0xe3,0xdd,0x89,0x9f,0xa9,0xca,0x2e,0x8f,0x61,0x1f,0xce,0x56,0x26,0x81,
        0x10,0x59,0x6c,0x9a,0x7f,0x2b,0xcb,0x11,0x20,0xef,0xd7,0x19,0x63,0xce,0x2a,0x87
    };

    ubyte pPub[3] = {0x01, 0x00, 0x01};
    
    ubyte pSalt[32] = {0};
    
    /* msg for signing or to be used as plaintext */
    ubyte pMsg[63] = {0}; /* big renough to test too big */
    ubyte4 msgLen = 32;
    
    /* buffer for resulting signature, plaintext, or ciphertext */
    ubyte *pResult = NULL;
    ubyte4 resultLen;
    
    /* Buffer for input signature or input ciphertext */
    ubyte pInputBuffer[128] = {0x01};

    ubyte4 verifyStatus;
    
    ubyte pLabel[32] = {0};
    
    /*
     RSA key operation error tests in crypto_interface_rsa_unit_test.c
     We here just properly setup keys in order to error test the pss and oaep APIs
     */
    
    /* Get a deterministc RNG */
    status = getDeterministicRngCtx(&pRandCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_seedRandomContext(pRandCtx, NULL, pSalt, sizeof(pSalt));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Get a deterministc RNG but don't seed it */
    status = getDeterministicRngCtx(&pNoRand);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Create new RSA keys */
    status = RSA_createKey(&pPrivKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = RSA_createKey(&pPubKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = RSA_createKey(&pNoKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, sizeof(pPub), pModulus, sizeof(pModulus), pP, sizeof(pP), pQ, sizeof(pQ), NULL);
    retVal +=  UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, sizeof(pPub), pModulus, sizeof(pModulus), NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* PKCS1_rsaPssSign ********/

    /* null params */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) NULL, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, NULL, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, NULL, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), NULL, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invlalid hashAlgo */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_none /* 0 */, MOC_PKCS1_ALG_MGF1, ht_none, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, 1, MOC_PKCS1_ALG_MGF1, 1, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, 16, MOC_PKCS1_ALG_MGF1, 16, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* non-matching hashAlgo */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha512, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* non default mask generation function mgf1 */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, 0, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
    {   /* mbed requires saltLen to be the same as the hash out len (32 here) */
        status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, 0, &pResult, &resultLen);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
        
        status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt) - 1, &pResult, &resultLen);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
        
        status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt) + 1, &pResult, &resultLen);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    }
    else
#endif
    {
        /* too small modulus (ie emLen) for the salt len */
        status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, 95, &pResult, &resultLen);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);
    }

    /* public key */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_KEY_NOT_READY);

    /* unset key */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pRandCtx, pNoKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_KEY_NOT_READY);
    
    /* unseeded rng */
    status = PKCS1_rsaPssSign(MOC_RSA(gpHwAccelCtx) pNoRand, pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, sizeof(pSalt), &pResult, &resultLen);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* PKCS1_rsaPssVerify ********/
    
    /* null params */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) NULL, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, NULL, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, NULL, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invlalid hashAlgo */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_none, MOC_PKCS1_ALG_MGF1, ht_none, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, 1, MOC_PKCS1_ALG_MGF1, 1, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, 16, MOC_PKCS1_ALG_MGF1, 16, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* non-matching hashAlgo */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha512, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* non default mask generation function mgf1 */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, 0, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {  
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
         /* For FIPS saltLen can't be bigger than hashLen */
        status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), 33, &verifyStatus);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
#else
         /* For non-FIPS and saltLen too large, we don't error at initial calculation and just get the general ERR_RSA_BAD_SIGNATURE at the end */
        status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), 95, &verifyStatus);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_BAD_SIGNATURE);
#endif
    }
    
    /* private key ok to use for RSA verify */
    
    /* unset key */
    status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pNoKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), (sbyte4) sizeof(pSalt), &verifyStatus);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_KEY_NOT_READY);
    
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {   /* zero signature */
        status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, 0, (sbyte4) sizeof(pSalt), &verifyStatus);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_OUT_OF_RANGE);
    }
    
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {   /* bad saltLen param */
        status = PKCS1_rsaPssVerify(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pInputBuffer, sizeof(pInputBuffer), -2, &verifyStatus);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    }
    
    /******* PKCS1_rsaOaepEncrypt *******/

    /* null params */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) NULL, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, NULL, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, NULL, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, NULL, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), NULL, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invlalid hashAlgo */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_none, MOC_PKCS1_ALG_MGF1, ht_none, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, 1, MOC_PKCS1_ALG_MGF1, 1, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, 16, MOC_PKCS1_ALG_MGF1, 16, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* non-matching hashAlgo */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha512, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* non default mask generation function mgf1 */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, 0, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* message too long, msgLen > (128 - 2 - 2 * sha256 out len) */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, 63, pLabel, sizeof(pLabel), &pResult, &resultLen);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);
    
    /* ok to use a private key to encrypt */
    
    /* unset key */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pRandCtx, pNoKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_KEY_NOT_READY);

    /* unseeded rng */
    status = PKCS1_rsaOaepEncrypt(MOC_RSA(gpHwAccelCtx) pNoRand, pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pMsg, msgLen, pLabel, sizeof(pLabel), &pResult, &resultLen);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__) && defined(__ENABLE_DIGICERT_RSA_MBED__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* PKCS1_rsaOaepDecrypt *******/
    
    /* null params */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) NULL, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, NULL, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer), NULL, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), NULL, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invlalid hashAlgo */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_none, MOC_PKCS1_ALG_MGF1, ht_none, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, 1, MOC_PKCS1_ALG_MGF1, 1, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, 16, MOC_PKCS1_ALG_MGF1, 16, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
   
    /* non-matching hashAlgo */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha512, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* non default mask generation function mgf1 */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, 0, ht_sha256, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);
    
    /* public key */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPubKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_KEY_NOT_READY);
    
    /* invlalid cipher text len */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, 0, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);

    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer) - 1, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);
    
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer) + 1, pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);
    
    /* unset key */
    status = PKCS1_rsaOaepDecrypt(MOC_RSA(gpHwAccelCtx) pNoKey, ht_sha256, MOC_PKCS1_ALG_MGF1, ht_sha256, pInputBuffer, sizeof(pInputBuffer), pLabel, sizeof(pLabel), &pResult, &resultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_RSA_KEY_NOT_READY);
    
exit:
    
    /* pResult should have never been allocated */
    if (NULL != pResult)
    {
        retVal += UNITTEST_INT(__MOC_LINE__, status, -1);
        DIGI_FREE((void **)&pResult);
    }
    
    if (NULL != pPrivKey)
    {
        RSA_freeKey(&pPrivKey, NULL);
    }
    if (NULL != pPubKey)
    {
        RSA_freeKey(&pPubKey, NULL);
    }
    if (NULL != pNoKey)
    {
        RSA_freeKey(&pNoKey, NULL);
    }
    if (NULL != pRandCtx)
    {
        CRYPTO_freeMocSymRandom(&pRandCtx);
    }
    if (NULL != pNoRand)
    {
        CRYPTO_freeMocSymRandom(&pNoRand);
    }
    
    return retVal;
}
#endif /* ifdef __ENABLE_DIGICERT_PKCS1__ */

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

static int testRsaSpeed(ubyte4 keyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    RSAKey *pKey1 = NULL;
    int i;
    struct tms tstart;
    struct tms tend;
    double diffTime;

    /* This is the digestinfo of a buffer with 50 zeros */
    ubyte pMessage[] = {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xCC, 0x27, 0x86, 0xE1, 0xF9,
        0x91, 0x0A, 0x9D, 0x81, 0x14, 0x00, 0xED, 0xCD, 0xDA, 0xF7, 0x07, 0x51,
        0x95, 0xF7, 0xA1, 0x6B, 0x21, 0x6D, 0xCB, 0xEF, 0xBA, 0x3B, 0xC7, 0xC4,
        0xF2, 0xAE, 0x51
    };
    ubyte4 messageLen = 51;

    ubyte pPlainText[256];
    ubyte4 plainTextLen = 0;
    ubyte pSignature[256] = { 0 };
    /* string formating for output */
    ubyte *pOutputFormat = "%-25s: %5g seconds\n";
    FILE *fp = NULL;

    AsymmetricKey asymKey1;
    AsymmetricKey asymKey2;
    ubyte *pSerialData = NULL;
    ubyte4 serialLen = 0;
    MKeySerialize pSupported[1] = {
        KeySerializeRsa
    };
    /* file to save times in */
    if(NULL == (fp = fopen(
        "../../../projects/cryptointerface_unittest/speed_test.txt", "a")))
        goto exit;

    status = RSA_createKey(&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* generate key material */
    status = RSA_generateKey(MOC_RSA(gpHwAccelCtx) g_pRandomContext, pKey1, keyLen, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* test signature speed */
    times(&tstart);
    for(i = 0;i < SIGN_ITERATIONS; i++){
        status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pKey1, pMessage, messageLen, pSignature,
            NULL);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "rsa sign speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "rsa sign speed",
        diffTime / sysconf(_SC_CLK_TCK));

    /* test verify speed */
    times(&tstart);
    for(i = 0;i < VERIFY_ITERATIONS; i++){
        status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pKey1, pSignature, pPlainText,
            &plainTextLen, NULL);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "rsa verify speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "rsa verify speed",
        diffTime / sysconf(_SC_CLK_TCK));

    /* init serialization object */
    status = CRYPTO_initAsymmetricKey(&asymKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymKey1, akt_rsa, (void **)&pKey1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    /* test serialization speed */
    times(&tstart);
    for(i = 0;i < SERIALIZE_ITERATIONS; i++){
        status = CRYPTO_serializeKey(MOC_ASYM(gpHwAccelCtx) 
            &asymKey1, pSupported, 1, privateKeyInfoDer, &pSerialData,
            &serialLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "rsa serialization speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "rsa serialization speed",
        diffTime / sysconf(_SC_CLK_TCK));

    times(&tstart);
    for(i = 0;i < DESERIALIZE_ITERATIONS; i++){
        status = CRYPTO_deserializeKey(MOC_ASYM(gpHwAccelCtx) 
            pSerialData, serialLen, pSupported, 1, &asymKey2);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    times(&tend);
    diffTime = tend.tms_utime - tstart.tms_utime;
    fprintf(fp, pOutputFormat, "rsa deserialization speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "rsa deserialization speed",
        diffTime / sysconf(_SC_CLK_TCK));

exit:

    if(NULL != fp)
        fclose(fp);

    if(OK != status)
        return 1;
    return 0;
}
#endif /* ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__ */

/*----------------------------------------------------------------------------*/

int crypto_interface_rsa_test_init()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    InitMocanaSetupInfo setupInfo = {0};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

 #ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
    errorCount = (errorCount + testRsaSpeed(2048));
#endif

    errorCount = (errorCount + rsaTest());
    ubyte pData[3] = "abc";
    ubyte4 dataLen = 3;

    /* if speed test flag not defined, run tests as before */
#ifndef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

    /* error cases for bad modulus */
    errorCount += testBadModulusErrorCases();

#ifdef __ENABLE_DIGICERT_PKCS1__

    /* FIPS does not allow RNG operator to be plugged in */
#ifndef __ENABLE_DIGICERT_FIPS_MODULE__
    errorCount += rsaPssVectorTests();
#endif

    ubyte pLabel[] = "Someone's Test Label";
    ubyte4 labelLen = DIGI_STRLEN((sbyte*)pLabel);

    ubyte pMsg[] = "Random Message.";
    ubyte4 msgLen = DIGI_STRLEN((sbyte*)pMsg);

    errorCount = (errorCount +
        rsaOaepTests(pMsg, msgLen, pLabel, labelLen, 2048));
    errorCount = (errorCount +
        rsaOaepTests(pMsg, msgLen, NULL, 0, 2048));

    /* error cases for pss and oaep APIs */
    errorCount += testPKCS1ErrorCases();
    
#endif /* ifdef __ENABLE_DIGICERT_PKCS1__ */

    /* Error Cases for RSA pkcs #1 v1.5 in crypto_interface_rsa_unit_test.c */
    
#ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__
    /* 2048 keys */
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha1));
    errorCount = (errorCount +
        rsaFunctionalTests(1024, pData, dataLen, ht_sha256));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha224));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha384));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha512));
#else
    /* 1024 keys */
    errorCount = (errorCount +
        rsaFunctionalTests(1024, pData, dataLen, ht_sha1));
    errorCount = (errorCount +
        rsaFunctionalTests(1024, pData, dataLen, ht_sha256));
    errorCount = (errorCount +
        rsaFunctionalTests(1024, pData, dataLen, ht_sha224));
    errorCount = (errorCount +
        rsaFunctionalTests(1024, pData, dataLen, ht_sha384));
    errorCount = (errorCount +
        rsaFunctionalTests(1024, pData, dataLen, ht_sha512));

    /* 2048 keys */
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha1));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha256));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha224));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha384));
    errorCount = (errorCount +
        rsaFunctionalTests(2048, pData, dataLen, ht_sha512));

    /* 3072 keys */
    errorCount = (errorCount +
        rsaFunctionalTests(3072, pData, dataLen, ht_sha1));
    errorCount = (errorCount +
        rsaFunctionalTests(3072, pData, dataLen, ht_sha256));
    errorCount = (errorCount +
        rsaFunctionalTests(3072, pData, dataLen, ht_sha224));
    errorCount = (errorCount +
        rsaFunctionalTests(3072, pData, dataLen, ht_sha384));
    errorCount = (errorCount +
        rsaFunctionalTests(3072, pData, dataLen, ht_sha512));

    /* 4096 keys */
    errorCount = (errorCount +
        rsaFunctionalTests(4096, pData, dataLen, ht_sha1));
    errorCount = (errorCount +
        rsaFunctionalTests(4096, pData, dataLen, ht_sha256));
    errorCount = (errorCount +
        rsaFunctionalTests(4096, pData, dataLen, ht_sha224));
    errorCount = (errorCount +
        rsaFunctionalTests(4096, pData, dataLen, ht_sha384));
    errorCount = (errorCount +
        rsaFunctionalTests(4096, pData, dataLen, ht_sha512));

#endif /* ifdef __ENABLE_DIGICERT_UNITTEST_CI_QUICKTEST__ */
#endif /* ifndef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__ */

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
