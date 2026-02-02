/*
 * performance_test.c
 * 
 * unit test for performance tests
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
#if __DIGICERT_PERFORMANCE_TESTS_ENABLE__ /* Enable only if you want to check performance */
#include "../../common/moptions.h"
#include "../../../unit_tests/unittest.h"

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../common/vlong.h"
#include "../../crypto/rsa.h"
#include "../../crypto/sha1.h"
#include "../../crypto/md5.h"
#include "../../crypto/md4.h"
#include "../../crypto/md2.h"
#include "../../crypto/crypto.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/md5.h"
#include "../../crypto/hmac.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto/aes_cmac.h"
#include "../../crypto/aes_ccm.h"
#include "../../crypto/aes_ecb.h"
#include "../../crypto/aes_xts.h"
#include "../../crypto/gcm.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/pkcs1.h"

#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif /* __ENABLE_DIGICERT_ECC__ */
#include "../../crypto/aes_eax.h"
#include "../../crypto/aes_xcbc_mac_96.h"
#include "../../crypto/arc4.h"
#include "../../crypto/arc2.h"
#include "../../crypto/blowfish.h"
#include "../../crypto/fips.h"
#include "../../crypto/fips_priv.h"
#include "../../crypto/nist_rng.h"

/* for performance testing */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined (__RTOS_OSX__)
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>

int RSA_perf_test(ubyte algo)
{
    const sbyte     testmsg[] = "Attack at dawn";
    sbyte*          pCipherText = NULL;
    sbyte*          pPlainText = NULL;
    randomContext*  pRandomContext = NULL;
    RSAKey*         pRSAKey = NULL;
    RSAKey*         pDerivedRSAKey = NULL;
    RSAKey*         pClonedRSAKey = NULL;
    vlong*          pQueue  = NULL;
    sbyte4          cipherTextLen = 0;
    sbyte4          plainTextLen = 0;
    ubyte*          pKeyBlob = NULL;
    ubyte4          keyBlobLen = 5000;
    byteBoolean     isKeyEqual;
    struct tms      tstart, tend;
    double          diffTime,totalDiffTime;
    sbyte4          i;
    MSTATUS         status = OK;

    /* Acquire the RNG context, needed for RSA key generation */
    if (OK > (status = RANDOM_acquireContextEx(&pRandomContext, algo)))
    {
        printf("\nAPI - RANDOM_acquireContext - Failed");
        goto exit;
    }

    /* Performance testing */
    /* Create the memory to hold RSA key */
    if (OK > (status = RSA_createKey(&pRSAKey)))
    {
        printf("\nAPI - RSA_createKey - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        /* Generate RSA public and private keys */
        if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, 1024, NULL)))
        {
            printf("\nAPI - RSA_generateKey - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("RSA_generateKey: 100x rounds in %g seconds of cputime\n",totalDiffTime); 

    RSA_freeKey(&pRSAKey, &pQueue);
    /* Create the memory to hold RSA key */
    if (OK > (status = RSA_createKey(&pRSAKey)))
    {
        printf("\nAPI - RSA_createKey - Failed");
        goto exit;
    }

    /* Generate RSA public and private keys */
    if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, 1024, NULL)))
    {
        printf("\nAPI - RSA_generateKey - Failed");
        goto exit;
    }

    /* Clone RSA Key */
    if (OK > (status = RSA_cloneKey(&pClonedRSAKey, pRSAKey, NULL)))
    {
        printf("\nAPI - RSA_cloneKey - Failed");
        goto exit;
    }

    /* Check if both keys are equal */
    if (OK > (status = RSA_equalKey(pRSAKey, pClonedRSAKey, &isKeyEqual)))
    {
        printf("\nAPI - RSA_equalKey - Failed");
        goto exit;
    }

    if (FALSE == isKeyEqual)
    {
        printf("\nRSA Keys are not equal");

        status = ERR_CRYPTO;
        goto exit;
    }

    /************** RSA encryption and decryption ****************************/
    /* Get the cipher text length */
    if (OK > (status = RSA_getCipherTextLength(pRSAKey, &cipherTextLen)))
    {
        printf("\nAPI - RSA_getCipherTextLength - Failed");
        goto exit;
    }

    /* Make a RSA Key Blob */
    if (NULL == (pKeyBlob = malloc(5000)))
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    if (OK > (status = RSA_byteStringFromKey(MOC_RSA(hwAccelCtx) pRSAKey, pKeyBlob, &keyBlobLen)))
    {
        printf("\nAPI - RSA_byteStringFromKey - Failed");
        goto exit;
    }

    /* Make key from Key Blob */
    if (OK > (status = RSA_keyFromByteString(MOC_RSA(hwAccelCtx) &pDerivedRSAKey, pKeyBlob, keyBlobLen, NULL)))
    {
        printf("\nAPI - RSA_keyFromByteString - Failed");
        goto exit;
    }

    /* Allocate memory for Cipher Text */
    pCipherText = malloc(cipherTextLen);
    if (NULL == pCipherText)
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        /* Now encrypt the plaintext */
        if (OK > (status = RSA_encrypt(MOC_RSA(hwAccelCtx) pDerivedRSAKey, testmsg, (sbyte4)DIGI_STRLEN(testmsg) + 1, pCipherText, RANDOM_rngFun, pRandomContext, &pQueue)))
        {
            printf("\nAPI - RSA_encrypt - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        VLONG_freeVlongQueue(&pQueue);
    }
    printf("RSA_encrypt: 10000x rounds in %g seconds of cputime\n",totalDiffTime); 

    memset(pCipherText, 0x00, (sbyte4)DIGI_STRLEN(testmsg) + 1);

    /* Now encrypt the plaintext */
    if (OK > (status = RSA_encrypt(MOC_RSA(hwAccelCtx) pDerivedRSAKey, testmsg, (sbyte4)DIGI_STRLEN(testmsg) + 1, pCipherText, RANDOM_rngFun, pRandomContext, &pQueue)))
    {
        printf("\nAPI - RSA_encrypt - Failed");
        goto exit;
    }
    /* Allocate memory for plaintext */
    pPlainText = malloc(cipherTextLen + 1);
    if (NULL == pPlainText)
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    memset(pPlainText, 0x00, cipherTextLen+1);

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        /* Now decrypt the cipher text */
        RSA_decrypt(MOC_RSA(hwAccelCtx) pDerivedRSAKey, pCipherText, pPlainText, &plainTextLen, NULL, NULL, &pQueue);
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("RSA_decrypt: 10000x rounds in %g seconds of cputime\n",totalDiffTime); 

    memset(pPlainText, 0x00, cipherTextLen+1);
    /* Now decrypt the cipher text */
    if (OK > (status = RSA_decrypt(MOC_RSA(hwAccelCtx) pDerivedRSAKey, pCipherText, pPlainText, &plainTextLen, NULL, NULL, &pQueue)))
    {
        printf("\nAPI - RSA_decrypt - Failed");
        goto exit;
    }

    if (0 != strcmp(testmsg, pPlainText))
    {
        printf("\nRSA bulk encryption failed");

        status = ERR_CRYPTO;
        goto exit;
    }

    /********** Signature Calculation and Verification ****************/
    /* Clear all memory */
    memset(pCipherText, 0x00, cipherTextLen); 
    memset(pPlainText, 0x00, cipherTextLen+1);
    plainTextLen = 0;


    /* RSA signature/verification API aren't taking care of message digest before calculating 
     * the signature, we need to do it from our own 
     */
    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        /* Calculate the signature */
        if (OK > (status = RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, testmsg, (sbyte4)DIGI_STRLEN(testmsg)+1, pCipherText, &pQueue)))
        {
            printf("\nAPI - RSA_signMessage - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("RSA_signMessage: 10000x rounds in %g seconds of cputime\n",totalDiffTime); 

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        /* Verify the signature, it doesn't memory compare the output, we need to do that from our own */
        if (OK > (status = RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey, pCipherText, pPlainText, &plainTextLen, &pQueue)))
        {
            printf("\nAPI - RSA_verifySigature - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("RSA_verifySigature: 10000x rounds in %g seconds of cputime\n",totalDiffTime); 

    if (0 != strcmp(testmsg, pPlainText))
    {
        printf("\nRSA sign verify failed");

        status = ERR_CRYPTO;
        goto exit;
    }
 
    /* Release all resources */
    RSA_freeKey(&pRSAKey, 0);
    RSA_freeKey(&pDerivedRSAKey, 0);
    RSA_freeKey(&pClonedRSAKey, 0);
    VLONG_freeVlongQueue(&pQueue);
    RANDOM_releaseContext(&pRandomContext);
    free(pPlainText);
    free(pCipherText);
    free(pKeyBlob);

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_ECC__
int PERF_ECDHTest(PEllipticCurvePtr pEC, randomContext* pRandomContext)
{
    ECCKey* pKey1 = 0;
    ECCKey* pKey2 = 0;
    ubyte*  sharedSecret1 = 0;
    ubyte*  sharedSecret2 = 0;
    ubyte4  sharedSecret1Len;
    ubyte4  sharedSecret2Len;
    sbyte4  res;
    struct tms              tstart, tend;
    double                  diffTime,totalDiffTime;
    sbyte4                  i;
    MSTATUS status;

    if (OK > (status = EC_newKey(pEC, &pKey1)))
    {
        goto exit;
    }

    if (OK > (status = EC_newKey(pEC, &pKey2)))
    {
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = EC_generateKeyPair(pEC, RANDOM_rngFun, pRandomContext, pKey1->k, pKey1->Qx, pKey1->Qy)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("EC_generateKeyPair: key1 100x rounds in %g seconds of cputime\n",totalDiffTime); 

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = EC_generateKeyPair(pEC, RANDOM_rngFun, pRandomContext, pKey2->k, pKey2->Qx, pKey2->Qy)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("EC_generateKeyPair: key2 100x rounds in %g seconds of cputime\n",totalDiffTime); 

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        if (OK > (status = ECDH_generateSharedSecretAux(pEC,
                                                        pKey1->Qx,  pKey1->Qy, pKey2->k, 
                                                        &sharedSecret2, &sharedSecret2Len, 1)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        FREE(sharedSecret2);
    }
    printf("ECDH_generateSharedSecretAux: key1 10000x rounds in %g seconds of cputime\n",totalDiffTime); 

    if (OK > (status = ECDH_generateSharedSecretAux(pEC,
                                                    pKey1->Qx,  pKey1->Qy, pKey2->k, 
                                                    &sharedSecret2, &sharedSecret2Len, 1)))
    {
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        if (OK > (status = ECDH_generateSharedSecretAux(pEC,
                                                        pKey2->Qx,  pKey2->Qy, pKey1->k, 
                                                        &sharedSecret1, &sharedSecret1Len, 1)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        FREE(sharedSecret1);
    }
    printf("ECDH_generateSharedSecretAux: key2 10000x rounds in %g seconds of cputime\n",totalDiffTime); 

    if (OK > (status = ECDH_generateSharedSecretAux(pEC,
                                                    pKey2->Qx,  pKey2->Qy, pKey1->k, 
                                                    &sharedSecret1, &sharedSecret1Len, 1)))
    {
        goto exit;
    }

    if (sharedSecret1Len != sharedSecret2Len)
    {
        status = ERR_FALSE; 
        goto exit;
    }

    DIGI_MEMCMP(sharedSecret1, sharedSecret2, sharedSecret1Len, &res);
    if (res != 0)
    {
        status = ERR_FALSE; 
        goto exit;
    }

exit:
    EC_deleteKey(&pKey1);
    EC_deleteKey(&pKey2);
    
    if (sharedSecret1)
    {
        FREE(sharedSecret1);
    }

    if (sharedSecret2)
    {
        FREE(sharedSecret2);
    }

    return status;
}


int ECDH_perf_test(ubyte algo)
{
    randomContext*  pRandomContext = NULL;
    MSTATUS         status;

    if (OK > (status = RANDOM_acquireContextEx(&pRandomContext, algo)))
    {
        goto exit;
    }

    printf("1. EC_P192:\n");
    if (OK > (status = PERF_ECDHTest(EC_P192, pRandomContext)))
    {
        goto exit;
    }

    printf("2. EC_P224:\n");
    if (OK > (status = PERF_ECDHTest(EC_P224, pRandomContext)))
    {
        goto exit;
    }

    printf("3. EC_P256:\n");
    if (OK > (status = PERF_ECDHTest(EC_P256, pRandomContext)))
    {
        goto exit;
    }

    printf("4. EC_P384:\n");
    if (OK > (status = PERF_ECDHTest(EC_P384, pRandomContext)))
    {
        goto exit;
    }

    printf("5. EC_P521:\n");
    if (OK > (status = PERF_ECDHTest(EC_P521, pRandomContext)))
    {
        goto exit;
    }

exit:    
    RANDOM_releaseContext(&pRandomContext);

    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_ECC__
int ECDSA_perf_test(ubyte algo)
{
    ubyte*                  mesg = "Sign this!";
    ubyte4                  mesgLen = 10;
    PFEPtr                  r = NULL;
    PFEPtr                  s = NULL;
    PrimeFieldPtr           pPF = NULL;
    ECCKey*                 pNewKey = NULL;
    randomContext*          pRandomContext = NULL;
    struct tms              tstart, tend;
    double                  diffTime,totalDiffTime;
    sbyte4                  i;
    MSTATUS                 status = OK;

    if (OK > (status = RANDOM_acquireContextEx(&pRandomContext, algo)))
    {
        printf("\nAPI - RANDOM_acquireContext - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = EC_newKey(EC_P192, &pNewKey)))
            goto exit;
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        EC_deleteKey(&pNewKey);
    }
    printf("EC_newKey: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    if (OK > (status = EC_newKey(EC_P192, &pNewKey)))
        goto exit;

    pPF = EC_getUnderlyingField(pNewKey->pCurve);

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = EC_generateKeyPair(pNewKey->pCurve,
                                          RANDOM_rngFun, pRandomContext,
                                          pNewKey->k, pNewKey->Qx, pNewKey->Qy)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("EC_generateKeyPair: 100x rounds in %g seconds of cputime\n",totalDiffTime);


    if (OK > (status = PRIMEFIELD_newElement(pPF, &r)))
        goto exit;

    if (OK > (status = PRIMEFIELD_newElement(pPF, &s)))
        goto exit;
   
    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = ECDSA_signDigestAux(pNewKey->pCurve, pNewKey->k, RANDOM_rngFun,
                                      pRandomContext, mesg, mesgLen, r, s)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("ECDSA_signDigestAux: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = ECDSA_verifySignature(pNewKey->pCurve,
                                                 pNewKey->Qx, pNewKey->Qy, mesg, mesgLen,
                                                 r, s)))
        {
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("ECDSA_verifySignature: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    status = OK;

exit:
    PRIMEFIELD_deleteElement(pPF, &r);
    PRIMEFIELD_deleteElement(pPF, &s);

    EC_deleteKey(&pNewKey);

    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);

    return status;
}
#endif

int DH_perf_test(ubyte algo)
{
    diffieHellmanContext*   pDhServer = NULL;
    diffieHellmanContext*   pDhClient = NULL;
    vlong*                  pVlongQueue = NULL;
    vlong*                  pMpintF = NULL;
//    vlong*                  pMpintE = NULL;
    randomContext*          pRandomContext = NULL;
    sbyte4                  comparisonResult;
    struct tms              tstart, tend;
    double                  diffTime,totalDiffTime;
    sbyte4                  i;
    MSTATUS                 status = OK;

    if (OK > (status = RANDOM_acquireContextEx(&pRandomContext, algo)))
    {
        printf("\nAPI - RANDOM_acquireContext - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = DH_allocateServer(MOC_DH(hwAccelCtx) pRandomContext, &pDhServer, DH_GROUP_2)))
        {
            printf("\nAPI - DH_allocateServer - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        DH_freeDhContext(&pDhServer, NULL);
    }
    printf("DH_allocateServer: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    if (OK > (status = DH_allocateServer(MOC_DH(hwAccelCtx) pRandomContext, &pDhServer, DH_GROUP_2)))
    {
        printf("\nAPI - DH_allocateServer - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        if (OK > (status = DH_allocate(&pDhClient)))
        {
            printf("\nAPI - DH_allocate - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        DH_freeDhContext(&pDhClient, NULL);
    }
    printf("DH_allocate: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    if (OK > (status = DH_allocate(&pDhClient)))
    {
        printf("\nAPI - DH_allocate - Failed");
        goto exit;
    }

    /* clone server's p & g for client */
    if (OK > (status = DH_setPG(MOC_DH(hwAccelCtx) pRandomContext, 20, pDhClient, COMPUTED_VLONG_P(pDhServer), COMPUTED_VLONG_G(pDhServer))))
    {
        printf("\nAPI - DH_setPG - Failed");
        goto exit;
    }

    /* Get the client public key into server's DH context */
    if (OK > (status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_F(pDhClient), &pMpintF, &pVlongQueue)))
    {
        printf("\nAPI - VLONG_makeVlongFromVlong - Failed");
        goto exit;
    }

    COMPUTED_VLONG_E(pDhServer) = pMpintF; pMpintF = NULL;

    /* Get the server public key into client's DH context */
    if (OK > (status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_F(pDhServer), &pMpintF, &pVlongQueue)))
    {
        printf("\nAPI - VLONG_makeVlongFromVlong - Failed");
        goto exit;
    }

    COMPUTED_VLONG_E(pDhClient) = pMpintF; pMpintF = NULL;

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        /* Compute shared secret for the server */
        if (OK > (status = DH_computeKeyExchange(MOC_DH(hwAccelCtx) pDhServer, &pVlongQueue)))
        {
            printf("\nAPI - DH_computeKeyExchange - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        VLONG_freeVlong( &COMPUTED_VLONG_K(pDhServer), &pVlongQueue);
    }
    printf("DH_computeKeyExchange: 10000x rounds in %g seconds of cputime\n",totalDiffTime);

    /* Compute shared secret for the server */
    if (OK > (status = DH_computeKeyExchange(MOC_DH(hwAccelCtx) pDhServer, &pVlongQueue)))
    {
        printf("\nAPI - DH_computeKeyExchange - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 10000; i++)
    {
        times(&tstart);
        if (OK > (status = DH_computeKeyExchange(MOC_DH(hwAccelCtx) pDhClient, &pVlongQueue)))
        {
            printf("\nAPI - DH_computeKeyExchange - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        VLONG_freeVlong( &COMPUTED_VLONG_K(pDhClient), &pVlongQueue);
    }
    printf("DH_computeKeyExchange: 10000x rounds in %g seconds of cputime\n",totalDiffTime);

    if (OK > (status = DH_computeKeyExchange(MOC_DH(hwAccelCtx) pDhClient, &pVlongQueue)))
    {
        printf("\nAPI - DH_computeKeyExchange - Failed");
        goto exit;
    }

    comparisonResult = VLONG_compareSignedVlongs(COMPUTED_VLONG_K(pDhClient), COMPUTED_VLONG_K(pDhServer));

    if (0 != comparisonResult)
    {
        printf("\nAPI - VLONG_compareSignedVlong - Failed");

        status = ERR_CRYPTO;
        goto exit;
    }

exit:
    if (NULL != pDhServer)
        DH_freeDhContext(&pDhServer, NULL);

    if (NULL != pDhClient)
        DH_freeDhContext(&pDhClient, NULL);

    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);

    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS1__

int PKCS1_perf_test(ubyte algo)
{
    randomContext*  pRandomContext = NULL;
    RSAKey*         pRSAKey = NULL;
    ubyte*          pSignature = NULL;
    ubyte4          signatureLen;
    intBoolean      isSignatureValid;
    ubyte*          mesg = "test message";
    hwAccelDescr    hwAccelCtx;
    struct tms      tstart, tend;
    double          diffTime,totalDiffTime;
    sbyte4          i;
    MSTATUS         status;

    
    if (OK > (MSTATUS)(status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
    {
        printf("main: HARDWARE_ACCEL_OPEN_CHANNEL failed, status = %d\n", status);
        return status;
    }

    /* Acquire the RNG context, needed for RSA key generation */
    if (OK > (status = RANDOM_acquireContextEx(&pRandomContext, algo)))
    {
        printf("\nAPI - RANDOM_acquireContext - Failed");
        goto exit;
    }

    /* Create the memory to hold RSA key */
    if (OK > (status = RSA_createKey(&pRSAKey)))
    {
        printf("\nAPI - RSA_createKey - Failed");
        goto exit;
    }

    /* Generate RSA public and private keys */
    if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, 1024, NULL)))
    {
        printf("\nAPI - RSA_generateKey - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 1000; i++)
    {
        times(&tstart);
        status = PKCS1_rsassaPssSign(MOC_RSA(hwAccelCtx) pRandomContext,
                                     pRSAKey, sha1withRSAEncryption, PKCS1_MGF1_FUNC,
                                     mesg, sizeof(mesg), 20,
                                     &pSignature, &signatureLen);
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        PKCS1_rsassaFreePssSign(MOC_RSA(hwAccelCtx) &pSignature);
    }
    printf("PKCS1_rsassaPssSign: 1000x rounds in %g seconds of cputime\n",totalDiffTime);

    status = PKCS1_rsassaPssSign(MOC_RSA(hwAccelCtx) pRandomContext,
                                 pRSAKey, sha1withRSAEncryption, PKCS1_MGF1_FUNC,
                                 mesg, sizeof(mesg), 20,
                                 &pSignature, &signatureLen);

    if (OK > status)
    {
        printf("\nAPI - PKCS1_rsassaPssSign - Failed");
        goto exit;
    }

#ifdef __DIGICERT_ENABLE_FAIL_PKCS1_PSS_TEST__
/*     if (OPS_TEST_SHOULDFAIL(xxx)) */
	{
        printf("CRYPTO_EXAMPLE_pkcs1: before value data[0] = %02x\n", pSignature[0]);
        pSignature[0] ^= 0x01;
        printf("CRYPTO_EXAMPLE_pkcs1: after  value data[0] = %02x\n", pSignature[0]);
	}
#endif

    totalDiffTime = 0;
    for (i = 0; i < 1000; i++)
    {
        times(&tstart);
        status = PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                   pRSAKey, sha1withRSAEncryption, PKCS1_MGF1_FUNC,
                                   mesg, sizeof(mesg),
                                   pSignature, signatureLen, 20,
                                   &isSignatureValid);
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("PKCS1_rsassaPssVerify: 1000x rounds in %g seconds of cputime\n",totalDiffTime);

    if (OK > status)
    {
        printf("\nAPI - PKCS1_rsassaPssVerify - Failed");
        goto exit;
    }

    if (TRUE != isSignatureValid)
    {
        printf("\nAPI - Test PKCS1_rsassaPssVerify(isSignatureValid == FALSE) - Failed");
        status = ERR_CRYPTO;
        goto exit;
    }

    status = OK;

exit:
    PKCS1_rsassaFreePssSign(MOC_RSA(hwAccelCtx) &pSignature);

    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);

    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_DSA__
#define SEED_SIZE  (32)
int DSA_perf_test(ubyte algo)
{
    randomContext*  pRandomContext = NULL;
    DSAKey*         pDSAKey = NULL;
    DSAKey*         pDerivedDSAKey = NULL;
    DSAKey*         pClonedDSAKey = NULL;
    vlong*          pH  = NULL;
    ubyte4          C = 0;
    ubyte           seed[SEED_SIZE] = {0};
    ubyte4          keySize = 2048;
    char*           pMsg = "Attack at dawn";
    vlong*          pBuff = NULL;
    vlong*          pR = NULL;
    vlong*          pS = NULL;
    intBoolean      isGoodSig;
    intBoolean      isGoodKey;
    ubyte*          pKeyBlob = NULL;
    ubyte4          keyBlobLen = 5000;
    struct tms      tstart, tend;
    double          diffTime,totalDiffTime;
    sbyte4          i;
    MSTATUS         status = OK;

    /* Acquire the RNG context, needed for DSA key generation */
    if (OK > (status = RANDOM_acquireContextEx(&pRandomContext,algo)))
    {
        printf("\nAPI - RANDOM_acquireContext - Failed status = %d\n",status);
        goto exit;
    }

    /* Create a DSA Key */
    if (OK > (status = DSA_createKey(&pDSAKey)))
    {
        printf("\nAPI - DSA_createKey - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        /* Generate DSA Key */
        if (OK > (status = DSA_generateKey(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, keySize, &C, seed, &pH, NULL)))
        {
            printf("\nAPI - DSA_generateKey - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        printf("--------------------> DSA_perf_test::DSA_generateKey_Loop[%d]::diffTime %g sec.\n", i, diffTime);
        VLONG_freeVlong(&pH, NULL);
    }
    printf("DSA_generateKey: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    totalDiffTime = 0;
    if (OK > (status = DSA_generateKey(MOC_DSA(hwAccelCtx) pRandomContext, pDSAKey, keySize, &C, seed, &pH, NULL)))
    {
        printf("\nAPI - DSA_generateKey - Failed");
        goto exit;
    }
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        /* Verify the DSA Keys */
        if (OK > (status = DSA_verifyKeysEx(MOC_DSA(hwAccelCtx) pRandomContext, seed, SEED_SIZE,
        	pDSAKey, DSA_sha256, DSA_186_4, C, pH, &isGoodKey, NULL)))
        {
            printf("\nAPI - DSA_verifyKeys - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        printf("--------------------> DSA_perf_test::DSA_verifyKeysEx_Loop[%d]::diffTime %g sec.\n", i, diffTime);
    }
    printf("DSA_verifyKeys: 100x rounds in %g seconds of cputime\n",totalDiffTime);

    if (FALSE == isGoodKey)
    {
        printf("\nDSA Keys are not good");

        status = ERR_CRYPTO;
        goto exit;
    }

    /* Make a DSA cloned Key */
    if (OK > (status = DSA_cloneKey(&pClonedDSAKey, pDSAKey)))
    {
        printf("\nAPI - DSA_cloneKey - Failed");
        goto exit;
    }

    /* Make DSA Key Blob */
    if (NULL == (pKeyBlob = MALLOC(5000)))
    {
        status = ERR_CRYPTO;
        goto exit;
    }

    if (OK > (status = DSA_makeKeyBlob(pClonedDSAKey, pKeyBlob, &keyBlobLen)))
    {
        printf("\nAPI - DSA_makeKeyBlob - Failed");
        goto exit;
    }

    /* Make Key from the Blob */
    if (OK > (status = DSA_extractKeyBlob(&pDerivedDSAKey, pKeyBlob, keyBlobLen)))
    {
        printf("\nAPI - DSA_extractKeyBlob - Failed");
        goto exit;
    }

    /* Converting the message string to VLONG */
    if (OK > (status = VLONG_vlongFromByteString(pMsg, (sbyte4)DIGI_STRLEN(pMsg), &pBuff, NULL)))
    {
        printf("\nAPI - VLONG_vlongFromByteString - Failed");
        goto exit;
    }

    totalDiffTime = 0;
    for (i = 0; i < 1000; i++)
    {
        times(&tstart);
        /* Compute the Signature */
        if (OK > (status = DSA_computeSignature(MOC_DSA(hwAccelCtx) pRandomContext, pDerivedDSAKey, pBuff, &isGoodSig, &pR, &pS, NULL)))
        {
            printf("\nAPI - DSA_computeSignature - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
        VLONG_freeVlong(&pR, NULL);
        VLONG_freeVlong(&pS, NULL);
    }
    printf("DSA_computeSignature: 1000x rounds in %g seconds of cputime\n",totalDiffTime);
   

    if (FALSE == isGoodSig)
    {
        printf("\nDSA signature is not good");

        status = ERR_CRYPTO;
        goto exit;
    }


    totalDiffTime = 0;
    if (OK > (status = DSA_computeSignature(MOC_DSA(hwAccelCtx) pRandomContext, pDerivedDSAKey, pBuff, &isGoodSig, &pR, &pS, NULL)))
    {
        printf("\nAPI - DSA_computeSignature - Failed");
        goto exit;
    }

    for (i = 0; i < 1000; i++)
    {
        times(&tstart);
        /* Verify the signature */
        if (OK > (status = DSA_verifySignature(MOC_DSA(hwAccelCtx) pDerivedDSAKey, pBuff, pR, pS, &isGoodSig, NULL)))
        {
            printf("\nAPI - DSA_verifySignature - Failed");
            goto exit;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime += diffTime;
    }
    printf("DSA_verifySignature: 1000x rounds in %g seconds of cputime\n",totalDiffTime);

    if (FALSE == isGoodSig)
    {
        printf("\nDSA signature is not good");

        status = ERR_CRYPTO;
        goto exit;
    }

exit:
    DSA_freeKey(&pDSAKey, NULL);
    DSA_freeKey(&pDerivedDSAKey, NULL);
    DSA_freeKey(&pClonedDSAKey, NULL);
    VLONG_freeVlong(&pH, NULL);
    VLONG_freeVlong(&pR, NULL);
    VLONG_freeVlong(&pS, NULL);
    VLONG_freeVlong(&pBuff, NULL);
    RANDOM_releaseContext(&pRandomContext);

    if (NULL != pKeyBlob)
        FREE(pKeyBlob);

    return status;
}
#endif

int RANDOM_test_perf(ubyte algo)
{
    int retVal = 0;

    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__)
    randomContext*   pRandomContext = NULL;
    ubyte            buff[40];
    int              i;
    struct tms       tstart, tend;
    double           diffTime;
    ubyte            entropyBits = 0x67;
    MSTATUS          status;
    double           totalDiffTime1, totalDiffTime2;
    
    //START_ALARM(TEST_SECONDS);
    totalDiffTime1 = 0;
    totalDiffTime2 = 0;
    for (i = 0; i < 100; i++)
    {
        times(&tstart);
        RANDOM_acquireContextEx(&pRandomContext, algo);
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        printf("--------------------> RANDOM_test_perf::RANDOM_acquireContextEx[%d]::diffTime %g sec.\n", i, diffTime);
        totalDiffTime1 += diffTime;

        times(&tstart);
        RANDOM_releaseContext(&pRandomContext);
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        totalDiffTime2 += diffTime;
    }
    printf("RANDOM_acquireContextEx: 100x rounds in %g seconds of cputime\n",totalDiffTime1);
    printf("RANDOM_releaseContext: 100x rounds in %g seconds of cputime\n",totalDiffTime2);

    RANDOM_acquireContextEx(&pRandomContext, algo);
    times(&tstart);
    for (i = 0; i < 1000; i++)
    {
        if (OK > (status = RANDOM_addEntropyBit(pRandomContext, entropyBits)))
        {
            printf("\nAPI - RANDOM_addEntropyBit - Failed status = %d\n",status);
            goto exit;
        }
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    printf("RANDOM_addEntropyBit: 1000x rounds in %g seconds of cputime\n",diffTime);

    times(&tstart);
    for (i = 0; i < 1000; i++)
    {
        if (OK > (status = RANDOM_numberGenerator(pRandomContext, buff, 16)))
        {
            printf("\nAPI - RANDOM_numberGenerator - Failed status = %d\n",status);
            goto exit;
        }
    }
    times(&tend);
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    printf("RANDOM_numberGenerator: 1000x rounds in %g seconds of cputime\n",diffTime);

exit:
    RANDOM_releaseContext(&pRandomContext);    

#endif

    return retVal;
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
FIPS_startUpTest()
{
    struct tms      tstart, tend;
    double          diffTime,totalDiffTime;
    sbyte4          i;

    times(&tstart);
    for (i = 0; i < 100; i++)
        FIPS_powerupSelfTest();
    
    times(&tend);
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    printf("FIPS_powerupSelfTest: 100x rounds in %g seconds of cputime\n",diffTime);
}
#endif

int performance_test_all()
{
#ifdef __DIGICERT_PERFORMANCE_TESTS_ENABLE__
    int     i,j;
    ubyte   mode[] =
    {
#ifdef __ENABLE_DIGICERT_RNG_DRBG_CTR__
                MODE_DRBG_CTR, 
#endif
                MODE_RNG_FIPS186
    };

    printf("-------- Performance tests ---------\n");    
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    FIPS_startUpTest();
#endif

    for (j = 0; j < 2; j++)
    {
        /* source Internal/External */
        printf("Entropy Source - %s\n",(j ? "ENTROPY_SRC_EXTERNAL":"ENTROPY_SRC_INTERNAL"));
        if (OK > (RANDOM_setEntropySource(j)))
            break;

        for (i = 0; i < sizeof(mode); i++)
        {
            printf("ALGO MODE - %s\n",((mode[i] == MODE_RNG_FIPS186) ? "MODE_RNG_FIPS186":"MODE_DRBG_CTR"));
            printf("RANDOM_xx APIs\n");
            RANDOM_test_perf(mode[i]);
#ifdef __ENABLE_DIGICERT_DSA__
            printf("\nDSA_xx APIs\n");
            DSA_perf_test(mode[i]);
#endif
#ifdef __ENABLE_DIGICERT_PKCS1__
            //printf("\nPKCS1_xx APIs\n");
            //PKCS1_perf_test(mode[i]);
#endif
            //printf("\nDH_xx APIs\n");
            //DH_perf_test(mode[i]);
#ifdef __ENABLE_DIGICERT_ECC__
            //printf("\nECDSA_xx APIs\n");
            //ECDSA_perf_test(mode[i]);
#endif
#ifdef __ENABLE_DIGICERT_ECC__
            //printf("\nECDH_xx APIs\n");
            //ECDH_perf_test(mode[i]);
#endif
            //printf("\nRSA_xx APIs\n");
            //RSA_perf_test(mode[i]);
            printf("\n\n");
        }
    }

#endif /* __DIGICERT_PERFORMANCE_TESTS_ENABLE__ */
    return OK;
}
#endif

#endif /* __DIGICERT_PERFORMANCE_TESTS_ENABLE__ */

