/*
 * crypto_interface_keygen_example.c
 *
 * Crypto Interface Key Generation Example Code
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/random.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"

#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../crypto_interface/crypto_interface_rsa.h"

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#include "../../crypto_interface/crypto_interface_dsa.h"
#endif
#ifdef __ENABLE_DIGICERT_PQC__
#include "../../crypto_interface/crypto_interface_qs.h"
#endif

/* macros for the names of the output files that will contain pem form keys */
#ifndef CI_ECC_PRIV_KEY_FILE
#define CI_ECC_PRIV_KEY_FILE "ecc_key_priv.pem"
#endif

#ifndef CI_ECC_PUB_KEY_FILE
#define CI_ECC_PUB_KEY_FILE "ecc_key_pub.pem"
#endif

#ifndef CI_ECC_ED_PRIV_KEY_FILE
#define CI_ECC_ED_PRIV_KEY_FILE "ecc_ed_key_priv.pem"
#endif

#ifndef CI_ECC_ED_PUB_KEY_FILE
#define CI_ECC_ED_PUB_KEY_FILE "ecc_ed_key_pub.pem"
#endif

#ifndef CI_RSA_PRIV_KEY_FILE
#define CI_RSA_PRIV_KEY_FILE "rsa_key_priv.pem"
#endif

#ifndef CI_RSA_PUB_KEY_FILE
#define CI_RSA_PUB_KEY_FILE "rsa_key_pub.pem"
#endif

#ifndef CI_DSA_PRIV_KEY_FILE
#define CI_DSA_PRIV_KEY_FILE "dsa_key_priv.pem"
#endif

#ifndef CI_DSA_PUB_KEY_FILE
#define CI_DSA_PUB_KEY_FILE "dsa_key_pub.pem"
#endif

#ifndef CI_COMPOSITE_PRIV_KEY_FILE
#define CI_COMPOSITE_PRIV_KEY_FILE "composite_key_priv.pem"
#endif

/* --------------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
static MSTATUS keygen_ecc_example(ubyte4 curveId, const char *privFile, const char *pubFile)
{
    MSTATUS status = OK;

    /* Pair of Asymmetric keys */
    AsymmetricKey privKey = {0};
    AsymmetricKey pubKey = {0};

    /* Template used for obtaining the public key from the generated private key */
    MEccKeyTemplate eccTemplate = {0};
   
    /* buffer to hold the serialized keys */
    ubyte *pKeyBuff = NULL;
    ubyte4 keyBuffLen = 0;
    
    /* Create a private key pair first, if the curve is Edward's form this API will set the proper key type in pKey */
    status = CRYPTO_createECCKeyEx(&privKey, curveId);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_EC_generateKeyPairAux(privKey.key.pECC, RANDOM_rngFun, (void *) g_pRandomContext);
    if (OK != status)
        goto exit;

    /* Serialize to a private key PEM form */
    status = CRYPTO_serializeAsymKey (&privKey, privateKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;
    
    /* And write it to a file */
    status = DIGICERT_writeFile(privFile, pKeyBuff, keyBuffLen);
    if (OK != status)
        goto exit;

    /* Clear the key buffer so we can re-use it for the public key */
    status = DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    if (OK != status)
        goto exit;

    /* We will need a new Asymmetric key containing a public ECC key to serialize to a public PEM form */
    status = CRYPTO_createECCKeyEx(&pubKey, curveId);
    if (OK != status)
        goto exit;
    
    /* get the public key from the private key passed into the method */
    status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(privKey.key.pECC, &eccTemplate, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
        goto exit;
    
    /* set it in the new key */
    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(pubKey.key.pECC, eccTemplate.pPublicKey, eccTemplate.publicKeyLen, 
                                                     NULL, 0);
    if (OK != status)
        goto exit;

    /* Output it to a public Key PEM form */
    status = CRYPTO_serializeAsymKey (&pubKey, publicKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;

    /* And write it to a file */
    status = DIGICERT_writeFile(pubFile, pKeyBuff, keyBuffLen);

exit:

    /* free our buffer holding the serialized key, no need to check return status since we're in exit block already */
    if (NULL != pKeyBuff)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    }

    /* Free the key template */
    (void) CRYPTO_INTERFACE_EC_freeKeyTemplateAux(privKey.key.pECC, &eccTemplate);

    /* Uninit the Asymmetric Key, which will free the underlying ECC key */
    (void) CRYPTO_uninitAsymmetricKey(&privKey, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    return status;
}
#endif

/* --------------------------------------------------------------------------------*/

static MSTATUS keygen_rsa_example(ubyte4 keySize)
{
    MSTATUS status = OK;

    /* Pair of Asymmetric keys */
    AsymmetricKey privKey = {0};
    AsymmetricKey pubKey = {0};

    /* Template used for obtaining the public key from the generated private key */
    MRsaKeyTemplate rsaTemplate = {0};
   
    /* buffer to hold the serialized keys */
    ubyte *pKeyBuff = NULL;
    ubyte4 keyBuffLen = 0;
    
    /* Create a private key pair first */
    status = CRYPTO_createRSAKey(&privKey, NULL);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_RSA_generateKey (g_pRandomContext, privKey.key.pRSA, keySize, NULL);
    if (OK != status)
        goto exit;

    /* Serialize to a private key PEM form */
    status = CRYPTO_serializeAsymKey (&privKey, privateKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;
    
    /* And write it to a file */
    status = DIGICERT_writeFile(CI_RSA_PRIV_KEY_FILE, pKeyBuff, keyBuffLen);
    if (OK != status)
        goto exit;

    /* Clear the key buffer so we can re-use it for the public key */
    status = DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    if (OK != status)
        goto exit;

    /* We will need a new Asymmetric key containing a public RSA key to serialize to a public PEM form */
    status = CRYPTO_createRSAKey(&pubKey, NULL);
    if (OK != status)
        goto exit;
    
    /* Get the public key values from the private key */
    status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(privKey.key.pRSA, &rsaTemplate, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
        goto exit;
    
    /* set it in the new public key */
    status = CRYPTO_INTERFACE_RSA_setPublicKeyData(pubKey.key.pRSA, rsaTemplate.pE, rsaTemplate.eLen,
                                                                    rsaTemplate.pN, rsaTemplate.nLen, NULL);
    if (OK != status)
        goto exit;

    /* Output it to a public Key PEM form */
    status = CRYPTO_serializeAsymKey (&pubKey, publicKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;

    /* And write it to a file */
    status = DIGICERT_writeFile(CI_RSA_PUB_KEY_FILE, pKeyBuff, keyBuffLen);

exit:

    /* free our buffer holding the serialized key, no need to check return status since we're in exit block already */
    if (NULL != pKeyBuff)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    }

    /* Free the key template */
    (void) CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(privKey.key.pRSA, &rsaTemplate);

    /* Uninit the Asymmetric Key, which will free the underlying RSA key */
    (void) CRYPTO_uninitAsymmetricKey(&privKey, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    return status;
}

/* --------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
static MSTATUS keygen_dsa_example(ubyte4 pSize, ubyte4 qSize)
{
    MSTATUS status = OK;

    /* Pair of Asymmetric keys */
    AsymmetricKey privKey = {0};
    AsymmetricKey pubKey = {0};

    /* Template used for obtaining the public key from the generated private key */
    MDsaKeyTemplate dsaTemplate = {0};
   
    /* buffer to hold the serialized keys */
    ubyte *pKeyBuff = NULL;
    ubyte4 keyBuffLen = 0;
    
    /* The sha chosen should match the qSize passed in*/
    DSAHashType hashType = (160 == qSize ? DSA_sha1 : (224 == qSize ? DSA_sha224 : DSA_sha256) );

    /* Create a private key pair first */    
    status = CRYPTO_createDSAKey(&privKey, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DSA_generateKeyAux2(g_pRandomContext, privKey.key.pDSA, pSize, qSize, hashType, NULL);
    if (OK != status)
        goto exit;

   /* Serialize to a private key PEM form */
    status = CRYPTO_serializeAsymKey (&privKey, privateKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;
    
    /* And write it to a file */
    status = DIGICERT_writeFile(CI_DSA_PRIV_KEY_FILE, pKeyBuff, keyBuffLen);
    if (OK != status)
        goto exit;

    /* Clear the key buffer so we can re-use it for the public key */
    status = DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    if (OK != status)
        goto exit;

    /* We will need a new Asymmetric key containing a public ECC key to serialize to a public PEM form */
    status = CRYPTO_createDSAKey(&pubKey, NULL);
    if (OK != status)
        goto exit;
    
    /* get the public key from the private key passed into the method */
    status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(privKey.key.pDSA, &dsaTemplate, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
        goto exit;

    /* set it in the new key */
    status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(pubKey.key.pDSA, &dsaTemplate);
    if (OK != status)
        goto exit;
    
    /* Output it to a public Key PEM form */
    status = CRYPTO_serializeAsymKey (&pubKey, publicKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;

    /* And write it to a file */
    status = DIGICERT_writeFile(CI_DSA_PUB_KEY_FILE, pKeyBuff, keyBuffLen);

exit:

    /* free our buffer holding the serialized key, no need to check return status since we're in exit block already */
    if (NULL != pKeyBuff)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    }

    /* Free the key template */
    (void) CRYPTO_INTERFACE_DSA_freeKeyTemplate(privKey.key.pDSA, &dsaTemplate);

    /* Uninit the Asymmetric Key, which will free the underlying DSA key */
    (void) CRYPTO_uninitAsymmetricKey(&privKey, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    return status;
}
#endif

/* --------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) && defined(__ENABLE_DIGICERT_PQC__)
static MSTATUS keygen_composite_example(ubyte4 clAlg, ubyte4 qsAlg)
{
    MSTATUS status = OK;

    /* We use a single Asymmetric keys */
    AsymmetricKey privKey = {0};

    /* For simplicity of cleanup we'll create the QS_CTX for the key first */
    QS_CTX *pCtx = NULL;
   
    /* buffer to hold the serialized keys */
    ubyte *pKeyBuff = NULL;
    ubyte4 keyBuffLen = 0;

    /* First we generate the QS key in the QS_CTX */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(gpHwAccelCtx) &pCtx, qsAlg);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(gpHwAccelCtx) pCtx, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* test if clAlg is ECC, ECC algorithm id's are all less than the first RSA algorithm id */
    if (clAlg < cid_RSA_2048_PKCS15)
    {
        status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(clAlg, (void **) &privKey.key.pECC, RANDOM_rngFun, g_pRandomContext, akt_ecc, NULL);
        if (OK != status)
            goto exit;
    }
    else /* clAlg is RSA */
    {
        ubyte4 keySize = 2048; /* default */
        
        /* get the correct keySize */
        if (clAlg == cid_RSA_3072_PKCS15 || clAlg == cid_RSA_3072_PSS)
            keySize = 3072;
        else if (clAlg == cid_RSA_4096_PKCS15 || clAlg == cid_RSA_4096_PSS)
            keySize = 4096;

        status = CRYPTO_createRSAKey(&privKey, NULL);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_RSA_generateKey (g_pRandomContext, privKey.key.pRSA, keySize, NULL);
        if (OK != status)
            goto exit;
    }

    /* change key type and transfer the QS_CTX */
    privKey.type = akt_hybrid;
    privKey.clAlg = clAlg;
    privKey.pQsCtx = pCtx; pCtx = NULL;

    /* Serialize to a private key PEM form */
    status = CRYPTO_serializeAsymKey (&privKey, privateKeyPem, &pKeyBuff, &keyBuffLen);
    if (OK != status)
        goto exit;
    
    /* And write it to a file */
    status = DIGICERT_writeFile(CI_COMPOSITE_PRIV_KEY_FILE, pKeyBuff, keyBuffLen);

exit:

    /* free our buffer holding the serialized key, no need to check return status since we're in exit block already */
    if (NULL != pKeyBuff)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuff, keyBuffLen);
    }

    /* Uninit the Asymmetric Key, which will free the underlying ECC and quantum safe keys */
    (void) CRYPTO_uninitAsymmetricKey(&privKey, NULL);

    /* in case the QS_CTX was not transferred and freed in the above call */
    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    return status;
}
#endif

MOC_EXTERN MSTATUS crypto_interface_keygen_example()
{
    MSTATUS status = OK;

    /* Example generation of an RSA 2048 bit key pair */
    status = keygen_rsa_example(2048);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
    /* Example generation of an ECC key pair for NIST curve P256 */
    status = keygen_ecc_example(cid_EC_P256, CI_ECC_PRIV_KEY_FILE, CI_ECC_PUB_KEY_FILE);
    if (OK != status)
        goto exit;

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    /* Example generation of an ECC key pair for Edward's curve25519 */
    status = keygen_ecc_example(cid_EC_Ed25519, CI_ECC_ED_PRIV_KEY_FILE, CI_ECC_ED_PUB_KEY_FILE);
    if (OK != status)
        goto exit;
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__ */

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    /* Example generation of a DSA 2048/256 (p size/q size) bit key pair */
    status = keygen_dsa_example(2048, 256);
    if (OK != status)
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) && defined(__ENABLE_DIGICERT_PQC__)
    /* Example generation of composite keypair consising of an ECC key on P256 and a quantum safe ML-DSA44 (Dilithium) key.*/
    status = keygen_composite_example(cid_EC_P256, cid_PQC_MLDSA_44);
#endif

exit:

    return status;
}
