/*
 * crypto_shim.c
 *
 * Crypto functions used with shim/connectors
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


/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#ifdef __ENABLE_ARC2_CIPHERS__
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#endif
#include "../crypto/des.h"
#ifndef __DISABLE_3DES_CIPHERS__
#include "../crypto/three_des.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#ifdef __ENABLE_BLOWFISH_CIPHERS__
#include "../crypto/blowfish.h"
#endif
#ifdef __ENABLE_NIL_CIPHER__
#include "../crypto/nil.h"
#endif
#include "../asn1/oiddefs.h"

#if defined (__ENABLE_DIGICERT_MBEDCRYPTO__)
#include "../crypto/hmac.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/dh.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/gcm.h"
#include "../common/mrtos.h"
#include "../crypto/rsa.h"
#include "../crypto/pkcs1.h"
#include "../crypto/cert_store.h"
#include "../crypto/des.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/keyblob.h"
#include "../mbedcrypto_wrapper/mbedcrypto_shim.h"
#endif

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_MBEDCRYPTO__)
#ifdef __ENABLE_DIGICERT_SERIALIZE__
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
#define ALG_RSA 1
#else
#define ALG_RSA 0
#endif

#ifdef __ENABLE_DIGICERT_TPM__
#define ALG_TPM 1
#else
#define ALG_TPM 0
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#define ALG_ECC 1
#else
#define ALG_ECC 0
#endif

#define ALG_COUNT (ALG_RSA + ALG_TPM + ALG_ECC)

MKeySerialize gMBEDTPMSupportedAlgos[] = {
#ifdef __ENABLE_DIGICERT_TPM__
    KeySerializeTpmRsa,
#endif
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
    KeySerializeRsa,
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    KeySerializeEcc,
#endif
};

#endif /* __ENABLE_DIGICERT_SERIALIZE__ */
#endif /* __ENABLE_DIGICERT_MBEDCRYPTO__ */

#if defined(__ENABLE_DIGICERT_MBEDCRYPTO__)

extern sbyte4
UninitAsymmetricKey_ALT(AsymmetricKey* pAsymKey)
{
    MSTATUS status = OK;
    status = CRYPTO_uninitAsymmetricKey (pAsymKey, NULL);
    return status;
}

#ifdef __ENABLE_DIGICERT_SERIALIZE__
extern sbyte4
DeserializeKey_ALT(ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  AsymmetricKey *pDeserializedKey)
{
    MSTATUS status = OK;

    status = CRYPTO_deserializeKey(pSerializedKey, serializedKeyLen,
                                   gMBEDTPMSupportedAlgos, ALG_COUNT,
                                   pDeserializedKey);
    return status;
}
#endif /* __ENABLE_DIGICERT_SERIALIZE__ */

/* Initialize CRYPTO-SHIM Methods */
extern sbyte4
NCRYPTO_bindShimMethods(NCRYPTO_METHODS *pMeth)
{
    if (!pMeth)
        return ERR_NULL_POINTER;

    pMeth->DIGI_MEMCPY = DIGI_MEMCPY;
    pMeth->DIGI_MEMCMP = DIGI_MEMCMP;
    pMeth->DIGI_MEMSET = DIGI_MEMSET;
    pMeth->DIGI_MALLOC = DIGI_MALLOC;
    pMeth->DIGI_FREE = DIGI_FREE;

    pMeth->CreateAESECBCtx = CreateAESECBCtx;
    pMeth->DoAESECB = DoAESECB;
    pMeth->DeleteAESECBCtx = DeleteAESECBCtx;
    pMeth->CreateAESCtx = CreateAESCtx;
    pMeth->DoAES = DoAES;
    pMeth->DeleteAESCtx = DeleteAESCtx;
    pMeth->CreateAESCFBCtx = CreateAESCFBCtx;

    pMeth->CreateAESCTRCtx = CreateAESCTRCtx;
    pMeth->DoAESCTR = DoAESCTR;

#if defined(__ENABLE_DIGICERT_GCM_256B__)
	/* AES-GCM 256b*/
	pMeth->GCM_CREATE_CTX = (NCRYPTO_GCM_createCtx_256b) GCM_createCtx_256b;
	pMeth->GCM_CIPHER = (NCRYPTO_GCM_cipher_256b) GCM_cipher_256b;
	pMeth->GCM_INIT = (NCRYPTO_GCM_init_256b) GCM_init_256b;
	pMeth->GCM_UPDATE_ENCRYPT = (NCRYPTO_GCM_update_encrypt_256b) GCM_update_encrypt_256b;
	pMeth->GCM_UPDATE_DECRYPT = (NCRYPTO_GCM_update_decrypt_256b) GCM_update_decrypt_256b;
	pMeth->GCM_FINAL = (NCRYPTO_GCM_final_256b) GCM_final_256b;
	pMeth->GCM_DELETE_CTX = (NCRYPTO_GCM_deleteCtx_256b) GCM_deleteCtx_256b;
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
	/* AES-GCM 4K */
	pMeth->GCM_CREATE_CTX = (NCRYPTO_GCM_createCtx_4k) GCM_createCtx_4k;
	pMeth->GCM_CIPHER = (NCRYPTO_GCM_cipher_4k) GCM_cipher_4k;
	pMeth->GCM_INIT = (NCRYPTO_GCM_init_4k) GCM_init_4k;
	pMeth->GCM_UPDATE_ENCRYPT = (NCRYPTO_GCM_update_encrypt_4k) GCM_update_encrypt_4k;
	pMeth->GCM_UPDATE_DECRYPT = (NCRYPTO_GCM_update_decrypt_4k) GCM_update_decrypt_4k;
	pMeth->GCM_FINAL = (NCRYPTO_GCM_final_4k) GCM_final_4k;
	pMeth->GCM_DELETE_CTX = (NCRYPTO_GCM_deleteCtx_4k) GCM_deleteCtx_4k;
#elif defined(__ENABLE_DIGICERT_GCM_64K__)
	/* AES-GCM 64 */
	pMeth->GCM_CREATE_CTX = (NCRYPTO_GCM_createCtx_64k) GCM_createCtx_64k;
	pMeth->GCM_CIPHER = (NCRYPTO_GCM_cipher_64k) GCM_cipher_64k;
	pMeth->GCM_INIT = (NCRYPTO_GCM_init_64k) GCM_init_64k;
	pMeth->GCM_UPDATE_ENCRYPT = (NCRYPTO_GCM_update_encrypt_64k) GCM_update_encrypt_64k;
	pMeth->GCM_UPDATE_DECRYPT = (NCRYPTO_GCM_update_decrypt_64k) GCM_update_decrypt_64k;
	pMeth->GCM_FINAL = (NCRYPTO_GCM_final_64k) GCM_final_64k;
	pMeth->GCM_DELETE_CTX = (NCRYPTO_GCM_deleteCtx_64k) GCM_deleteCtx_64k;
#endif

    pMeth->CreateRC4Ctx = CreateRC4Ctx;
    pMeth->DeleteRC4Ctx = DeleteRC4Ctx;
    pMeth->DoRC4 = DoRC4;
    
    pMeth->DES_encipher = (NCRYPTO_DES_encipher) DES_encipher;
    pMeth->DES_decipher = (NCRYPTO_DES_decipher) DES_decipher;
    pMeth->CreateDESCtx = (NCRYPTO_CreateDESCtx) CreateDESCtx;
    pMeth->DeleteDESCtx = (NCRYPTO_DeleteDESCtx) DeleteDESCtx;
    pMeth->DoDES = (NCRYPTO_DoDES) DoDES;
    
    pMeth->THREE_DES_encipher = (NCRYPTO_THREE_DES_encipher) THREE_DES_encipher;
    pMeth->THREE_DES_decipher = (NCRYPTO_THREE_DES_decipher) THREE_DES_decipher;
    pMeth->Create3DESCtx = (NCRYPTO_Create3DESCtx) Create3DESCtx;
    pMeth->Create2Key3DESCtx = (NCRYPTO_Create2Key3DESCtx) Create2Key3DESCtx;
    pMeth->Delete3DESCtx = (NCRYPTO_Delete3DESCtx) Delete3DESCtx;
    pMeth->Do3DES = (NCRYPTO_Do3DES) Do3DES;
    
    pMeth->MD4Alloc = MD4Alloc;
    pMeth->MD4Free = MD4Free;
    pMeth->MD4Init = (NCRYPTO_MD4Init)MD4Init;
    pMeth->MD4Update = (NCRYPTO_MD4Update)MD4Update;
    pMeth->MD4Final = (NCRYPTO_MD4Final)MD4Final;
    
    pMeth->MD5Alloc_m = MD5Alloc_m;
    pMeth->MD5Free_m = MD5Free_m;
    pMeth->MD5Init_m = (NCRYPTO_MD5Init_m)MD5Init_m;
    pMeth->MD5Update_m = (NCRYPTO_MD5Update_m)MD5Update_m;
    pMeth->MD5Final_m = (NCRYPTO_MD5Final_m)MD5Final_m;

	/* SHA1 */
    pMeth->SHA1_allocDigest = SHA1_allocDigest;
    pMeth->SHA1_freeDigest = SHA1_freeDigest;
    pMeth->SHA1_initDigest = (NCRYPTO_SHA1_initDigest)SHA1_initDigest;
    pMeth->SHA1_updateDigest = (NCRYPTO_SHA1_updateDigest)SHA1_updateDigest;
    pMeth->SHA1_finalDigest = (NCRYPTO_SHA1_finalDigest)SHA1_finalDigest;

#if !defined( __DISABLE_DIGICERT_SHA256__) || !defined(__DISABLE_DIGICERT_SHA224__)
    pMeth->SHA256_allocDigest = SHA256_allocDigest;
    pMeth->SHA256_freeDigest = SHA256_freeDigest;
#endif
	/* SHA256 */
#ifndef __DISABLE_DIGICERT_SHA224__
    pMeth->SHA224_initDigest = (NCRYPTO_SHA224_initDigest)SHA224_initDigest;
    pMeth->SHA224_updateDigest = (NCRYPTO_SHA224_updateDigest)SHA224_updateDigest;
    pMeth->SHA224_finalDigest = (NCRYPTO_SHA224_finalDigest)SHA224_finalDigest;
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    pMeth->SHA256_initDigest = (NCRYPTO_SHA256_initDigest)SHA256_initDigest;
    pMeth->SHA256_updateDigest = (NCRYPTO_SHA256_updateDigest)SHA256_updateDigest;
    pMeth->SHA256_finalDigest = (NCRYPTO_SHA256_finalDigest)SHA256_finalDigest;
#endif

#if !defined( __DISABLE_DIGICERT_SHA512__) || !defined(__DISABLE_DIGICERT_SHA384__)
    pMeth->SHA512_allocDigest = SHA512_allocDigest;
    pMeth->SHA512_freeDigest = SHA512_freeDigest;
#endif
	/* SHA512 */
#ifndef __DISABLE_DIGICERT_SHA384__
    pMeth->SHA384_initDigest = (NCRYPTO_SHA384_initDigest) SHA384_initDigest;
    pMeth->SHA384_updateDigest = (NCRYPTO_SHA384_updateDigest) SHA384_updateDigest;
    pMeth->SHA384_finalDigest = (NCRYPTO_SHA384_finalDigest) SHA384_finalDigest;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    pMeth->SHA512_initDigest = (NCRYPTO_SHA512_initDigest) SHA512_initDigest;
    pMeth->SHA512_updateDigest = (NCRYPTO_SHA512_updateDigest) SHA512_updateDigest;
    pMeth->SHA512_finalDigest = (NCRYPTO_SHA512_finalDigest) SHA512_finalDigest;
#endif

    pMeth->HmacCreate = (NCRYPTO_HmacCreate) HmacCreate;
    pMeth->HmacKey = (NCRYPTO_HmacKey) HmacKey;
    pMeth->HmacReset = (NCRYPTO_HmacReset) HmacReset;
    pMeth->HmacUpdate = (NCRYPTO_HmacUpdate) HmacUpdate;
    pMeth->HmacFinal = (NCRYPTO_HmacFinal) HmacFinal;
    pMeth->HmacDelete = (NCRYPTO_HmacDelete) HmacDelete;
    pMeth->HmacQuick = (NCRYPTO_HmacQuick) HmacQuick;
    
    pMeth->CRYPTO_getRSAHashAlgo = (NCRYPTO_CRYPTO_getRSAHashAlgo) CRYPTO_getRSAHashAlgo;
    
    pMeth->DH_allocate = (NCRYPTO_DH_allocate) DH_allocate;
    pMeth->DH_setPG = (NCRYPTO_DH_setPG) DH_setPG;
    pMeth->DH_freeDhContext = (NCRYPTO_DH_freeDhContext) DH_freeDhContext;
    pMeth->DH_computeKeyExchange = (NCRYPTO_DH_computeKeyExchange) DH_computeKeyExchange;
    
    pMeth->VLONG_vlongFromByteString = (NCRYPTO_VLONG_vlongFromByteString) VLONG_vlongFromByteString;
    pMeth->VLONG_byteStringFromVlong = (NCRYPTO_VLONG_byteStringFromVlong) VLONG_byteStringFromVlong;
    pMeth->VLONG_freeVlong = (NCRYPTO_VLONG_freeVlong) VLONG_freeVlong;
    pMeth->VLONG_compareSignedVlongs = (NCRYPTO_VLONG_compareSignedVlongs) VLONG_compareSignedVlongs;
    
    pMeth->RANDOM_acquireContext = (NCRYPTO_RANDOM_acquireContext) RANDOM_acquireContext;
    pMeth->RANDOM_releaseContext = (NCRYPTO_RANDOM_releaseContext) RANDOM_releaseContext;

#ifdef __ENABLE_DIGICERT_ECC__    
    pMeth->PRIMEFIELD_newElement = (NCRYPTO_PRIMEFIELD_newElement) PRIMEFIELD_newElement;
    pMeth->PRIMEFIELD_getElementByteStringLen = (NCRYPTO_PRIMEFIELD_getElementByteStringLen) PRIMEFIELD_getElementByteStringLen;
    pMeth->PRIMEFIELD_setToByteString = (NCRYPTO_PRIMEFIELD_setToByteString) PRIMEFIELD_setToByteString;
    pMeth->PRIMEFIELD_getAsByteString = (NCRYPTO_PRIMEFIELD_getAsByteString) PRIMEFIELD_getAsByteString;
    pMeth->PRIMEFIELD_deleteElement = (NCRYPTO_PRIMEFIELD_deleteElement) PRIMEFIELD_deleteElement;

    pMeth->EC_getUnderlyingField = (NCRYPTO_EC_getUnderlyingField) EC_getUnderlyingField;
    pMeth->EC_verifyPublicKey = (NCRYPTO_EC_verifyPublicKey) EC_verifyPublicKey;
    pMeth->ECDH_generateSharedSecretAux = (NCRYPTO_ECDH_generateSharedSecretAux) ECDH_generateSharedSecretAux;

    pMeth->EC_newKey = (NCRYPTO_EC_newKey) EC_newKey;
    pMeth->EC_generateKeyPair = (NCRYPTO_EC_generateKeyPair) EC_generateKeyPair;
    pMeth->EC_deleteKey = (NCRYPTO_EC_deleteKey) EC_deleteKey;
    pMeth->ECDSA_sign = (NCRYPTO_ECDSA_sign) ECDSA_signDigestAux;
    pMeth->ECDSA_verifySignature = (NCRYPTO_ECDSA_verifySignature) ECDSA_verifySignature;
#endif 

    pMeth->RSA_generateKey = (NCRYPTO_RSA_generateKey) RSA_generateKey;
    pMeth->RSA_getCipherTextLength = (NCRYPTO_RSA_getCipherTextLength) RSA_getCipherTextLength;
    pMeth->RSA_freeKey = (NCRYPTO_RSA_freeKey) RSA_freeKey;
    pMeth->RSA_createKey = (NCRYPTO_RSA_createKey) RSA_createKey;
    pMeth->RSA_RSAVP1 = (NCRYPTO_RSA_RSAVP1) RSA_RSAVP1;
    pMeth->RSA_prepareKey = (NCRYPTO_RSA_prepareKey) RSA_prepareKey;
    pMeth->RSA_RSASP1 = (NCRYPTO_RSA_RSASP1) RSA_RSASP1;
    pMeth->RSA_encrypt = (NCRYPTO_RSA_encrypt) RSA_encrypt;
    pMeth->RSA_decrypt = (NCRYPTO_RSA_decrypt) RSA_decrypt;
    pMeth->RSA_signMessage = (NCRYPTO_RSA_signMessage) RSA_signMessage;
    pMeth->RSA_verifySignature = (NCRYPTO_RSA_verifySignature) RSA_verifySignature;
#ifdef __ENABLE_DIGICERT_PKCS1__
    pMeth->PKCS1_rsaesOaepEncrypt = (NCRYPTO_PKCS1_rsaesOaepEncrypt) PKCS1_rsaesOaepEncrypt;
    pMeth->PKCS1_rsassaPssVerify = (NCRYPTO_PKCS1_rsassaPssVerify) PKCS1_rsassaPssVerify;
#if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))
    pMeth->PKCS1_rsaesOaepDecrypt = (NCRYPTO_PKCS1_rsaesOaepDecrypt) PKCS1_rsaesOaepDecrypt;
    pMeth->PKCS1_rsassaPssSign = (NCRYPTO_PKCS1_rsassaPssSign) PKCS1_rsassaPssSign;
    pMeth->PKCS1_rsassaFreePssSign = (NCRYPTO_PKCS1_rsassaFreePssSign) PKCS1_rsassaFreePssSign;
#endif
#endif

    /*Cert*/
    pMeth->createCertStore = (NCRYPTO_createCertStore) CERT_STORE_createStore;
    pMeth->releaseCertStore = (NCRYPTO_releaseCertStore) CERT_STORE_releaseStore;

    pMeth->initAsymmetricKey    = (NCRYPTO_initAsymmetricKey) CRYPTO_initAsymmetricKey;
    pMeth->uninitAsymmetricKey  = (NCRYPTO_uninitAsymmetricKey) UninitAsymmetricKey_ALT;
#ifdef __ENABLE_DIGICERT_SERIALIZE__
    pMeth->deserializeKey = (NCRYPTO_deserializeKey)DeserializeKey_ALT;
#endif
     pMeth->decodeCertificate = (NCRYPTO_decodeCertificate)CA_MGMT_decodeCertificate;
     pMeth->mocanaReadFile = (NCRYPTO_mocanaReadFile)DIGICERT_readFile;
     pMeth->makeKeyBlobEx = (NCRYPTO_makeKeyBlobEx)KEYBLOB_makeKeyBlobEx;
     pMeth->addIdenCertChain = (NCRYPTO_addIdentityCertChain)CERT_STORE_addIdentityWithCertificateChain;

    return OK;
}
#endif /* __ENABLE_DIGICERT_MBEDCRYPTO__ */
