/*
 * mocana_glue.c
 *
 * Defines a structures used for providing algogithm implementation through Openssl's EVP.
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#ifndef MOCANA_GLUE_H
#define MOCANA_GLUE_H

#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <openssl/crypto.h>
#endif
#define ASN1_ITEM MOC_ASN1_ITEM
#ifdef __RTOS_VXWORKS__
#include <common/moptions.h>
#include <common/mtypes.h>
#include <common/mocana.h>
#include <common/mdefs.h>
#include <common/merrors.h>
#include <common/mrtos.h>
#include <common/vlong.h>
#include <common/random.h>
#include <common/mstdlib.h>
#include <common/mversion.h>
#include <crypto/md2.h>
#include <crypto/md4.h>
#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <crypto/crypto.h>
#include <crypto/rsa.h>
#include <crypto/dsa.h>
#include <crypto/dsa2.h>
#include <crypto/dh.h>
#include <crypto/des.h>
#include <crypto/primefld.h>
#include <crypto/primeec.h>
#include <crypto/three_des.h>
#include <crypto/aes.h>
#include <crypto/aes_ecb.h>
#include <crypto/aes_keywrap.h>
#include <crypto/arc2.h>
#include <crypto/rc2algo.h>
#include <crypto/arc4.h>
#include <crypto/rc4algo.h>
#include <crypto/rc5algo.h>
#include <crypto/pkcs1.h>
#include <crypto/aes_ctr.h>
#include <crypto/gcm.h>
#include <crypto/aes_ccm.h>
#ifndef __DISABLE_AES_XTS__
#include <crypto/aes_xts.h>
#endif
#include <crypto/chacha20.h>
#include <crypto/pubcrypto.h>
#include <crypto/ca_mgmt.h>
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include <crypto_interface/cryptointerface.h>
#include <crypto_interface/crypto_interface_aes.h>
#include <crypto_interface/crypto_interface_aes_ctr.h>
#include <crypto_interface/crypto_interface_aes_ccm.h>
#ifndef __DISABLE_AES_XTS__
#include <crypto_interface/crypto_interface_aes_xts.h>
#endif
#include <crypto_interface/crypto_interface_aes_keywrap.h>
#include <crypto_interface/crypto_interface_dsa.h>
#include <crypto_interface/crypto_interface_dh.h>
#include <crypto_interface/crypto_interface_pkcs1.h>
#include <crypto_interface/crypto_interface_chacha20.h>
#include <crypto_interface/crypto_interface_rc5.h>
#endif
#ifdef __ENABLE_DIGICERT_TAP__
#include <tap/tap.h>
#include <crypto/mocasymkeys/rsatap.h>
#include <crypto/mocasymkeys/ecctap.h>
#endif
#else /* not VX WORKS */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mocana.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mrtos.h"
#include "../../../src/common/vlong.h"
#include "../../../src/common/random.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/mversion.h"
#include "../../../src/crypto/md2.h"
#include "../../../src/crypto/md4.h"
#include "../../../src/crypto/md5.h"
#include "../../../src/crypto/sha1.h"
#include "../../../src/crypto/sha256.h"
#include "../../../src/crypto/sha512.h"
#else
#include "../../../../src/common/moptions.h"
#include "../../../../src/common/mtypes.h"
#include "../../../../src/common/mocana.h"
#include "../../../../src/common/mdefs.h"
#include "../../../../src/common/merrors.h"
#include "../../../../src/common/mrtos.h"
#include "../../../../src/common/vlong.h"
#include "../../../../src/common/random.h"
#include "../../../../src/common/mstdlib.h"
#include "../../../../src/common/mversion.h"
#include "../../../../src/crypto/md2.h"
#include "../../../../src/crypto/md4.h"
#include "../../../../src/crypto/md5.h"
#include "../../../../src/crypto/sha1.h"
#include "../../../../src/crypto/sha256.h"
#include "../../../../src/crypto/sha512.h"
#endif /* defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#include "../../../../src/crypto/sha3.h"
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "../../../src/crypto/sha3.h"
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "../../../src/crypto/crypto.h"
#include "../../../src/crypto/rsa.h"
#include "../../../src/crypto/dsa.h"
#include "../../../src/crypto/dsa2.h"
#include "../../../src/crypto/dh.h"
#include "../../../src/crypto/des.h"
#include "../../../src/crypto/primefld.h"
#include "../../../src/crypto/primeec.h"
#include "../../../src/crypto/three_des.h"
#include "../../../src/crypto/aes.h"
#include "../../../src/crypto/aes_ecb.h"
#include "../../../src/crypto/aes_keywrap.h"
#include "../../../src/crypto/arc2.h"
#include "../../../src/crypto/rc2algo.h"
#include "../../../src/crypto/arc4.h"
#include "../../../src/crypto/rc4algo.h"
#include "../../../src/crypto/rc5algo.h"
#include "../../../src/crypto/pkcs1.h"
#include "../../../src/crypto/aes_ctr.h"
#include "../../../src/crypto/gcm.h"
#include "../../../src/crypto/aes_ccm.h"
#ifndef __DISABLE_AES_XTS__
#include "../../../src/crypto/aes_xts.h"
#endif
#include "../../../src/crypto/chacha20.h"
#include "../../../src/crypto/pubcrypto.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "../../../src/common/initmocana.h"
#include "../../../src/tap/tap.h"
#include "../../../src/crypto/mocasymkeys/tap/rsatap.h"
#include "../../../src/crypto/mocasymkeys/tap/ecctap.h"
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../../src/crypto_interface/cryptointerface.h"
#include "../../../src/crypto_interface/crypto_interface_aes.h"
#include "../../../src/crypto_interface/crypto_interface_aes_ctr.h"
#include "../../../src/crypto_interface/crypto_interface_aes_ccm.h"
#ifndef __DISABLE_AES_XTS__
#include "../../../src/crypto_interface/crypto_interface_aes_xts.h"
#endif
#include "../../../src/crypto_interface/crypto_interface_aes_keywrap.h"
#include "../../../src/crypto_interface/crypto_interface_tdes.h"
#include "../../../src/crypto_interface/crypto_interface_dsa.h"
#include "../../../src/crypto_interface/crypto_interface_dh.h"
#include "../../../src/crypto_interface/crypto_interface_pkcs1.h"
#include "../../../src/crypto_interface/crypto_interface_chacha20.h"
#include "../../../src/crypto_interface/crypto_interface_aes_ccm.h"
#include "../../../src/crypto_interface/crypto_interface_md4.h"
#include "../../../src/crypto_interface/crypto_interface_md5.h"
#include "../../../src/crypto_interface/crypto_interface_rc5.h"
#include "../../../src/crypto_interface/crypto_interface_sha1.h"
#include "../../../src/crypto_interface/crypto_interface_sha256.h"
#include "../../../src/crypto_interface/crypto_interface_sha512.h"
#include "../../../src/crypto_interface/crypto_interface_sha3.h"
#include "../../../src/crypto_interface/crypto_interface_des.h"
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#else /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include "../../../../src/crypto/crypto.h"
#include "../../../../src/crypto/rsa.h"
#include "../../../../src/crypto/dsa.h"
#include "../../../../src/crypto/dsa2.h"
#include "../../../../src/crypto/dh.h"
#include "../../../../src/crypto/des.h"
#include "../../../../src/crypto/primefld.h"
#include "../../../../src/crypto/primeec.h"
#include "../../../../src/crypto/three_des.h"
#include "../../../../src/crypto/aes.h"
#include "../../../../src/crypto/aes_ecb.h"
#include "../../../../src/crypto/aes_keywrap.h"
#include "../../../../src/crypto/arc2.h"
#include "../../../../src/crypto/rc2algo.h"
#include "../../../../src/crypto/arc4.h"
#include "../../../../src/crypto/rc4algo.h"
#include "../../../../src/crypto/rc5algo.h"
#include "../../../../src/crypto/pkcs1.h"
#include "../../../../src/crypto/aes_ctr.h"
#include "../../../../src/crypto/gcm.h"
#include "../../../../src/crypto/aes_ccm.h"
#ifndef __DISABLE_AES_XTS__
#include "../../../../src/crypto/aes_xts.h"
#endif
#include "../../../../src/crypto/chacha20.h"
#include "../../../../src/crypto/pubcrypto.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "../../../../src/common/initmocana.h"
#include "../../../../src/tap/tap.h"
#include "../../../../src/crypto/mocasymkeys/tap/rsatap.h"
#include "../../../../src/crypto/mocasymkeys/tap/ecctap.h"
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../../../src/crypto_interface/cryptointerface.h"
#include "../../../../src/crypto_interface/crypto_interface_aes.h"
#include "../../../../src/crypto_interface/crypto_interface_aes_ctr.h"
#include "../../../../src/crypto_interface/crypto_interface_aes_ccm.h"
#ifndef __DISABLE_AES_XTS__
#include "../../../../src/crypto_interface/crypto_interface_aes_xts.h"
#endif
#include "../../../../src/crypto_interface/crypto_interface_aes_keywrap.h"
#include "../../../../src/crypto_interface/crypto_interface_dsa.h"
#include "../../../../src/crypto_interface/crypto_interface_dh.h"
#include "../../../../src/crypto_interface/crypto_interface_pkcs1.h"
#include "../../../../src/crypto_interface/crypto_interface_chacha20.h"
#include "../../../../src/crypto_interface/crypto_interface_aes_ccm.h"
#include "../../../../src/crypto_interface/crypto_interface_md4.h"
#include "../../../../src/crypto_interface/crypto_interface_md5.h"
#include "../../../../src/crypto_interface/crypto_interface_rc5.h"
#include "../../../../src/crypto_interface/crypto_interface_sha1.h"
#include "../../../../src/crypto_interface/crypto_interface_sha256.h"
#include "../../../../src/crypto_interface/crypto_interface_sha512.h"
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#include "../../../../src/crypto_interface/crypto_interface_sha3.h"
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
#include "../../../src/crypto_interface/crypto_interface_des.h"
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif /* __RTOS_VXWORKS__ */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "../../../src/crypto_interface/crypto_interface_sha256.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define MOC_EVP_MAX_MD_SIZE                 (64) /* SHA512_RESULT_SIZE */
#define MOC_EVP_MAX_KEY_LENGTH              (32)
#define MOC_EVP_MAX_IV_LENGTH               (64)
#define MOC_EVP_MAX_BLOCK_LENGTH            (32)
#define MOC_EVP_CHACHAPOLY_TAG_LEN          (16)

#define MOC_SHA_DIGEST_LENGTH               (20)

#define TPM_ENGINE_EX_DATA_UNINIT           -1

typedef struct MOC_EVP_KEY_DATA_s
{
    ubyte4 contentsLen;
    ubyte *pContents;
    MKeyContextCallbackInfo *cb_data;
	void *pData;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
    ubyte *pCred;
    ubyte4 credLen;
#endif
} MOC_EVP_KEY_DATA;

typedef struct MOC_EVP_MD_s
{
    const struct BulkHashAlgo* pHashAlgo;
    int digestResultSize;
    int NID;
} MOC_EVP_MD;

typedef struct MOC_EVP_MD_CTX_s
{
    const MOC_EVP_MD*    pDigestAlgo;
    void*                   pDigestData;
} MOC_EVP_MD_CTX;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

typedef struct MOC_EVP_MD_SHA3_CTX_s
{
    SHA3_CTX *pCtx;
    int mdSize;
} MOC_EVP_MD_SHA3_CTX;

#endif

struct BulkHashAlgo; /* defined in crypto.h */

typedef struct MOC_EVP_CIPHER_s
{
    const BulkEncryptionAlgo*   pBEAlgo;
    sbyte4                      keySize;
    int                         NID;
} MOC_EVP_CIPHER;

typedef struct MOC_EVP_CIPHER_CTX_s
{
    const MOC_EVP_CIPHER *pEncrAlgo;
    void*                pEncrData;
    int                  pad;

    ubyte                oIv[MOC_EVP_MAX_IV_LENGTH];    /* original iv */
    ubyte                wIv[MOC_EVP_MAX_IV_LENGTH];    /* working iv */

    ubyte4               blockBufLen;
    ubyte                blockBuf[MOC_EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    sbyte4               finalBlkUsed;
    ubyte                finalBlk[MOC_EVP_MAX_BLOCK_LENGTH]; /* final decrypted block */
    ubyte4               ivLen; /* iv length required for aead cipher modes */
    ubyte4               aadLen;
    ubyte*               aad;
    ubyte4               dataLen;
    ubyte4               tagLen;
    ubyte                tag[MOC_EVP_MAX_BLOCK_LENGTH]; /* Authentication data tag */
    ubyte		        *key;
    intBoolean           ivSet;
    ubyte4               rc2EffectiveKeyBits;
    intBoolean           init;
} MOC_EVP_CIPHER_CTX;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_GCM_64K__)
#define CRYPTO_INTERFACE_GCM_createCtx       CRYPTO_INTERFACE_GCM_createCtx_64k
#define CRYPTO_INTERFACE_GCM_deleteCtx       CRYPTO_INTERFACE_GCM_deleteCtx_64k
#define CRYPTO_INTERFACE_GCM_init            CRYPTO_INTERFACE_GCM_init_64k
#define CRYPTO_INTERFACE_GCM_update_encrypt  CRYPTO_INTERFACE_GCM_update_encrypt_64k
#define CRYPTO_INTERFACE_GCM_update_decrypt  CRYPTO_INTERFACE_GCM_update_decrypt_64k
#define CRYPTO_INTERFACE_GCM_final           CRYPTO_INTERFACE_GCM_final_64k
#define CRYPTO_INTERFACE_GCM_cipher          CRYPTO_INTERFACE_GCM_cipher_64k
#define CRYPTO_INTERFACE_GCM_clone           CRYPTO_INTERFACE_GCM_clone_64k
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
#define CRYPTO_INTERFACE_GCM_createCtx       CRYPTO_INTERFACE_GCM_createCtx_4k
#define CRYPTO_INTERFACE_GCM_deleteCtx       CRYPTO_INTERFACE_GCM_deleteCtx_4k
#define CRYPTO_INTERFACE_GCM_init            CRYPTO_INTERFACE_GCM_init_4k
#define CRYPTO_INTERFACE_GCM_update_encrypt  CRYPTO_INTERFACE_GCM_update_encrypt_4k
#define CRYPTO_INTERFACE_GCM_update_decrypt  CRYPTO_INTERFACE_GCM_update_decrypt_4k
#define CRYPTO_INTERFACE_GCM_final           CRYPTO_INTERFACE_GCM_final_4k
#define CRYPTO_INTERFACE_GCM_cipher          CRYPTO_INTERFACE_GCM_cipher_4k
#define CRYPTO_INTERFACE_GCM_clone           CRYPTO_INTERFACE_GCM_clone_4k
#elif defined(__ENABLE_DIGICERT_GCM_256B__)
#define CRYPTO_INTERFACE_GCM_createCtx       CRYPTO_INTERFACE_GCM_createCtx_256b
#define CRYPTO_INTERFACE_GCM_deleteCtx       CRYPTO_INTERFACE_GCM_deleteCtx_256b
#define CRYPTO_INTERFACE_GCM_init            CRYPTO_INTERFACE_GCM_init_256b
#define CRYPTO_INTERFACE_GCM_update_encrypt  CRYPTO_INTERFACE_GCM_update_encrypt_256b
#define CRYPTO_INTERFACE_GCM_update_decrypt  CRYPTO_INTERFACE_GCM_update_decrypt_256b
#define CRYPTO_INTERFACE_GCM_final           CRYPTO_INTERFACE_GCM_final_256b
#define CRYPTO_INTERFACE_GCM_cipher          CRYPTO_INTERFACE_GCM_cipher_256b
#define CRYPTO_INTERFACE_GCM_clone           CRYPTO_INTERFACE_GCM_clone_256b
#endif
#else
#if defined(__ENABLE_DIGICERT_GCM_64K__)
#define GCM_createCtx       GCM_createCtx_64k
#define GCM_deleteCtx       GCM_deleteCtx_64k
#define GCM_init            GCM_init_64k
#define GCM_update_encrypt  GCM_update_encrypt_64k
#define GCM_update_decrypt  GCM_update_decrypt_64k
#define GCM_final           GCM_final_64k
#define GCM_cipher          GCM_cipher_64k
#define GCM_clone           GCM_clone_64k
#elif defined(__ENABLE_DIGICERT_GCM_4K__)
#define GCM_createCtx       GCM_createCtx_4k
#define GCM_deleteCtx       GCM_deleteCtx_4k
#define GCM_init            GCM_init_4k
#define GCM_update_encrypt  GCM_update_encrypt_4k
#define GCM_update_decrypt  GCM_update_decrypt_4k
#define GCM_final           GCM_final_4k
#define GCM_cipher          GCM_cipher_4k
#define GCM_clone           GCM_clone_4k
#elif defined(__ENABLE_DIGICERT_GCM_256B__)
#define GCM_createCtx       GCM_createCtx_256b
#define GCM_deleteCtx       GCM_deleteCtx_256b
#define GCM_init            GCM_init_256b
#define GCM_update_encrypt  GCM_update_encrypt_256b
#define GCM_update_decrypt  GCM_update_decrypt_256b
#define GCM_final           GCM_final_256b
#define GCM_cipher          GCM_cipher_256b
#define GCM_clone           GCM_clone_256b
#endif
#endif

typedef struct MOC_EVP_AES_GCM_CIPHER_CTX_s
{
    intBoolean keySet;
    ubyte *pIv;
    sbyte4 ivLen;
    ubyte *pCopyIv;
    ubyte4 copyIvLen;
    intBoolean ivSet;
    intBoolean ivGen;
    sbyte4 tlsAadLen;
    ubyte *pAad;
    ubyte4 aadLen;
    BulkCtx pGcmCtx;
    intBoolean init;
    sbyte4 tagLen;
} MOC_EVP_AES_GCM_CIPHER_CTX;

typedef struct MOC_EVP_RC5_CIPHER_CTX_s
{
    void*                pEncrData;
    sbyte4               encrypt;
    sbyte4               roundCount;
    ubyte*               pKey;
} MOC_EVP_RC5_CIPHER_CTX;

#define MOC_EVP_CHACHA_NONCE_SIZE 12
    
typedef struct MOC_EVP_CHACHAPOLY_CIPHER_CTX_s
{
    void*                pEncrData;
    sbyte4               encrypt;
    ubyte                pTag[MOC_EVP_CHACHAPOLY_TAG_LEN];
    ubyte4               tagLen;
    ubyte                pIv[MOC_EVP_CHACHA_NONCE_SIZE];
} MOC_EVP_CHACHAPOLY_CIPHER_CTX;

extern void DIGI_EVP_CIPHER_CTX_init(MOC_EVP_CIPHER_CTX *ctx);
extern void DIGI_EVP_setEncrAlgo(MOC_EVP_CIPHER_CTX *ctx, int ciphertype);
extern int DIGI_EVP_CIPHER_CTX_cleanup(MOC_SYM(hwAccelDescr hwAccelCtx) MOC_EVP_CIPHER_CTX *ctx);

int DIGI_EVP_digestFinal(MOC_HASH(hwAccelDescr hwAccelCtx)MOC_EVP_MD_CTX *ctx, unsigned char *md);
int DIGI_EVP_digestUpdate(MOC_HASH(hwAccelDescr hwAccelCtx) MOC_EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
void DIGI_EVP_setDigestAlgo(MOC_EVP_MD_CTX *ctx, int digesttype);
void DIGI_EVP_MD_CTX_init(MOC_EVP_MD_CTX *ctx);
int DIGI_EVP_MD_CTX_cleanup(MOC_HASH(hwAccelDescr hwAccelCtx) MOC_EVP_MD_CTX *ctx);

#ifdef  __cplusplus
}
#endif
#endif
