/*
 * evp.h
 *
 * OpenSSL EVP and RAND interface for MOCANA
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
#ifndef __DISABLE_MOCANA_OPENSSL_EVP__

#ifndef __EVP_HEADER__
#define __EVP_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/random.h"

#include "hw_accel.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "crypto.h"
#include "aes.h"
#include "des.h"
#include "arc4.h"
#include "rsa.h"
#include "pkcs1.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define EVP_MAX_MD_SIZE                 (64) /* SHA512_RESULT_SIZE */
#define EVP_MAX_KEY_LENGTH              (32)
#define EVP_MAX_IV_LENGTH               (16)
#define EVP_MAX_BLOCK_LENGTH            (32)

#define SHA_DIGEST_LENGTH               (20)

/* thes constants are copied from OpenSSL's obj_mac.h */
#define NID_undef                       0
#define NID_rsaEncryption               6
#define NID_md2WithRSAEncryption        7
#define NID_md4WithRSAEncryption        396
#define NID_md5WithRSAEncryption        8
#define NID_sha1WithRSAEncryption       65
#define NID_sha256WithRSAEncryption     668
#define NID_sha384WithRSAEncryption     669
#define NID_sha512WithRSAEncryption     670
#define NID_sha224WithRSAEncryption     671

#define NID_dsa                         116
#define NID_dsaWithSHA1                 113

#define NID_dhKeyAgreement              28

#define NID_rc4                         5
#define NID_des_cbc                     31
#define NID_des_ede3_cbc                44
#define NID_aes_128_ecb                 418
#define NID_aes_128_cbc                 419
#define NID_aes_128_ofb                 420
#define NID_aes_192_ecb                 422
#define NID_aes_192_cbc                 423
#define NID_aes_192_ofb                 424
#define NID_aes_256_ecb                 426
#define NID_aes_256_cbc                 427
#define NID_aes_256_ofb                 428

#define NID_commonName                  13
#define NID_subject_alt_name            85


#define MD5_DIGEST_LENGTH               16

struct EVP_MD;

typedef struct EVP_MD_CTX
{
    const struct EVP_MD*    pDigestAlgo;
    void*                   pDigestData;
} EVP_MD_CTX;

typedef struct engine_st ENGINE;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
struct BulkHashAlgo; /* defined in crypto.h */

typedef struct EVP_MD
{
    const struct BulkHashAlgo* pHashAlgo;
    int (*Sign)(int type, const unsigned char *m, unsigned int m_length,
            unsigned char *sigret, unsigned int *siglen, void *key);
    int (*Verify)(int type, const unsigned char *m, unsigned int m_length,
            const unsigned char *sigbuf, unsigned int siglen, void *key);
    int digestResultSize;
    int NID;
} EVP_MD;


const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);


int EVP_MD_size(const EVP_MD *md);

#define EVP_MD_CTX_size(e)		EVP_MD_size(EVP_MD_CTX_md(e))


#ifndef __EVP_C__
/* all structures are opaque except HMAC_CTX */

#if defined( __DISABLE_MOCANA_SHA512__) && defined(__DISABLE_MOCANA_SHA384__)
#define HMAC_BLOCK_SIZE            (64)  /* Maximum Hash Block Size = MD5_BLOCK_SIZE = SHA1_BLOCK_SIZE  = SHA256_BLOCK_SIZE */
#else
#define HMAC_BLOCK_SIZE            (128) /* Maximum Hash Block Size = SHA512_BLOCK_SIZE */
#endif

typedef struct HMAC_CTX
{
    const void*             pBHAlgo;        /* external pointer, not a copy */
    void*                   hashCtxt;

    unsigned long           keyLen;
    unsigned char           key[HMAC_BLOCK_SIZE];
    unsigned char           kpad[HMAC_BLOCK_SIZE];
}HMAC_CTX;
#endif

#ifndef __DISABLE_3DES_CIPHERS__
static const unsigned char oddParity[256]={
  1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254};
#endif

/* key types */
#define EVP_PKEY_NONE   NID_undef
#define EVP_PKEY_RSA    NID_rsaEncryption
#define EVP_PKEY_RSA2   NID_rsa
#define EVP_PKEY_DSA    NID_dsa
#define EVP_PKEY_DSA1   NID_dsa_2
#define EVP_PKEY_DSA2   NID_dsaWithSHA
#define EVP_PKEY_DSA3   NID_dsaWithSHA1
#define EVP_PKEY_DSA4   NID_dsaWithSHA1_2
#define EVP_PKEY_DH     NID_dhKeyAgreement


#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_KEY_WRAP_PAD_BYTE (0xA6)

#define SHA_CTX SHA1_CTX


typedef struct AES_KEY
{
    BulkCtx ctx;
    unsigned char * key;
    int numbits;

}
AES_KEY;

MOC_EXTERN int MD5_Init(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX * ctx);
MOC_EXTERN int MD5_Update(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *c, const void *data,unsigned long len);
MOC_EXTERN int MD5_Final(MOC_HASH(hwAccelDescr hwAccelCtx) unsigned char *md, MD5_CTX *c);

#ifdef __ENABLE_MOCANA_MD4__
MOC_EXTERN int MD4_Init(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX * ctx);
MOC_EXTERN int MD4_Update(MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *c, const void *data,unsigned long len);
MOC_EXTERN int MD4_Final(MOC_HASH(hwAccelDescr hwAccelCtx) unsigned char *md, MD4_CTX *c);
#endif

typedef struct RC4_KEY
{
    rc4_key key;
}
RC4_KEY;

#if (!defined(__DISABLE_ARC4_CIPHERS__) && !defined(__ARC4_HARDWARE_CIPHER__))
MOC_EXTERN void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
MOC_EXTERN void RC4(RC4_KEY *key, unsigned long len, const unsigned char *indata,unsigned char *outdata);
#endif /* !__DISABLE_ARC4_CIPHERS__ &&  !__ARC4_HARDWARE_CIPHER__ */

MOC_EXTERN int SHA1_Init(MOC_HASH(hwAccelDescr hwAccelCtx) SHA_CTX *c);
MOC_EXTERN int SHA1_Update(MOC_HASH(hwAccelDescr hwAccelCtx) SHA_CTX *c, const void *data,unsigned long len);
MOC_EXTERN int SHA1_Final(MOC_HASH(hwAccelDescr hwAccelCtx) unsigned char *md, SHA_CTX *c);

MOC_EXTERN int SHA256_Init(MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *c);
MOC_EXTERN int SHA256_Update(MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *c, const void *data,unsigned long len);
MOC_EXTERN int SHA256_Final(MOC_HASH(hwAccelDescr hwAccelCtx) unsigned char *md, SHA256_CTX *c);

MOC_EXTERN unsigned char *SHA1(MOC_HASH(hwAccelDescr hwAccelCtx) const unsigned char *d, unsigned long n,unsigned char *md);
#define SHA SHA1

typedef unsigned char DES_cblock[8];
typedef struct DES_key_schedule
{
    des_ctx ctx;

}DES_key_schedule;

MOC_EXTERN void DES_set_odd_parity( DES_cblock * pKey8 );
MOC_EXTERN int DES_is_weak_key( DES_cblock * pKey8 );
MOC_EXTERN int DES_key_sched(const DES_cblock *key, DES_key_schedule *schedule);
MOC_EXTERN void DES_ecb_encrypt(const DES_cblock *input, DES_cblock *output,DES_key_schedule *ks, int enc);
#define DES_set_key(key,sched) DES_key_sched(key,sched)

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

struct rsa_st;
struct dsa_st;
struct dh_st;

typedef struct EVP_PKEY
{
    int     type;
    int     references;
    ubyte*  keyBlob;
    ubyte4  keyBlobLen;
    union {
      void* ptr;
      struct rsa_st* rsa;
      struct dsa_st* dsa;
      struct dh_st* dh;
    } pkey;
}EVP_PKEY;

MOC_EXTERN int AES_set_encrypt_key(const unsigned char *key, int numbits, AES_KEY * aeskey);
MOC_EXTERN int AES_set_decrypt_key(const unsigned char *key, int numbits, AES_KEY * aeskey);
MOC_EXTERN void AES_cfb128_encrypt(MOC_SYM(hwAccelDescr hwAccelCtx) const unsigned char * buf_tmp, unsigned char * buf, int len, AES_KEY * aesKey, unsigned char * iv, int * num, int enc);
MOC_EXTERN void AES_cbc_encrypt(MOC_SYM(hwAccelDescr hwAccelCtx) const unsigned char * buf_tmp, unsigned char * buf, int len, AES_KEY * aesKey, unsigned char * iv, int enc);
MOC_EXTERN void AES_ecb_encrypt(MOC_SYM(hwAccelDescr hwAccelCtx) const unsigned char *in, unsigned char *out,AES_KEY *key, const int enc);




MOC_EXTERN void     EVP_MD_CTX_init(EVP_MD_CTX *ctx);
MOC_EXTERN int      EVP_MD_CTX_cleanup(MOC_HASH(hwAccelDescr hwAccelCtx) EVP_MD_CTX *ctx);

MOC_EXTERN int      EVP_DigestInit(MOC_HASH(hwAccelDescr hwAccelCtx)EVP_MD_CTX *ctx, const EVP_MD *type);
MOC_EXTERN int      EVP_DigestUpdate(MOC_HASH(hwAccelDescr hwAccelCtx)EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
MOC_EXTERN int      EVP_DigestFinal(MOC_HASH(hwAccelDescr hwAccelCtx)EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);


/* MOC_EXTERN void     EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type); */
/* MOC_EXTERN int      EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);*/
#define         EVP_SignInit( ctx, type)        EVP_DigestInit(ctx,type)
#define         EVP_SignUpdate(ctx, d, cnt)     EVP_DigestUpdate(ctx,d, cnt)
MOC_EXTERN int      EVP_SignFinal(MOC_HASH(hwAccelDescr hwAccelCtx)EVP_MD_CTX *ctx, unsigned char *sig, unsigned int *s, EVP_PKEY *pkey);

/* MOC_EXTERN int      EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);*/
/* MOC_EXTERN int      EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);*/
#define         EVP_VerifyInit( ctx, type)        EVP_DigestInit(ctx,type)
#define         EVP_VerifyUpdate(ctx, d, cnt)     EVP_DigestUpdate(ctx,d, cnt)
MOC_EXTERN int      EVP_VerifyFinal(MOC_HASH(hwAccelDescr hwAccelCtx)EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);
MOC_EXTERN void EVP_cleanup(void);

struct AsymmetricKey;

MOC_EXTERN int      EVP_PKEY_size(EVP_PKEY *pkey);
MOC_EXTERN int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
MOC_EXTERN void		EVP_PKEY_free(EVP_PKEY *pkey);
MOC_EXTERN EVP_PKEY*    EVP_PKEY_reference(EVP_PKEY *pkey);
MOC_EXTERN EVP_PKEY*    EVP_PKEY_new_from_pkcs8(const unsigned char*, unsigned int);
MOC_EXTERN EVP_PKEY*    EVP_PKEY_new_from_file(const char* filename, int type);
MOC_EXTERN EVP_PKEY*    EVP_PKEY_new_from_AKey(struct AsymmetricKey *key, ubyte* keyBlob, ubyte4 keyBlobLen);


MOC_EXTERN void     HMAC_CTX_init(HMAC_CTX *ctx);
MOC_EXTERN void     HMAC_CTX_cleanup(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx);

#define         HMAC_cleanup(ctx) HMAC_CTX_cleanup(ctx)

MOC_EXTERN void     HMAC_Init(MOC_HASH(hwAccelDescr hwAccelCtx)HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md);
MOC_EXTERN void     HMAC_Update(MOC_HASH(hwAccelDescr hwAccelCtx)HMAC_CTX *ctx, const unsigned char *data, int len);
MOC_EXTERN void     HMAC_Final(MOC_HASH(hwAccelDescr hwAccelCtx)HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
MOC_EXTERN unsigned char *HMAC(MOC_HASH(hwAccelDescr hwAccelCtx) const EVP_MD *evp_md, const void *key,int key_len, const unsigned char *d, int n,unsigned char *md, unsigned int *md_len);

MOC_EXTERN const EVP_MD*    EVP_dss1(void); /* DSA/SHA1 */
#ifdef __ENABLE_MOCANA_MD4__
MOC_EXTERN const EVP_MD*    EVP_md4(void);  /* RSA/MD4 */
#endif
MOC_EXTERN const EVP_MD*    EVP_md5(void);  /* RSA/MD5 */
MOC_EXTERN const EVP_MD*    EVP_sha1(void); /* RSA/SHA1 */
MOC_EXTERN const EVP_MD*    EVP_sha256(void); /* RSA/SHA256 */


typedef struct EVP_CIPHER
{
    const BulkEncryptionAlgo*   pBEAlgo;
    sbyte4                      keySize;
    int                         NID;
} EVP_CIPHER;

typedef struct EVP_CIPHER_CTX
{
    const struct EVP_CIPHER*    pEncrAlgo;
    void*                       pEncrData;
    int                         pad;

    ubyte                       oIv[EVP_MAX_IV_LENGTH];    /* original iv */
    ubyte                       wIv[EVP_MAX_IV_LENGTH];    /* working iv */

    ubyte4                      blockBufLen;
    ubyte                       blockBuf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    sbyte4                      finalBlkUsed;
    ubyte                       finalBlk[EVP_MAX_BLOCK_LENGTH]; /* final decrypted block */
} EVP_CIPHER_CTX;


ubyte4 EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
ubyte4 EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
ubyte4 EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);


#ifdef __ENABLE_DES_CIPHER__
MOC_EXTERN const EVP_CIPHER *EVP_des_cbc(void);
MOC_EXTERN const EVP_CIPHER *EVP_des_ofb(void);
#endif
#ifndef __DISABLE_AES_CIPHERS__
MOC_EXTERN const EVP_CIPHER *EVP_aes_128_cbc(void);
MOC_EXTERN const EVP_CIPHER *EVP_aes_192_cbc(void);
MOC_EXTERN const EVP_CIPHER *EVP_aes_256_cbc(void);

MOC_EXTERN const EVP_CIPHER *EVP_aes_128_ecb(void);
MOC_EXTERN const EVP_CIPHER *EVP_aes_256_ecb(void);

MOC_EXTERN const EVP_CIPHER *EVP_aes_128_ofb(void);
MOC_EXTERN const EVP_CIPHER *EVP_aes_192_ofb(void);
MOC_EXTERN const EVP_CIPHER *EVP_aes_256_ofb(void);
#endif
#ifndef __DISABLE_3DES_CIPHERS__
MOC_EXTERN const EVP_CIPHER *EVP_des_ede3_cbc(void);
MOC_EXTERN const EVP_CIPHER *EVP_des_ede3_ofb(void);
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
MOC_EXTERN const EVP_CIPHER *EVP_rc4(void);
#endif

MOC_EXTERN void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
MOC_EXTERN int  EVP_CIPHER_CTX_cleanup(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *a);
MOC_EXTERN int  EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);

MOC_EXTERN int  EVP_CipherInit( MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                                   const unsigned char *key, const unsigned char *iv, int isEncrypt );

MOC_EXTERN int  EVP_EncryptInit(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx,
                                   const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv);
MOC_EXTERN int  EVP_EncryptUpdate(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx,
                                  unsigned char *out, int *outl, const unsigned char *in, int inl);
MOC_EXTERN int  EVP_EncryptFinal(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

MOC_EXTERN int  EVP_DecryptInit(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx,
                                   const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv);
MOC_EXTERN int  EVP_DecryptUpdate(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx,
                                  unsigned char *out, int *outl, const unsigned char *in, int inl);
MOC_EXTERN int  EVP_DecryptFinal(MOC_SYM(hwAccelDescr hwAccelCtx) EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

/*
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
                                        const unsigned char *key, const unsigned char *iv);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
*/
#define EVP_EncryptInit_ex(ct,c,e,k,i)  EVP_EncryptInit(ct,c,k,i)
#define EVP_EncryptFinal_ex(ct,o,l)     EVP_EncryptFinal(ct,o,l)
/*
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
                                        const unsigned char *key, const unsigned char *iv);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
*/
#define EVP_DecryptInit_ex(ct,c,e,k,i)  EVP_DecryptInit(ct,c,k,i)
#define EVP_DecryptFinal_ex(ct,o,l)     EVP_DecryptFinal(ct,o,l)

/* RAND */


MOC_EXTERN void RAND_add(const void *buf, int num, double entropy);
MOC_EXTERN int RAND_bytes(unsigned char * buf, int num);
MOC_EXTERN void RAND_seed(const void *buf, int num);
MOC_EXTERN const char *RAND_file_name(char *file, unsigned long num);
MOC_EXTERN int RAND_load_file(const char *file, long max_bytes);
MOC_EXTERN int RAND_status(void);

#define RAND_pseudo_bytes RAND_bytes

#ifdef __ENABLE_MOCANA_PKCS5__
MOC_EXTERN int PKCS5_PBKDF2_HMAC_SHA1(MOC_HASH(hwAccelDescr hwAccelCtx)
                                      const char *pass, int passlen,
                                      const unsigned char *salt, int saltlen, int iter,
                                      int keylen, unsigned char *out);
#endif

/* This is for internal use only */
MOC_EXTERN const ubyte* GetOIDFromOSSLNID( int NID);

#ifdef  __cplusplus
}
#endif

#endif
#endif
