/*
 * sshc_trans.c
 *
 * SSH Developer API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_CLIENT__


#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#define __ENABLE_INBOUND_SSH_DEFINITIONS__

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/memory_debug.h"
#include "../../common/mem_pool.h"
#include "../../common/absstream.h"
#include "../../common/tree.h"
#include "../../common/memfile.h"
#include "../../common/circ_buf.h"
#include "../../common/int64.h"
#include "../../common/sizedbuffer.h"
#include "../../common/prime.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#include "../../crypto/aes.h"
#include "../../crypto/blowfish.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto/gcm.h"
#include "../../crypto/chacha20.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"

#ifndef __DISABLE_MOCANA_SHA256__
#include "../../crypto/sha256.h"
#endif

#if (!defined(__DISABLE_MOCANA_384__) || !defined(__DISABLE_MOCANA_512__))
#include "../../crypto/sha512.h"
#endif

#include "../../crypto/hmac.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/rsa.h"
#include "../../crypto/pkcs1.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/oiddefs.h"
#include "../../crypto/cert_chain.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_auth.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/ssh_dss.h"
#include "../../ssh/ssh_rsa.h"
#include "../../ssh/ssh_ecdsa.h"
#include "../../ssh/ssh_ocsp.h"
#include "../../ssh/ssh_cert.h"
#include "../../harness/harness.h"
#include "../../ssh/ssh_mpint.h"

#ifdef __ENABLE_MOCANA_PQC__
#include "../../ssh/ssh_hybrid.h"
#include "../../ssh/ssh_qs.h"
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_kem.h"
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_aes.h"
#include "../../crypto_interface/crypto_interface_aes_ctr.h"
#include "../../crypto_interface/crypto_interface_blowfish.h"
#include "../../crypto_interface/crypto_interface_chacha20.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif

/*------------------------------------------------------------------*/

#ifndef PATCH_CONST
#define PATCH_CONST
#endif

#ifndef __MOCANA_SELFSIGNED_CERT_CHECK_OPTIONS__
#define __MOCANA_SELFSIGNED_CERT_CHECK_OPTIONS__  (0xFFFF) /* everything turned on by default */
#endif

#ifndef __MOCANA_PARENT_CERT_CHECK_OPTIONS__
#define __MOCANA_PARENT_CERT_CHECK_OPTIONS__      (0xFFFF) /* everything turned on by default */
#endif

#define SSH_DH_PRIV_LEN     32

#define SSH_DHG_MIN         1024
#define SSH_DHG_PREF        2048
#define SSH_DHG_MAX         8192
#define SSH_DHG_VAL(X)      ((X >> 24) & 0xff), ((X >> 16) & 0xff), ((X >> 8) & 0xff), (X & 0xff)

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static ubyte m_gexRequest[] = { SSH_DHG_VAL(SSH_DHG_MIN), SSH_DHG_VAL(SSH_DHG_PREF), SSH_DHG_VAL(SSH_DHG_MAX) };
#endif


/*------------------------------------------------------------------*/

/* prototypes */
static MSTATUS SSHC_TRANS_allocClassicDH(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_freeClassicDH(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_sendClientKeyExchange(struct sshClientContext *pContextSSH);

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static MSTATUS SSHC_TRANS_allocGroupDH(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_freeGroupDH(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_sendServerDHGRequest(struct sshClientContext *pContextSSH);
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static MSTATUS SSHC_TRANS_allocRSA(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_freeRSA(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_sendKexRsaSecret(sshClientContext *pContextSSH);
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS SSHC_TRANS_allocHybrid(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_freeHybrid(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_sendKexHybridInit(struct sshClientContext *pContextSSH);
#endif
static MSTATUS SSHC_TRANS_allocECDH(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_freeECDH(struct sshClientContext *pContextSSH);
static MSTATUS SSHC_TRANS_sendKexEcdhInit(struct sshClientContext *pContextSSH);
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
static MSTATUS SSHC_TRANS_parseRawDsaCert(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
static MSTATUS SSHC_TRANS_verifyDsaSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pKey, sshStringBuffer *pSignature, ubyte *pDigestData, ubyte4 digestLen, intBoolean *pRetIsGoodSignature, vlong **ppVlongQueue);
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
static MSTATUS SSHC_TRANS_parseRawRsaCert(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
static MSTATUS SSHC_TRANS_verifyRsaSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pKey, sshStringBuffer *pSignature, ubyte *pDigestData, ubyte4 digestLen, intBoolean *pRetIsGoodSignature, vlong **ppVlongQueue);
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
/* TODO: proper guard */
static MSTATUS SSHC_TRANS_parseRawHybridKeyBlob(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
static MSTATUS SSHC_TRANS_parseRawEcdsaCert(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);

/* TODO: proper guard */
static MSTATUS SSHC_TRANS_verifyHybridSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature, ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);
static MSTATUS SSHC_TRANS_verifyEcdsaSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature, ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);
#endif

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS SSHC_TRANS_parseRawQsKeyBlob(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
static MSTATUS SSHC_TRANS_verifyQsSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature, ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);
#endif

#if (defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__))
#if (defined(__ENABLE_MOCANA_PQC__))
extern MSTATUS SSHC_TRANS_parseCertHybrid(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
extern MSTATUS SSHC_TRANS_parseCertQs(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
#endif
extern MSTATUS SSHC_TRANS_parseCertRSA(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
extern MSTATUS SSHC_TRANS_parseCertECDSA(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
extern MSTATUS SSHC_TRANS_parseCertRSASHA1(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
#endif

static BulkCtx SSHC_TRANS_createAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
static MSTATUS SSHC_TRANS_doAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);


#if (defined(__ENABLE_MOCANA_CHACHA20__))
static MSTATUS SSHC_TRANS_doChaCha20(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
#endif

/*------------------------------------------------------------------*/

/* Key Exchange Init Related Strings */
static sshStringBuffer *sshc_algorithmMethods[] =
{
    &sshc_kexMethods,
    &sshc_hostKeyMethods,
    &sshc_encC2SMethods,
    &sshc_encS2CMethods,
    &sshc_macC2SMethods,
    &sshc_macS2CMethods,
    &sshc_compC2SMethods,
    &sshc_compS2CMethods,
    &sshc_langC2SMethods,
    &sshc_langS2CMethods
};

#define NUM_ALGORITHM_METHODS   (sizeof(sshc_algorithmMethods) / sizeof(sshStringBuffer *))


/*------------------------------------------------------------------*/

#define HOST_KEY_METHODS_INDEX          (1)

/* lengths & indices */
#define SSH2_KEXINIT_PAYLOAD_HEADER     (17)
#define SSH2_KEXINIT_PAYLOAD_TAIL       (5)
#define SSH2_KEXINIT_RANDOM_PAD_LENGTH  (16)
#define SSH2_BLOWFISH_KEY_SIZE          (16)

/*
 * avoid adding another field, since neither side has both private keys (!)
 */
#define COMPUTED_VLONG_X(X)             (X)->dh_y


/*------------------------------------------------------------------*/

/* key exchange alloc/free methods */

static sshcKeyExMethods dhClassicMethods = { SSHC_TRANS_allocClassicDH, SSHC_TRANS_freeClassicDH, SSHC_TRANS_sendClientKeyExchange };

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static sshcKeyExMethods dhGroupMethods   = { SSHC_TRANS_allocGroupDH,   SSHC_TRANS_freeGroupDH,   SSHC_TRANS_sendServerDHGRequest };
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static sshcKeyExMethods rsaMethods       = { SSHC_TRANS_allocRSA,       SSHC_TRANS_freeRSA,       NULL };
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_PQC__))
static sshcKeyExMethods hybridMethods    = { SSHC_TRANS_allocHybrid,    SSHC_TRANS_freeHybrid,  SSHC_TRANS_sendKexHybridInit };
#endif
static sshcKeyExMethods ecdhMethods      = { SSHC_TRANS_allocECDH,      SSHC_TRANS_freeECDH,    SSHC_TRANS_sendKexEcdhInit   };
#endif


/*------------------------------------------------------------------*/

/* handshake hash algorithms */
static sshcHashHandshake sshHandshakeSHA1   = { SHA1_allocDigest,   SHA1_freeDigest,   (BulkCtxInitFunc)SHA1_initDigest,   (BulkCtxUpdateFunc)SHA1_updateDigest,   (BulkCtxFinalFunc)SHA1_finalDigest,   SHA1_RESULT_SIZE   };

#ifndef __DISABLE_MOCANA_SHA256__
static sshcHashHandshake sshHandshakeSHA256 = { SHA256_allocDigest, SHA256_freeDigest, (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, SHA256_RESULT_SIZE };
#endif
#ifndef __DISABLE_MOCANA_SHA384__
static sshcHashHandshake sshHandshakeSHA384 = { SHA384_allocDigest, SHA384_freeDigest, (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, SHA384_RESULT_SIZE };
#endif
#ifndef __DISABLE_MOCANA_SHA512__
static sshcHashHandshake sshHandshakeSHA512 = { SHA512_allocDigest, SHA512_freeDigest, (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, SHA512_RESULT_SIZE };
#endif


/*------------------------------------------------------------------*/

static PATCH_CONST SSHC_keyExSuiteInfo mKeyExSuites[] =
{   /* debugString keyExName keyExNameLength hintForKeyExAlgo kexExCtx hashAlgo ec_oid nextState rekeyNextState */
#if defined(__ENABLE_MOCANA_ECC__)
#if defined(__ENABLE_MOCANA_PQC__)
    { (sbyte *)"mlkem768nistp256-sha256",         (sbyte *)"mlkem768nistp256-sha256",         23,
        cid_EC_P256,   cid_PQC_MLKEM_768,        &hybridMethods, &sshHandshakeSHA256, NULL, kTransReceiveHybrid, kReduxTransReceiveHybrid },
    { (sbyte *)"mlkem1024nistp384-sha384",        (sbyte *)"mlkem1024nistp384-sha384",        24,
        cid_EC_P384,   cid_PQC_MLKEM_1024,       &hybridMethods, &sshHandshakeSHA384, NULL, kTransReceiveHybrid, kReduxTransReceiveHybrid },
    { (sbyte *)"mlkem768x25519-sha256",           (sbyte *)"mlkem768x25519-sha256",           21,
        cid_EC_X25519, cid_PQC_MLKEM_768,        &hybridMethods, &sshHandshakeSHA256, NULL, kTransReceiveHybrid, kReduxTransReceiveHybrid },
#endif /* __ENABLE_MOCANA_PQC__ */
#if (defined(__ENABLE_MOCANA_ECC_EDDH_25519__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"curve25519-sha256", (sbyte *)"curve25519-sha256",                      17, cid_EC_X25519,
        0, &ecdhMethods,      &sshHandshakeSHA256, ecdh25519_OID, kTransReceiveECDH,                 kReduxTransReceiveECDH },
    { (sbyte *)"curve25519-sha256@libssh.org", (sbyte *)"curve25519-sha256@libssh.org", 28, cid_EC_X25519,
        0, &ecdhMethods,      &sshHandshakeSHA256, ecdh25519_OID, kTransReceiveECDH,                 kReduxTransReceiveECDH },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDH_448__) && !defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"curve448-sha512", (sbyte *)"curve448-sha512",                          15, cid_EC_X448,
        0, &ecdhMethods,      &sshHandshakeSHA512, ecdh448_OID, kTransReceiveECDH,                 kReduxTransReceiveECDH },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__) && !defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"ecdh-sha2-nistp521", (sbyte *)"ecdh-sha2-nistp521",                    18, cid_EC_P521,
        0, &ecdhMethods,      &sshHandshakeSHA512, secp521r1_OID, kTransReceiveECDH,                kReduxTransReceiveECDH },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"ecdh-sha2-nistp384", (sbyte *)"ecdh-sha2-nistp384",                    18, cid_EC_P384,
        0, &ecdhMethods,      &sshHandshakeSHA384, secp384r1_OID, kTransReceiveECDH,                kReduxTransReceiveECDH },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ecdh-sha2-nistp256", (sbyte *)"ecdh-sha2-nistp256",                    18, cid_EC_P256,
        0, &ecdhMethods,      &sshHandshakeSHA256, secp256r1_OID, kTransReceiveECDH,                kReduxTransReceiveECDH },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */

#if (!defined(__DISABLE_MOCANA_SSH_RSA_KEY_EXCHANGE__) && defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"rsa2048-sha256",      (sbyte *)"rsa2048-sha256",                       14, 2048,
        0, &rsaMethods,       &sshHandshakeSHA256, NULL,          kTransReceiveRSA,                 kReduxTransReceiveRSA },
#endif
#ifndef __ENABLE_MOCANA_FIPS_MODULE__
    { (sbyte *)"rsa1024-sha1",        (sbyte *)"rsa1024-sha1",                         12, 1024,
        0, &rsaMethods,       &sshHandshakeSHA1,   NULL,          kTransReceiveRSA,                 kReduxTransReceiveRSA },
#endif
#endif

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"dh-group-ex-256",     (sbyte *)"diffie-hellman-group-exchange-sha256", 36, DH_GROUP_14,
        0, &dhGroupMethods,   &sshHandshakeSHA256, NULL,          kTransReceiveDiffieHellmanGroup1, kReduxTransReceiveDiffieHellmanGroup1 },
#endif
    { (sbyte *)"dh-group-ex-1",       (sbyte *)"diffie-hellman-group-exchange-sha1",   34, DH_GROUP_14,
        0, &dhGroupMethods,   &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanGroup1, kReduxTransReceiveDiffieHellmanGroup1 },
#endif

#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"diffie-hellman-group14-sha256", (sbyte *)"diffie-hellman-group14-sha256", 29, DH_GROUP_14,
        0, &dhClassicMethods, &sshHandshakeSHA256,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#endif
#if (!defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"diffie-hellman-group15-sha512", (sbyte *)"diffie-hellman-group15-sha512", 29, DH_GROUP_15,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group16-sha512", (sbyte *)"diffie-hellman-group16-sha512", 29, DH_GROUP_16,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group17-sha512", (sbyte *)"diffie-hellman-group17-sha512", 29, DH_GROUP_17,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group18-sha512", (sbyte *)"diffie-hellman-group18-sha512", 29, DH_GROUP_18,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#endif
    { (sbyte *)"dh-group14",          (sbyte *)"diffie-hellman-group14-sha1",          27, DH_GROUP_14,
        0, &dhClassicMethods, &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#ifndef __ENABLE_MOCANA_FIPS_MODULE__
    { (sbyte *)"dh-group2",           (sbyte *)"diffie-hellman-group1-sha1",           26, DH_GROUP_2,
        0, &dhClassicMethods, &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic }
#endif

};

#define NUM_SSH_KEYEX_SUITES    (sizeof(mKeyExSuites)/sizeof(SSHC_keyExSuiteInfo))


/*------------------------------------------------------------------*/

#if (!defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__) && !defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && !defined(__ENABLE_MOCANA_ECC__))
#error SSH Client configuration error (host key)
#endif

static SSHC_hostKeySuiteInfo mHostKeySuites[] =

{   /* pHostKeyName, hostKeyNameLength, pSignatureName, signatureNameLength, authType, hashLen, identityType, pFuncParseCert, pFuncVerifySig */
#if ((defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)))
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
#ifdef __ENABLE_MOCANA_PQC__
    { (sbyte *)"x509v3-mldsa44",             14, (sbyte *)"x509v3-mldsa44",             14, CERT_STORE_AUTH_TYPE_QS,     0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertQs,     SSHC_TRANS_verifyQsSignature },
    { (sbyte *)"x509v3-mldsa65",             14, (sbyte *)"x509v3-mldsa65",             14, CERT_STORE_AUTH_TYPE_QS,     0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertQs,     SSHC_TRANS_verifyQsSignature },
    { (sbyte *)"x509v3-mldsa87",             14, (sbyte *)"x509v3-mldsa87",             14, CERT_STORE_AUTH_TYPE_QS,     0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertQs,     SSHC_TRANS_verifyQsSignature },
#ifdef __ENABLE_MOCANA_ECC__
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"x509v3-mldsa44-es256",       20, (sbyte *)"x509v3-mldsa44-es256",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertHybrid, SSHC_TRANS_verifyHybridSignature },
    { (sbyte *)"x509v3-mldsa65-es256",       20, (sbyte *)"x509v3-mldsa65-es256",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertHybrid, SSHC_TRANS_verifyHybridSignature },     
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"x509v3-mldsa87-es384",       20, (sbyte *)"x509v3-mldsa87-es384",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertHybrid, SSHC_TRANS_verifyHybridSignature},
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"x509v3-mldsa44-ed25519",     22, (sbyte *)"x509v3-mldsa44-ed25519",     22, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertHybrid, SSHC_TRANS_verifyHybridSignature },
    { (sbyte *)"x509v3-mldsa65-ed25519",     22, (sbyte *)"x509v3-mldsa65-ed25519",     22, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertHybrid, SSHC_TRANS_verifyHybridSignature },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
    { (sbyte *)"x509v3-mldsa87-ed448",       20, (sbyte *)"x509v3-mldsa87-ed448",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertHybrid, SSHC_TRANS_verifyHybridSignature },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */
#endif /* __ENABLE_MOCANA_PRE_DRAFT_PQC__ */

#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P256__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp256", 26, (sbyte *)"x509v3-ecdsa-sha2-nistp256", 26, CERT_STORE_AUTH_TYPE_ECDSA, SHA256_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertECDSA,    SSHC_TRANS_verifyEcdsaSignature },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp384", 26, (sbyte *)"x509v3-ecdsa-sha2-nistp384", 26, CERT_STORE_AUTH_TYPE_ECDSA, SHA384_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertECDSA,    SSHC_TRANS_verifyEcdsaSignature },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp521", 26, (sbyte *)"x509v3-ecdsa-sha2-nistp521", 26, CERT_STORE_AUTH_TYPE_ECDSA, SHA512_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertECDSA,    SSHC_TRANS_verifyEcdsaSignature },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
    { (sbyte *)"x509v3-rsa2048-sha256",      21, (sbyte *)"x509v3-rsa2048-sha256",      21, CERT_STORE_AUTH_TYPE_RSA,   SHA256_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertRSA,      SSHC_TRANS_verifyRsaSignature   },
    { (sbyte *)"x509v3-ssh-rsa",             14, (sbyte *)"ssh-rsa",                     7, CERT_STORE_AUTH_TYPE_RSA,   20,                 CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertRSA,      SSHC_TRANS_verifyRsaSignature   },
#if (defined(__ENABLE_MOCANA_X509_DRAFT3__))
    /* Note: client only supports x509v3-sign-rsa-sha1 from Draft 3 */
    { (sbyte *)"x509v3-sign-rsa-sha1",       20, (sbyte *)"ssh-rsa",                     7, CERT_STORE_AUTH_TYPE_RSA,   20,                 CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, SSHC_TRANS_parseCertRSA,      SSHC_TRANS_verifyRsaSignature   },
#endif /* __ENABLE_MOCANA_X509_DRAFT3__ */
#endif/* ((defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__))) */

#ifdef __ENABLE_MOCANA_PQC__
    { (sbyte *)"ssh-mldsa44",                11, (sbyte *)"ssh-mldsa44",                11, CERT_STORE_AUTH_TYPE_QS,     0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawQsKeyBlob,     SSHC_TRANS_verifyQsSignature },
    { (sbyte *)"ssh-mldsa65",                11, (sbyte *)"ssh-mldsa65",                11, CERT_STORE_AUTH_TYPE_QS,     0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawQsKeyBlob,     SSHC_TRANS_verifyQsSignature },
    { (sbyte *)"ssh-mldsa87",                11, (sbyte *)"ssh-mldsa87",                11, CERT_STORE_AUTH_TYPE_QS,     0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawQsKeyBlob,     SSHC_TRANS_verifyQsSignature },
#ifdef __ENABLE_MOCANA_ECC__
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ssh-mldsa44-es256",          17, (sbyte *)"ssh-mldsa44-es256",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawHybridKeyBlob, SSHC_TRANS_verifyHybridSignature },
    { (sbyte *)"ssh-mldsa65-es256",          17, (sbyte *)"ssh-mldsa65-es256",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawHybridKeyBlob, SSHC_TRANS_verifyHybridSignature },     
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"ssh-mldsa87-es384",          17, (sbyte *)"ssh-mldsa87-es384",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawHybridKeyBlob, SSHC_TRANS_verifyHybridSignature},
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"ssh-mldsa44-ed25519",        19, (sbyte *)"ssh-mldsa44-ed25519",        19, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawHybridKeyBlob, SSHC_TRANS_verifyHybridSignature },
    { (sbyte *)"ssh-mldsa65-ed25519",        19, (sbyte *)"ssh-mldsa65-ed25519",        19, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawHybridKeyBlob, SSHC_TRANS_verifyHybridSignature },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
    { (sbyte *)"ssh-mldsa87-ed448",          17, (sbyte *)"ssh-mldsa87-ed448",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSHC_TRANS_parseRawHybridKeyBlob, SSHC_TRANS_verifyHybridSignature },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */
#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"ssh-ed25519",                11, (sbyte *)"ssh-ed25519",                11, CERT_STORE_AUTH_TYPE_EDDSA, SHA256_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED,        SSHC_TRANS_parseRawEcdsaCert, SSHC_TRANS_verifyEcdsaSignature },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P256__))
    { (sbyte *)"ecdsa-sha2-nistp256",        19, (sbyte *)"ecdsa-sha2-nistp256",        19, CERT_STORE_AUTH_TYPE_ECDSA, SHA256_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED,        SSHC_TRANS_parseRawEcdsaCert, SSHC_TRANS_verifyEcdsaSignature },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__))
    { (sbyte *)"ecdsa-sha2-nistp384",        19, (sbyte *)"ecdsa-sha2-nistp384",        19, CERT_STORE_AUTH_TYPE_ECDSA, SHA384_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED,        SSHC_TRANS_parseRawEcdsaCert, SSHC_TRANS_verifyEcdsaSignature },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__))
    { (sbyte *)"ecdsa-sha2-nistp521",        19, (sbyte *)"ecdsa-sha2-nistp521",        19, CERT_STORE_AUTH_TYPE_ECDSA, SHA512_RESULT_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED,        SSHC_TRANS_parseRawEcdsaCert, SSHC_TRANS_verifyEcdsaSignature },
#endif
#endif
#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
    { (sbyte *)"ssh-dss",                     7, (sbyte *)"ssh-dss",                     7, CERT_STORE_AUTH_TYPE_DSA,   20,                 CERT_STORE_IDENTITY_TYPE_NAKED,        SSHC_TRANS_parseRawDsaCert,   SSHC_TRANS_verifyDsaSignature   },
#endif
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
#if (!defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"rsa-sha2-512",               12, (sbyte *)"ssh-rsa",                     7, CERT_STORE_AUTH_TYPE_RSA,   SHA512_RESULT_SIZE,  CERT_STORE_IDENTITY_TYPE_NAKED,       SSHC_TRANS_parseRawRsaCert,   SSHC_TRANS_verifyRsaSignature   },
#endif
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"rsa-sha2-256",               12, (sbyte *)"ssh-rsa",                     7, CERT_STORE_AUTH_TYPE_RSA,   SHA256_RESULT_SIZE,  CERT_STORE_IDENTITY_TYPE_NAKED,       SSHC_TRANS_parseRawRsaCert,   SSHC_TRANS_verifyRsaSignature   },
#endif
    { (sbyte *)"ssh-rsa",                     7, (sbyte *)"ssh-rsa",                     7, CERT_STORE_AUTH_TYPE_RSA,   20,                 CERT_STORE_IDENTITY_TYPE_NAKED,        SSHC_TRANS_parseRawRsaCert,   SSHC_TRANS_verifyRsaSignature   },
#endif
    { (sbyte *)"placeholder",                11, (sbyte *)"dummy",                       5, 0,                           0,                 0,                                     NULL,                         NULL   }
};

#define NUM_SSH_HOST_KEY_SUITES ((sizeof(mHostKeySuites)/sizeof(SSHC_hostKeySuiteInfo)) - 1)


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo AESCTRSuite =
    { 16, (CreateBulkCtxFunc)SSHC_TRANS_createAESCTRCtx, CRYPTO_INTERFACE_DeleteAESCTRCtx, SSHC_TRANS_doAESCTR, CRYPTO_INTERFACE_CloneAESCTRCtx };
#else
static BulkEncryptionAlgo AESCTRSuite =
    { 16, (CreateBulkCtxFunc)SSHC_TRANS_createAESCTRCtx, DeleteAESCTRCtx, SSHC_TRANS_doAESCTR, CloneAESCTRCtx};
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo AESSuite =
    { 16, CRYPTO_INTERFACE_CreateAESCtx, CRYPTO_INTERFACE_DeleteAESCtx, CRYPTO_INTERFACE_DoAES, CRYPTO_INTERFACE_CloneAESCtx };
#else
static BulkEncryptionAlgo AESSuite =
    { 16, CreateAESCtx, DeleteAESCtx, DoAES, CloneAESCtx };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#ifdef __ENABLE_BLOWFISH_CIPHERS__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo BlowfishSuite =
    { 8, CRYPTO_INTERFACE_CreateBlowfishCtx, CRYPTO_INTERFACE_DeleteBlowfishCtx, CRYPTO_INTERFACE_DoBlowfish, CRYPTO_INTERFACE_CloneBlowfishCtx };
#else
static BulkEncryptionAlgo BlowfishSuite =
    { 8, CreateBlowfishCtx, DeleteBlowfishCtx, DoBlowfish, CloneBlowfishCtx};
#endif
#endif

#ifndef __DISABLE_3DES_CIPHERS__
static BulkEncryptionAlgo TripleDESSuite =
    { 8, Create3DESCtx, Delete3DESCtx, Do3DES, Clone3DESCtx };
#endif


#if defined(__ENABLE_MOCANA_GCM__)

#define GCM_FIXED_IV_LENGTH     (4)
#define GCM_RECORD_IV_LENGTH    (8)

#ifdef __ENABLE_MOCANA_GCM_64K__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_cipher_64k };
#else
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_cipher_64k };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo GCMSuite =
    { 16, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, NULL, CRYPTO_INTERFACE_GCM_clone_64k };
#else
static BulkEncryptionAlgo GCMSuite =
    { 16, GCM_createCtx_64k, GCM_deleteCtx_64k, NULL, GCM_clone_64k };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_GCM_64K__ */
#ifdef __ENABLE_MOCANA_GCM_4K__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_cipher_4k};
#else
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_cipher_4k };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo GCMSuite =
    { 16, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, NULL, CRYPTO_INTERFACE_GCM_clone_4k };
#else
static BulkEncryptionAlgo GCMSuite =
    { 16, GCM_createCtx_4k, GCM_deleteCtx_4k, NULL, GCM_clone_4k };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_GCM_4K__ */

#ifdef __ENABLE_MOCANA_GCM_256B__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_cipher_256b };
#else
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_cipher_256b };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo GCMSuite =
    { 16, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, NULL, CRYPTO_INTERFACE_GCM_clone_256b };
#else
static BulkEncryptionAlgo GCMSuite =
    { 16, GCM_createCtx_256b, GCM_deleteCtx_256b, NULL, GCM_clone_256b };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_GCM_256B__ */
#endif /* __ENABLE_MOCANA_GCM__ */

#if (defined(__ENABLE_MOCANA_POLY1305__) && defined(__ENABLE_MOCANA_CHACHA20__))
static sshAeadAlgo ChaChaPolyAeadSuite =
    /* first two values are used for GCM, can be 0 for chacha20-poly1305, 128 bit tag  */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    { 0, 0, 16, CRYPTO_INTERFACE_ChaCha20Poly1305_cipherSSH };
#else
    { 0, 0, 16, ChaCha20Poly1305_cipherSSH };
#endif
static BulkEncryptionAlgo ChaChaPolySuite =
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    { 64, CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx, CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx, SSHC_TRANS_doChaCha20, CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx };
#else
    { 64, ChaCha20Poly1305_createCtx, ChaCha20Poly1305_deleteCtx, SSHC_TRANS_doChaCha20, ChaCha20Poly1305_cloneCtx };
#endif
#endif /* (defined(__ENABLE_MOCANA_POLY1305__) && defined(__ENABLE_MOCANA_CHACHA20__)) */

static SSH_CipherSuiteInfo mCipherSuites[] =
{     /* cipherName cipherNameLength keysize ivsize cipherSuiteDescr */

#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES128_CIPHER__))
    { (sbyte *)"AEAD_AES_128_GCM",      16, 16, 16, &GCMSuite,          &GCMAeadSuite },
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    { (sbyte *)"aes128-gcm@openssh.com",      22, 16, 16, &GCMSuite,          &GCMAeadSuite },
#endif
#endif
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES256_CIPHER__))
    { (sbyte *)"AEAD_AES_256_GCM",      16, 32, 16, &GCMSuite,          &GCMAeadSuite },
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    { (sbyte *)"aes256-gcm@openssh.com",      22, 32, 16, &GCMSuite,          &GCMAeadSuite },
#endif
#endif
#if defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)
    { (sbyte *)"chacha20-poly1305@openssh.com", 29, 32, 8, &ChaChaPolySuite, &ChaChaPolyAeadSuite },
#endif

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES128_CIPHER__
    { (sbyte *)"aes128-ctr",            10, 16, 16, &AESCTRSuite,       NULL },
    { (sbyte *)"aes128-cbc",            10, 16, 16, &AESSuite,          NULL },
    { (sbyte *)"rijndael128-cbc",       15, 16, 16, &AESSuite,          NULL },
#endif
#ifndef __DISABLE_AES256_CIPHER__
    { (sbyte *)"aes256-ctr",            10, 32, 16, &AESCTRSuite,       NULL },
    { (sbyte *)"aes256-cbc",            10, 32, 16, &AESSuite,          NULL },
    { (sbyte *)"rijndael256-cbc",       15, 32, 16, &AESSuite,          NULL },
#endif
#ifndef __DISABLE_AES192_CIPHER__
    { (sbyte *)"aes192-ctr",            10, 24, 16, &AESCTRSuite,       NULL },
    { (sbyte *)"aes192-cbc",            10, 24, 16, &AESSuite,          NULL },
    { (sbyte *)"rijndael192-cbc",       15, 24, 16, &AESSuite,          NULL },
#endif
#endif

#ifdef __ENABLE_BLOWFISH_CIPHERS__
    { (sbyte *)"blowfish-cbc",          12, 16,  8, &BlowfishSuite,     NULL },
#endif

#ifndef __DISABLE_3DES_CIPHERS__
    { (sbyte *)"3des-cbc",               8, 24,  8, &TripleDESSuite,    NULL },
#endif


    { (sbyte *)"ignore",                 6, 16,  8, NULL,               NULL }     /* this entry will not be accessed */
};

#define NUM_SSHC_CIPHER_SUITES   ((sizeof(mCipherSuites)/sizeof(SSH_CipherSuiteInfo)) - 1)


/*------------------------------------------------------------------*/

static SSH_hmacSuiteInfo mHmacSuites[] =
{   /* hmacName hmacNameLength allocSize keyLength digestLength hmacSuiteDescr */
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES128_CIPHER__))
    { (sbyte *)"AEAD_AES_128_GCM",      16,  0, 16, NULL,           &GCMAeadSuite },
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    { (sbyte *)"aes128-gcm@openssh.com",      22,  0, 16, NULL,           &GCMAeadSuite },
#endif
#endif
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES256_CIPHER__))
    { (sbyte *)"AEAD_AES_256_GCM",      16,  0, 16, NULL,           &GCMAeadSuite },
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    { (sbyte *)"aes256-gcm@openssh.com",      22,  0, 16, NULL,           &GCMAeadSuite },
#endif
#endif

#if defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)
    { (sbyte *)"chacha20-poly1305@openssh.com", 29, 0, 16, NULL, &ChaChaPolyAeadSuite },
#endif

#ifndef __DISABLE_MOCANA_SHA256__
    { (sbyte *)"hmac-sha2-256",         13, SHA256_RESULT_SIZE, SHA256_RESULT_SIZE, HMAC_SHA256,    NULL },
#endif
#ifndef __DISABLE_MOCANA_SHA512__
    { (sbyte *)"hmac-sha2-512",         13, SHA512_RESULT_SIZE, SHA512_RESULT_SIZE, HMAC_SHA512,    NULL },
#endif
#ifndef __DISABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"hmac-sha1",              9, 20, 20, HMAC_SHA1,      NULL },
    { (sbyte *)"hmac-sha1-96",          12, 20, 12, HMAC_SHA1,      NULL },
    { (sbyte *)"hmac-md5",               8, 16, 16, HMAC_MD5,       NULL },
    { (sbyte *)"hmac-md5-96",           11, 16, 12, HMAC_MD5,       NULL }
#endif
};


#define NUM_SSHC_HMAC_SUITES     (sizeof(mHmacSuites)/sizeof(SSH_hmacSuiteInfo))


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

/* Per RFC 4419, 1024 <= prime group <= 8192 bits */
#if (!defined(SSH_DHG_PRIME_MIN_BIT_LENGTH))
#define SSH_DHG_PRIME_MIN_BIT_LENGTH            (1024)
#endif

#if (1024 > SSH_DHG_PRIME_MIN_BIT_LENGTH)
#error SSH_DHG_PRIME_MIN_BIT_LENGTH should be greater than 1024
#endif

#if (!defined(SSH_DHG_PRIME_MAX_BIT_LENGTH))
#define SSH_DHG_PRIME_MAX_BIT_LENGTH            (8192)
#endif

#if (SSH_DHG_PRIME_MAX_BIT_LENGTH < SSH_DHG_PRIME_MIN_BIT_LENGTH)
#error SSH_DHG_PRIME_MAX_BIT_LENGTH must be greater than SSH_DHG_PRIME_MIN_BIT_LENGTH
#endif

#endif /* (!defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */

#if (defined(__ENABLE_MOCANA_SSHC_TRANS_HANDSHAKE_DATA__))
static void
DUMP(ubyte *pString, ubyte *pMesg, ubyte4 mesgLen)
{
    DEBUG_PRINTNL(0, pString);
    DEBUG_HEXDUMP(0, pMesg, mesgLen);
}
#else
#define DUMP(X,Y,Z)
#endif


/*------------------------------------------------------------------*/

extern sbyte *
SSHC_TRANS_keyExList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSH_KEYEX_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mKeyExSuites[index].keyExNameLength;

    return mKeyExSuites[index].pKeyExName;
}


/*------------------------------------------------------------------*/

extern sbyte *
SSHC_TRANS_hostKeyList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSH_HOST_KEY_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mHostKeySuites[index].hostKeyNameLength;

    return mHostKeySuites[index].pHostKeyName;
}


/*------------------------------------------------------------------*/

extern sbyte *
SSHC_TRANS_cipherList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSHC_CIPHER_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mCipherSuites[index].cipherNameLength;

    return mCipherSuites[index].pCipherName;
}


/*------------------------------------------------------------------*/

extern sbyte *
SSHC_TRANS_hmacList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSHC_HMAC_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mHmacSuites[index].hmacNameLength;

    return mHmacSuites[index].pHmacName;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_cipherVerify(ubyte *pCipher, intBoolean *pIsAvailable)
{
    ubyte4  index;
    sbyte4  result;
    MSTATUS status = OK;

    if ((NULL == pCipher) || (NULL == pIsAvailable))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsAvailable = FALSE;

    for (index = 0; NUM_SSHC_CIPHER_SUITES > index; index++)
    {
        if ((OK <= (status = MOC_MEMCMP(pCipher, (ubyte *)(mCipherSuites[index].pCipherName), 1 + mCipherSuites[index].cipherNameLength, &result))) &&
            (0 == result) )
        {
            *pIsAvailable = TRUE;
            break;
        }

        if (OK > status)
            break;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_hmacVerify(ubyte *pHmac, intBoolean *pIsAvailable)
{
    ubyte4  index;
    sbyte4  result;
    MSTATUS status = OK;

    if ((NULL == pHmac) || (NULL == pIsAvailable))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsAvailable = FALSE;

    for (index = 0; NUM_SSHC_HMAC_SUITES > index; index++)
    {
        if ((OK <= (status = MOC_MEMCMP(pHmac, (ubyte *)(mHmacSuites[index].pHmacName), 1 + mHmacSuites[index].hmacNameLength, &result))) &&
            (0 == result) )
        {
            *pIsAvailable = TRUE;
            break;
        }

        if (OK > status)
            break;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_allocClassicDH(struct sshClientContext *pContextSSH)
{
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_DH_allocateServer(MOC_DH(pContextSSH->hwAccelCookie) g_pRandomContext, &SSH_DH_CTX(pContextSSH), pContextSSH->pKeyExSuiteInfo->keyExHint);
#else
    return DH_allocateServer(MOC_DH(pContextSSH->hwAccelCookie) g_pRandomContext, &SSH_DH_CTX(pContextSSH), pContextSSH->pKeyExSuiteInfo->keyExHint);
#endif
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_freeClassicDH(struct sshClientContext *pContextSSH)
{
    if (NULL != SSH_DH_CTX(pContextSSH))
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        return CRYPTO_INTERFACE_DH_freeDhContext(&SSH_DH_CTX(pContextSSH), NULL);
#else
        return DH_freeDhContext(&SSH_DH_CTX(pContextSSH), NULL);
#endif
    }

    return OK;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static MSTATUS
SSHC_TRANS_allocGroupDH(struct sshClientContext *pContextSSH)
{
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_DH_allocate(&pContextSSH->sshKeyExCtx.p_dhContext);
#else
    return DH_allocate(&pContextSSH->sshKeyExCtx.p_dhContext);
#endif
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static MSTATUS
SSHC_TRANS_freeGroupDH(struct sshClientContext *pContextSSH)
{
    if (NULL != pContextSSH->sshKeyExCtx.p_dhContext)
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        return CRYPTO_INTERFACE_DH_freeDhContext(&pContextSSH->sshKeyExCtx.p_dhContext, NULL);
#else
        return DH_freeDhContext(&pContextSSH->sshKeyExCtx.p_dhContext, NULL);
#endif
    }

    return OK;
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static MSTATUS
SSHC_TRANS_allocRSA(struct sshClientContext *pContextSSH)
{
    MSTATUS status;

    status = CRYPTO_createRSAKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);

    DEBUG_RELABEL_MEMORY(pContextSSH->sshKeyExCtx.transientKey.key.pRSA);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static MSTATUS
SSHC_TRANS_freeRSA(struct sshClientContext *pContextSSH)
{
    return CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSHC_TRANS_allocHybrid(struct sshClientContext *pContextSSH)
{
    ECCKey *pECCKey = NULL;
    QS_CTX *pQsCtx = NULL;
    HybridKey *pKeys = NULL;
    MSTATUS status;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MOC_MALLOC((void **) &pKeys, sizeof(HybridKey));
    if (OK != status)
        goto exit;

    status = CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
    if (OK != status)
        goto exit;

    /* ecc portion */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(pContextSSH->hwAccelCookie) pContextSSH->pKeyExSuiteInfo->keyExHint, (void**)&pECCKey, RANDOM_rngFun, g_pRandomContext, akt_ecc, NULL);
    if (OK != status)
        goto exit;

    pKeys->pKey1 = (void *) pECCKey;
    pKeys->clAlg = pContextSSH->pKeyExSuiteInfo->keyExHint;
    pECCKey = NULL;

    /* qs portion */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(pContextSSH->hwAccelCookie) &(pQsCtx), pContextSSH->pKeyExSuiteInfo->qsKeyExHint);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(pContextSSH->hwAccelCookie) pQsCtx, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    pKeys->pKey2 = (void *) pQsCtx;
    pQsCtx = NULL;

    status = CRYPTO_loadAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, akt_hybrid, (void**)&pKeys);

exit:

    if (NULL != pECCKey)
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pECCKey);

    if (NULL != pQsCtx)
        CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);

    if (NULL != pKeys)    
        MOC_FREE((void **) &pKeys);

    return status;

} /* SSH_TRANS_allocHybrid */
#endif


static MSTATUS
SSHC_TRANS_allocECDH(struct sshClientContext *pContextSSH)
{
    ECCKey*             pECCKey = NULL;
    MSTATUS             status;

    status = CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(pContextSSH->hwAccelCookie) pContextSSH->pKeyExSuiteInfo->keyExHint, (void**)&pECCKey, RANDOM_rngFun, g_pRandomContext, akt_ecc, NULL);
    if (OK != status)
        goto exit;
#else
    status = EC_newKeyEx(pContextSSH->pKeyExSuiteInfo->keyExHint, &pECCKey);
    if (OK != status)
        goto exit;

    status = EC_generateKeyPairEx(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;
#endif

    status = CRYPTO_loadAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, akt_ecc, (void**)&pECCKey);

    pECCKey = NULL;

exit:
    return status;

} /* SSH_TRANS_allocECDH */

#endif /* (defined(__ENABLE_MOCANA_ECC__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSHC_TRANS_freeHybrid(struct sshClientContext *pContextSSH)
{
    return CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
}
#endif

static MSTATUS
SSHC_TRANS_freeECDH(struct sshClientContext *pContextSSH)
{
    return CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
}
#endif


/*------------------------------------------------------------------*/


static BulkCtx
SSHC_TRANS_createAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial,
                           sbyte4 keyLength, sbyte4 encrypt)
{
    ubyte   tempKeyMaterial[32 + AES_BLOCK_SIZE];
    BulkCtx pRetCtx = NULL;

    if ((OK <= MOC_MEMCPY(tempKeyMaterial, keyMaterial, keyLength)) &&              /* copy key material to larger buffer */
        (OK <= MOC_MEMSET(keyLength + tempKeyMaterial, 0x00, AES_BLOCK_SIZE)) )     /* zero counter portion */
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        pRetCtx = CRYPTO_INTERFACE_CreateAESCTRCtx(MOC_SYM(hwAccelCtx) keyMaterial, keyLength + AES_BLOCK_SIZE, encrypt);
#else
        pRetCtx = CreateAESCTRCtx(MOC_SYM(hwAccelCtx) keyMaterial, keyLength + AES_BLOCK_SIZE, encrypt);
#endif
    }

    return pRetCtx;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_doAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
                    sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS                 status;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK <= (status = CRYPTO_INTERFACE_DoAESCTR(MOC_SYM(hwAccelCtx) ctx, data, dataLength, encrypt, iv)))
    {
        /* save counter for next run */
        status = CRYPTO_INTERFACE_GetCounterBlockAESCTR(MOC_SYM(hwAccelCtx) ctx, iv);
    }
#else
    if (OK <= (status = DoAESCTR(MOC_SYM(hwAccelCtx) ctx, data, dataLength, encrypt, iv)))
    {
        /* save counter for next run */
        status = GetCounterBlockAESCTR(MOC_SYM(hwAccelCtx) ctx, iv);
    }
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */


    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_CHACHA20__))
/* IV is used as the nonce for chacha20, for SSH protocol, the nonce is the sequence number
 * of the packet */
static MSTATUS
SSHC_TRANS_doChaCha20(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
                   sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status = ERR_NULL_POINTER;
    MOC_UNUSED(encrypt);
    if (NULL == ctx)
        goto exit;

    /* set nonce before calling DoChaCha20 */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_CHACHA20_setNonceAndCounterSSH(MOC_SYM(hwAccelCtx) ctx, iv, 8, NULL, 0);
#else
    status = CHACHA20_setNonceAndCounterSSH(MOC_SYM(hwAccelCtx) ctx, iv, 8, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* DoChaCha20 does not use encrypt or iv argument */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DoChaCha20(MOC_SYM(hwAccelCtx) ctx, data, dataLength, 0, NULL);
#else
    status = DoChaCha20(MOC_SYM(hwAccelCtx) ctx, data, dataLength, 0, NULL);
#endif
    if (OK != status)
        goto exit;

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_sendHello(sshClientContext *pContextSSH)
{
    ubyte   tmpMesg[sizeof(CLIENT_HELLO_STRING) + sizeof(CRLF)];
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    /* send server hello message to client */
    MOC_MEMCPY(tmpMesg, CLIENT_HELLO_STRING, sizeof(CLIENT_HELLO_STRING)-1);
    MOC_MEMCPY(tmpMesg + sizeof(CLIENT_HELLO_STRING)-1, CRLF, sizeof(CRLF));

    status = TCP_WRITE(SOCKET(pContextSSH), (sbyte *)tmpMesg, sizeof(CLIENT_HELLO_STRING) + sizeof(CRLF) - 2, &numBytesWritten);

#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINTNL(DEBUG_SSHC,(sbyte *) "\nSSHC_TRANS_sendHello:");
    DEBUG_HEXDUMP(DEBUG_SSHC, tmpMesg, sizeof(CLIENT_HELLO_STRING) + sizeof(CRLF) - 2);
#endif

    return status;

} /* SSHC_TRANS_sendHello */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_setMessageTimer(sshClientContext *pContextSSH, ubyte4 msTimeToExpire)
{
    MSTATUS status = OK;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    RTOS_deltaMS(NULL, &(SSH_TIMER_START_TIME(pContextSSH)));
    SSH_TIMER_MS_EXPIRE(pContextSSH)  = msTimeToExpire;  /* in milliseconds */

#ifdef __DEBUG_SSH_TIMER__
    DEBUG_PRINT(DEBUG_SSHC, "\nSSH_TRANS_setMessageTimer: current time = ");
#endif

#ifdef __ENABLE_MOCANA_SSH_ASYNC_CLIENT_API__
    if (NULL != SSHC_sshClientSettings()->funcPtrStartTimer)
    {
        if (kOpenState <= SSH_UPPER_STATE(pContextSSH))
            SSHC_sshClientSettings()->funcPtrStartTimer(CONNECTION_INSTANCE(pContextSSH), msTimeToExpire, 1);  /* authentication completed */
        else
            SSHC_sshClientSettings()->funcPtrStartTimer(CONNECTION_INSTANCE(pContextSSH), msTimeToExpire, 0);  /* authentication not completed */
    }
#endif /* __ENABLE_MOCANA_SSH_ASYNC_CLIENT_API__ */

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
digestString(sshClientContext *pContextSSH, BulkCtx *pKeyExHash, ubyte *pRawData, ubyte4 rawLength)
{
    ubyte*  pLength = NULL;
    MSTATUS status;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pLength))))
        goto exit;

    pLength[0] = (ubyte)(rawLength >> 24);
    pLength[1] = (ubyte)(rawLength >> 16);
    pLength[2] = (ubyte)(rawLength >>  8);
    pLength[3] = (ubyte)(rawLength);

    if (OK <= (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pKeyExHash, pLength, 4)))
    {
        if (0 < rawLength)
        {
            status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pKeyExHash, pRawData, rawLength);
        }
    }

    DUMP("update:", pLength, 4);
    DUMP("update:", pRawData, rawLength);

exit:
    MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pLength));

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_sendClientAlgorithms(sshClientContext *pContextSSH)
{
    intBoolean  copyToBuffer = FALSE;
    ubyte*      pPayload = NULL;
    ubyte4      index, i;
    ubyte4      numBytesWritten;
    MSTATUS     status;

    index = 0;

    do
    {
        for (i = 0; i < NUM_ALGORITHM_METHODS; i++)
        {
            if (NULL == pContextSSH->sshc_algorithmMethods[i].pString)
                status = SSH_STR_copyFromString(pPayload, &index, sshc_algorithmMethods[i], copyToBuffer);
            else
                status = SSH_STR_copyFromString(pPayload, &index, &pContextSSH->sshc_algorithmMethods[i], copyToBuffer);

            if (OK > status)
                goto exit;
        }

        if (FALSE == copyToBuffer)
        {
            if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, index + SSH2_KEXINIT_PAYLOAD_HEADER + SSH2_KEXINIT_PAYLOAD_TAIL, TRUE, &pPayload)))
                goto exit;

            DEBUG_RELABEL_MEMORY(pPayload);

            index = SSH2_KEXINIT_PAYLOAD_HEADER;
            copyToBuffer = TRUE;
        }
        else
        {
            copyToBuffer = FALSE;
        }

    } while (FALSE != copyToBuffer);

    pPayload[0] = SSH_MSG_KEXINIT;

    /* fill in with random data */
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, pPayload+1, SSH2_KEXINIT_RANDOM_PAD_LENGTH)))
        goto exit;

    pPayload[index] = '\0';                         /* first kex packet follow is FALSE */
    index++;

    MOC_MEMSET(pPayload+index, 0x00, sizeof(ubyte4));   /* 0 --- reserved for future extension */
    index += sizeof(ubyte4);

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, index, &numBytesWritten);

    if ((OK <= status) && (index != numBytesWritten))
    {
        status = ERR_PAYLOAD_TOO_LARGE;
        goto exit;
    }

    /* remove potential memory leak during rekeyex */
    if (NULL != CLIENT_KEX_INIT_PAYLOAD(pContextSSH))
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &CLIENT_KEX_INIT_PAYLOAD(pContextSSH));

    /* save payload here */
    CLIENT_KEX_INIT_PAYLOAD(pContextSSH)     = pPayload;
    CLIENT_KEX_INIT_PAYLOAD_LEN(pContextSSH) = numBytesWritten;
    pPayload = NULL;

exit:
    if (NULL != pPayload)
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &pPayload);

    return status;

} /* SSHC_TRANS_sendClientAlgorithms */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_sendAlgorithms(sshClientContext *pContextSSH)
{
    MSTATUS status;

    if (OK > (status = SSHC_TRANS_sendClientAlgorithms(pContextSSH)))
        goto exit;

    INBOUND_BYTES_READ(pContextSSH) = 0;
    INBOUND_STATE(pContextSSH) = kReceiveInit;

    status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutKeyExchange);

exit:
    return status;

} /* SSHC_TRANS_sendAlgorithms */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_rematchAeadAlgorithms(sshClientContext *pContextSSH, ubyte *pOptionsSelected,
                                 ubyte4 cipherIndex, ubyte4 hmacIndex)
{
    intBoolean  inString;
    ubyte4      optionIndex;
    MSTATUS     status;

    /* AEAD algorithms MUST match their HMAC algorithm */
    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_rematchAeadAlgorithms: AEAD mismatch, cipher chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName);
    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_rematchAeadAlgorithms: AEAD mismatch, hmac chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName);

    if (NULL != mCipherSuites[pOptionsSelected[cipherIndex] - 1].pAeadSuiteInfo)
    {
        /* aead symmetric takes precedence over (any [aead | hmac]) hmac */
        if (OK > (status = SSH_STR_findOption(((NULL == pContextSSH->sshc_algorithmMethods[hmacIndex].pString) ?
                                                    sshc_algorithmMethods[hmacIndex] : &pContextSSH->sshc_algorithmMethods[hmacIndex] ),
                                              (ubyte *)mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName,
                                              mCipherSuites[pOptionsSelected[cipherIndex] - 1].cipherNameLength,
                                              &inString, &optionIndex)))
        {
            goto exit;
        }

        if (FALSE == inString)
        {
            /* not able to match aead algorithm 1) custom option is misconfigured, or 2) mocana code modified */
            status = ERR_SSH_MISMATCH_AEAD_ALGO;
            goto exit;
        }
        /* In case of UseThisList (custom list used) - recompute the optionIndex */
        /* verify custom option available(/map to) in larger list */
         if (NULL != pContextSSH->sshc_algorithmMethods[hmacIndex].pString)
         {
            if (OK > (status = SSH_STR_findOption( sshc_algorithmMethods[hmacIndex],
                                (ubyte *)mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName,
                                mCipherSuites[pOptionsSelected[cipherIndex] - 1].cipherNameLength,
                                &inString, &optionIndex)))
            {
              goto exit;
            }
            if (FALSE == inString)
            {
              /* not able to match aead algorithm 1) custom option is misconfigured, or 2) mocana code modified */
              status = ERR_SSH_MISMATCH_AEAD_ALGO;
              goto exit;
            }
         }


        pOptionsSelected[hmacIndex] = optionIndex;

        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_rematchAeadAlgorithms: AEAD rematch, cipher chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName);
        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_rematchAeadAlgorithms: AEAD rematch, hmac chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName);
    }
    else
    {
        /* hmac takes precedence over non-aead symmetric */
        if (OK > (status = SSH_STR_findOption(((NULL == pContextSSH->sshc_algorithmMethods[cipherIndex].pString) ?
                                                    sshc_algorithmMethods[cipherIndex] : &pContextSSH->sshc_algorithmMethods[cipherIndex]),
                                              (ubyte *)mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName,
                                              mHmacSuites[pOptionsSelected[hmacIndex] - 1].hmacNameLength,
                                              &inString, &optionIndex)) )
        {
            goto exit;
        }

        if (FALSE == inString)
        {
            /* not able to match aead algorithm 1) custom option is misconfigured, or 2) mocana code modified */
            status = ERR_SSH_MISMATCH_AEAD_ALGO;
            goto exit;
        }
        /* In case of UseThisList (custom list used) - recompute the optionIndex */
        /* verify custom option available(/map to) in larger list */
         if (NULL != pContextSSH->sshc_algorithmMethods[cipherIndex].pString)
         {
            if (OK > (status = SSH_STR_findOption( sshc_algorithmMethods[cipherIndex],
                               (ubyte *)mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName,
                               mHmacSuites[pOptionsSelected[hmacIndex] - 1].hmacNameLength,
                               &inString, &optionIndex)) )
            {
              goto exit;
            }
            if (FALSE == inString)
            {
              /* not able to match aead algorithm 1) custom option is misconfigured, or 2) mocana code modified */
              status = ERR_SSH_MISMATCH_AEAD_ALGO;
              goto exit;
            }
         }

        pOptionsSelected[cipherIndex] = optionIndex;

        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_rematchAeadAlgorithms: AEAD rematch, cipher chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName);
        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_rematchAeadAlgorithms: AEAD rematch, hmac chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_receiveServerAlgorithms(sshClientContext *pContextSSH, ubyte *pOptionsSelected,
                                   ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*                    pServerAlgorithm[NUM_ALGORITHM_METHODS];
    ubyte4                              optionIndex;
    ubyte*                              pClonedMesg;
    ubyte4                              index, i, count;
    MSTATUS                             status = OK;

    /* init array of pointers */
    for (index = 0; index < NUM_ALGORITHM_METHODS; index++)
        pServerAlgorithm[index] = NULL;

    if (SSH_MSG_KEXINIT != (*pNewMesg))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    index = SSH2_KEXINIT_PAYLOAD_HEADER;

    for (i = 0; i < NUM_ALGORITHM_METHODS; i++)
    {
        status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &(pServerAlgorithm[i]));
        if (OK > status)
            goto exit;

        DEBUG_RELABEL_MEMORY(pServerAlgorithm[i]);
    }

    count = 0;

    /*
     * check the remaining bytes -- 1 byte boolean && 4 bytes of 0.  This means that we
     * expect there to be no kex packet following.
     */
    if (5 != (newMesgLen - index))
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    for (i = 0; i < NUM_ALGORITHM_METHODS; i++)
    {
        if (NULL == pContextSSH->sshc_algorithmMethods[i].pString)
            status = SSH_STR_locateOption1(sshc_algorithmMethods[i], pServerAlgorithm[i], &optionIndex);
        else
        {
            /* first verify that the forced option is supported by the server */
            if (OK > (status = SSH_STR_locateOption1(&pContextSSH->sshc_algorithmMethods[i], pServerAlgorithm[i], &optionIndex)))
                goto exit;

            /* look up the index for the forced option in our complete option list */
            if (0 != optionIndex)
                status = SSH_STR_locateOption1(sshc_algorithmMethods[i], &pContextSSH->sshc_algorithmMethods[i], &optionIndex);
        }

        if (OK > status)
            goto exit;

        if ((0 != optionIndex) || ((NUM_ALGORITHM_METHODS - 2) <= i))
        {
            /* ignore language fields */
            count++;
            pOptionsSelected[i] = (ubyte)optionIndex;
        }
    }

    if (NUM_ALGORITHM_METHODS != count)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* save the payload */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, newMesgLen, TRUE, &pClonedMesg)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pClonedMesg);

    status = MOC_MEMCPY(pClonedMesg, pNewMesg, (sbyte4)newMesgLen);

    /* remove potential memory free during rekeyex */
    if (NULL != SERVER_KEX_INIT_PAYLOAD(pContextSSH))
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &SERVER_KEX_INIT_PAYLOAD(pContextSSH));

    SERVER_KEX_INIT_PAYLOAD(pContextSSH)     = pClonedMesg;
    SERVER_KEX_INIT_PAYLOAD_LEN(pContextSSH) = newMesgLen;

    /* ---------------------------- */
    /* handle key exchange algorithm */
    if (NULL != pContextSSH->pKeyExSuiteInfo)
    {
        if (NULL != pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx)
        {
            /* free DH context to avoid memory leak when client sends key re-exchange message */
            pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx(pContextSSH);
        }

        if ((NULL != pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo) && (NULL != pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc))
        {
            /* free hash context to avoid memory leak when we re-key */
            if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
                pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &(pContextSSH->sshKeyExCtx.pKeyExHash));

            if (NULL != SSH_HASH_H(pContextSSH))
            {
                if (OK > (status = CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &SSH_HASH_H(pContextSSH))))
                    goto exit;

                SSH_HASH_H(pContextSSH) = NULL;
            }
        }
    }

    pContextSSH->pKeyExSuiteInfo = &(mKeyExSuites[pOptionsSelected[0] - 1]);

    if ((NULL == pContextSSH->pKeyExSuiteInfo) ||
        (NULL == pContextSSH->pKeyExSuiteInfo->pKeyExMethods) ||
        (NULL == pContextSSH->pKeyExSuiteInfo->pKeyExMethods->allocCtx))
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_receiveServerAlgorithms: keyEx algo chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pContextSSH->pKeyExSuiteInfo->pDebugString);

    /* allocate / initialize key exchange ctx */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pKeyExMethods->allocCtx(pContextSSH)))
        goto exit;

    /* allocate / initialize key exchange hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pAllocFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash)))
        goto exit;

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pInitFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &SSH_HASH_H(pContextSSH))))
        goto exit;

    DEBUG_RELABEL_MEMORY(SSH_HASH_H(pContextSSH));

    /* add V_C to the hash */
    if (OK > (status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, CLIENT_HELLO_COMMENT(pContextSSH), CLIENT_HELLO_COMMENT_LEN(pContextSSH))))
        goto exit;

    /* add V_S to the hash */
    if (OK > (status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, SERVER_HELLO_COMMENT(pContextSSH), SERVER_HELLO_COMMENT_LEN(pContextSSH))))
        goto exit;

    /* add I_C to the hash */
    if (OK > (status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, CLIENT_KEX_INIT_PAYLOAD(pContextSSH), CLIENT_KEX_INIT_PAYLOAD_LEN(pContextSSH))))
        goto exit;

    /* add I_S to the hash */
    if (OK > (status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, SERVER_KEX_INIT_PAYLOAD(pContextSSH), SERVER_KEX_INIT_PAYLOAD_LEN(pContextSSH))))
        goto exit;

    /* ---------------------------------------- */
    /* handle host key authentication algorithm */
    pContextSSH->pHostKeySuites = &mHostKeySuites[pOptionsSelected[1] - 1];

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "SSHC_TRANS_receiveServerAlgorithms: hostAuth algo chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pContextSSH->pHostKeySuites->pHostKeyName);

    /* ---------------------------------------------------------- */
    /* handle AEAD algorithm (RFC-5647, Section 5.1, Paragraph 2) */
    if ((NULL != mCipherSuites[pOptionsSelected[2] - 1].pAeadSuiteInfo) ||
        (NULL != mHmacSuites[pOptionsSelected[4] - 1].pAeadSuiteInfo))
    {
        /* AEAD algorithms MUST match their HMAC algorithm */
        if ((mCipherSuites[pOptionsSelected[2] - 1].cipherNameLength != mHmacSuites[pOptionsSelected[4] - 1].hmacNameLength) ||
            (0 != MOC_STRCMP(mCipherSuites[pOptionsSelected[2] - 1].pCipherName, mHmacSuites[pOptionsSelected[4] - 1].pHmacName)) )
        {
            if (OK > (status = SSHC_TRANS_rematchAeadAlgorithms(pContextSSH, pOptionsSelected, 2, 4)))
                goto exit;
        }
    }

    if ((NULL != mCipherSuites[pOptionsSelected[3] - 1].pAeadSuiteInfo) ||
        (NULL != mHmacSuites[pOptionsSelected[5] - 1].pAeadSuiteInfo))
    {
        /* AEAD algorithms MUST match their HMAC algorithm */
        if ((mCipherSuites[pOptionsSelected[3] - 1].cipherNameLength != mHmacSuites[pOptionsSelected[5] - 1].hmacNameLength) ||
            (0 != MOC_STRCMP(mCipherSuites[pOptionsSelected[3] - 1].pCipherName, mHmacSuites[pOptionsSelected[5] - 1].pHmacName)) )
        {
            if (OK > (status = SSHC_TRANS_rematchAeadAlgorithms(pContextSSH, pOptionsSelected, 3, 5)))
                goto exit;
        }
    }

exit:
    /* free array of pointers */
    for (index = 0; index < NUM_ALGORITHM_METHODS; index++)
        if (NULL != pServerAlgorithm[index])
            SSH_STR_freeStringBuffer(&pServerAlgorithm[index]);

    return status;

} /* SSHC_TRANS_receiveServerAlgorithms */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_sendClientKeyExchange(struct sshClientContext *pContextSSH)
{
    ubyte*      pStringMpintE = NULL;
    ubyte4      stringLenE;
    ubyte*      pMesg         = NULL;
    ubyte4      mesgLen;
    ubyte4      bytesWritten;
    vlong*      pVlongQueue   = NULL;
    MDhKeyTemplate template = {0};
    MSTATUS     status;
    /* free G (Generator if one is already present */
    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_F(SSH_DH_CTX(pContextSSH)));

    /* get client public key */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DH_CTX(pContextSSH), MOC_GET_PUBLIC_KEY_DATA, NULL)))
    {
        goto exit;
    }
#else
    if (OK > (status = DH_getKeyParametersAllocExt(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DH_CTX(pContextSSH), MOC_GET_PUBLIC_KEY_DATA, NULL)))
    {
        goto exit;
    }
#endif

    /* make mpint from public key byte string */
    if (OK > (status = SSH_mpintByteStringFromByteString(template.pF, template.fLen, 0,
                                                        &pStringMpintE, (sbyte4 *)&stringLenE)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pStringMpintE);

    /* Send SSH_MSG_KEXDH_INIT message */
    mesgLen = 1 + stringLenE;

    if (NULL == (pMesg = MALLOC(mesgLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set message type */
    pMesg[0] = SSH_MSG_KEXDH_INIT;

    /* copy E mpint string */
    if (OK > (status = MOC_MEMCPY(pMesg + 1, pStringMpintE, stringLenE)))
        goto exit;

    /* send it out */
    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pMesg, mesgLen, &bytesWritten)))
        goto exit;

exit:
    if (NULL != pMesg)
        FREE(pMesg);

    if (NULL != pStringMpintE)
        FREE(pStringMpintE);
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(NULL, &template, NULL);
#else
    DH_freeKeyTemplateExt(NULL, &template, NULL);
#endif

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSHC_TRANS_sendClientKeyExchange */

/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_computeClientPubKeyHash(sshClientContext *pContextSSH, ubyte* pDigestData, ubyte4 digestLen, ubyte *pShaOutput, vlong **ppM, vlong **ppVlongQueue)
{
    MSTATUS     status;

    switch (pContextSSH->pHostKeySuites->hashLen)
     {
#ifndef __DISABLE_MOCANA_SHA256__
       case SHA256_RESULT_SIZE :  if (OK > (status = SHA256_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, pShaOutput)))
                  {
                    goto exit;
                  }
                  break;
#endif
#ifndef __DISABLE_MOCANA_SHA384__
       case SHA384_RESULT_SIZE :  if (OK > (status = SHA384_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, pShaOutput)))
                  {
                    goto exit;
                  }
                  break;
#endif
#ifndef __DISABLE_MOCANA_SHA512__
       case SHA512_RESULT_SIZE :  if (OK > (status = SHA512_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, pShaOutput)))
                  {
                    goto exit;
                  }
                  break;
#endif
       case SHA1_RESULT_SIZE :
       default :  if (OK > (status = SHA1_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, pShaOutput)))
                  {
                    goto exit;
                  }
                  break;
        }
    if (NULL != ppM)
    {
        status = VLONG_vlongFromByteString(pShaOutput, SHA_HASH_RESULT_SIZE, ppM, ppVlongQueue);

        DEBUG_RELABEL_MEMORY(*ppM);
    }

exit:
    return status;

} /* SSHC_TRANS_computeClientPubKeyHash */

/*------------------------------------------------------------------*/

/* 
 * This function takes a byte string, converts it to Mpint byte string, and adds the result of that 
 * conversion to the hash context with an update call.
 */
static MSTATUS
digestMpintFromByteString(sshClientContext *pContextSSH, BulkCtx *pKeyExHash, ubyte *pRawBytes, ubyte4 rawBytesLen)
{
    ubyte*  pAsciiVlong = NULL;
    ubyte*  pAsciiVlongClone = NULL;
    sbyte4  asciiLength = 0;
    MSTATUS status;

    status = SSH_mpintByteStringFromByteString(pRawBytes, rawBytesLen, 0, &pAsciiVlong, &asciiLength); 
    if (OK != status)
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, asciiLength, TRUE, &pAsciiVlongClone)))
        goto exit;

    status = MOC_MEMCPY(pAsciiVlongClone, pAsciiVlong, asciiLength);
    if (OK != status)
        goto exit;

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pKeyExHash, pAsciiVlongClone, (ubyte4)asciiLength);
    DUMP("update:", pAsciiVlongClone, asciiLength);

exit:
    if (NULL != pAsciiVlongClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, (void **)(&pAsciiVlongClone));

    if (NULL != pAsciiVlong)
        FREE(pAsciiVlong);

    return status;
}


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
digestMpint(sshClientContext *pContextSSH, BulkCtx *pKeyExHash, vlong *pRawVlong)
{
    ubyte*  pAsciiVlong = NULL;
    ubyte*  pAsciiVlongClone = NULL;
    sbyte4  asciiLength;
    MSTATUS status;

    if (OK > (status = VLONG_mpintByteStringFromVlong(pRawVlong, &pAsciiVlong, &asciiLength)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, asciiLength, TRUE, &pAsciiVlongClone)))
        goto exit;

    MOC_MEMCPY(pAsciiVlongClone, pAsciiVlong, asciiLength);

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pKeyExHash, pAsciiVlongClone, (ubyte4)asciiLength);
    DUMP("update:", pAsciiVlongClone, asciiLength);

exit:
    if (NULL != pAsciiVlongClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, (void **)(&pAsciiVlongClone));

    if (NULL != pAsciiVlong)
        FREE(pAsciiVlong);

    return status;
}
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */


/*------------------------------------------------------------------*/

static MSTATUS
makeKeyFromByteString(sshClientContext *pContextSSH, BulkCtx* pHashContext, ubyte *k, ubyte4 kLen, ubyte *H, ubyte chr, ubyte *pSessionId, ubyte *pKeyBuffer, ubyte4 keyBufferSize)
{
    ubyte*      stringK = NULL;
    ubyte*      stringKClone = NULL;
    ubyte4      stringLenK, m;
    ubyte*      pChr = NULL;
    ubyte*      pTempKeyBuffer = NULL;
    MSTATUS     status;

    status = SSH_mpintByteStringFromByteString(k, kLen, 0, &stringK, (sbyte4 *)&stringLenK);
    if (OK != status)
        goto exit;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, stringLenK, TRUE, &stringKClone)))
        goto exit;

    status = MOC_MEMCPY(stringKClone, stringK, stringLenK);
    if (OK != status)
        goto exit;

    if (NULL != stringK)
    {
        FREE(stringK);
        stringK = NULL;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->mediumPool, (void **)&(pTempKeyBuffer))))
        goto exit;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pChr))))
        goto exit;

    (*pChr) = chr;

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pInitFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext)))
        goto exit;

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, stringKClone, stringLenK)))
        goto exit;

    DUMP("makeKeyFromByteString update:", stringKClone, stringLenK);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize /* SHA_HASH_RESULT_SIZE */)))
        goto exit;

    DUMP("makeKeyFromByteString update:", H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pChr, 1)))
        goto exit;

    DUMP("makeKeyFromByteString update:", pChr, 1);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pSessionId, pContextSSH->sessionIdLength)))
        goto exit;

    DUMP("makeKeyFromByteString update:", pSessionId, pContextSSH->sessionIdLength);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer)))
        goto exit;

    DUMP("makeKeyFromByteString final:", pTempKeyBuffer, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    m = 1;
    /* add as much key material as required for the key */
    while (keyBufferSize > m*pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)
    {
        /* in the future we may need more bits, but for now 160 bits is plenty */
        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pInitFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext)))
            goto exit;

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, stringKClone, stringLenK)))
            goto exit;

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)))
            goto exit;

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer, m*pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)))
            goto exit;

        MOC_MEMSET(pTempKeyBuffer + m*pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, 0xff, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer + m*pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)))
            goto exit;

        m++;
    }

    /* copy out appropriate number of key data bytes */
    status = MOC_MEMCPY(pKeyBuffer, pTempKeyBuffer, keyBufferSize);
    if (OK != status)
        goto exit;

exit:
    if (NULL != stringK)
        FREE(stringK);

    if (NULL != stringKClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &stringKClone);

    if (NULL != pTempKeyBuffer)
        MEM_POOL_putPoolObject(&pContextSSH->mediumPool, (void **)(&pTempKeyBuffer));

    if (NULL != pChr)
        MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pChr));

    return status;

} /* makeKeyFromByteString */

/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
makeKey(sshClientContext *pContextSSH, BulkCtx* pHashContext, vlong *k, ubyte *H, ubyte chr,
        ubyte *pSessionId, ubyte *pKeyBuffer, ubyte4 keyBufferSize)
{
    ubyte*      stringK = NULL;
    ubyte*      stringKClone = NULL;
    ubyte4      stringLenK;
    ubyte*      pChr = NULL;
    ubyte*      pTempKeyBuffer = NULL;
    MSTATUS     status;

    if (OK > (status = VLONG_mpintByteStringFromVlong(k, &stringK, (sbyte4 *)&stringLenK)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, stringLenK, TRUE, &stringKClone)))
        goto exit;

    MOC_MEMCPY(stringKClone, stringK, stringLenK);

    if (NULL != stringK)
    {
        FREE(stringK);
        stringK = NULL;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->mediumPool, (void **)&(pTempKeyBuffer))))
        goto exit;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pChr))))
        goto exit;

    (*pChr) = chr;

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pInitFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext)))
        goto exit;

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, stringKClone, stringLenK)))
        goto exit;

    DUMP("makeKey update:", stringKClone, stringLenK);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize /* SHA_HASH_RESULT_SIZE */)))
        goto exit;

    DUMP("makeKey update:", H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pChr, 1)))
        goto exit;

    DUMP("makeKey update:", pChr, 1);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pSessionId, pContextSSH->sessionIdLength)))
        goto exit;

    DUMP("makeKey update:", pSessionId, pContextSSH->sessionIdLength);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer)))
        goto exit;

    DUMP("makeKey final:", pTempKeyBuffer, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    if (keyBufferSize > pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)
    {
        /* in the future we may need more bits, but for now 160 bits is plenty */
        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pInitFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext)))
            goto exit;

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, stringKClone, stringLenK)))
            goto exit;

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)))
            goto exit;

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)))
            goto exit;

        MOC_MEMSET(pTempKeyBuffer + pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, 0xff, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer + pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)))
            goto exit;
    }

    /* copy out appropriate number of key data bytes */
    MOC_MEMCPY(pKeyBuffer, pTempKeyBuffer, keyBufferSize);

exit:
    if (NULL != stringK)
        FREE(stringK);

    if (NULL != stringKClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &stringKClone);

    if (NULL != pTempKeyBuffer)
        MEM_POOL_putPoolObject(&pContextSSH->mediumPool, (void **)(&pTempKeyBuffer));

    if (NULL != pChr)
        MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pChr));

    return status;

} /* makeKey */
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

/*------------------------------------------------------------------*/

static MSTATUS
sendNewKeysMessage(sshClientContext *pContextSSH)
{
    ubyte       payload = (ubyte)SSH_MSG_NEWKEYS;
    ubyte4      length;
    MSTATUS     status;

    /* zero out bytes transmitted each time we send out NEWKEYS */
    ZERO_U8(pContextSSH->bytesTransmitted);

    /* send SSH_MSG_NEWKEYS message */
    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, &payload, 1, &length)))
        goto exit;

    if (1 != length)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
static MSTATUS
validateFirstCertificate(ASN1_ITEM* pRootItem, CStream cs, struct sshClientContext *pContextSSH)
{
    MSTATUS   status;
    MSTATUS   ret = OK;
    ASN1_ITEM* pKeyUsageExtension = 0;
    byteBoolean bitVal;
    intBoolean critical = 0;
    ASN1_ITEM* pExtensions = NULL;
    ASN1_ITEM* pExtValue = NULL;
    ASN1_ITEM* pExtendedKeyUsage = NULL;
    TimeDate td;

#if !defined(__DISABLE_MOCANA_SSH_COMMON_NAME_CHECK__)
    /* verify common name - SSH does not store the DNS name */
    status = X509_compSubjectCommonName(ASN1_FIRST_CHILD(pRootItem), cs, pContextSSH->pCommonName);

    if (ERR_CERT_BAD_COMMON_NAME == status)
    {
        status = X509_compSubjectAltNames( ASN1_FIRST_CHILD(pRootItem), cs,
                                           pContextSSH->pCommonName,
                                           (1 << 2)); /* 2 = DNS name tag */
    }

    if (OK > status)
        goto exit;
#endif /* __DISABLE_MOCANA_SSH_COMMON_NAME_CHECK__ */
    /* verify the key usage */
    if (OK > (status = X509_getCertificateKeyUsage( ASN1_FIRST_CHILD(pRootItem), cs,
                                                    &pKeyUsageExtension)))
    {
        goto exit;
    }

    /* if there is a pKeyUsageExtension then check its value */
    if (pKeyUsageExtension)
    {
        /* enforcing digitalSignature as per RFC 6187, Section 2.1.1 */
        ASN1_getBitStringBit( pKeyUsageExtension, cs, digitalSignature, &bitVal);
        if (!bitVal)
        {
            status = ERR_CERT_INVALID_KEYUSAGE;
            goto exit;
        }
    }

    /* if there is a extendedKeyUsage Extension then check its value */
    ret = X509_getCertificateExtensions(ASN1_FIRST_CHILD(pRootItem), &pExtensions);

    if ((OK == ret) && (pExtensions))
    {
        ret = X509_getCertExtension(pExtensions, cs, extendedKeyUsage_OID,
                                    &critical, &pExtendedKeyUsage);
        if ((OK == ret) && (pExtendedKeyUsage))
        {
            /* check for id-kp-secureShellServer */
            for(pExtValue = ASN1_FIRST_CHILD(pExtendedKeyUsage); pExtValue; pExtValue = ASN1_NEXT_SIBLING(pExtValue))
            {
                if (OK == (status = ASN1_VerifyOID(pExtValue, cs, id_kp_secureShellServer)))
                    break;
            }

            if (!pExtValue)
            {
                status = ERR_CERT_INVALID_EXTENDED_KEYUSAGE;
                goto exit;
            }
        }
    }

    RTOS_timeGMT(&td);
    /* verify time validity of pCertificate */
    status = X509_verifyValidityTime( pRootItem, cs, &td);

exit:
    return status;

} /* validateFirstCertificate() */
#endif /* __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
#ifdef __ENABLE_MOCANA_PQC__
extern MSTATUS
SSHC_TRANS_parseCertHybrid(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    certChainPtr        pNewCertChain = NULL;
    ValidationConfig    vc = {0};
    ubyte2              keyUsage = ( 1 << digitalSignature);
    const ubyte*        pCertParse;
    ubyte4              certParseLen;
    ubyte4              bufIndex;
    sbyte4              result;
#ifdef __ENABLE_MOCANA_OCSP_CLIENT__
    ubyte*              pOcsp = NULL;
    ubyte               numResponses;
    ubyte4              respLen;
    ubyte4              numCertificates;
#endif
    sshStringBuffer*    ssh_sign = NULL;
    ubyte               i = 0;
    MSTATUS             status = OK;
    MSTATUS             cert_status = OK;
    ubyte*              pLeafCert;
    ubyte4              leafCertLen;
    ubyte*              pAlgoName;
    ubyte4              algoNameLen;
    sbyte4              exists;

/*  string  hybrid_cert_algorithm
    uint32  certificate-count
    string  certificate[1..certificate-count]
    uint32  ocsp-response-count
    string  ocsp-response[0..ocsp-response-count]
*/
    if (NULL == pCertMessage)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContextSSH->pCertStore)
    {
        /* config error. unable to validate cert chain without a store */
        status = ERR_SSH_NO_CERT_STORE_FOUND;
        goto exit;
    }

    /* skips past the string length for cert string, which was already extracted (in pCertMessage) */
    bufIndex = 4;

    pCertParse = pCertMessage->pString;
    certParseLen = pCertMessage->stringLen;

    algoNameLen  = ((ubyte4)pCertParse[bufIndex + 3]);
    algoNameLen |= ((ubyte4)pCertParse[bufIndex + 2]) <<  8;
    algoNameLen |= ((ubyte4)pCertParse[bufIndex + 1]) << 16;
    algoNameLen |= ((ubyte4)pCertParse[bufIndex + 0]) << 24;

    /* move past 4  bytes of algorithm name */
    bufIndex += 4;

    /* get pointer to start of name */
    pAlgoName = (ubyte *) pCertParse + bufIndex;

    exists = -1;
    status = SSH_HYBRID_verifyAlgorithmNameEx(pAlgoName, algoNameLen, &exists);
    if (OK != status)
        goto exit;

    if (0 != exists)
    {
        status = ERR_SSH_MALFORMED_CERTIFICATE;
        goto exit;
    }

    bufIndex += algoNameLen;

    if (OK > (status = CERTCHAIN_createFromSSHEx(MOC_ASYM(pContextSSH->hwAccelCookie) &pNewCertChain, pCertParse, certParseLen, &bufIndex, &SSH_STR_walkStringInPayload)))
        goto exit;

    /* the other ciphers are ephemeral so certificate keys
         are not used for the key exchange proper */

    vc.keyUsage = keyUsage;                   /* verify key usage */
    vc.pCertStore = pContextSSH->pCertStore;  /* verify Trust Point */
    vc.commonName = pContextSSH->pCommonName;

    cert_status = CERTCHAIN_validate(MOC_ASYM(pContextSSH->hwAccelCookie) pNewCertChain, &vc) ;

#ifdef __ENABLE_MOCANA_OCSP_CLIENT__

    if(OK == cert_status)
    {

        pOcsp = (ubyte *) (pCertParse + bufIndex);
        numResponses = ((ubyte4)pOcsp[3]);
        numResponses |= ((ubyte4)pOcsp[2]) << 8;
        numResponses |= ((ubyte4)pOcsp[1]) << 16;
        numResponses |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        respLen = ((ubyte4)pOcsp[3]);
        respLen |= ((ubyte4)pOcsp[2]) << 8;
        respLen |= ((ubyte4)pOcsp[1]) << 16;
        respLen |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        DB_PRINT("numResponses = %d, respLen =%d\n", numResponses,respLen);

        if (numResponses)
        {
            ubyte*          pAnchor = NULL;
            ubyte4          anchorLen = 0;
            ubyte           isValid = 0;
            ubyte           certOcspStatus = 0;

            ASN1_ITEMPTR    pRoot = 0;
            ASN1_ITEMPTR    pIssuer, pSerialNumber;
            CStream         cs;
            MemFile         mf;
            ubyte*          cert;
            void*           pIterator;
            const ubyte*    dn;
            ubyte*          pIssuerCert;
            ubyte4          issuerCertLen;

            if (OK > (status = CERTCHAIN_numberOfCertificates(pNewCertChain, &numCertificates)))
                goto exit;

            if (numCertificates <= 0)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte **)&pAnchor, &anchorLen)))
            {
                goto exit;
            }

            /* If certChain has more than one certificate, then the 0 is leaf certificate and 1 is the issuer */
            if(numCertificates > 1)
            {
                if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 1, (const ubyte **)&pIssuerCert, &issuerCertLen)))
                {
                    goto exit;
                }
            }
            else if (numCertificates == 1)
            {
                cert = pAnchor;

                MF_attach(&mf,anchorLen, cert);

                CS_AttachMemFile(&cs, &mf);

                if (OK > ( status = ASN1_Parse(cs, &pRoot)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                     &pIssuer,
                                                                     &pSerialNumber)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                dn = CS_memaccess(cs,pIssuer->dataOffset, pIssuer->length);

                if (OK > (status = (CERT_STORE_findTrustPointBySubjectFirst(pContextSSH->pCertStore,
                                                                            dn, pIssuer->length,
                                                                            (const ubyte **)&pIssuerCert,
                                                                            &issuerCertLen, (const void **)&pIterator))))
                {
                    goto exit;
                }

                if (pAnchor == NULL)
                {
                    status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                    goto exit;
                }
                TREE_DeleteTreeItem((TreeItem*)pRoot);
                pRoot = NULL;
            }
            status = SSH_OCSP_validateOcspResponse(pAnchor, anchorLen, pIssuerCert, issuerCertLen,
                                                   pOcsp, respLen, &certOcspStatus, &isValid);

            if (status == OK)
            {
                if (!isValid)
                    status = ERR_OCSP;
                else if (1 == certOcspStatus)
                    status = ERR_CERT_REVOKED;
                else if (2 == certOcspStatus)
                    status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS;
            }
            cert_status = status ;
        }
    }
#endif

    if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte** )&pLeafCert, &leafCertLen)))
        goto exit;


    /* call application api to validate the certificate status */
    if (NULL != SSHC_sshClientSettings()->funcPtrCertStatus)
    {
        if(OK > (status = (SSHC_sshClientSettings()->funcPtrCertStatus)
                        (CONNECTION_INSTANCE(pContextSSH),
                         cert_status,
                         pLeafCert, leafCertLen, pNewCertChain,
                        vc.anchorCert, vc.anchorCertLen)))
        {
            goto exit ;
        }
    }
    else
    {
        if(OK > cert_status )
        {
            status = cert_status ;
            goto exit ;
        }
    }

    if (OK > (status = CERTCHAIN_getKey(MOC_RSA(pContextSSH->hwAccelCookie) pNewCertChain, 0, pPublicKey)))
    {
        goto exit;
    }

    /* if hybrid, verify the public key is of sufficient size */
    if (akt_hybrid != pPublicKey->type)
    {
        /* bad key type */
        status = ERR_SSH_EXPECTED_HYBRID_KEY;
        goto exit;
    }
exit:
    CERTCHAIN_delete(&pNewCertChain);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_parseCertQs(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    certChainPtr        pNewCertChain = NULL;
    ValidationConfig    vc = {0};
    ubyte2              keyUsage = ( 1 << digitalSignature);
    const ubyte*        pCertParse;
    ubyte4              certParseLen;
    ubyte4              bufIndex;
    sbyte4              result;
#ifdef __ENABLE_MOCANA_OCSP_CLIENT__
    ubyte*              pOcsp = NULL;
    ubyte               numResponses;
    ubyte4              respLen;
    ubyte4              numCertificates;
#endif
    sshStringBuffer*    ssh_sign = NULL;
    ubyte               i = 0;
    MSTATUS             status = OK;
    MSTATUS             cert_status = OK;
    ubyte*              pLeafCert;
    ubyte4              leafCertLen;
    ubyte*              pAlgoName;
    ubyte4              algoNameLen;
    sbyte4              exists;

/*  string  qs_cert_algorithm
    uint32  certificate-count
    string  certificate[1..certificate-count]
    uint32  ocsp-response-count
    string  ocsp-response[0..ocsp-response-count]
*/
    if (NULL == pCertMessage)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContextSSH->pCertStore)
    {
        /* config error. unable to validate cert chain without a store */
        status = ERR_SSH_NO_CERT_STORE_FOUND;
        goto exit;
    }

    /* skips past the string length for cert string, which was already extracted (in pCertMessage) */
    bufIndex = 4;

    pCertParse = pCertMessage->pString;
    certParseLen = pCertMessage->stringLen;

    algoNameLen  = ((ubyte4)pCertParse[bufIndex + 3]);
    algoNameLen |= ((ubyte4)pCertParse[bufIndex + 2]) <<  8;
    algoNameLen |= ((ubyte4)pCertParse[bufIndex + 1]) << 16;
    algoNameLen |= ((ubyte4)pCertParse[bufIndex + 0]) << 24;

    /* move past 4  bytes of algorithm name */
    bufIndex += 4;

    /* get pointer to start of name */
    pAlgoName = (ubyte *) pCertParse + bufIndex;

    exists = -1;
    status = SSH_QS_verifyAlgorithmNameEx(pAlgoName, algoNameLen, &exists);
    if (OK != status)
        goto exit;

    if (0 != exists)
    {
        status = ERR_SSH_MALFORMED_CERTIFICATE;
        goto exit;
    }

    bufIndex += algoNameLen;

    if (OK > (status = CERTCHAIN_createFromSSHEx(MOC_ASYM(pContextSSH->hwAccelCookie) &pNewCertChain, pCertParse, certParseLen, &bufIndex, &SSH_STR_walkStringInPayload)))
        goto exit;

    /* the other ciphers are ephemeral so certificate keys
         are not used for the key exchange proper */

    vc.keyUsage = keyUsage;                   /* verify key usage */
    vc.pCertStore = pContextSSH->pCertStore;  /* verify Trust Point */
    vc.commonName = pContextSSH->pCommonName;

    cert_status = CERTCHAIN_validate(MOC_ASYM(pContextSSH->hwAccelCookie) pNewCertChain, &vc) ;

#ifdef __ENABLE_MOCANA_OCSP_CLIENT__

    if(OK == cert_status)
    {

        pOcsp = (ubyte *) (pCertParse + bufIndex);
        numResponses = ((ubyte4)pOcsp[3]);
        numResponses |= ((ubyte4)pOcsp[2]) << 8;
        numResponses |= ((ubyte4)pOcsp[1]) << 16;
        numResponses |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        respLen = ((ubyte4)pOcsp[3]);
        respLen |= ((ubyte4)pOcsp[2]) << 8;
        respLen |= ((ubyte4)pOcsp[1]) << 16;
        respLen |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        DB_PRINT("numResponses = %d, respLen =%d\n", numResponses,respLen);

        if (numResponses)
        {
            ubyte*          pAnchor = NULL;
            ubyte4          anchorLen = 0;
            ubyte           isValid = 0;
            ubyte           certOcspStatus = 0;

            ASN1_ITEMPTR    pRoot = 0;
            ASN1_ITEMPTR    pIssuer, pSerialNumber;
            CStream         cs;
            MemFile         mf;
            ubyte*          cert;
            void*           pIterator;
            const ubyte*    dn;
            ubyte*          pIssuerCert;
            ubyte4          issuerCertLen;

            if (OK > (status = CERTCHAIN_numberOfCertificates(pNewCertChain, &numCertificates)))
                goto exit;

            if (numCertificates <= 0)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte **)&pAnchor, &anchorLen)))
            {
                goto exit;
            }

            /* If certChain has more than one certificate, then the 0 is leaf certificate and 1 is the issuer */
            if(numCertificates > 1)
            {
                if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 1, (const ubyte **)&pIssuerCert, &issuerCertLen)))
                {
                    goto exit;
                }
            }
            else if (numCertificates == 1)
            {
                cert = pAnchor;

                MF_attach(&mf,anchorLen, cert);

                CS_AttachMemFile(&cs, &mf);

                if (OK > ( status = ASN1_Parse(cs, &pRoot)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                     &pIssuer,
                                                                     &pSerialNumber)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                dn = CS_memaccess(cs,pIssuer->dataOffset, pIssuer->length);

                if (OK > (status = (CERT_STORE_findTrustPointBySubjectFirst(pContextSSH->pCertStore,
                                                                            dn, pIssuer->length,
                                                                            (const ubyte **)&pIssuerCert,
                                                                            &issuerCertLen, (const void **)&pIterator))))
                {
                    goto exit;
                }

                if (pAnchor == NULL)
                {
                    status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                    goto exit;
                }
                TREE_DeleteTreeItem((TreeItem*)pRoot);
                pRoot = NULL;
            }
            status = SSH_OCSP_validateOcspResponse(pAnchor, anchorLen, pIssuerCert, issuerCertLen,
                                                   pOcsp, respLen, &certOcspStatus, &isValid);

            if (status == OK)
            {
                if (!isValid)
                    status = ERR_OCSP;
                else if (1 == certOcspStatus)
                    status = ERR_CERT_REVOKED;
                else if (2 == certOcspStatus)
                    status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS;
            }
            cert_status = status ;
        }
    }
#endif

    if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte** )&pLeafCert, &leafCertLen)))
        goto exit;


    /* call application api to validate the certificate status */
    if (NULL != SSHC_sshClientSettings()->funcPtrCertStatus)
    {
        if(OK > (status = (SSHC_sshClientSettings()->funcPtrCertStatus)
                        (CONNECTION_INSTANCE(pContextSSH),
                         cert_status,
                         pLeafCert, leafCertLen, pNewCertChain,
                        vc.anchorCert, vc.anchorCertLen)))
        {
            goto exit ;
        }
    }
    else
    {
        if(OK > cert_status )
        {
            status = cert_status ;
            goto exit ;
        }
    }

    if (OK > (status = CERTCHAIN_getKey(MOC_RSA(pContextSSH->hwAccelCookie) pNewCertChain, 0, pPublicKey)))
    {
        goto exit;
    }

    /* if qs, verify the public key is of sufficient type */
    if (akt_qs != pPublicKey->type)
    {
        /* bad key type */
        status = ERR_SSH_EXPECTED_QS_KEY;
        goto exit;
    }
exit:
    CERTCHAIN_delete(&pNewCertChain);

    return status;
}
#endif /* __ENABLE_MOCANA_PQC__ */

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_parseCertECDSA(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    certChainPtr        pNewCertChain = NULL;
    ValidationConfig    vc = {0};
    ubyte2              keyUsage = ( 1 << digitalSignature);
    const ubyte*        pCertParse;
    ubyte4              certParseLen;
    ubyte4              bufIndex;
    sbyte4              result;
#ifdef __ENABLE_MOCANA_OCSP_CLIENT__
    ubyte*              pOcsp = NULL;
    ubyte               numResponses;
    ubyte4              respLen;
    ubyte4              numCertificates;
#endif
    sshStringBuffer*    ssh_sign = NULL;
    ubyte               i = 0;
    MSTATUS             status = OK;
    MSTATUS             cert_status = OK;
    ubyte*              pLeafCert;
    ubyte4              leafCertLen;

    sshStringBuffer*    curveIdString[] =
    {
#if (!defined(__DISABLE_MOCANA_ECC_P192__))
        &sshc_ecdsa_cert_signature_p192,
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P224__))
        &sshc_ecdsa_cert_signature_p224,
#endif 
#if (!defined(__DISABLE_MOCANA_ECC_P256__))
        &sshc_ecdsa_cert_signature_p256,
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__))
        &sshc_ecdsa_cert_signature_p384, 
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__))
        &sshc_ecdsa_cert_signature_p521, 
#endif
        NULL
    };

/*  string  "x509v3-ecdsa-sha2-[identifier]"
    uint32  certificate-count
    string  certificate[1..certificate-count]
    uint32  ocsp-response-count
    string  ocsp-response[0..ocsp-response-count]
*/
    if (NULL == pCertMessage)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContextSSH->pCertStore)
    {
        /* config error. unable to validate cert chain without a store */
        status = ERR_SSH_NO_CERT_STORE_FOUND;
        goto exit;
    }

    /* skips past the string length for cert string, which was already extracted (in pCertMessage) */
    bufIndex = 4;

    pCertParse = pCertMessage->pString;
    certParseLen = pCertMessage->stringLen;

    while (NULL != curveIdString[i])
    {
        ssh_sign = curveIdString[i];

        /* Compare the x509v3-ecdsa-sha2-[identifier] */
        if (OK > (status = MOC_MEMCMP(bufIndex + pCertParse, ssh_sign->pString, ssh_sign->stringLen, &result)))
            goto exit;

        if (0 == result)
            break;
        i++;
    }

    switch (i)
    {
        case 0:
            bufIndex += sshc_ecdsa_cert_signature_p192.stringLen;
            break;
        case 1:
            bufIndex += sshc_ecdsa_cert_signature_p224.stringLen;
            break;
        case 2:
            bufIndex += sshc_ecdsa_cert_signature_p256.stringLen;
            break;
        case 3:
            bufIndex += sshc_ecdsa_cert_signature_p384.stringLen;
            break;
        case 4:
            bufIndex += sshc_ecdsa_cert_signature_p521.stringLen;
            break;
        default:
            break;
    }

    if (OK > (status = CERTCHAIN_createFromSSHEx(MOC_ASYM(pContextSSH->hwAccelCookie) &pNewCertChain, pCertParse, certParseLen, &bufIndex, &SSH_STR_walkStringInPayload)))
        goto exit;

    /* the other ciphers are ephemeral so certificate keys
         are not used for the key exchange proper */

    vc.keyUsage = keyUsage;                   /* verify key usage */
    vc.pCertStore = pContextSSH->pCertStore;  /* verify Trust Point */
    vc.commonName = pContextSSH->pCommonName;

    cert_status = CERTCHAIN_validate(MOC_ASYM(pContextSSH->hwAccelCookie) pNewCertChain, &vc) ;

#ifdef __ENABLE_MOCANA_OCSP_CLIENT__

    if(OK == cert_status)
    {

        pOcsp = (ubyte *) (pCertParse + bufIndex);
        numResponses = ((ubyte4)pOcsp[3]);
        numResponses |= ((ubyte4)pOcsp[2]) << 8;
        numResponses |= ((ubyte4)pOcsp[1]) << 16;
        numResponses |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        respLen = ((ubyte4)pOcsp[3]);
        respLen |= ((ubyte4)pOcsp[2]) << 8;
        respLen |= ((ubyte4)pOcsp[1]) << 16;
        respLen |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        DB_PRINT("numResponses = %d, respLen =%d\n", numResponses,respLen);

        if (numResponses)
        {
            ubyte*          pAnchor = NULL;
            ubyte4          anchorLen = 0;
            ubyte           isValid = 0;
            ubyte           certOcspStatus = 0;

            ASN1_ITEMPTR    pRoot = 0;
            ASN1_ITEMPTR    pIssuer, pSerialNumber;
            CStream         cs;
            MemFile         mf;
            ubyte*          cert;
            void*           pIterator;
            const ubyte*    dn;
            ubyte*          pIssuerCert;
            ubyte4          issuerCertLen;

            if (OK > (status = CERTCHAIN_numberOfCertificates(pNewCertChain, &numCertificates)))
                goto exit;

            if (numCertificates <= 0)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte **)&pAnchor, &anchorLen)))
            {
                goto exit;
            }

            /* If certChain has more than one certificate, then the 0 is leaf certificate and 1 is the issuer */
            if(numCertificates > 1)
            {
                if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 1, (const ubyte **)&pIssuerCert, &issuerCertLen)))
                {
                    goto exit;
                }
            }
            else if (numCertificates == 1)
            {
                cert = pAnchor;
    
                MF_attach(&mf,anchorLen, cert);
    
                CS_AttachMemFile(&cs, &mf);
    
                if (OK > ( status = ASN1_Parse(cs, &pRoot)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                     &pIssuer,
                                                                     &pSerialNumber)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }
    
                dn = CS_memaccess(cs,pIssuer->dataOffset, pIssuer->length);
    
                if (OK > (status = (CERT_STORE_findTrustPointBySubjectFirst(pContextSSH->pCertStore,
                                                                            dn, pIssuer->length,
                                                                            (const ubyte **)&pIssuerCert,
                                                                            &issuerCertLen, (const void **)&pIterator))))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }
    
                if (pAnchor == NULL)
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                    goto exit;
                }
            }

            status = SSH_OCSP_validateOcspResponse(pAnchor, anchorLen, pIssuerCert, issuerCertLen,
                                                   pOcsp, respLen, &certOcspStatus, &isValid);
    
            if (status == OK)
            {
                if (!isValid)
                    status = ERR_OCSP;
                else if (1 == certOcspStatus)
                    status = ERR_CERT_REVOKED;
                else if (2 == certOcspStatus)
                    status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS;
            }
            cert_status = status ;
            TREE_DeleteTreeItem((TreeItem*)pRoot);
            pRoot = NULL;
        }
    }
#endif

    if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte** )&pLeafCert, &leafCertLen)))
        goto exit;


    /* call application api to validate the certificate status */
    if (NULL != SSHC_sshClientSettings()->funcPtrCertStatus)
    {
        if(OK > (status = (SSHC_sshClientSettings()->funcPtrCertStatus)
                        (CONNECTION_INSTANCE(pContextSSH),
                         cert_status,
                         pLeafCert, leafCertLen, pNewCertChain, 
                        vc.anchorCert, vc.anchorCertLen)))
        {
            goto exit ;
        }
    }
    else 
    {
        if(OK > cert_status )
        {
            status = cert_status ;
            goto exit ;
        }
    }

    if (OK > (status = CERTCHAIN_getKey(MOC_RSA(pContextSSH->hwAccelCookie) pNewCertChain, 0, pPublicKey)))
    {
        goto exit;
    }

        /* if ECDSA, verify the public key is of sufficient size (FREAK) */
    if (akt_ecc != pPublicKey->type)
    {
        /* bad key type */
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }
exit:
    CERTCHAIN_delete(&pNewCertChain);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_parseCertRSA(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertMessage, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    certChainPtr        pNewCertChain = NULL;
    ValidationConfig    vc = {0};
    ubyte2              keyUsage = ( 1 << digitalSignature);    /*!!!! need double check this... */
    const ubyte*        pCertParse;
    ubyte4              certParseLen;
    ubyte4              bufIndex;
    sbyte4              result;
    MSTATUS             status = OK;
    MSTATUS             cert_status = OK;
#ifdef __ENABLE_MOCANA_OCSP_CLIENT__
    ubyte*              pOcsp = NULL;
    ubyte4              numResponses;
    ubyte4              respLen;
    ubyte4              numCertificates;
#endif
    ubyte*              pLeafCert;
    ubyte4              leafCertLen;
    ubyte4              length;
    /*          
        string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" / "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]"
        uint32  certificate-count
        string  certificate[1..certificate-count]
        uint32  ocsp-response-count
        string  ocsp-response[0..ocsp-response-count]
    */

    if (NULL == pCertMessage)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContextSSH->pCertStore)
    {
        /* config error. unable to validate cert chain without a store */
        status = ERR_SSH_NO_CERT_STORE_FOUND;
        goto exit;
    }

    /* skips past the string length for cert string, which was already extracted (in pCertMessage) */
    bufIndex = 4;

    pCertParse = pCertMessage->pString;
    certParseLen = pCertMessage->stringLen;

    /* Make sure the type is present and "x509v3-rsa-sha1" */
    if (pContextSSH->pHostKeySuites->hashLen > 20)
    {
        if (OK > (status = MOC_MEMCMP(bufIndex + pCertParse, sshc_rsa2048_cert_sign_signature.pString, sshc_rsa2048_cert_sign_signature.stringLen, &result)))
            goto exit;
    
        bufIndex += sshc_rsa2048_cert_sign_signature.stringLen;
    }
    else
    {
        if (OK > (status = MOC_MEMCMP(bufIndex + pCertParse, sshc_cert_sign_signature.pString, sshc_cert_sign_signature.stringLen, &result)))
            goto exit;
    
        bufIndex += sshc_cert_sign_signature.stringLen;
    }

    if (0 != result)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }


    if (OK > (status = CERTCHAIN_createFromSSHEx(MOC_ASYM(pContextSSH->hwAccelCookie) &pNewCertChain, pCertParse, certParseLen, &bufIndex, &SSH_STR_walkStringInPayload)))
        goto exit;

        /* key usage: flags depend on the key exchange.*/
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
        if (&rsaMethods == pContextSSH->pKeyExSuiteInfo->pKeyExMethods)
        {
            keyUsage |= (1 << keyEncipherment);
        }
#endif

        /* the other ciphers are ephemeral so certificate keys
         are not used for the key exchange proper */

        vc.keyUsage = keyUsage;                   /* verify key usage */
        vc.pCertStore = pContextSSH->pCertStore;  /* verify Trust Point */
        vc.commonName = pContextSSH->pCommonName;

        cert_status = CERTCHAIN_validate(MOC_ASYM(pContextSSH->hwAccelCookie) pNewCertChain, &vc) ;

    /*!!!! we will ignore OCSP for now */
#ifdef __ENABLE_MOCANA_OCSP_CLIENT__

    if(OK == cert_status) 
    {
        pOcsp = (ubyte *)(pCertParse + bufIndex);
        numResponses  = ((ubyte4)pOcsp[3]);
        numResponses |= ((ubyte4)pOcsp[2]) << 8;
        numResponses |= ((ubyte4)pOcsp[1]) << 16;
        numResponses |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        respLen  = ((ubyte4)pOcsp[3]);
        respLen |= ((ubyte4)pOcsp[2]) << 8;
        respLen |= ((ubyte4)pOcsp[1]) << 16;
        respLen |= ((ubyte4)pOcsp[0]) << 24;
        pOcsp += 4;

        DB_PRINT("numResponses = %d, respLen =%d\n", numResponses,respLen);

        if (numResponses)
        {
            ubyte*          pAnchor = NULL;
            ubyte4          anchorLen = 0;
            ubyte           isValid = 0;
            ubyte           certOcspStatus = 0;

            ASN1_ITEMPTR    pRoot = 0;
            ASN1_ITEMPTR    pIssuer, pSerialNumber;
            CStream         cs;
            MemFile         mf;
            ubyte*          cert;
            void*           pIterator;
            const ubyte*    dn;
            ubyte*          pIssuerCert;
            ubyte4          issuerCertLen;

            if (OK > (status = CERTCHAIN_numberOfCertificates(pNewCertChain, &numCertificates)))
                goto exit;

            if (numCertificates <= 0)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, numCertificates-1, (const ubyte **)&pAnchor, &anchorLen)))
            {   
                goto exit;
            }

            /* If certChain has more than one certificate, then the 0 is leaf certificate and 1 is the issuer */
            if (numCertificates > 1)
            {
                if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 1, (const ubyte **)&pIssuerCert, &issuerCertLen)))
                {
                    goto exit;
                }
            }
            else if (numCertificates == 1)
            {
                cert = pAnchor;

                MF_attach(&mf,anchorLen, cert);

                CS_AttachMemFile(&cs, &mf);

                if (OK > ( status = ASN1_Parse(cs, &pRoot)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                 &pIssuer,
                                                                 &pSerialNumber)))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                dn = CS_memaccess(cs,pIssuer->dataOffset, pIssuer->length );

                if (OK > (status = (CERT_STORE_findTrustPointBySubjectFirst(pContextSSH->pCertStore,
                                                                        dn, pIssuer->length,
                                                                        (const ubyte **)&pIssuerCert,
                                                                        &issuerCertLen,
                                                                        (const void **)&pIterator))))
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    goto exit;
                }

                if (pAnchor == NULL)
                {
                    TREE_DeleteTreeItem((TreeItem*)pRoot);
                    pRoot = NULL;
                    status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                    goto exit;
                }
            }

            status = SSH_OCSP_validateOcspResponse(pAnchor, anchorLen, pIssuerCert, issuerCertLen,
                                               pOcsp, respLen, &certOcspStatus, &isValid);

            if (status == OK)
            {
                if (!isValid)
                    status = ERR_OCSP;
                else if (1 == certOcspStatus)
                    status = ERR_CERT_REVOKED;
                else if (2 == certOcspStatus)
                    status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS;
            }
            cert_status = status;
            TREE_DeleteTreeItem((TreeItem*)pRoot);
            pRoot = NULL;
        }
    }
#endif

    if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte** )&pLeafCert, &leafCertLen)))
        goto exit;

    
    /* call application api to validate the certificate status */
    if (NULL != SSHC_sshClientSettings()->funcPtrCertStatus)
    {
        if(OK > (status = (SSHC_sshClientSettings()->funcPtrCertStatus)
                        (CONNECTION_INSTANCE(pContextSSH),
                         cert_status,
                         pLeafCert, leafCertLen, pNewCertChain, 
                        vc.anchorCert, vc.anchorCertLen)))
        {
            goto exit;
        }
    }
    else 
    {
        if(OK > cert_status )
        {
            status = cert_status;
            goto exit;
        }
    }

    if (OK > (status = CERTCHAIN_getKey(MOC_RSA(pContextSSH->hwAccelCookie) pNewCertChain, 0, pPublicKey)))
    {
        goto exit;
    }

    /* if RSA, verify the public key is of sufficient size (FREAK) */
    if (akt_rsa != pPublicKey->type)
    {
        /* bad key type */
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }


#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(pContextSSH->hwAccelCookie) pPublicKey->key.pRSA, (sbyte4 *) &length);
    if (OK != status)
        goto exit;
#else
    status = RSA_getCipherTextLength(MOC_RSA(pContextSSH->hwAccelCookie) pPublicKey->key.pRSA, (sbyte4 *) &length);
    if (OK != status)
        goto exit;
#endif
    /* length given in bytes, MIN_SSH_RSA_SIZE counts in bits */
    length *= 8;
    if ((MIN_SSH_RSA_SIZE - 1) > length)
    {
        status = ERR_SSH_RSA_KEY_SIZE;
        goto exit;
    }
exit:
    CERTCHAIN_delete(&pNewCertChain);

    return status;
}
#endif /* __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__ */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_parseCert(sshClientContext *pContextSSH,
                     sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey,
                     sshStringBuffer *pExpectedKeyFormat,
                     MSTATUS(*extractCertificate)(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pCertificate, AsymmetricKey* pPublicKey, ubyte4 index, vlong **ppVlongQueue),
                     vlong **ppVlongQueue)
{
    /* RFC 4253 legacy naked keys */
    ubyte4              index = 4;
    sbyte4              result = -1;
    sshStringBuffer*    pKeyFormat = NULL;
    MSTATUS             status;

    if (NULL == extractCertificate)
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

    /* compare received pubkey w/ cached pubkey */
    if (OK > (status = SSH_STR_copyStringFromPayload(pCertificate->pString,
                                                     pCertificate->stringLen,
                                                     &index, &pKeyFormat)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pKeyFormat);
    DEBUG_RELABEL_MEMORY(pKeyFormat->pString);

    /* Skip the length 4 bytes */
    if (NULL != pExpectedKeyFormat)
    {
        if (OK > (status = MOC_MEMCMP(pKeyFormat->pString+4, pExpectedKeyFormat->pString+4, pExpectedKeyFormat->stringLen-4, &result)))
            goto exit;
    }

    if (0 != result)
    { /* Handling for OpenSSH - Incase the Signature Name and Host Key Name does not match */
      /* Skip the length 4 bytes */
      if (OK > (status = MOC_MEMCMP((const ubyte*)pKeyFormat->pString+4, (const ubyte*)pContextSSH->pHostKeySuites->pSignatureName,pContextSSH->pHostKeySuites->signatureNameLength, &result)))
        goto exit;
    }

    if (0 != result)
    {
        status = ERR_SSH_MALFORMED_CERTIFICATE;
        goto exit;
    }

    status = extractCertificate(MOC_ASYM(pContextSSH->hwAccelCookie) pCertificate, pPublicKey, index, ppVlongQueue);

exit:
    SSH_STR_freeStringBuffer(&pKeyFormat);

    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
static MSTATUS
SSHC_TRANS_parseRawDsaCert(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    MSTATUS             status;

    if (OK > (status = CRYPTO_createDSAKey(pPublicKey, ppVlongQueue)))
        goto exit;

    status = SSHC_TRANS_parseCert(pContextSSH, (sshStringBuffer *)pCertificate, pPublicKey,
                                  &sshc_dss_signature, SSH_DSS_extractDssCertificate, ppVlongQueue);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
static MSTATUS
SSHC_TRANS_parseRawRsaCert(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    MSTATUS             status;

    if (OK > (status = CRYPTO_createRSAKey(pPublicKey, ppVlongQueue)))
        goto exit;

    if (pContextSSH->pHostKeySuites->hashLen > 20)
    {
        status = SSHC_TRANS_parseCert(pContextSSH, (sshStringBuffer *)pCertificate,
                                      pPublicKey, &sshc_rsa2048sha256_signature,
                                      SSH_RSA_extractRsaCertificate, ppVlongQueue);
    }
    else
    {
        status = SSHC_TRANS_parseCert(pContextSSH, (sshStringBuffer *)pCertificate, pPublicKey,
                                      &sshc_rsa_signature, SSH_RSA_extractRsaCertificate, ppVlongQueue);
    }

exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__) && defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSHC_TRANS_parseRawHybridKeyBlob(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    return SSHC_TRANS_parseCert(pContextSSH, (sshStringBuffer *)pCertificate, pPublicKey,
                                NULL, SSH_HYBRID_extractHybridKey, ppVlongQueue);
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PQC__
static MSTATUS
SSHC_TRANS_parseRawQsKeyBlob(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    return SSHC_TRANS_parseCert(pContextSSH, (sshStringBuffer *)pCertificate, pPublicKey,
                                NULL, SSH_QS_extractQsKey, ppVlongQueue);
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS
SSHC_TRANS_parseRawEcdsaCert(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
     return SSHC_TRANS_parseCert(pContextSSH, (sshStringBuffer *)pCertificate, pPublicKey,
                                 &sshc_ecdsa_signature,
                                 SSH_ECDSA_extractEcdsaCertificate, ppVlongQueue);
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
static MSTATUS
SSHC_TRANS_verifyDsaSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature,
                              ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    ubyte*  pShaOutput = NULL;
    vlong*  pH = NULL;
    MSTATUS status;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pShaOutput))))
        goto exit;

    /* compute H hash */
    if (OK > (status = SSHC_TRANS_computeClientPubKeyHash(pContextSSH, pDigestData, digestLen, pShaOutput, &pH, ppVlongQueue)))
        goto exit;

    status = SSH_DSS_verifyDssSignature(MOC_DSA(pContextSSH->hwAccelCookie) pPublicKey, FALSE, pH, pSignature, pIsGoodSignature, ppVlongQueue);

exit:
    VLONG_freeVlong(&pH, ppVlongQueue);
    if (NULL != pShaOutput)
        MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pShaOutput));

    return status;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_MOCANA_ECC__) && defined(__ENABLE_MOCANA_PQC__)
static MSTATUS
SSHC_TRANS_verifyHybridSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature,
                                ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    if (NULL == pPublicKey)
        return ERR_NULL_POINTER;

    return SSH_HYBRID_verifyHybridSignature(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKey, FALSE, pDigestData, digestLen, pSignature, pIsGoodSignature, ppVlongQueue);
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PQC__
static MSTATUS
SSHC_TRANS_verifyQsSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature,
                             ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    if (NULL == pPublicKey)
        return ERR_NULL_POINTER;

    return SSH_QS_verifyQsSignature(MOC_HASH(pContextSSH->hwAccelCookie) pPublicKey, FALSE, pDigestData, digestLen, pSignature, pIsGoodSignature, ppVlongQueue);
}
#endif /* __ENABLE_MOCANA_PQC__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS
SSHC_TRANS_verifyEcdsaSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature,
                                ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status;
    ubyte*  pShaOutput = NULL;
    ubyte4 hashAlgo = 0;

    if (NULL == pPublicKey)
    {
        return ERR_NULL_POINTER;
    }

    if (akt_ecc_ed == pPublicKey->type)
    {
        switch (pContextSSH->pHostKeySuites->hashLen)
        {
#ifndef __DISABLE_MOCANA_SHA256__
            case SHA256_RESULT_SIZE :
                hashAlgo = ht_sha256;
                break;
#endif
#ifndef __DISABLE_MOCANA_SHA384__
            case SHA384_RESULT_SIZE :
                hashAlgo = ht_sha384;
                break;
#endif
#ifndef __DISABLE_MOCANA_SHA512__
            case SHA512_RESULT_SIZE :
                hashAlgo = ht_sha512;
                break;
#endif
            case SHA1_RESULT_SIZE :
                hashAlgo = ht_sha1;
                break;
            default :
                break;
        }

        status = SSH_ECDSA_verifyEdDSASignature(MOC_ECC(pContextSSH->hwAccelCookie) pPublicKey, hashAlgo, pDigestData, digestLen, pSignature, pIsGoodSignature, ppVlongQueue);
    }
    else
    {
        if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->mediumPool, (void **)&(pShaOutput))))
            goto exit;

        /* compute H hash */
        if (OK > (status = SSHC_TRANS_computeClientPubKeyHash(pContextSSH, pDigestData, digestLen, pShaOutput, NULL, ppVlongQueue)))
            goto exit;

        status = SSH_ECDSA_verifyEcdsaSignature(MOC_ECC(pContextSSH->hwAccelCookie) pPublicKey, FALSE, pShaOutput, pContextSSH->pHostKeySuites->hashLen, pSignature, pIsGoodSignature, ppVlongQueue);
    }

exit:

    if (NULL != pShaOutput)
        MEM_POOL_putPoolObject(&pContextSSH->mediumPool, (void **)(&pShaOutput));

    return status;
}
#endif

/*------------------------------------------------------------------*/ 
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
static MSTATUS
SSHC_TRANS_verifyRsaSignature(struct sshClientContext *pContextSSH, AsymmetricKey *pPublicKey, sshStringBuffer *pSignature,
                              ubyte *pDigestData, ubyte4 digestLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    ubyte*          pShaOutput = NULL;
    MSTATUS         status;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pShaOutput))))
        goto exit;

    /* compute H hash */
    if (OK > (status = SSHC_TRANS_computeClientPubKeyHash(pContextSSH, pDigestData, digestLen, pShaOutput, NULL, ppVlongQueue)))
        goto exit;

    status = SSH_RSA_verifyRsaSignature(MOC_RSA(pContextSSH->hwAccelCookie) pPublicKey, FALSE,
                                        pShaOutput, pContextSSH->pHostKeySuites->hashLen,
                                        pSignature, pIsGoodSignature,
                                        ppVlongQueue);

exit:
    if (NULL != pShaOutput)
    {
        MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pShaOutput));
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

static MSTATUS
receiveServerKeyExchange(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pCertificate = NULL;
    sshStringBuffer*    pSignature = NULL;
    ubyte4              bytesUsed;
    AsymmetricKey       publicKey;
    intBoolean          isGoodSignature;
    vlong*              pVlongQueue = NULL;
    MSTATUS             status;
    ubyte*              pCertClone = NULL;
    ubyte4              serverPubKeyLen = 0, offset;
    ubyte*              pSharedSecret = NULL, *pServerPubKey = NULL;
    sbyte4              sharedSecretLen;
    sshcKeyExDescr*     pKeyEx = NULL;
    MDhKeyTemplate      template = {0};

    if (OK > (status = CRYPTO_initAsymmetricKey(&publicKey)))   /* always initialize the key first */
        return status;

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pHostKeySuites))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((SSH_MSG_KEXDH_REPLY != (*pNewMesg)) || (0 == newMesgLen))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if ((NULL == pContextSSH->pHostKeySuites->pFuncParseCert) || (NULL == pContextSSH->pHostKeySuites->pFuncVerifySig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }

    pNewMesg++;  /* move past message type */
    newMesgLen--;
    bytesUsed = 0;

    /* extract server's host key (K_S) */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &pCertificate)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pCertificate);

    /* clone the certificate into crypto memory space */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, bytesUsed, TRUE, &pCertClone)))
        goto exit;

    MOC_MEMCPY(pCertClone, pNewMesg, bytesUsed);

    /* add K_S to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pCertClone, bytesUsed)))
        goto exit;
    DUMP("update:", pCertClone, bytesUsed);

    pNewMesg += bytesUsed;
    newMesgLen -= bytesUsed;

    if (OK > (status = SSH_getByteStringFromMpintBytes(pNewMesg, newMesgLen, &pServerPubKey, &serverPubKeyLen)))
    {
        goto exit;
    }
    /* length header bytes + key length */
    bytesUsed = 4 + serverPubKeyLen;

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_E(SSH_DH_CTX(pContextSSH)));

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DH_CTX(pContextSSH), MOC_GET_PUBLIC_KEY_DATA, NULL)))
    {
        goto exit;
    }
#else
    if (OK > (status = DH_getKeyParametersAllocExt(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DH_CTX(pContextSSH), MOC_GET_PUBLIC_KEY_DATA, NULL)))
    {
        goto exit;
    }
#endif

    /* add e to hash, (DH context it is F) */
    if (OK > (status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, template.pF, template.fLen)))
    {
        goto exit;
    }

    /* add f to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg, bytesUsed)))
        goto exit;
    DUMP("update:", pNewMesg, bytesUsed);

    pNewMesg += bytesUsed;
    newMesgLen -= bytesUsed;

    /* signature of H */
    bytesUsed = 0;
    if (0 > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &pSignature)))
        goto exit;

    if (bytesUsed != newMesgLen)
    {
        status = ERR_SSH_MALFORMED_SERVER_KEXDH_REPLY_MESG;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pSignature);

#if 1
/*!!!!! this needs to be changed for RFC 6187 */
    /* SSHC_TRANS_parseRawDsaCert, SSHC_TRANS_parseRawRsaCert */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncParseCert((struct sshClientContext *)pContextSSH, pCertificate, &publicKey, &pVlongQueue)))
        goto exit;

#endif

    offset = 0;
    while ((offset < serverPubKeyLen) && (0x00 == pServerPubKey[offset])) offset++;
    /* Compute K (Shared Secret). */
    /*!!!! we need to switch to DH_computeKeyExchange */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(pContextSSH->hwAccelCookie) SSH_DH_CTX(pContextSSH), NULL, pServerPubKey + offset, serverPubKeyLen - offset, &pSharedSecret,
        (ubyte4 *) &sharedSecretLen, NULL)))
    {
        goto exit;
    }
#else
    if (OK > (status = DH_computeKeyExchangeExExt(MOC_DH(pContextSSH->hwAccelCookie) SSH_DH_CTX(pContextSSH), NULL, pServerPubKey, serverPubKeyLen, &pSharedSecret,
        (ubyte4 *) &sharedSecretLen, NULL)))
    {
        goto exit;
    }
#endif

    DEBUG_RELABEL_MEMORY(COMPUTED_VLONG_K(SSH_DH_CTX(pContextSSH)));
    /* add K to hash */
    if (OK > (status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pSharedSecret, sharedSecretLen)))
    {
        goto exit;
    }

    offset = 0;
    while (((sbyte4) offset < sharedSecretLen) && (0x00 == pSharedSecret[offset])) offset++;

    pKeyEx->bytesSharedSecretLen = sharedSecretLen - offset;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pKeyEx->pBytesSharedSecret, pSharedSecret + offset, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    /* compute hash H */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;

    DUMP("final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &(SSH_SESSION_ID(pContextSSH)))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &pCertClone );

    /* SSHC_TRANS_verifyDsaSignature, SSHC_TRANS_verifyRsaSignature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncVerifySig((struct sshClientContext *)pContextSSH, &publicKey, pSignature, SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, &isGoodSignature, &pVlongQueue)))
        goto exit;

    if (!isGoodSignature)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

#if 1
/*!!!!! this needs to be changed for RFC 6187 */
    /* do not call funcPtrServerPubKeyAuth for x509v3 identity types */
    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != pContextSSH->pHostKeySuites->identityType)
    {
        if (NULL != SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)
        {
            sbyte4 isAuth;

            isAuth = (SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)(pContextSSH->connectionInstance,
                                                                         pCertificate->pString + 4, pCertificate->stringLen - 4);
            isGoodSignature = (TRUE == isAuth);
        }
    }
    else
    {
        /*!!!! look up certificate */
    }
#endif

    if (!isGoodSignature)
        status = ERR_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;

exit:
    if ((OK != status) && (NULL != pKeyEx) && (NULL != pKeyEx->pBytesSharedSecret))
        MOC_MEMSET_FREE(&pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);

    if (pContextSSH && (NULL != pContextSSH->sshKeyExCtx.pKeyExHash))
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

    if (NULL != pCertificate)
        SSH_STR_freeStringBuffer(&pCertificate);

    if (NULL != pSignature)
        SSH_STR_freeStringBuffer(&pSignature);

    if (NULL != pServerPubKey)
        MOC_FREE((void**)&pServerPubKey);

    if (NULL != pSharedSecret)
    {
        MOC_MEMSET(pSharedSecret, 0x00, sharedSecretLen);
        MOC_FREE((void**)&pSharedSecret);
    }

    if (pContextSSH && (NULL != pCertClone))
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &pCertClone);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(NULL, &template, NULL);
#else
    DH_freeKeyTemplateExt(NULL, &template, NULL);
#endif

    CRYPTO_uninitAsymmetricKey(&publicKey, 0);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* receiveServerKeyExchange */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
SSHC_TRANS_sendServerDHGRequest(struct sshClientContext *pContextSSH)
{
    ubyte*      pGexRequest   = NULL;
    ubyte4      bytesWritten;
    MSTATUS     status;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pGexRequest))))
        goto exit;

    /* form SSH_MSG_KEY_DH_GEX_REQUEST message */
    *pGexRequest = SSH_MSG_KEY_DH_GEX_REQUEST;

    MOC_MEMCPY(1 + pGexRequest, m_gexRequest, sizeof(m_gexRequest));

    /* send it out */
    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pGexRequest, 1 + sizeof(m_gexRequest), &bytesWritten)))
        goto exit;

exit:
    MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pGexRequest));

    return status;

} /* SSHC_TRANS_sendServerDHGRequest */

#endif /* (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
receiveServerDHGKeyExchange(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte4  bytesUsed;
    MSTATUS status;
    MDhKeyTemplate template = {0};
    diffieHellmanContext *pCtx = NULL;
    ubyte4 privKeyLen;
    intBoolean isValid = FALSE;

    MOC_MEMSET((void*)&template, 0x00, sizeof(MDhKeyTemplate));
    if ((SSH_MSG_KEX_DH_GEX_GROUP != (*pNewMesg)) || ((1 + 4 + 128 + 4 + 2) > newMesgLen))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    pNewMesg++;
    newMesgLen--;

    /* create shell for DH context */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_allocate(&pCtx);
#else
    status = DH_allocate(&pCtx);
#endif
    if (OK != status)
        goto exit;

    /* get prime P from mpint buffer */
    status = SSH_getByteStringFromMpintBytes(pNewMesg, newMesgLen, &(template.pP), &(template.pLen));
    if (OK != status)
        goto exit;

    /* check that P is not too large, account for a leading 0x00 byte */
    if (template.pLen > MAX_SSH_DH_SIZE/8 + 1)
    {
        status = ERR_SSH_DH_KEY_SIZE;
        goto exit;        
    }

    pNewMesg += template.pLen + 4;
    newMesgLen -= template.pLen - 4;

    /* get generator G from mpint buffer */
    status = SSH_getByteStringFromMpintBytes(pNewMesg, newMesgLen, &(template.pG), &(template.gLen));
    if (OK != status)
        goto exit;

    /* sanity check that G is not too large */
    if (template.gLen > template.pLen)
    {
        status = ERR_SSH_DH_KEY_SIZE;
        goto exit;        
    }

    /* set P and G for context */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_setKeyParameters(MOC_DH(pContextSSH->hwAccelCookie) pCtx, &template);
    if (OK != status)
        goto exit;
#else
    status = DH_setKeyParameters(MOC_DH(pContextSSH->hwAccelCookie) pCtx, &template);
    if (OK != status)
        goto exit;
#endif

    /* validate domain parameters */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_verifySafePG(pCtx, &isValid, &privKeyLen, NULL);
#else
    status = DH_verifySafePG(pCtx, &isValid, &privKeyLen, NULL);
#endif
    if (OK != status)
        goto exit;

    if (FALSE == isValid)
    {
#if (defined(__ENABLE_MOCANA_FIPS_MODULE__) && defined(__ENABLE_MOCANA_STRICT_DH_GROUP__))
        status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
        goto exit;
#else
        privKeyLen = SSH_DH_PRIV_LEN;
#endif
    }

    /* pick a private value, and compute the corresponding public key */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_generateKeyPair(MOC_DH(pContextSSH->hwAccelCookie) pCtx, g_pRandomContext, privKeyLen);
    if (OK != status)
        goto exit;
#else
    status = DH_generateKeyPair(MOC_DH(pContextSSH->hwAccelCookie) pCtx, g_pRandomContext, privKeyLen);
    if (OK != status)
        goto exit;
#endif

    pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx(pContextSSH);
    SSH_DH_CTX(pContextSSH) = pCtx;
    pCtx = NULL;
exit:

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplate(SSH_DH_CTX(pContextSSH), &template);
#else
    DH_freeKeyTemplate(SSH_DH_CTX(pContextSSH), &template);
#endif

    MOC_FREE((void **)&pCtx);
    return status;

} /* receiveServerDHGKeyExchange */

#endif /* (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
sendServerDHGInit(sshClientContext *pContextSSH)
{
    ubyte*      pStringMpintE = NULL;
    ubyte4      stringLenE;
    ubyte*      pMesg         = NULL;
    ubyte4      mesgLen;
    ubyte4      bytesWritten;
    vlong*      pVlongQueue   = NULL;
    MSTATUS     status;
    ubyte*      pPubKey       = NULL;
    ubyte4      pubKeyLen;

    /* context is already generated with public and private key for client. 
        get the public key from DH context and send it to the SERVER */
    /* make MPINT string from e */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_getPublicKey(MOC_DH(pContextSSH->hwAccelCookie) SSH_DH_CTX(pContextSSH), &pPubKey, &pubKeyLen);
#else
    status = DH_getPublicKey(MOC_DH(pContextSSH->hwAccelCookie) SSH_DH_CTX(pContextSSH), &pPubKey, &pubKeyLen);
#endif
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(pPubKey, pubKeyLen, 0, &pStringMpintE, (sbyte4*)&stringLenE);
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(pStringMpintE);
    /* Send SSH_MSG_KEX_DH_GEX_INIT message */
    mesgLen = 1 + stringLenE;

    if (NULL == (pMesg = MALLOC(mesgLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set message type */
    pMesg[0] = SSH_MSG_KEX_DH_GEX_INIT;

    /* copy E mpint string */
    if (OK > (status = MOC_MEMCPY(pMesg + 1, pStringMpintE, stringLenE)))
        goto exit;

    /* send it out */
    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pMesg, mesgLen, &bytesWritten)))
        goto exit;

exit:
    if (NULL != pMesg)
        FREE(pMesg);

    if (NULL != pStringMpintE)
        FREE(pStringMpintE);

    if (NULL != pPubKey)
        FREE(pPubKey);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* sendServerDHGInit */

#endif /* (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
receiveServerDHGKeyExchangeReply(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pCertificate = NULL;
    sshStringBuffer*    pSignature = NULL;
    ubyte4              bytesUsed;
    AsymmetricKey       publicKey;
    intBoolean          isGoodSignature;
    vlong*              pVlongQueue = NULL;
    ubyte*              pCertClone = NULL;
    ubyte*              pMinPrefMax = NULL;
    MSTATUS             status;
    MDhKeyTemplate      template = {0};
    ubyte*              pServerKey = NULL;
    ubyte4              serverKeyLen = 0, i = 0, offset = 0;
    ubyte*              pSharedSecret = NULL;
    ubyte4              sharedSecretLen = 0;
    sshcKeyExDescr*          pKeyEx = NULL;

    if (OK > (status = CRYPTO_initAsymmetricKey(&publicKey)))   /* always initialize the key first */
        return status;

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pHostKeySuites))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if ((SSH_MSG_KEX_DH_GEX_REPLY != (*pNewMesg)) || (0 == newMesgLen))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if ((NULL == pContextSSH->pHostKeySuites->pFuncParseCert) || (NULL == pContextSSH->pHostKeySuites->pFuncVerifySig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }

    pNewMesg++;  /* move past message type */
    newMesgLen--;
    bytesUsed = 0;

    /* extract server's host key (K_S) */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &pCertificate)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pCertificate);

    /* clone the certificate into crypto memory space */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, bytesUsed, TRUE, &pCertClone)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pCertClone);

    MOC_MEMCPY(pCertClone, pNewMesg, bytesUsed);

    /* add K_S to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pCertClone, bytesUsed)))
        goto exit;
    DUMP("update:", pCertClone, bytesUsed);

    pNewMesg += bytesUsed;
    newMesgLen -= bytesUsed;

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(pMinPrefMax))))
        goto exit;

    MOC_MEMCPY(pMinPrefMax, m_gexRequest, sizeof(m_gexRequest));

    /* add min, n, max to hash */
    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, (ubyte *)pMinPrefMax, sizeof(m_gexRequest));
    DUMP("update:", pMinPrefMax, sizeof(m_gexRequest));

    MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pMinPrefMax));

    if (OK > status)
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_getKeyParametersAlloc(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DH_CTX(pContextSSH), MOC_GET_PUBLIC_KEY_DATA);
#else
    status = DH_getKeyParametersAlloc(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DH_CTX(pContextSSH), MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, template.pP, template.pLen);
    if (OK != status)
        goto exit;
     
    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, template.pG, template.gLen);
    if (OK != status)
        goto exit;

    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, template.pF, template.fLen);
    if (OK != status)
        goto exit;

    status = SSH_getByteStringFromMpintBytes(pNewMesg, newMesgLen, &pServerKey, &serverKeyLen);
    if (OK != status)
        goto exit;

    bytesUsed = serverKeyLen + 4;
    if(pServerKey)
    {
	while ((offset < serverKeyLen) && (0x00 == pServerKey[offset])) offset++;
    }

    /* add f to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg, bytesUsed)))
        goto exit;
    DUMP("update:", pNewMesg, bytesUsed);

    pNewMesg += bytesUsed;
    newMesgLen -= bytesUsed;

    /* signature of H */
    bytesUsed = 0;
    if (0 > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &pSignature)))
        goto exit;

    if (bytesUsed != newMesgLen)
    {
        status = ERR_SSH_MALFORMED_SERVER_KEXDH_REPLY_MESG;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pSignature);

    /* SSHC_TRANS_parseRawDsaCert, SSHC_TRANS_parseRawRsaCert */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncParseCert((struct sshClientContext *)pContextSSH, pCertificate, &publicKey, &pVlongQueue)))
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_computeKeyExchangeEx(MOC_DH(pContextSSH->hwAccelCookie) SSH_DH_CTX(pContextSSH), g_pRandomContext,  pServerKey + offset, serverKeyLen - offset, &pSharedSecret, &sharedSecretLen);
    if (OK != status)
        goto exit;
#else
    status = DH_computeKeyExchangeEx(MOC_DH(pContextSSH->hwAccelCookie) SSH_DH_CTX(pContextSSH), g_pRandomContext,  pServerKey + offset, serverKeyLen - offset, &pSharedSecret, &sharedSecretLen);
    if (OK != status)
        goto exit;
#endif

    /* offset will be value of 0x00 bytes at the front of the pSharedSecret */
    offset = 0;
    while ((offset < sharedSecretLen) && (0x00 == pSharedSecret[offset])) offset++;

    pKeyEx->bytesSharedSecretLen = sharedSecretLen - offset;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pKeyEx->pBytesSharedSecret, pSharedSecret + offset, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    /* compute hash H */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;
    DUMP("final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &(SSH_SESSION_ID(pContextSSH)))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pCertClone);

    /* SSHC_TRANS_verifyDsaSignature, SSHC_TRANS_verifyRsaSignature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncVerifySig((struct sshClientContext *)pContextSSH, &publicKey, pSignature,
                                                                   SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize,
                                                                   &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }

    if (!isGoodSignature)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* do not call funcPtrServerPubKeyAuth for x509v3 identity types */
    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != pContextSSH->pHostKeySuites->identityType)
    {
        if (NULL != SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)
        {
            sbyte4 isAuth;

            isAuth = (SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)(pContextSSH->connectionInstance,
                                                                         pCertificate->pString + 4, pCertificate->stringLen - 4);
            isGoodSignature = (TRUE == isAuth);
        }
    }

    if (!isGoodSignature)
        status = ERR_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;

exit:
    if ((OK != status) && (NULL != pKeyEx) && (NULL != pKeyEx->pBytesSharedSecret))
        MOC_MEMSET_FREE(&pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);

    if(NULL != pContextSSH)
    {
        if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);
    
        if ((NULL != (pContextSSH)->pKeyExSuiteInfo) &&
            (NULL != (pContextSSH)->pKeyExSuiteInfo->pKeyExMethods) &&
            (NULL != (pContextSSH)->pKeyExSuiteInfo->pKeyExMethods->freeCtx))
        {
            /* free key exchange context (dh, rsa, ecdh, etc) */
            pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx(pContextSSH);
        }
    }

    if (NULL != pCertificate)
        SSH_STR_freeStringBuffer(&pCertificate);

    if (NULL != pSignature)
        SSH_STR_freeStringBuffer(&pSignature);

    if (NULL != pCertClone)
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &pCertClone);

    if (NULL != pServerKey)
        FREE(pServerKey);

    if (NULL != pSharedSecret)
    {
        MOC_MEMSET(pSharedSecret, 0x00, sharedSecretLen);
        MOC_FREE((void**)&pSharedSecret);
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplate(NULL, &template);
#else
    DH_freeKeyTemplate(NULL, &template);
#endif

    CRYPTO_uninitAsymmetricKey(&publicKey, 0);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* receiveServerDHGKeyExchangeReply */

#endif /* (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))

static MSTATUS
SSHC_TRANS_receiveServerKexRsaPubKey(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    K_T = NULL;
    ubyte4              bytesUsed;
    ubyte*              K_T_clone = NULL;
    ubyte*              K_S_clone = NULL;
    ubyte4              index;
    sbyte4              result;
    vlong*              pVlongQueue = NULL;
    MSTATUS             status;

    if (OK > (status = CRYPTO_createRSAKey(&pContextSSH->sshKeyExCtx.transientKey, &pVlongQueue)))  /* always initialize the key first */
        return status;

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pHostKeySuites))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((SSH_MSG_KEXRSA_PUBKEY != (*pNewMesg)) || (9 > newMesgLen))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    pNewMesg++;  /* move past message type */
    newMesgLen--;
    bytesUsed = 0;

    /* extract server's host key (K_S) */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &pContextSSH->pCertificate)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pContextSSH->pCertificate);

    /* clone the certificate into crypto memory space */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, bytesUsed, TRUE, &K_S_clone)))
        goto exit;

    DEBUG_RELABEL_MEMORY(K_S_clone);

    MOC_MEMCPY(K_S_clone, pNewMesg, bytesUsed);

    /* add K_S to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, K_S_clone, bytesUsed)))
        goto exit;
    DUMP("update:", K_S_clone, bytesUsed);

    pNewMesg += bytesUsed;
    newMesgLen -= bytesUsed;
    bytesUsed = 0;

    /* extract server's transient key (K_T) */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &K_T)))
        goto exit;

    DEBUG_RELABEL_MEMORY(K_T);

    /* handle rsa key format */
    index = 4;

    /* Signature Name is dictated by the hostKey */
    if (pContextSSH->pHostKeySuites->hashLen > 20)
    {
        if (OK > (status = MOC_MEMCMP(index + K_T->pString, sshc_rsa2048sha256_signature.pString, sshc_rsa2048sha256_signature.stringLen, &result)))
            goto exit;

        index += sshc_rsa2048sha256_signature.stringLen;
    }
    else
    {
        if (OK > (status = MOC_MEMCMP(index + K_T->pString, sshc_rsa_signature.pString, sshc_rsa_signature.stringLen, &result)))
            goto exit;

        index += sshc_rsa_signature.stringLen;
    }

    if (0 != result)
    {
        /* expected to match ssh-rsa */
        status = ERR_SSH_MALFORMED_CERTIFICATE;
        goto exit;
    }

    if (OK > (status = SSH_RSA_extractRsaCertificate(K_T, &pContextSSH->sshKeyExCtx.transientKey, index, &pVlongQueue)))
        goto exit;

    /* clone the certificate into crypto memory space */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, bytesUsed, TRUE, &K_T_clone)))
        goto exit;

    DEBUG_RELABEL_MEMORY(K_T_clone);

    MOC_MEMCPY(K_T_clone, pNewMesg, bytesUsed);

    /* add K_T to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, K_T_clone, bytesUsed)))
        goto exit;
    DUMP("update:", K_T_clone, bytesUsed);


    pNewMesg += bytesUsed;
    newMesgLen -= bytesUsed;

    if (0 != newMesgLen)
    {
        status = ERR_SSH_KEYEX_MESG_FORMAT;
        goto exit;
    }

exit:
    if (NULL != K_T_clone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &K_T_clone);

    if (NULL != K_T)
        SSH_STR_freeStringBuffer(&K_T);

    if (NULL != K_S_clone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &K_S_clone);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSHC_TRANS_receiveServerKexRsaPubKey */

#endif /* (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
SSHC_TRANS_sendKexRsaSecret(sshClientContext *pContextSSH)
{
    vlong*  pRandomValue = NULL;
    ubyte*  pSecret = NULL;
    sbyte4  secretLength;
    ubyte*  pEncryptedSecret = NULL;
    ubyte4  encryptedLen;
    ubyte*  pPayload = NULL;
    ubyte4  payloadLength;
    ubyte4  numBitsLong;
    ubyte4  numBytesWritten;
    ubyte   H_rsaAlgoId;
    MSTATUS status;

    /* RFC 4432, section 4: 0 <= K < 2^(KLEN-2*HLEN-49) */
    numBitsLong = pContextSSH->pKeyExSuiteInfo->keyExHint - (2 * (8 * pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)) - 50;

    /* RFC 4432: only two RSA-SHA methods defined */
    H_rsaAlgoId = (2048 == pContextSSH->pKeyExSuiteInfo->keyExHint) ? sha256withRSAEncryption : sha1withRSAEncryption;

    /* generate random shared secret K */
    if (OK > (status = VLONG_makeRandomVlong(g_pRandomContext, &pRandomValue, numBitsLong, NULL)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pRandomValue);

    if (OK > (status = VLONG_mpintByteStringFromVlong(pRandomValue, &pSecret, &secretLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSecret);

    if (OK > (status = PKCS1_rsaesOaepEncrypt(MOC_RSA(pContextSSH->hwAccelCookie) g_pRandomContext,
                                              pContextSSH->sshKeyExCtx.transientKey.key.pRSA, H_rsaAlgoId, PKCS1_MGF1_FUNC, pSecret,
                                              (ubyte4)secretLength, NULL, 0, &pEncryptedSecret, &encryptedLen)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pEncryptedSecret);
    payloadLength = 1 + 4 + encryptedLen;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, payloadLength, TRUE, &pPayload)))
        goto exit;

    pPayload[0] = SSH_MSG_KEXRSA_SECRET;

    pPayload[1] = (ubyte)(encryptedLen >> 24);
    pPayload[2] = (ubyte)(encryptedLen >> 16);
    pPayload[3] = (ubyte)(encryptedLen >>  8);
    pPayload[4] = (ubyte)(encryptedLen);

    MOC_MEMCPY(pPayload + 5, pEncryptedSecret, encryptedLen);

    /* add encrypted secret to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, 1 + pPayload, 4 + encryptedLen)))
        goto exit;
    DUMP("update:", 1 + pPayload, 4 + encryptedLen);

    /* add K (random shared secret) to hash */
    if (OK > (status = digestMpint(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pRandomValue)))
        goto exit;

    /* store shared secret (K) for later consumption */
    if (OK > (status = VLONG_makeVlongFromVlong(pRandomValue, &(SSH_K(pContextSSH)), NULL)))
        goto exit;

    DEBUG_RELABEL_MEMORY(SSH_K(pContextSSH));

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, payloadLength, &numBytesWritten);

exit:
    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pPayload);

    if (NULL != pEncryptedSecret)
        FREE(pEncryptedSecret);

    if (NULL != pSecret)
        FREE(pSecret);

    VLONG_freeVlong(&pRandomValue, NULL);

    return status;
}
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

#endif /* (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))

static MSTATUS
SSHC_TRANS_receiveServerKexRsaDone(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pSignature = NULL;
    ubyte4              bytesUsed;
    AsymmetricKey       publicKey;
    intBoolean          isGoodSignature;
    vlong*              pVlongQueue = NULL;
    MSTATUS             status;

    CRYPTO_initAsymmetricKey(&publicKey);

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pHostKeySuites))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (SSH_MSG_KEXRSA_DONE != *pNewMesg)
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if ((NULL == pContextSSH->pHostKeySuites->pFuncParseCert) || (NULL == pContextSSH->pHostKeySuites->pFuncVerifySig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }

    pNewMesg++;  /* move past message type */
    newMesgLen--;
    bytesUsed = 0;

    /* signature of H */
    bytesUsed = 0;
    if (0 > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &bytesUsed, &pSignature)))
        goto exit;

    if (bytesUsed != newMesgLen)
    {
        status = ERR_SSH_MALFORMED_SERVER_KEXDH_REPLY_MESG;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pSignature);

    /* compute hash H */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;
    DUMP("final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &(SSH_SESSION_ID(pContextSSH)))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    /* SSHC_TRANS_parseRawDsaCert, SSHC_TRANS_parseRawRsaCert */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncParseCert((struct sshClientContext *)pContextSSH, pContextSSH->pCertificate, &publicKey, &pVlongQueue)))
        goto exit;

    /* SSHC_TRANS_verifyDsaSignature, SSHC_TRANS_verifyRsaSignature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncVerifySig((struct sshClientContext *)pContextSSH, &publicKey, pSignature, SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, &isGoodSignature, &pVlongQueue)))
        goto exit;

    if (!isGoodSignature)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* do not call funcPtrServerPubKeyAuth for x509v3 identity types */
    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != pContextSSH->pHostKeySuites->identityType)
    {
        if (NULL != SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)
        {
            sbyte4 isAuth;

            isAuth = (SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)(pContextSSH->connectionInstance,
                                                                         pContextSSH->pCertificate->pString + 4,
                                                                         pContextSSH->pCertificate->stringLen - 4);

            isGoodSignature = (TRUE == isAuth);
        }
    }

    if (!isGoodSignature)
        status = ERR_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;

exit:
    if (NULL != pContextSSH) {
        if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

        if (NULL != pSignature)
            SSH_STR_freeStringBuffer(&pSignature);

        if (NULL != pContextSSH->pCertificate)
            SSH_STR_freeStringBuffer(&pContextSSH->pCertificate);

        CRYPTO_uninitAsymmetricKey(&publicKey, 0);
        CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, 0);
    }

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSHC_TRANS_receiveServerKexRsaDone */

#endif /* (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSHC_TRANS_sendKexHybridInit(struct sshClientContext *pContextSSH)
{
    MSTATUS status;
    ECCKey *pECCKey = NULL;
    QS_CTX *pQsCtx = NULL;
    ubyte*              pPayload = NULL;
    ubyte4              payloadLength;
    ubyte4              ephemeralEccKeyLen;
    ubyte4              ephemeralQsKeyLen;
    ubyte4              numBytesWritten;
    ubyte4              index;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pECCKey = pContextSSH->sshKeyExCtx.transientKey.key.pECC;;
    pQsCtx  = pContextSSH->sshKeyExCtx.transientKey.pQsCtx;

    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &ephemeralEccKeyLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pQsCtx, &ephemeralQsKeyLen);
    if (OK != status)
        goto exit;

    /* form SSH_MSG_KEX_HYBRID_INIT */
    payloadLength = 1 + 4 + ephemeralEccKeyLen + ephemeralQsKeyLen;

    status = MOC_MALLOC((void **) &pPayload, payloadLength);
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(pPayload);

    pPayload[0] = SSH_MSG_KEX_HYBRID_INIT;
    pPayload[1] = (((ephemeralEccKeyLen + ephemeralQsKeyLen) >> 24) & 0xff);
    pPayload[2] = (((ephemeralEccKeyLen + ephemeralQsKeyLen) >> 16) & 0xff);
    pPayload[3] = (((ephemeralEccKeyLen + ephemeralQsKeyLen) >> 8)  & 0xff);
    pPayload[4] = ( (ephemeralEccKeyLen + ephemeralQsKeyLen)        & 0xff);

    index = 5;
    /* QS public key first */
    status = CRYPTO_INTERFACE_QS_getPublicKey(pQsCtx, pPayload + index, ephemeralQsKeyLen);
    if (OK != status)
        goto exit;

    index += ephemeralQsKeyLen;
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, pPayload + index, ephemeralEccKeyLen);
    if (OK != status)
        goto exit;

    /* save C_INIT = C_PK2 || C_PK1 for later consumption, we save with the 4 byte length prefix */
    pContextSSH->sshKeyExCtx.tempBufferLen = 4 + ephemeralEccKeyLen + ephemeralQsKeyLen;
    status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->sshKeyExCtx.tempBufferLen, TRUE, &(pContextSSH->sshKeyExCtx.pTempBuffer));
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(pContextSSH->sshKeyExCtx.pTempBuffer);

    status = MOC_MEMCPY(pContextSSH->sshKeyExCtx.pTempBuffer, 1 + pPayload, pContextSSH->sshKeyExCtx.tempBufferLen);
    if (OK != status)
        goto exit;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, payloadLength, &numBytesWritten);
    
exit:
    if (NULL != pPayload)
        MOC_FREE((void **) &pPayload);

    return status;
}
#endif /* __ENABLE_MOCANA_PQC__ */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_sendKexEcdhInit(struct sshClientContext *pContextSSH)
{
    ECCKey*             pECCKey = NULL;
    ubyte*              pPayload = NULL;
    ubyte4              payloadLength;
    ubyte4              ephemeralKeyLen;
    ubyte4              numBytesWritten;
    MSTATUS             status;

    /* set short cut */
    pECCKey = pContextSSH->sshKeyExCtx.transientKey.key.pECC;;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &ephemeralKeyLen);
    if (OK != status)
        goto exit;
#else
    status = EC_getPointByteStringLenEx(pECCKey, &ephemeralKeyLen);
    if (OK != status)
        goto exit;
#endif

    /* form SSH_MSG_KEX_ECDH_INIT */
    payloadLength = 1 + 4 + ephemeralKeyLen;

    if (NULL == (pPayload = MALLOC(payloadLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pPayload);

    pPayload[0] = SSH_MSG_KEX_ECDH_INIT;
    pPayload[1] = ((ephemeralKeyLen >> 24) & 0xff);
    pPayload[2] = ((ephemeralKeyLen >> 16) & 0xff);
    pPayload[3] = ((ephemeralKeyLen >> 8)  & 0xff);
    pPayload[4] = ((ephemeralKeyLen)       & 0xff);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, pPayload + 5, ephemeralKeyLen);
    if (OK != status)
        goto exit;
#else
    status = EC_writePublicKeyToBuffer(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, pPayload + 5, ephemeralKeyLen); 
    if (OK != status)
        goto exit;
#endif

    /* save ephemeral point for later consumption */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, ephemeralKeyLen, TRUE, &pContextSSH->sshKeyExCtx.pTempBuffer)))
        goto exit;

    pContextSSH->sshKeyExCtx.tempBufferLen = ephemeralKeyLen;

    DEBUG_RELABEL_MEMORY(pContextSSH->sshKeyExCtx.pTempBuffer);

    MOC_MEMCPY(pContextSSH->sshKeyExCtx.pTempBuffer, 5 + pPayload, ephemeralKeyLen);

    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, payloadLength, &numBytesWritten)))
        goto exit;

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSHC_TRANS_receiveServerHybridReply(sshClientContext *pContextSSH,
                                  ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pCertificate = NULL;
    sshStringBuffer*    pEphemeralKey = NULL;
    ubyte4              qsCipherLen;
    sshStringBuffer*    pSignature = NULL;
    ubyte4              index;
    AsymmetricKey       publicKey = {0};
    intBoolean          isGoodSignature;
    vlong*              pVlongQueue = NULL;
    ubyte*              pCertClone = NULL;
    ubyte*              pEccSharedSecret = NULL;
    sbyte4              eccSharedSecretLen;
    ubyte*              pQsSharedSecret = NULL;
    sbyte4              qsSharedSecretLen;
    ECCKey*             pECCKey = NULL;
    ECCKey*             pECCPubKey = NULL;
    QS_CTX*             pQsCtx = NULL;
    MSTATUS             status;
    ubyte4              curveID;
    ubyte*              ptr = NULL;
    sshcKeyExDescr*     pKeyEx = NULL;
    BulkCtx             ssHashCtx = NULL;

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pHostKeySuites))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((SSH_MSG_KEX_HYBRID_REPLY != (*pNewMesg)) || (13 > newMesgLen))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if ((NULL == pContextSSH->pHostKeySuites->pFuncParseCert) || (NULL == pContextSSH->pHostKeySuites->pFuncVerifySig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }

    pECCKey = pContextSSH->sshKeyExCtx.transientKey.key.pECC;
    pQsCtx = pContextSSH->sshKeyExCtx.transientKey.pQsCtx;

    pNewMesg++;  /* move past message type */
    newMesgLen--;
    index = 0;

    /* extract server's host key (K_S) */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pCertificate)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pCertificate);

    /* add K_S to hash */
    /*!!!! clone K_S */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pCertificate->pString, pCertificate->stringLen)))
        goto exit;
    DUMP("update:", pCertificate->pString, pCertificate->stringLen);

    /* add C_INIT = C_PK2 || C_PK1 to the hash, remember it was saved in pTempBuffer */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pContextSSH->sshKeyExCtx.pTempBuffer, pContextSSH->sshKeyExCtx.tempBufferLen)))
        goto exit;
    DUMP("update:", pContextSSH->sshKeyExCtx.pTempBuffer, pContextSSH->sshKeyExCtx.tempBufferLen);
    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pContextSSH->sshKeyExCtx.pTempBuffer);

    /* extract server's ephemeral public key */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pEphemeralKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEphemeralKey);

    /* add S_REPLY = S_CT2 || S_PK1 to the hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pEphemeralKey->pString, pEphemeralKey->stringLen)))
        goto exit;
    DUMP("update:", pEphemeralKey->pString, pEphemeralKey->stringLen);

    /* signature of H */
    if (0 > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pSignature)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSignature);

    if (index != newMesgLen)
    {
        status = ERR_SSH_MALFORMED_SERVER_KEXDH_REPLY_MESG;
        goto exit;
    }

    /* SSHC_TRANS_parseRawDsaCert, SSHC_TRANS_parseRawRsaCert */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncParseCert((struct sshClientContext *)pContextSSH, pCertificate, &publicKey, &pVlongQueue)))
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pQsCtx, &qsCipherLen);  
    if (OK != status)
        goto exit;

    /* validate we have at least more than qsCipherLen */
    if (pEphemeralKey->stringLen - 4 <= qsCipherLen)
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc(pQsCtx, pEphemeralKey->pString + 4, qsCipherLen, &pQsSharedSecret, &qsSharedSecretLen);
    if (OK != status)
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveID);
    if(OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux(MOC_ECC(pContextSSH->hwAccelCookie) curveID, &pECCPubKey, pEphemeralKey->pString + 4 + qsCipherLen, pEphemeralKey->stringLen - 4 - qsCipherLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, pECCPubKey, &pEccSharedSecret, (sbyte4*)&eccSharedSecretLen, 1, NULL); 
    if (OK != status)
        goto exit;

    /* Hash the shared secrets */
    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pAllocFunc(MOC_HASH(pContextSSH->hwAccelCookie) &ssHashCtx);
    if (OK != status)
        goto exit;

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) ssHashCtx,
                                                                           pQsSharedSecret, qsSharedSecretLen);
    if (OK != status)
        goto exit;

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) ssHashCtx,
                                                                           pEccSharedSecret, eccSharedSecretLen);
    if (OK != status)
        goto exit;

    /* alloc space for the shared secret, ie the hash result */
    pKeyEx->bytesSharedSecretLen = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) ssHashCtx, pKeyEx->pBytesSharedSecret);

    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(SSH_K(pContextSSH));

    /* add combined shared secret to hash H */
    status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    /* compute hash H */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;
    DUMP("final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &(SSH_SESSION_ID(pContextSSH)))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pCertClone);

    /* SSHC_TRANS_verifyDsaSignature, SSHC_TRANS_verifyRsaSignature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncVerifySig((struct sshClientContext *)pContextSSH, &publicKey, pSignature,
                                                                   SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize,
                                                                   &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }

    if (!isGoodSignature)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* do not call funcPtrServerPubKeyAuth for x509v3 identity types */
    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != pContextSSH->pHostKeySuites->identityType)
    {
        if (NULL != SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)
        {
            sbyte4 isAuth;

            isAuth = (SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)(pContextSSH->connectionInstance,
                                                                         pCertificate->pString + 4, pCertificate->stringLen - 4);
            isGoodSignature = (TRUE == isAuth);
        }
    }

    if (!isGoodSignature)
        status = ERR_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;

exit:

    if ((NULL != pContextSSH) && (NULL != pContextSSH->sshKeyExCtx.pKeyExHash))
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

    if ((NULL != pContextSSH) && (NULL != ssHashCtx))
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &ssHashCtx);

    if (NULL != pCertificate)
        SSH_STR_freeStringBuffer(&pCertificate);

    if (NULL != pSignature)
        SSH_STR_freeStringBuffer(&pSignature);

    if (NULL != pEphemeralKey)
        SSH_STR_freeStringBuffer(&pEphemeralKey);

    if (NULL != pCertClone)
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &pCertClone);

    if (NULL != pEccSharedSecret)
    {
        MOC_MEMSET(pEccSharedSecret, 0x00, eccSharedSecretLen);
        MOC_FREE((void **) &pEccSharedSecret);
    }

    if (NULL != pQsSharedSecret)
    {
        MOC_MEMSET(pQsSharedSecret, 0x00, qsSharedSecretLen);
        MOC_FREE((void **) &pQsSharedSecret);
    }

    if (NULL != pECCPubKey)
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pECCPubKey);
#else
        EC_deleteKey(&pECCPubKey);
#endif
    }

    CRYPTO_uninitAsymmetricKey(&publicKey, 0);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}
#endif /* __ENABLE_MOCANA_PQC__ */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_TRANS_receiveServerEcdhReply(sshClientContext *pContextSSH,
                                  ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pCertificate = NULL;
    sshStringBuffer*    pEphemeralKey = NULL;
    sshStringBuffer*    pSignature = NULL;
    ubyte4              index;
    AsymmetricKey       publicKey;
    intBoolean          isGoodSignature;
    vlong*              pVlongQueue = NULL;
    ubyte*              pCertClone = NULL;
    ubyte*              sharedSecret = NULL;
    sbyte4              sharedSecretLen;
    ECCKey*             pECCKey = NULL;
    ECCKey*             pECCPubKey = NULL;
    MSTATUS             status;
    ubyte4              curveID;
    ubyte*              ptr = NULL;
    sshcKeyExDescr*     pKeyEx = NULL;
    CRYPTO_initAsymmetricKey(&publicKey);

    /* this variable is used to offset past 0x00 bytes in generated secret */
    ubyte4 offset = 0;

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pHostKeySuites))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if ((SSH_MSG_KEX_ECDH_REPLY != (*pNewMesg)) || (13 > newMesgLen))
    {
        SSHC_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if ((NULL == pContextSSH->pHostKeySuites->pFuncParseCert) || (NULL == pContextSSH->pHostKeySuites->pFuncVerifySig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }
    pECCKey = pContextSSH->sshKeyExCtx.transientKey.key.pECC;

    pNewMesg++;  /* move past message type */
    newMesgLen--;
    index = 0;

    /* extract server's host key (K_S) */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pCertificate)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pCertificate);

    /* add K_S to hash */
    /*!!!! clone K_S */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pCertificate->pString, pCertificate->stringLen)))
        goto exit;
    DUMP("update:", pCertificate->pString, pCertificate->stringLen);

    /* add ephemeral point to hash */
    if (OK > (status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pContextSSH->sshKeyExCtx.pTempBuffer, pContextSSH->sshKeyExCtx.tempBufferLen)))
        goto exit;
    DUMP("update:", pContextSSH->sshKeyExCtx.pTempBuffer, pContextSSH->sshKeyExCtx.tempBufferLen);
    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pContextSSH->sshKeyExCtx.pTempBuffer);

    /* extract server's ephemeral public key */
    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pEphemeralKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEphemeralKey);

    /* add server's ephemeral public key to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pEphemeralKey->pString, pEphemeralKey->stringLen)))
        goto exit;
    DUMP("update:", pEphemeralKey->pString, pEphemeralKey->stringLen);

    /* signature of H */
    if (0 > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pSignature)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSignature);

    if (index != newMesgLen)
    {
        status = ERR_SSH_MALFORMED_SERVER_KEXDH_REPLY_MESG;
        goto exit;
    }

    /* SSHC_TRANS_parseRawDsaCert, SSHC_TRANS_parseRawRsaCert */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncParseCert((struct sshClientContext *)pContextSSH, pCertificate, &publicKey, &pVlongQueue)))
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveID);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveID);
    if (OK != status)
        goto exit;
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux(MOC_ECC(pContextSSH->hwAccelCookie) curveID, &pECCPubKey, 4 + pEphemeralKey->pString, pEphemeralKey->stringLen - 4);
    if (OK != status)
        goto exit;
#else
    status = EC_newPublicKeyFromByteString(MOC_ECC(pContextSSH->hwAccelCookie) curveID, &pECCPubKey, 4 + pEphemeralKey->pString, pEphemeralKey->stringLen - 4);
    if (OK != status)
        goto exit;
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, pECCPubKey, &sharedSecret, (ubyte4*)&sharedSecretLen, 1, NULL); 
    if (OK != status)
        goto exit;
#else
    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(pContextSSH->hwAccelCookie) pECCKey, pECCPubKey, &sharedSecret, (ubyte4*)&sharedSecretLen, 1, NULL);
    if (OK != status)
        goto exit;
#endif

    /* offset will be value of 0x00 bytes at the front of sharedSecret */
    offset = 0;
    while (((sbyte4)offset < sharedSecretLen) && (0x00 == sharedSecret[offset])) offset++;

    DEBUG_RELABEL_MEMORY(sharedSecret);

    pKeyEx->bytesSharedSecretLen = sharedSecretLen - offset;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pKeyEx->pBytesSharedSecret, sharedSecret + offset, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(SSH_K(pContextSSH));

    /* add shared secret (K) to hash */
    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;


    /* compute hash H */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;
    DUMP("final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &(SSH_SESSION_ID(pContextSSH)))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pCertClone);

    /* SSHC_TRANS_verifyDsaSignature, SSHC_TRANS_verifyRsaSignature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncVerifySig((struct sshClientContext *)pContextSSH, &publicKey, pSignature,
                                                                   SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize,
                                                                   &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }

    if (!isGoodSignature)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* do not call funcPtrServerPubKeyAuth for x509v3 identity types */
    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != pContextSSH->pHostKeySuites->identityType)
    {
        if (NULL != SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)
        {
            sbyte4 isAuth;

            isAuth = (SSHC_sshClientSettings()->funcPtrServerPubKeyAuth)(pContextSSH->connectionInstance,
                                                                         pCertificate->pString + 4, pCertificate->stringLen - 4);
            isGoodSignature = (TRUE == isAuth);
        }
    }

    if (!isGoodSignature)
        status = ERR_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;

exit:
    if ((OK != status) && (NULL != pKeyEx) && (NULL != pKeyEx->pBytesSharedSecret))
        MOC_MEMSET_FREE(&pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);

    if ((NULL != pContextSSH) && (NULL != pContextSSH->sshKeyExCtx.pKeyExHash))
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

    if (NULL != pCertificate)
        SSH_STR_freeStringBuffer(&pCertificate);

    if (NULL != pSignature)
        SSH_STR_freeStringBuffer(&pSignature);

    if (NULL != pEphemeralKey)
        SSH_STR_freeStringBuffer(&pEphemeralKey);

    if (NULL != pCertClone)
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &pCertClone);

    if (NULL != sharedSecret)
    {
        MOC_MEMSET(sharedSecret, 0x00, sharedSecretLen);
        FREE(sharedSecret);
    }

    if (NULL != pECCPubKey)
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pECCPubKey);
#else
        EC_deleteKey(&pECCPubKey);
#endif
    }


    CRYPTO_uninitAsymmetricKey(&publicKey, 0);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}

#endif /* __ENABLE_MOCANA_ECC__ */


/*------------------------------------------------------------------*/

static MSTATUS
receiveNewKeysMessage(sshClientContext *pContextSSH, ubyte *pOptionsSelected,
                      ubyte *pNewMesg, ubyte4 newMesgLen)
{
    SSH_CipherSuiteInfo*    pCipherSuite;
    SSH_hmacSuiteInfo*      pHmacSuite;
    ubyte*                  pKeyBuffer = NULL;
    BulkCtx                 hashContext = NULL;
    MSTATUS                 status = OK;

    if ((1 != newMesgLen) || (SSH_MSG_NEWKEYS != *pNewMesg))
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pAllocFunc(MOC_HASH(pContextSSH->hwAccelCookie) &hashContext)))
        goto exit;

    DEBUG_RELABEL_MEMORY(hashContext);

     pHmacSuite = &(mHmacSuites[pOptionsSelected[SSH_ALG_INDEX_MAC_S2C] - 1]);
     if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, (4 * pHmacSuite->hmacDigestLength), TRUE, &pKeyBuffer)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pKeyBuffer);

    /* switch to the new algorithms */
    /* ---------------------------- */
    /* handle server --> client decryption */
    pCipherSuite =  &(mCipherSuites[pOptionsSelected[SSH_ALG_INDEX_ENCRYPT_S2C] - 1]);

    INBOUND_CIPHER_TYPE(pContextSSH) = pOptionsSelected[SSH_ALG_INDEX_ENCRYPT_S2C] - 1;

    DEBUG_PRINT(DEBUG_SSHC, "receiveNewKeysMessage: decrypt cipher chosen = ");
    DEBUG_PRINTNL(DEBUG_SSHC, pCipherSuite->pCipherName);

    /* free previous context */
    if (NULL != INBOUND_CIPHER_CONTEXT_FREE(pContextSSH))
        (INBOUND_CIPHER_CONTEXT_FREE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) &INBOUND_CIPHER_CONTEXT(pContextSSH));

    /* init inbound iv key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'B', SSH_SESSION_ID(pContextSSH),
                               INBOUND_CIPHER_IV(pContextSSH), pCipherSuite->ivSize)))
    {
        goto exit;
    }

    if ((NULL == (INBOUND_CIPHER_SUITE_INFO(pContextSSH) = pCipherSuite)) || (NULL == pCipherSuite->pBEAlgo))
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

    /* init inbound decipher key */
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
    if (CHACHA20_POLY1305_OPENSSH == INBOUND_CIPHER_TYPE(pContextSSH))
    {
        if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                                   pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                                   pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                                   SSH_HASH_H(pContextSSH),
                                   'D', SSH_SESSION_ID(pContextSSH),
                                   pKeyBuffer, 2*pCipherSuite->keySize)))
        {
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT,(sbyte *) "DECRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, 2*pCipherSuite->keySize);
        /* K_2 context is used to decrypt payload */
        if (NULL == (INBOUND_CIPHER_CONTEXT(pContextSSH) = INBOUND_CIPHER_CREATE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 0)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* K_1 context for decrypting payload length bytes */
        if (NULL == (INBOUND_CIPHER_CONTEXT2(pContextSSH) = INBOUND_CIPHER_CREATE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer + pCipherSuite->keySize, pCipherSuite->keySize, 0)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
    {
        if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                                   pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                                   pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                                   SSH_HASH_H(pContextSSH),
                                   'D', SSH_SESSION_ID(pContextSSH),
                                   pKeyBuffer, pCipherSuite->keySize)))
        {
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT,(sbyte *) "DECRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, pCipherSuite->keySize);

        if (NULL == (INBOUND_CIPHER_CONTEXT(pContextSSH) = INBOUND_CIPHER_CREATE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 0)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    /* block / iv size */
    /* ----------------------------------- */
    /* handle client --> server encryption */
    pCipherSuite =  &(mCipherSuites[pOptionsSelected[SSH_ALG_INDEX_ENCRYPT_C2S] - 1]);

    OUTBOUND_CIPHER_TYPE(pContextSSH) = pOptionsSelected[SSH_ALG_INDEX_ENCRYPT_C2S] - 1;

    DEBUG_PRINT(DEBUG_SSHC, "receiveNewKeysMessage: encrypt cipher chosen = ");
    DEBUG_PRINTNL(DEBUG_SSHC, pCipherSuite->pCipherName);

    /* free previous context */
    if (NULL != OUTBOUND_CIPHER_CONTEXT_FREE(pContextSSH))
        OUTBOUND_CIPHER_CONTEXT_FREE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) &OUTBOUND_CIPHER_CONTEXT(pContextSSH));

    /* init outbound iv key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'A', SSH_SESSION_ID(pContextSSH),
                               OUTBOUND_CIPHER_IV(pContextSSH), pCipherSuite->ivSize)))
    {
        goto exit;
    }

    if ((NULL == (OUTBOUND_CIPHER_SUITE_INFO(pContextSSH) = pCipherSuite)) || (NULL == pCipherSuite->pBEAlgo))
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

    /* init outbound decipher key */
#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
    if (CHACHA20_POLY1305_OPENSSH == OUTBOUND_CIPHER_TYPE(pContextSSH))
    {
        if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                                   pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                                   pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                                   SSH_HASH_H(pContextSSH),
                                   'C', SSH_SESSION_ID(pContextSSH),
                                   pKeyBuffer, 2*pCipherSuite->keySize)))
        {
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT,(sbyte *) "ENCRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, 2*pCipherSuite->keySize);

        /* K_2 context is used to encrypt payload */
        if (NULL == (OUTBOUND_CIPHER_CONTEXT(pContextSSH) = OUTBOUND_CIPHER_CREATE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* K_1 context is used to encrypt payload length bytes */
        if (NULL == (OUTBOUND_CIPHER_CONTEXT2(pContextSSH) = OUTBOUND_CIPHER_CREATE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer + pCipherSuite->keySize, pCipherSuite->keySize, 1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
    {
        if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                                   pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                                   pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                                   SSH_HASH_H(pContextSSH),
                                   'C', SSH_SESSION_ID(pContextSSH),
                                   pKeyBuffer, pCipherSuite->keySize)))
        {
            goto exit;
        }
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, (sbyte *)"ENCRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, pCipherSuite->keySize);

        if (NULL == (OUTBOUND_CIPHER_CONTEXT(pContextSSH) = OUTBOUND_CIPHER_CREATE(pContextSSH)(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    /* block / iv size */
    /* ---------------------------------------- */
    /* configure for server to client hmac-sha1 */
    /* free inbound hmac buffer */
    if (NULL != INBOUND_MAC_BUFFER(pContextSSH))
    {
        FREE(INBOUND_MAC_BUFFER(pContextSSH));
        INBOUND_MAC_BUFFER(pContextSSH) = NULL;
    }

    /* free inbound key data */
    if (NULL != INBOUND_KEY_DATA(pContextSSH))
    {
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &(INBOUND_KEY_DATA(pContextSSH)) );
        INBOUND_KEY_DATA(pContextSSH) = NULL;
    }

    pHmacSuite = &(mHmacSuites[pOptionsSelected[SSH_ALG_INDEX_MAC_S2C] - 1]);

    DEBUG_PRINT(DEBUG_SSHC, "receiveNewKeysMessage: inbound hmac chosen = ");
    DEBUG_PRINTNL(DEBUG_SSHC, pHmacSuite->pHmacName);

    /* inbound hmac-sha1 buffer */
    if (NULL == (INBOUND_MAC_BUFFER(pContextSSH) = MALLOC(pHmacSuite->hmacDigestLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* init inbound hmac key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'F', SSH_SESSION_ID(pContextSSH),
                               pKeyBuffer, pHmacSuite->hmacDigestLength)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pHmacSuite->hmacDigestLength, TRUE, &(INBOUND_KEY_DATA(pContextSSH)))))
        goto exit;

    DEBUG_RELABEL_MEMORY(INBOUND_KEY_DATA(pContextSSH));

    MOC_MEMCPY(INBOUND_KEY_DATA(pContextSSH), pKeyBuffer, pHmacSuite->hmacDigestLength);

    INBOUND_KEY_DATA_LEN(pContextSSH)  = pHmacSuite->hmacKeyLength;

    /* inbound hmac methods */
    INBOUND_MAC_INFO(pContextSSH)      = pHmacSuite;

    /* ---------------------------------------- */
    /* configure for client to server hmac-sha1 */
    /* free outbound key data */
    if (NULL != OUTBOUND_KEY_DATA(pContextSSH))
    {
        /*FREE(OUTBOUND_KEY_DATA(pContextSSH));*/
        CRYPTO_FREE( (pContextSSH)->hwAccelCookie, TRUE, &(OUTBOUND_KEY_DATA(pContextSSH)) ) ;
        OUTBOUND_KEY_DATA(pContextSSH) = NULL;
    }

    pHmacSuite = &(mHmacSuites[pOptionsSelected[SSH_ALG_INDEX_MAC_C2S] - 1]);

    DEBUG_PRINT(DEBUG_SSHC, "receiveNewKeysMessage: outbound hmac chosen = ");
    DEBUG_PRINTNL(DEBUG_SSHC, pHmacSuite->pHmacName);

    /* init outbound hmac key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'E', SSH_SESSION_ID(pContextSSH),
                               pKeyBuffer, pHmacSuite->hmacDigestLength)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pHmacSuite->hmacDigestLength , TRUE, &(OUTBOUND_KEY_DATA(pContextSSH)))))
        goto exit;

    DEBUG_RELABEL_MEMORY(OUTBOUND_KEY_DATA(pContextSSH));

    MOC_MEMCPY(OUTBOUND_KEY_DATA(pContextSSH), pKeyBuffer, pHmacSuite->hmacDigestLength);

    OUTBOUND_KEY_DATA_LEN(pContextSSH)  = pHmacSuite->hmacKeyLength;

    /* outbound hmac methods */
    OUTBOUND_MAC_INFO(pContextSSH)      = pHmacSuite;

#if 0
    /*!-!-!-! placeholder for compression support */
    if (1 == pOptionsSelected[6])
    {
        /* both sides should agree on compression none */
    }

    if (1 == pOptionsSelected[7])
    {
        /* both sides should agree on compression none */
    }
#endif

exit:
    if (NULL != hashContext)
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &hashContext);

    if (NULL != pKeyBuffer)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pKeyBuffer);

    if (NULL != SSH_HASH_H(pContextSSH))
    {
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &SSH_HASH_H(pContextSSH));
        SSH_HASH_H(pContextSSH) = NULL;
    }
    if (NULL != pContextSSH->sshKeyExCtx.pBytesSharedSecret)
    {
        MOC_MEMSET(pContextSSH->sshKeyExCtx.pBytesSharedSecret, 0x00, pContextSSH->sshKeyExCtx.bytesSharedSecretLen);
        MOC_FREE((void**)&pContextSSH->sshKeyExCtx.pBytesSharedSecret);
    }

    VLONG_freeVlong(&SSH_K(pContextSSH), NULL);

    return status;

} /* receiveNewKeysMessage */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_versionExchange(sshClientContext *pContextSSH)
{
    ubyte*  pTempClientHelloClone;
    MSTATUS status;

    /* copy default server hello string */
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, (sizeof(CLIENT_HELLO_STRING)-1), TRUE, &pTempClientHelloClone)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTempClientHelloClone);

    MOC_MEMCPY(pTempClientHelloClone, (ubyte *)CLIENT_HELLO_STRING, sizeof(CLIENT_HELLO_STRING)-1);

    CLIENT_HELLO_COMMENT_LEN(pContextSSH) = sizeof(CLIENT_HELLO_STRING)-1;
    CLIENT_HELLO_COMMENT(pContextSSH) = pTempClientHelloClone;
    pTempClientHelloClone = NULL;

    if (OK > (status = SSHC_TRANS_sendHello(pContextSSH)))
        goto exit;

exit:
    CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pTempClientHelloClone);

    return status;

} /* SSHC_TRANS_versionExchange */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_TRANS_doProtocol(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte*  optionsSelected = SSH_OPTIONS_SELECTED(pContextSSH);
    MSTATUS status = OK;

    if ((SSH_MSG_IGNORE == *pNewMesg) || (SSH_MSG_DEBUG == *pNewMesg))
    {
        goto exit;
    }
    else if (SSH_MSG_DISCONNECT == *pNewMesg)
    {
        if (4 < newMesgLen)
        {
            if (15 < (status = *(4 + pNewMesg)))
                status = 0;

            if (NULL != SSHC_sshClientSettings()->funcPtrDisconnectMsg)
            {
                ubyte4 msgLen;

                pNewMesg += 1 + 4;
                msgLen  = ((ubyte4)pNewMesg[0]) << 24;
                msgLen |= ((ubyte4)pNewMesg[1]) << 16;
                msgLen |= ((ubyte4)pNewMesg[2]) <<  8;
                msgLen |= ((ubyte4)pNewMesg[3]);

                SSHC_sshClientSettings()->funcPtrDisconnectMsg(CONNECTION_INSTANCE(pContextSSH),
                                       (ubyte4)status, pNewMesg + 4, msgLen, pNewMesg + 4 + msgLen);
            }

            /* return specific disconnect reason */
            status = ERR_SSH_DISCONNECT - status;
        }

        goto exit;
    }

#ifdef __DEBUG_SSHC_TRANS_STATE__
    DEBUG_ERROR(DEBUG_SSHC, "SSHC_TRANS_doProtocol: incoming state = ", SSH_UPPER_STATE(pContextSSH));
#endif

    switch (SSH_UPPER_STATE(pContextSSH))
    {
        case kTransAlgorithmExchange:
        case kReduxTransAlgorithmExchange:
        {
            if (OK > (status = SSHC_TRANS_receiveServerAlgorithms(pContextSSH, optionsSelected, pNewMesg, newMesgLen)))
                break;

            if (kTransAlgorithmExchange == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = pContextSSH->pKeyExSuiteInfo->nextStateFirstExchange;
            else
                SSH_UPPER_STATE(pContextSSH) = pContextSSH->pKeyExSuiteInfo->nextStateReKeyExchange;

            if (NULL != pContextSSH->pKeyExSuiteInfo->pKeyExMethods->sendResp)
            {
                /* send back our response to the server keyex algo selection */
                if (OK > (status = pContextSSH->pKeyExSuiteInfo->pKeyExMethods->sendResp(pContextSSH)))
                    goto exit;
            }

            break;
        }

        case kTransReceiveDiffieHellmanClassic:
        case kReduxTransReceiveDiffieHellmanClassic:
        {
            if (OK > (status = receiveServerKeyExchange(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveDiffieHellmanClassic == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutNewKeys);
            break;
        }

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
        case kTransReceiveDiffieHellmanGroup1:
        case kReduxTransReceiveDiffieHellmanGroup1:
        {
            /* handle DH Group Key Exchange Step 1 */
            if (OK > (status = receiveServerDHGKeyExchange(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveDiffieHellmanGroup1 == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransReceiveDiffieHellmanGroup2;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransReceiveDiffieHellmanGroup2;

            if (OK > (status = sendServerDHGInit(pContextSSH)))
                break;

            break;
        }

        case kTransReceiveDiffieHellmanGroup2:
        case kReduxTransReceiveDiffieHellmanGroup2:
        {
            /* handle DH Group Key Exchange Step 2 */
            if (OK > (status = receiveServerDHGKeyExchangeReply(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveDiffieHellmanGroup2 == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutNewKeys);
            break;
        }
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
        case kTransReceiveRSA:
        case kReduxTransReceiveRSA:
        {
            /* handle RSA Key Exchange */
            if (OK > (status = SSHC_TRANS_receiveServerKexRsaPubKey(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveRSA == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransReceiveRSADone;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransReceiveRSADone;

            if (OK > (status = SSHC_TRANS_sendKexRsaSecret(pContextSSH)))
                break;

            break;
        }

        case kTransReceiveRSADone:
        case kReduxTransReceiveRSADone:
        {
            /* handle RSA Key Exchange */
            if (OK > (status = SSHC_TRANS_receiveServerKexRsaDone(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveRSADone == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutNewKeys);
            break;
        }
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_PQC__))
        case kTransReceiveHybrid:
        case kReduxTransReceiveHybrid:
        {
            /* handle ECDH Key Exchange */
            if (OK > (status = SSHC_TRANS_receiveServerHybridReply(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveHybrid == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutNewKeys);
            break;
        }
#endif /* __ENABLE_MOCANA_PQC__ */
        case kTransReceiveECDH:
        case kReduxTransReceiveECDH:
        {
            /* handle ECDH Key Exchange */
            if (OK > (status = SSHC_TRANS_receiveServerEcdhReply(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveECDH == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutNewKeys);
            break;
        }
#endif

        case kTransNewKeys:
        case kReduxTransNewKeys:
        {
            if (OK > (status = receiveNewKeysMessage(pContextSSH, optionsSelected, pNewMesg, newMesgLen)))
                break;

            if (kTransNewKeys == SSH_UPPER_STATE(pContextSSH))
            {
                SSH_UPPER_STATE(pContextSSH) = kAuthServiceRequest;
                status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutServiceRequest);

                if (OK > (status = SSHC_AUTH_SendUserAuthServiceRequest(pContextSSH)))
                    break;

            }
            else
            {
                SSH_UPPER_STATE(pContextSSH) = kOpenState;
                status = SSHC_TRANS_setMessageTimer(pContextSSH, SSHC_sshClientSettings()->sshTimeOutDefaultOpenState);
            }

            /* allow non-key messages to flow again */
            pContextSSH->isReKeyOccuring = FALSE;

            break;
        }

        case kAuthServiceRequest:
        case kAuthReceiveMessage:
        {
            status = SSHC_AUTH_doProtocol(pContextSSH, pNewMesg, newMesgLen);
            break;
        }

        case kOpenState:
        {
            status = SSHC_SESSION_receiveMessage(pContextSSH, pNewMesg, newMesgLen);
            break;
        }

        default:
        {
            status = ERR_SSH_BAD_TRANS_RECEIVE_STATE;
            break;
        }
    }

    if (OK > status)
        goto exit;

    /* was a strict rekey request ignored? */
    if ((TRUE == pContextSSH->isReKeyInitiatedByMe) && (TRUE == pContextSSH->isReKeyStrict))
    {
        /* maybe, let's see how the timer looks */
        if (RTOS_deltaMS(&pContextSSH->timeOfReKey, NULL) > pContextSSH->numMilliSecForReKey)
        {
            /* sadly we have been ignored, we have to shutdown the session */
            status = ERR_SSH_REKEY_REQUEST_IGNORED;
        }
    }

exit:

#ifdef __DEBUG_SSHC_TRANS_STATE__
    DEBUG_ERROR(DEBUG_SSHC, "SSHC_TRANS_doProtocol: exit state = ", SSH_UPPER_STATE(pContextSSH));
#endif

    return status;

} /* SSHC_TRANS_doProtocol */


/*------------------------------------------------------------------*/

extern void
SSHC_TRANS_sendDisconnectMesg(sshClientContext *pContextSSH, ubyte4 sshError)
{
    ubyte4  payloadLength = 5 + sshc_disconnectMesg.stringLen + sshc_languageTag.stringLen;
    ubyte*  pPayload = MALLOC(payloadLength);
    ubyte4  dummy;

    if (NULL == pPayload)
        goto exit;

    pPayload[0] = SSH_MSG_DISCONNECT;

    pPayload[1] = (ubyte)(sshError >> 24);
    pPayload[2] = (ubyte)(sshError >> 16);
    pPayload[3] = (ubyte)(sshError >>  8);
    pPayload[4] = (ubyte)(sshError);

    MOC_MEMCPY(pPayload + 5, sshc_disconnectMesg.pString, sshc_disconnectMesg.stringLen);
    MOC_MEMCPY(pPayload + 5 + sshc_disconnectMesg.stringLen, sshc_languageTag.pString, sshc_languageTag.stringLen);

    SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, payloadLength, &dummy);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeDhContext(&(pContextSSH->sshKeyExCtx.p_dhContext), NULL);
#else
    DH_freeDhContext(&(pContextSSH->sshKeyExCtx.p_dhContext), NULL);
#endif

    MOC_MEMSET(pContextSSH->sshKeyExCtx.pBytesSharedSecret, 0x00, pContextSSH->sshKeyExCtx.bytesSharedSecretLen);
    MOC_FREE((void**)&(pContextSSH->sshKeyExCtx.pBytesSharedSecret));

    pContextSSH->sshKeyExCtx.bytesSharedSecretLen = 0;

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    return;
}
#if (defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__))

static MSTATUS
SSH_CERT_buildRawX509v3Cert(sshClientContext *pContextSSH, sshStringBuffer *pSshCertType,
                            SizedBuffer *pCertificates, ubyte4 numCertificates,
                            ubyte **ppRetCert, ubyte4 *pRetCertLen)
{
    ubyte4          numOcspResponses    = 0;
    ubyte*          pOcspResponse       = NULL;
    ubyte4          retOcspResponseLen  = 0;
    ubyte*          pMessage            = NULL;
    ubyte4          messageSize;
    ubyte4          index               = 0;

#ifdef __ENABLE_MOCANA_SSH_OCSP_SUPPORT__
    ubyte*          pIssuerCert;
    ubyte4          issuerCertLen;
    ASN1_ITEMPTR    pRoot               = 0;
    ASN1_ITEMPTR    pIssuer, pSerialNumber;
    CStream         cs;
    MemFile         mf;
    ubyte*          cert;
    void*           pIterator;
    const ubyte*    dn;
#endif

    MSTATUS         status = OK;
    ubyte4          i;

    if ((NULL == pCertificates) || (NULL == ppRetCert) || (NULL == pRetCertLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    /*
        string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" /
        "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]"
        uint32  certificate-count
        string  certificate[1..certificate-count]
        uint32  ocsp-response-count
        string  ocsp-response[0..ocsp-response-count]
    */

#ifdef __ENABLE_MOCANA_SSH_OCSP_SUPPORT__
    /* get the OCSP response */

    cert = pCertificates[numCertificates - 1].data;

    MF_attach(&mf, pCertificates[numCertificates - 1].length, cert);

    CS_AttachMemFile(&cs, &mf);

    if (OK > ( status = ASN1_Parse(cs, &pRoot)))
    {
        goto exit;
    }

    if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                             &pIssuer,
                                                             &pSerialNumber)))
    {
        goto exit;
    }

    dn = CS_memaccess(cs,pIssuer->dataOffset, pIssuer->length ) ;

    if (OK > (status = (CERT_STORE_findTrustPointBySubjectFirst(pContextSSH->pCertStore,
                                                                dn, pIssuer->length,
                                                                (const ubyte **)&pIssuerCert,
                                                                &issuerCertLen, (const void **)&pIterator))))
    {
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_SSH_SERVER__))
    if (OK > (status = SSH_OCSP_getOcspResponse(SSH_sshSettings()->pOcspResponderUrl,
                                                pCertificates[numCertificates - 1].data,
                                                pCertificates[numCertificates - 1].length,
                                                pIssuerCert, issuerCertLen,
                                                &pOcspResponse, &retOcspResponseLen)))
    {
        goto exit;
    }
#endif

    /* supporting only 1 certificate for now */
    numOcspResponses = 1;
#else
    retOcspResponseLen = 0;
    numOcspResponses = 0;
#endif

    /* Compute length of signature, cert count, length of chain,
     *    number of OCSP responses, and OCSP responses
     */
    /* string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" / "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]" */
    messageSize  = pSshCertType->stringLen;

    /* uint32  certificate-count */
    messageSize += sizeof(ubyte4);

    /* string  certificate[1..certificate-count] */
    for (i = 0; i < numCertificates; i++)
        messageSize += sizeof(ubyte4) + pCertificates[i].length;

    /* uint32  ocsp-response-count */
    messageSize += sizeof(ubyte4);

    /* string  ocsp-response[0..ocsp-response-count] */
    if (0 != numOcspResponses)
    {
        /* to store OCSP message length */
        messageSize += sizeof(ubyte4);
        messageSize += retOcspResponseLen;
    }

    if (OK != (status = MOC_MALLOC((void**)&pMessage, 4 + messageSize)))
        goto exit;
    MOC_MEMSET(pMessage, 0x00, (messageSize + 4));

    /* string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" / "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]" */
    pMessage[0] = (ubyte)(messageSize >> 24);
    pMessage[1] = (ubyte)(messageSize >> 16);
    pMessage[2] = (ubyte)(messageSize >>  8);
    pMessage[3] = (ubyte)(messageSize);
    messageSize += 4;
    index = 4;

    /* ssh sign algo into the buffer */
    MOC_MEMCPY(pMessage + index, pSshCertType->pString, (sbyte4)pSshCertType->stringLen);
    index += pSshCertType->stringLen;

    /* uint32  certificate-count */
    pMessage[index + 0] = (ubyte)(numCertificates >> 24);
    pMessage[index + 1] = (ubyte)(numCertificates >> 16);
    pMessage[index + 2] = (ubyte)(numCertificates >>  8);
    pMessage[index + 3] = (ubyte)(numCertificates);
    index += 4;

    /* string  certificate[1..certificate-count] */
    for (i = 0; i < numCertificates; i++)
    {
        ubyte4 certLength = pCertificates[i].length;

        /* Add length of the certificate */
        pMessage[index + 0] = (ubyte)(certLength >> 24);
        pMessage[index + 1] = (ubyte)(certLength >> 16);
        pMessage[index + 2] = (ubyte)(certLength >>  8);
        pMessage[index + 3] = (ubyte)(certLength);
        index += 4;

        /* Copy the cert chain into the buffer */
        MOC_MEMCPY(pMessage + index, pCertificates[i].data, (sbyte4)pCertificates[i].length);
        index += pCertificates[i].length;
    }


    /* uint32  ocsp-response-count */
    pMessage[index + 0] = (ubyte)(numOcspResponses >> 24);
    pMessage[index + 1] = (ubyte)(numOcspResponses >> 16);
    pMessage[index + 2] = (ubyte)(numOcspResponses >>  8);
    pMessage[index + 3] = (ubyte)(numOcspResponses);
    index += 4;

    /* string  ocsp-response[0..ocsp-response-count] */
    if (0 != numOcspResponses)
    {
        /*!!!!!*/
        pMessage[index + 0] = (ubyte)(retOcspResponseLen >> 24);
        pMessage[index + 1] = (ubyte)(retOcspResponseLen >> 16);
        pMessage[index + 2] = (ubyte)(retOcspResponseLen >>  8);
        pMessage[index + 3] = (ubyte)(retOcspResponseLen);
        index += 4;

        MOC_MEMCPY(pMessage + index, pOcspResponse, retOcspResponseLen);
        index += retOcspResponseLen;
    }

    *ppRetCert = pMessage; pMessage = NULL;
    *pRetCertLen = messageSize;

exit:
    MOC_FREE((void**)&pMessage);

    return status;

} /* SSH_CERT_buildRawX509v3Cert */

MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertRSA(sshClientContext *pContextSSH,SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-ssh-rsa" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH,&sshc_cert_sign_signature, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}

MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertRSA2048(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-rsa2048-sha256" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH,&sshc_rsa2048_cert_sign_signature, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}

#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P192__))
MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertECDSAP192(sshClientContext *pContextSSH,SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-ecdsa-ssh2-nistp192" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &sshc_ecdsa_cert_signature_p192, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}
#endif

#if (!defined(__DISABLE_MOCANA_ECC_P224__))
MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertECDSAP224(sshClientContext *pContextSSH,SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-ecdsa-ssh2-nistp224" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &sshc_ecdsa_cert_signature_p224, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}
#endif

#if (!defined(__DISABLE_MOCANA_ECC_P256__))
MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertECDSAP256(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-ecdsa-ssh2-nistp256" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &sshc_ecdsa_cert_signature_p256, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}
#endif

#if (!defined(__DISABLE_MOCANA_ECC_P384__))
MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertECDSAP384(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-ecdsa-ssh2-nistp384" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &sshc_ecdsa_cert_signature_p384, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}
#endif

#if (!defined(__DISABLE_MOCANA_ECC_P521__))
MOC_EXTERN MSTATUS
SSH_CERT_buildClientCertECDSAP521(sshClientContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates, ubyte **ppRetHostBlob, ubyte4 *pRetHostBlobLen)
{
    /* "x509v3-ecdsa-ssh2-nistp521" */
    MSTATUS     status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &sshc_ecdsa_cert_signature_p521, pCertificates, numCertificates, ppRetHostBlob, pRetHostBlobLen);

    return status;
}
#endif
#endif
#endif
#endif /*__ENABLE_MOCANA_SSH_CLIENT__*/
