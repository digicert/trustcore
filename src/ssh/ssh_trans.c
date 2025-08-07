/*
 * ssh_trans.c
 *
 * SSH Transport Protocol
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

#ifdef __ENABLE_MOCANA_SSH_SERVER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../harness/harness.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../common/int64.h"
#include "../common/sizedbuffer.h"
#include "../common/prime.h"
#include "../common/random.h"
#include "../common/absstream.h"
#include "../common/tree.h"
#include "../common/memfile.h"
#include "../crypto/crypto.h"
#include "../crypto/blowfish.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"
#include "../crypto/chacha20.h"
#include "../crypto/des.h"
#include "../crypto/dsa.h"
#include "../crypto/three_des.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/hmac.h"
#include "../crypto/dh.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/rsa.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs1.h"
#include "../crypto/cert_store.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/cert_chain.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_dss.h"
#include "../ssh/ssh_rsa.h"
#include "../ssh/ssh_ecdsa.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh_trans.h"
#include "../ssh/ssh_in_mesg.h"
#include "../ssh/ssh_out_mesg.h"
#include "../ssh/ssh_defs.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh_session.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh_ocsp.h"
#include "../ssh/ssh_cert.h"
#include "../ssh/ssh_mpint.h"

#ifdef __ENABLE_MOCANA_PQC__ 
#include "../ssh/ssh_hybrid.h"
#include "../ssh/ssh_qs.h"
#include "../crypto_interface/crypto_interface_qs_kem.h"
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_aes_ctr.h"
#include "../crypto_interface/crypto_interface_blowfish.h"
#include "../crypto_interface/crypto_interface_chacha20.h"
#include "../crypto_interface/crypto_interface_dh.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif

#if 0
#define __DEBUG_SSH_TIMER__
#define __DEBUG_SSH_TRANS_STATE__
#endif

#ifndef PATCH_CONST
#define PATCH_CONST
#endif


/*------------------------------------------------------------------*/

/* prototypes */
static MSTATUS SSH_TRANS_allocClassicDH(struct sshContext *pContextSSH);
static MSTATUS SSH_TRANS_freeClassicDH(struct sshContext *pContextSSH);

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static MSTATUS SSH_TRANS_allocGroupDH(struct sshContext *pContextSSH);
static MSTATUS SSH_TRANS_freeGroupDH(struct sshContext *pContextSSH);
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static MSTATUS SSH_TRANS_allocRSA(struct sshContext *pContextSSH);
static MSTATUS SSH_TRANS_freeRSA(struct sshContext *pContextSSH);
static MSTATUS SSH_TRANS_sendKexRsaPubKey(struct sshContext *pContextSSH);
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS SSH_TRANS_allocECDH(struct sshContext *pContextSSH);
static MSTATUS SSH_TRANS_freeECDH(struct sshContext *pContextSSH);
#endif


#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS SSH_TRANS_buildHybridKey(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);
static MSTATUS SSH_TRANS_buildQsKey(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);
#endif

#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
static MSTATUS SSH_TRANS_buildDsaSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
static MSTATUS SSH_TRANS_buildRsaSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS SSH_TRANS_buildEcdsaSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
#endif

#if (defined(__ENABLE_MOCANA_ECC__) && defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSH_TRANS_buildHybridSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
#endif

#ifdef __ENABLE_MOCANA_PQC__
static MSTATUS
SSH_TRANS_buildQsSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
#endif

#if (defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__))    /*!!!! eliminate? */
extern MSTATUS SSH_TRANS_buildRawX509v3Cert(sshContext *pContextSSH, ubyte **ppRetCert, ubyte4 *pRetCertLen, certDescriptor *pKey); /*!!!!*/
#endif


#ifndef __DISABLE_AES_CIPHERS__
static BulkCtx SSH_TRANS_createAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
static MSTATUS SSH_TRANS_doAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
#endif

#if (defined(__ENABLE_MOCANA_CHACHA20__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
static MSTATUS SSH_TRANS_doChaCha20(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
#endif
#endif

/*------------------------------------------------------------------*/

/* Key Exchange Init Related Strings */
static sshStringBuffer *ssh_algorithmMethods[] =
{
    &ssh_kexMethods,
    &ssh_hostKeyMethods,
    &ssh_encC2SMethods,
    &ssh_encS2CMethods,
    &ssh_macC2SMethods,
    &ssh_macS2CMethods,
    &ssh_compC2SMethods,
    &ssh_compS2CMethods,
    &ssh_langC2SMethods,
    &ssh_langS2CMethods
};

#define NUM_ALGORITHM_METHODS   (sizeof(ssh_algorithmMethods) / sizeof(sshStringBuffer *))


/*------------------------------------------------------------------*/

/* lengths & indices */
#define SSH2_KEXINIT_PAYLOAD_HEADER     (17)
#define SSH2_KEXINIT_PAYLOAD_TAIL       (5)
#define SSH2_KEXINIT_RANDOM_PAD_LENGTH  (16)


/*------------------------------------------------------------------*/

/* key exchange alloc/free methods */
static sshKeyExCtxMethods dhClassicMethods = { SSH_TRANS_allocClassicDH, SSH_TRANS_freeClassicDH, NULL };

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static sshKeyExCtxMethods dhGroupMethods   = { SSH_TRANS_allocGroupDH,   SSH_TRANS_freeGroupDH,   NULL };
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static sshKeyExCtxMethods rsaMethods       = { SSH_TRANS_allocRSA,       SSH_TRANS_freeRSA,       SSH_TRANS_sendKexRsaPubKey };
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_PQC__))
static sshKeyExCtxMethods hybridMethods     = { SSH_TRANS_allocECDH,      SSH_TRANS_freeECDH,      NULL };
#endif
static sshKeyExCtxMethods ecdhMethods      = { SSH_TRANS_allocECDH,      SSH_TRANS_freeECDH,      NULL };
#endif


/*------------------------------------------------------------------*/

/* handshake hash algorithms */
static sshHashHandshake sshHandshakeSHA1   = { SHA1_allocDigest,   SHA1_freeDigest,   (BulkCtxInitFunc)SHA1_initDigest,   (BulkCtxUpdateFunc)SHA1_updateDigest,   (BulkCtxFinalFunc)SHA1_finalDigest,   SHA1_RESULT_SIZE };

#ifndef __DISABLE_MOCANA_SHA256__
static sshHashHandshake sshHandshakeSHA256 = { SHA256_allocDigest, SHA256_freeDigest, (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, SHA256_RESULT_SIZE };
#endif
#ifndef __DISABLE_MOCANA_SHA384__
static sshHashHandshake sshHandshakeSHA384 = { SHA384_allocDigest, SHA384_freeDigest, (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, SHA384_RESULT_SIZE };
#endif
#ifndef __DISABLE_MOCANA_SHA512__
static sshHashHandshake sshHandshakeSHA512 = { SHA512_allocDigest, SHA512_freeDigest, (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, SHA512_RESULT_SIZE };
#endif

/*------------------------------------------------------------------*/

static PATCH_CONST SSH_keyExSuiteInfo mKeyExSuites[] =
{   /* debugString keyExName keyExNameLength hintForKeyExAlgo kexExCtx hashAlgo ec_oid nextState rekeyNextState */
#if defined(__ENABLE_MOCANA_ECC__)
#if defined(__ENABLE_MOCANA_PQC__)
    { (sbyte *)"mlkem768nistp256-sha256",        (sbyte *)"mlkem768nistp256-sha256",         23,
        cid_EC_P256,   cid_PQC_MLKEM_768,        &hybridMethods, &sshHandshakeSHA256, NULL, kTransReceiveHybrid, kReduxTransReceiveHybrid },
    { (sbyte *)"mlkem1024nistp384-sha384",       (sbyte *)"mlkem1024nistp384-sha384",        24,
        cid_EC_P384,   cid_PQC_MLKEM_1024,       &hybridMethods, &sshHandshakeSHA384, NULL, kTransReceiveHybrid, kReduxTransReceiveHybrid },
    { (sbyte *)"mlkem768x25519-sha256",          (sbyte *)"mlkem768x25519-sha256",           21,
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
        0, &ecdhMethods,      &sshHandshakeSHA512, secp521r1_OID, kTransReceiveECDH,                 kReduxTransReceiveECDH },
#endif

#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"ecdh-sha2-nistp384", (sbyte *)"ecdh-sha2-nistp384",                    18, cid_EC_P384,
        0, &ecdhMethods,      &sshHandshakeSHA384, secp384r1_OID, kTransReceiveECDH,                 kReduxTransReceiveECDH },
#endif

#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ecdh-sha2-nistp256", (sbyte *)"ecdh-sha2-nistp256",                    18, cid_EC_P256,
        0, &ecdhMethods,      &sshHandshakeSHA256, secp256r1_OID, kTransReceiveECDH,                 kReduxTransReceiveECDH },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */

#if (!defined(__DISABLE_MOCANA_SSH_RSA_KEY_EXCHANGE__) && defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"rsa2048-sha256",      (sbyte *)"rsa2048-sha256",                       14, 2048,
        0, &rsaMethods,       &sshHandshakeSHA256, NULL,          kTransReceiveRSA,                  kReduxTransReceiveRSA },
#endif
#ifndef __ENABLE_MOCANA_FIPS_MODULE__
#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"rsa1024-sha1",        (sbyte *)"rsa1024-sha1",                         12, 1024,
        0, &rsaMethods,       &sshHandshakeSHA1,   NULL,          kTransReceiveRSA,                  kReduxTransReceiveRSA },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
#endif
#endif

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"dh-group-ex-256",     (sbyte *)"diffie-hellman-group-exchange-sha256", 36, DH_GROUP_14,
        0, &dhGroupMethods,   &sshHandshakeSHA256, NULL,          kTransReceiveDiffieHellmanGroup1,  kReduxTransReceiveDiffieHellmanGroup1 },
#endif
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"dh-group-ex-1",       (sbyte *)"diffie-hellman-group-exchange-sha1",   34, DH_GROUP_14,
        0, &dhGroupMethods,   &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanGroup1,  kReduxTransReceiveDiffieHellmanGroup1 },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"diffie-hellman-group14-sha256",    (sbyte *)"diffie-hellman-group14-sha256",          29, DH_GROUP_14,
        0, &dhClassicMethods, &sshHandshakeSHA256,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#endif
#if (!defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"diffie-hellman-group15-sha512",    (sbyte *)"diffie-hellman-group15-sha512",          29, DH_GROUP_15,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group16-sha512",    (sbyte *)"diffie-hellman-group16-sha512",          29, DH_GROUP_16,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group17-sha512",    (sbyte *)"diffie-hellman-group17-sha512",          29, DH_GROUP_17,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group18-sha512",    (sbyte *)"diffie-hellman-group18-sha512",          29, DH_GROUP_18,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#endif
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"dh-group14",          (sbyte *)"diffie-hellman-group14-sha1",          27, DH_GROUP_14,
        0, &dhClassicMethods, &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#ifndef __ENABLE_MOCANA_FIPS_MODULE__
    { (sbyte *)"dh-group2",           (sbyte *)"diffie-hellman-group1-sha1",           26, DH_GROUP_2,
        0, &dhClassicMethods, &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic }
#endif
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
};

#define NUM_SSH_KEYEX_SUITES    (sizeof(mKeyExSuites)/sizeof(SSH_keyExSuiteInfo))


/*------------------------------------------------------------------*/

static PATCH_CONST SSH_keyExSuiteInfo mKeyExSuitesNoEcc[] =
{   /* debugString keyExName keyExNameLength hintForKeyExAlgo kexExCtx hashAlgo ec_oid nextState rekeyNextState */

#if (!defined(__DISABLE_MOCANA_SSH_RSA_KEY_EXCHANGE__) && defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"rsa2048-sha256",      (sbyte *)"rsa2048-sha256",                       14, 2048,
        0, &rsaMethods,       &sshHandshakeSHA256, NULL,          kTransReceiveRSA,                  kReduxTransReceiveRSA },
#endif
#ifndef __ENABLE_MOCANA_FIPS_MODULE__
#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"rsa1024-sha1",        (sbyte *)"rsa1024-sha1",                         12, 1024,
        0, &rsaMethods,       &sshHandshakeSHA1,   NULL,          kTransReceiveRSA,                  kReduxTransReceiveRSA },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
#endif
#endif

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"dh-group-ex-256",     (sbyte *)"diffie-hellman-group-exchange-sha256", 36, DH_GROUP_14,
        0, &dhGroupMethods,   &sshHandshakeSHA256, NULL,          kTransReceiveDiffieHellmanGroup1,  kReduxTransReceiveDiffieHellmanGroup1 },
#endif
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"dh-group-ex-1",       (sbyte *)"diffie-hellman-group-exchange-sha1",   34, DH_GROUP_14,
        0, &dhGroupMethods,   &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanGroup1,  kReduxTransReceiveDiffieHellmanGroup1 },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"diffie-hellman-group14-sha256",    (sbyte *)"diffie-hellman-group14-sha256",          29, DH_GROUP_14,
        0, &dhClassicMethods, &sshHandshakeSHA256,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#endif
#if (!defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"diffie-hellman-group15-sha512",    (sbyte *)"diffie-hellman-group15-sha512",          29, DH_GROUP_15,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group16-sha512",    (sbyte *)"diffie-hellman-group16-sha512",          29, DH_GROUP_16,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group17-sha512",    (sbyte *)"diffie-hellman-group17-sha512",          29, DH_GROUP_17,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
    { (sbyte *)"diffie-hellman-group18-sha512",    (sbyte *)"diffie-hellman-group18-sha512",          29, DH_GROUP_18,
        0, &dhClassicMethods, &sshHandshakeSHA512,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#endif
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"dh-group14",          (sbyte *)"diffie-hellman-group14-sha1",          27, DH_GROUP_14,
        0, &dhClassicMethods, &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic },
#ifndef __ENABLE_MOCANA_FIPS_MODULE__
    { (sbyte *)"dh-group2",           (sbyte *)"diffie-hellman-group1-sha1",           26, DH_GROUP_2,
        0, &dhClassicMethods, &sshHandshakeSHA1,   NULL,          kTransReceiveDiffieHellmanClassic, kReduxTransReceiveDiffieHellmanClassic }
#endif
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
};

#define NUM_SSH_NO_ECC_KEYEX_SUITES    (sizeof(mKeyExSuitesNoEcc)/sizeof(SSH_keyExSuiteInfo))

/*------------------------------------------------------------------*/

#if (!defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__) && !defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && !defined(__ENABLE_MOCANA_ECC__))
#error SSH Server configuration error (host key)
#endif

#if 0   /*!!!!!!!!*/
    sbyte*                  pHostKeyName;
    ubyte4                  hostKeyNameLength;
    sbyte*                  pSignatureName;
    ubyte4                  signatureNameLength;
    ubyte4                  authType;
    ubyte4                  hashLen;
    ubyte4                  minAlgoDetail;      /* this could be a curve or key size; if curve, the min and max should match however only the min is used */
    ubyte4                  maxAlgoDetail;      /* to force a certain key size have min and max match */
    ubyte4                  identityType;
    MSTATUS (*pFuncBuildCert)     (struct sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);
    MSTATUS (*pFuncBuildSig)      (struct sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
    MSTATUS (*pFuncBuildCertChain)(struct sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);
#endif

static PATCH_CONST SSH_hostKeySuiteInfo mHostKeySuites[] =
{   /* pHostKeyName hostKeyNameLength pSignatureName signatureNameLength pFuncCreateKey, pFuncBuildCert pFuncBuildSig */
#if (defined(__ENABLE_MOCANA_SSH_SERVER_CERT_AUTH__))
#if ((defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__)))
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
#ifdef __ENABLE_MOCANA_PQC__
    { (sbyte *)"x509v3-mldsa44",             14, (sbyte *)"x509v3-mldsa44",             14, CERT_STORE_AUTH_TYPE_QS,     0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildQsSignature,     SSH_CERT_buildCertQs },
    { (sbyte *)"x509v3-mldsa65",             14, (sbyte *)"x509v3-mldsa65",             14, CERT_STORE_AUTH_TYPE_QS,     0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildQsSignature,     SSH_CERT_buildCertQs },
    { (sbyte *)"x509v3-mldsa87",             14, (sbyte *)"x509v3-mldsa87",             14, CERT_STORE_AUTH_TYPE_QS,     0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildQsSignature,     SSH_CERT_buildCertQs },
#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"x509v3-mldsa44-es256",       20, (sbyte *)"x509v3-mldsa44-es256",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildHybridSignature, SSH_CERT_buildCertHybrid },
    { (sbyte *)"x509v3-mldsa65-es256",       20, (sbyte *)"x509v3-mldsa65-es256",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildHybridSignature, SSH_CERT_buildCertHybrid },     
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"x509v3-mldsa87-es384",       20, (sbyte *)"x509v3-mldsa87-es384",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildHybridSignature, SSH_CERT_buildCertHybrid },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"x509v3-mldsa44-ed25519",     22, (sbyte *)"x509v3-mldsa44-ed25519",     22, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildHybridSignature, SSH_CERT_buildCertHybrid },
    { (sbyte *)"x509v3-mldsa65-ed25519",     22, (sbyte *)"x509v3-mldsa65-ed25519",     22, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildHybridSignature, SSH_CERT_buildCertHybrid },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
    { (sbyte *)"x509v3-mldsa87-ed448",       20, (sbyte *)"x509v3-mldsa87-ed448",       20, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildHybridSignature, SSH_CERT_buildCertHybrid },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */
#endif /* __ENABLE_MOCANA_PRE_DRAFT_PQC__ */

#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P256__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp256", 26, (sbyte *)"x509v3-ecdsa-sha2-nistp256", 26, CERT_STORE_AUTH_TYPE_ECDSA, SHA256_RESULT_SIZE, 256, 256, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildEcdsaSignature, SSH_CERT_buildCertECDSAP256 },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp384", 26, (sbyte *)"x509v3-ecdsa-sha2-nistp384", 26, CERT_STORE_AUTH_TYPE_ECDSA, SHA384_RESULT_SIZE, 384, 384, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildEcdsaSignature, SSH_CERT_buildCertECDSAP384 },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp521", 26, (sbyte *)"x509v3-ecdsa-sha2-nistp521", 26, CERT_STORE_AUTH_TYPE_ECDSA, SHA512_RESULT_SIZE, 521, 521, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildEcdsaSignature, SSH_CERT_buildCertECDSAP521 },
#endif
#endif
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"x509v3-rsa2048-sha256",      21, (sbyte *)"x509v3-rsa2048-sha256",      21, CERT_STORE_AUTH_TYPE_RSA,   SHA256_RESULT_SIZE, SSH_RSA_2048_SIZE, SSH_RSA_2048_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildRsaSignature, SSH_CERT_buildCertRSA2048 },
#endif
    { (sbyte *)"x509v3-ssh-rsa",             14, (sbyte *)"x509v3-ssh-rsa",             14, CERT_STORE_AUTH_TYPE_RSA,   SHA_HASH_RESULT_SIZE,   SSH_RSA_MIN_SIZE,  SSH_RSA_MAX_SIZE,  CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, NULL, SSH_TRANS_buildRsaSignature, SSH_CERT_buildCertRSA },
#endif/* __ENABLE_MOCANA_SSH_RSA_SUPPORT__ */
#endif/* __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__ && __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__ */
#endif/* __ENABLE_MOCANA_SSH_SERVER_CERT_AUTH__ */

#ifdef __ENABLE_MOCANA_PQC__
    { (sbyte *)"ssh-mldsa44",                11, (sbyte *)"ssh-mldsa44",                11, CERT_STORE_AUTH_TYPE_QS,     0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildQsKey,   SSH_TRANS_buildQsSignature, NULL },
    { (sbyte *)"ssh-mldsa65",                11, (sbyte *)"ssh-mldsa65",                11, CERT_STORE_AUTH_TYPE_QS,     0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildQsKey,   SSH_TRANS_buildQsSignature, NULL },
    { (sbyte *)"ssh-mldsa87",                11, (sbyte *)"ssh-mldsa87",                11, CERT_STORE_AUTH_TYPE_QS,     0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildQsKey,   SSH_TRANS_buildQsSignature, NULL },
#ifdef __ENABLE_MOCANA_ECC__
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ssh-mldsa44-es256",          17, (sbyte *)"ssh-mldsa44-es256",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildHybridKey, SSH_TRANS_buildHybridSignature, NULL },
    { (sbyte *)"ssh-mldsa65-es256",          17, (sbyte *)"ssh-mldsa65-es256",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildHybridKey, SSH_TRANS_buildHybridSignature, NULL },     
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"ssh-mldsa87-es384",          17, (sbyte *)"ssh-mldsa87-es384",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildHybridKey, SSH_TRANS_buildHybridSignature, NULL },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"ssh-mldsa44-ed25519",        19, (sbyte *)"ssh-mldsa44-ed25519",        19, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildHybridKey, SSH_TRANS_buildHybridSignature, NULL },
    { (sbyte *)"ssh-mldsa65-ed25519",        19, (sbyte *)"ssh-mldsa65-ed25519",        19, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildHybridKey, SSH_TRANS_buildHybridSignature, NULL },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
    { (sbyte *)"ssh-mldsa87-ed448",          17, (sbyte *)"ssh-mldsa87-ed448",          17, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED, SSH_TRANS_buildHybridKey, SSH_TRANS_buildHybridSignature, NULL },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */
#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"ssh-ed25519",                11,         (sbyte *)"ssh-ed25519",        11, CERT_STORE_AUTH_TYPE_EDDSA, SHA256_RESULT_SIZE, 256,               256,               CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_TRANS_buildRawEcdsaCert, SSH_TRANS_buildEcdsaSignature, NULL },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P256__))
    { (sbyte *)"ecdsa-sha2-nistp256",        19, (sbyte *)"ecdsa-sha2-nistp256",        19, CERT_STORE_AUTH_TYPE_ECDSA, SHA256_RESULT_SIZE, 256,               256,               CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_TRANS_buildRawEcdsaCert, SSH_TRANS_buildEcdsaSignature, NULL },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__))
    { (sbyte *)"ecdsa-sha2-nistp384",        19, (sbyte *)"ecdsa-sha2-nistp384",        19, CERT_STORE_AUTH_TYPE_ECDSA, SHA384_RESULT_SIZE, 384,               384,               CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_TRANS_buildRawEcdsaCert, SSH_TRANS_buildEcdsaSignature, NULL },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__))
    { (sbyte *)"ecdsa-sha2-nistp521",        19, (sbyte *)"ecdsa-sha2-nistp521",        19, CERT_STORE_AUTH_TYPE_ECDSA, SHA512_RESULT_SIZE, 521,               521,               CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_TRANS_buildRawEcdsaCert, SSH_TRANS_buildEcdsaSignature, NULL },
#endif
#endif
#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
    { (sbyte *)"ssh-dss",                     7, (sbyte *)"ssh-dss", 7, CERT_STORE_AUTH_TYPE_DSA,   SHA_HASH_RESULT_SIZE,   SSH_RFC_DSA_SIZE,  SSH_RFC_DSA_SIZE,  CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_CERT_buildRawDsaCert,    SSH_TRANS_buildDsaSignature,   NULL },
#endif
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
#if (!defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"rsa-sha2-512",               12, (sbyte *)"ssh-rsa", 7, CERT_STORE_AUTH_TYPE_RSA,   SHA512_RESULT_SIZE,     SSH_RSA_2048_SIZE, SSH_RSA_2048_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_CERT_buildRawRsaCert,    SSH_TRANS_buildRsaSignature,   NULL },
#endif
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"rsa-sha2-256",               12, (sbyte *)"ssh-rsa", 7, CERT_STORE_AUTH_TYPE_RSA,   SHA256_RESULT_SIZE,     SSH_RSA_2048_SIZE, SSH_RSA_2048_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_CERT_buildRawRsaCert,    SSH_TRANS_buildRsaSignature,   NULL },
#endif
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"ssh-rsa",                     7, (sbyte *)"ssh-rsa", 7, CERT_STORE_AUTH_TYPE_RSA,   SHA_HASH_RESULT_SIZE,   SSH_RSA_MIN_SIZE,  SSH_RSA_MAX_SIZE,  CERT_STORE_IDENTITY_TYPE_NAKED,        SSH_CERT_buildRawRsaCert,    SSH_TRANS_buildRsaSignature,   NULL },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
    { (sbyte *)"placeholder",                11, (sbyte *)"dummy",   5, 0,                          0,                      0,                 0,                 0,                                     NULL,                        NULL,                          NULL }
};

#define NUM_SSH_HOST_KEY_SUITES ((sizeof(mHostKeySuites)/sizeof(SSH_hostKeySuiteInfo)) - 1)


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo AESCTRSuite =
    { 16, (CreateBulkCtxFunc)SSH_TRANS_createAESCTRCtx, CRYPTO_INTERFACE_DeleteAESCTRCtx, SSH_TRANS_doAESCTR, CRYPTO_INTERFACE_CloneAESCTRCtx };
#else
static BulkEncryptionAlgo AESCTRSuite =
    { 16, (CreateBulkCtxFunc)SSH_TRANS_createAESCTRCtx, DeleteAESCTRCtx, SSH_TRANS_doAESCTR, CloneAESCTRCtx };
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo AESSuite =
    { 16, CRYPTO_INTERFACE_CreateAESCtx, CRYPTO_INTERFACE_DeleteAESCtx, CRYPTO_INTERFACE_DoAES, CRYPTO_INTERFACE_CloneAESCtx };
#else
static BulkEncryptionAlgo AESSuite =
    { 16, CreateAESCtx, DeleteAESCtx, DoAES, CloneAESCtx };
#endif /*__ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#ifdef __ENABLE_BLOWFISH_CIPHERS__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo BlowfishSuite =
    { 8, CRYPTO_INTERFACE_CreateBlowfishCtx, CRYPTO_INTERFACE_DeleteBlowfishCtx, CRYPTO_INTERFACE_DoBlowfish, CRYPTO_INTERFACE_CloneBlowfishCtx };
#else
static BulkEncryptionAlgo BlowfishSuite =
    { 8, CreateBlowfishCtx, DeleteBlowfishCtx, DoBlowfish, CloneBlowfishCtx };
#endif
#endif

#ifndef __DISABLE_3DES_CIPHERS__
static BulkEncryptionAlgo TripleDESSuite =
    { 8, Create3DESCtx, Delete3DESCtx, Do3DES, Clone3DESCtx };
#endif


#ifdef __ENABLE_MOCANA_SP800_135_ACVP__
#include "../ssh/nist/ssh_nist_cs_defs.inc"
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
    { 16, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, NULL, CRYPTO_INTERFACE_GCM_clone_64k};
#else
static BulkEncryptionAlgo GCMSuite =
    { 16, GCM_createCtx_64k, GCM_deleteCtx_64k, NULL, GCM_clone_64k};
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_GCM_64K__ */
#ifdef __ENABLE_MOCANA_GCM_4K__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_cipher_4k };
#else
static sshAeadAlgo GCMAeadSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_cipher_4k };
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static BulkEncryptionAlgo GCMSuite =
    { 16, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, NULL, CRYPTO_INTERFACE_GCM_clone_4k};
#else
static BulkEncryptionAlgo GCMSuite =
    { 16, GCM_createCtx_4k, GCM_deleteCtx_4k, NULL, GCM_clone_4k};
#endif /*__ENABLE_MOCANA_CRYPTO_INTERFACE__  */
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
    { 16, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, NULL, CRYPTO_INTERFACE_GCM_clone_256b};
#else
static BulkEncryptionAlgo GCMSuite =
    { 16, GCM_createCtx_256b, GCM_deleteCtx_256b, NULL, GCM_clone_256b};
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_GCM_256B__ */
#endif /* __ENABLE_MOCANA_GCM__ */

#if (defined(__ENABLE_MOCANA_POLY1305__) && defined(__ENABLE_MOCANA_CHACHA20__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
static sshAeadAlgo ChaChaPolyAeadSuite =
    /* first two values are used for GCM, can be 0 for chacha20-poly1305, 128 bit tag  */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    { 0, 0, 16, CRYPTO_INTERFACE_ChaCha20Poly1305_cipherSSH };
#else
    { 0, 0, 16, ChaCha20Poly1305_cipherSSH };
#endif
static BulkEncryptionAlgo ChaChaPolySuite =
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    { 64, CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx, CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx, SSH_TRANS_doChaCha20, CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx };
#else
    { 64, ChaCha20Poly1305_createCtx, ChaCha20Poly1305_deleteCtx, SSH_TRANS_doChaCha20, ChaCha20Poly1305_cloneCtx };
#endif
#endif
#endif /* (defined(__ENABLE_MOCANA_POLY1305__) && defined(__ENABLE_MOCANA_CHACHA20__)) */

static PATCH_CONST SSH_CipherSuiteInfo mCipherSuites[] =
{     /* cipherName cipherNameLength keysize ivsize cipherSuiteDescr aeadCipherSuiteDescr */
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
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"chacha20-poly1305@openssh.com", 29, 32, 8, &ChaChaPolySuite, &ChaChaPolyAeadSuite },
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__))
#if (!defined(__DISABLE_AES128_CIPHER__))
    { (sbyte *)"aes128-ctr",            10, 16, 16, &AESCTRSuite,       NULL },
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"aes128-cbc",            10, 16, 16, &AESSuite,          NULL },
    { (sbyte *)"rijndael128-cbc",       15, 16, 16, &AESSuite,          NULL },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif /* __DISABLE_AES128_CIPHER__ */

#if (!defined(__DISABLE_AES256_CIPHER__))
    { (sbyte *)"aes256-ctr",            10, 32, 16, &AESCTRSuite,       NULL },
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"aes256-cbc",            10, 32, 16, &AESSuite,          NULL },
    { (sbyte *)"rijndael256-cbc",       15, 32, 16, &AESSuite,          NULL },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif /* __DISABLE_AES256_CIPHER__ */

#ifndef __DISABLE_AES192_CIPHER__
    { (sbyte *)"aes192-ctr",            10, 24, 16, &AESCTRSuite,       NULL },
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"aes192-cbc",            10, 24, 16, &AESSuite,          NULL },
    { (sbyte *)"rijndael192-cbc",       15, 24, 16, &AESSuite,          NULL },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_AES_CIPHERS__ */

#ifdef __ENABLE_BLOWFISH_CIPHERS__
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"blowfish-cbc",          12, 16,  8, &BlowfishSuite,     NULL },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_3DES_CIPHERS__
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"3des-cbc",               8, 24,  8, &TripleDESSuite,    NULL },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#endif
#ifdef __ENABLE_MOCANA_SP800_135_ACVP__
#include "../ssh/nist/ssh_nist_cs_list.inc"
#endif

    { (sbyte *)"ignore",                 6, 16,  8, NULL,               NULL }     /* this entry will not be accessed */
};

#define NUM_SSH_CIPHER_SUITES   ((sizeof(mCipherSuites)/sizeof(SSH_CipherSuiteInfo)) - 1)


/*------------------------------------------------------------------*/

static PATCH_CONST SSH_hmacSuiteInfo mHmacSuites[] =
{   /* hmacName hmacNameLength keyLength digestLength hmacSuiteDescr */
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES128_CIPHER__))
    { (sbyte *)"AEAD_AES_128_GCM",      16,  0, 16, NULL,           &GCMAeadSuite, FALSE },
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    { (sbyte *)"aes128-gcm@openssh.com",      22, 0, 16, NULL,          &GCMAeadSuite, FALSE },
#endif
#endif
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES256_CIPHER__))
    { (sbyte *)"AEAD_AES_256_GCM",      16,  0, 16, NULL,           &GCMAeadSuite, FALSE },

#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    { (sbyte *)"aes256-gcm@openssh.com",      22, 0, 16, NULL,          &GCMAeadSuite, FALSE },
#endif
#endif

#if defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"chacha20-poly1305@openssh.com", 29, 0, 16, NULL, &ChaChaPolyAeadSuite, FALSE },
#endif
#endif

#ifndef __DISABLE_MOCANA_SHA256__
    { (sbyte *)"hmac-sha2-256",         13, SHA256_RESULT_SIZE, SHA256_RESULT_SIZE, HMAC_SHA256,    NULL, FALSE },
    { (sbyte *)"hmac-sha2-256-etm@openssh.com", 29, SHA256_RESULT_SIZE, SHA256_RESULT_SIZE, HMAC_SHA256,    NULL, TRUE },
#endif
#ifndef __DISABLE_MOCANA_SHA512__
    { (sbyte *)"hmac-sha2-512",         13, SHA512_RESULT_SIZE, SHA512_RESULT_SIZE, HMAC_SHA512,    NULL, FALSE },
    { (sbyte *)"hmac-sha2-512-etm@openssh.com", 29, SHA512_RESULT_SIZE, SHA512_RESULT_SIZE, HMAC_SHA512,    NULL, TRUE },
#endif
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"hmac-sha1",              9, 20, 20, HMAC_SHA1,      NULL, FALSE },
    { (sbyte *)"hmac-sha1-etm@openssh.com", 25, 20, 20, HMAC_SHA1,      NULL, TRUE },
    { (sbyte *)"hmac-sha1-96",          12, 20, 12, HMAC_SHA1,      NULL, FALSE },
    { (sbyte *)"hmac-md5",               8, 16, 16, HMAC_MD5,       NULL, FALSE },
    { (sbyte *)"hmac-md5-etm@openssh.com", 24, 16, 16, HMAC_MD5,    NULL, TRUE },
    { (sbyte *)"hmac-md5-96",           11, 16, 12, HMAC_MD5,       NULL, FALSE }
#endif
};

#define NUM_SSH_HMAC_SUITES     (sizeof(mHmacSuites)/sizeof(SSH_hmacSuiteInfo))


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

#if (!defined(SSH_DHG_PRIME_STEP_BIT_LENGTH))
#define SSH_DHG_PRIME_STEP_BIT_LENGTH           (1024)
#endif

#if (((SSH_DHG_PRIME_MAX_BIT_LENGTH - SSH_DHG_PRIME_MIN_BIT_LENGTH) < SSH_DHG_PRIME_STEP_BIT_LENGTH) && !(defined(__DISABLE_MOCANA_DHG_STEP_WARNING__)))
#error WARNING: SSH_DHG_PRIME_STEP_BIT_LENGTH is too long to have any affect, to ignore define __DISABLE_MOCANA_DHG_STEP_WARNING__
#endif

#if (!defined(SSH_DHG_PRIME_NUM_GEN_EACH_STEP))
#define SSH_DHG_PRIME_NUM_GEN_EACH_STEP         (1)
#endif

#if (0 >= SSH_DHG_PRIME_NUM_GEN_EACH_STEP)
#error SSH_DHG_PRIME_NUM_GEN_EACH_STEP must be greater than zero
#endif

#define SSH_DHG_ARRAY_SIZE  (1 + (SSH_DHG_PRIME_NUM_GEN_EACH_STEP * ((SSH_DHG_PRIME_MAX_BIT_LENGTH - SSH_DHG_PRIME_MIN_BIT_LENGTH + (SSH_DHG_PRIME_STEP_BIT_LENGTH - 1)) / SSH_DHG_PRIME_STEP_BIT_LENGTH)))

static vlong *mp_dhSafePrimes[SSH_DHG_ARRAY_SIZE];

#endif /* (!defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
static AsymmetricKey m_transientRsaKey1024;
#endif
static AsymmetricKey m_transientRsaKey2048;
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_TRANS_HANDSHAKE_DATA__))
static void
DUMP(ubyte *pString, ubyte *pMesg, ubyte4 mesgLen)
{
    DEBUG_PRINTNL(0, (sbyte *)pString);
    DEBUG_HEXDUMP(0, pMesg, mesgLen);
}
#else
#define DUMP(X,Y,Z)
#endif



#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static MSTATUS
makeSafePrimesDHG(MOC_PRIME(hwAccelDescr hwAccelCtx) vlong **ppRetPrimeP, ubyte4 bitLength, vlong **ppVlongQueue)
{
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    return OK;
#else
    return DH_getP(DH_GROUP_14, ppRetPrimeP);
#endif
}
#endif /* (!defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
extern MSTATUS
SSH_TRANS_initSafePrimesDHG(hwAccelDescr hwAccelCtx)
{
    ubyte4  safePrimeSize = SSH_DHG_PRIME_MIN_BIT_LENGTH;
    ubyte4  index;
    ubyte4  count;
    vlong*  pVlongQueue   = NULL;
    MSTATUS status;

    index = 0;

    for (safePrimeSize = SSH_DHG_PRIME_MIN_BIT_LENGTH; safePrimeSize <= SSH_DHG_PRIME_MAX_BIT_LENGTH; safePrimeSize += SSH_DHG_PRIME_STEP_BIT_LENGTH)
    {
        for (count = 0; count < SSH_DHG_PRIME_NUM_GEN_EACH_STEP; count++)
        {
            if (OK > (status = makeSafePrimesDHG(MOC_PRIME(hwAccelCtx) &(mp_dhSafePrimes[index]), safePrimeSize, &pVlongQueue)))
                goto exit;

            DEBUG_RELABEL_MEMORY(mp_dhSafePrimes[index]);

            index++;
        }
    }

    if (index != SSH_DHG_ARRAY_SIZE)
    {
        count = SSH_DHG_ARRAY_SIZE;
        status = -1;    /*!!!!*/
    }

exit:
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* (!defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
extern MSTATUS
SSH_TRANS_initRsaKeyExchange(hwAccelDescr hwAccelCtx)
{
    vlong*  pVlongQueue = NULL;
    MSTATUS status;

#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
    CRYPTO_initAsymmetricKey(&m_transientRsaKey1024);
#endif
    CRYPTO_initAsymmetricKey(&m_transientRsaKey2048);

    /* set default RSA transient key for keyex */
#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
    if (OK > (status = CRYPTO_createRSAKey(&m_transientRsaKey1024, &pVlongQueue)))
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_generateKey(MOC_RSA(hwAccelCtx) g_pRandomContext,
                                       m_transientRsaKey1024.key.pRSA, 1024, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) g_pRandomContext,
                                       m_transientRsaKey1024.key.pRSA, 1024, &pVlongQueue)))
    {
        goto exit;
    }
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_MOCANA_RSA_ALL_KEYSIZE__ */

    if (OK > (status = CRYPTO_createRSAKey(&m_transientRsaKey2048, &pVlongQueue)))
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_generateKey(MOC_RSA(hwAccelCtx) g_pRandomContext,
                                       m_transientRsaKey2048.key.pRSA, 2048, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) g_pRandomContext,
                                       m_transientRsaKey2048.key.pRSA, 2048, &pVlongQueue)))
    {
        goto exit;
    }
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

exit:
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_TRANS_releaseStaticKeys(void)
{
#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
    ubyte4  index;
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
    CRYPTO_uninitAsymmetricKey(&m_transientRsaKey1024, 0);
#endif
    CRYPTO_uninitAsymmetricKey(&m_transientRsaKey2048, 0);
#endif

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
    for (index = 0; index < SSH_DHG_ARRAY_SIZE; index++)
        VLONG_freeVlong(&mp_dhSafePrimes[index], 0);
#endif

    return OK;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
SSH_TRANS_findSafePrimesDHG(const ubyte4 min, const ubyte4 max, const ubyte4 preferred,
                            vlong **ppRetP, vlong **ppRetG)
{
    vlong*          pTempP = NULL;
    vlong*          pTempG = NULL;
    ubyte4          index = SSH_DHG_ARRAY_SIZE / 2;
    ubyte4          bitLength;
    MSTATUS         status;

    /* TODO if this ever grows to be a long list, we should use a binary search */
    if (preferred != (bitLength = VLONG_bitLength(mp_dhSafePrimes[index])))
    {
        if (bitLength < preferred)
        {
            /* bitLength less than preferred, search up the list */
            while (((SSH_DHG_ARRAY_SIZE-1) > index) && (bitLength < preferred))
            {
                bitLength = VLONG_bitLength(mp_dhSafePrimes[++index]);
                break;
            }
        }
        else
        {
            /* bitLength longer than preferred, search down the list */
            while ((0 < index) && (bitLength > preferred))
            {
                bitLength = VLONG_bitLength(mp_dhSafePrimes[--index]);
                break;
            }
        }
    }

    if (OK > (status = VLONG_makeVlongFromVlong(mp_dhSafePrimes[index], &pTempP, NULL)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTempP);

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(2, &pTempG, NULL)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTempG);

    *ppRetP = pTempP;   pTempP = NULL;
    *ppRetG = pTempG;   pTempG = NULL;

exit:
    VLONG_freeVlong(&pTempG, NULL);
    VLONG_freeVlong(&pTempP, NULL);

    return status;
}
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */
#endif /* (!defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

extern sbyte *
SSH_TRANS_keyExList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
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
SSH_TRANS_keyExListNoEcc(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSH_NO_ECC_KEYEX_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mKeyExSuitesNoEcc[index].keyExNameLength;

    return mKeyExSuitesNoEcc[index].pKeyExName;
}


/*------------------------------------------------------------------*/

extern sbyte *
SSH_TRANS_hostKeyList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
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
SSH_TRANS_cipherList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSH_CIPHER_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mCipherSuites[index].cipherNameLength;

    return mCipherSuites[index].pCipherName;
}


/*------------------------------------------------------------------*/

extern sbyte *
SSH_TRANS_hmacList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (NUM_SSH_HMAC_SUITES <= index)
        return NULL;

    if (NULL != pRetStringLength)
        *pRetStringLength = mHmacSuites[index].hmacNameLength;

    return mHmacSuites[index].pHmacName;
}


/*------------------------------------------------------------------*/

extern sbyte *
SSH_TRANS_hostKeyList1(ubyte4 index, ubyte4 *pRetStringLength, void *pCookie)
{
    MSTATUS status;
    AsymmetricKey*  pKey = NULL;

    if (NUM_SSH_HOST_KEY_SUITES <= index)
        return NULL;

    /* verify key exists within certificate store for auth/identity types */
    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != mHostKeySuites[index].identityType)
    {
        if ((OK > CERT_STORE_findIdentityByTypeFirst(pCookie, mHostKeySuites[index].authType, mHostKeySuites[index].identityType, (const AsymmetricKey **)&pKey, NULL, NULL, NULL)) || (NULL == pKey))
            return NULL;

#ifdef __ENABLE_MOCANA_PQC__
        /* We want to make sure that the Host Key suite corresponds to the qs alg of the key extracted */
        if (akt_qs == pKey->type)
        {
            ubyte4 qsAlgoId = 0;
            sshStringBuffer *pAlgoName = NULL;
            ubyte4 cmpRes = -1;

            /* get QS algorithm identifier from context */
            if (OK > CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgoId))
                return NULL;

            /* get name of qs algorithm */
            if (OK > SSH_QS_getQsAlgorithmName(qsAlgoId, FALSE, &pAlgoName))
                return NULL;

            if (OK > MOC_MEMCMP(mHostKeySuites[index].pHostKeyName, pAlgoName->pString + 4, pAlgoName->stringLen - 4, &cmpRes))
                return NULL;

            if (0 != cmpRes)
                return NULL;
        }
#ifdef __ENABLE_MOCANA_ECC__
        else if (akt_hybrid == pKey->type)
        {
            ubyte4 qsAlgoId = 0;
            sshStringBuffer *pAlgoName = NULL;
            ubyte4 cmpRes = -1;

            /* get QS algorithm identifier from context */
            if (OK > CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgoId))
                return NULL;

            /* get name of qs algorithm */
            if (OK > SSH_HYBRID_getHybridAlgorithmName(pKey->clAlg, qsAlgoId, FALSE, &pAlgoName))
                return NULL;

            if (OK > MOC_MEMCMP(mHostKeySuites[index].pHostKeyName, pAlgoName->pString + 4, pAlgoName->stringLen - 4, &cmpRes))
                return NULL;

            if (0 != cmpRes)
                return NULL;
        }
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */

#ifdef __ENABLE_MOCANA_ECC__
        /* We want to make sure that the Host Key suite corresponds to the curve of the key extracted */
        if (akt_ecc == pKey->type)
        {
            ubyte4 curveId;
            ubyte4 expectedKeyLength;
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
            if (OK > CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pKey->key.pECC, &curveId))
#else
            if (OK > EC_getCurveIdFromKey(pKey->key.pECC, &curveId))
#endif
                return NULL;

            switch (curveId)
            {
                case cid_EC_P192:
                    expectedKeyLength = SSH_ECDSA_P192_SIZE;
                    break;
                case cid_EC_P224:
                    expectedKeyLength = SSH_ECDSA_P224_SIZE;
                    break;
                case cid_EC_P256:
                    expectedKeyLength = SSH_ECDSA_P256_SIZE;
                    break;
                case cid_EC_P384:
                    expectedKeyLength = SSH_ECDSA_P384_SIZE;
                    break;
                case cid_EC_P521:
                    expectedKeyLength = SSH_ECDSA_P521_SIZE;
                    break;
                default:
                    return NULL;
            };

            if (expectedKeyLength != mHostKeySuites[index].maxAlgoDetail)
                return NULL;
        }
#endif
    }
    else
    {
        ubyte4              pubKeyType = 0;
        const SizedBuffer*  pRetCertificates = NULL;
        ubyte4              numberCertificates = 0;

#ifdef __ENABLE_MOCANA_PQC__
        sshStringBuffer*    pName = NULL;
#endif

        ubyte4              curveId;
        ubyte4              qsAlgoId = 0;
        ubyte4              *pAlgoIdList = NULL;
        ubyte4              algoIdListLen = 0;

#ifdef __ENABLE_MOCANA_PQC__
        if (CERT_STORE_AUTH_TYPE_QS == mHostKeySuites[index].authType)
        {
            status = SSH_STR_makeStringBuffer(&pName, mHostKeySuites[index].hostKeyNameLength + 4);
            if (OK != status)
                return NULL;

            BIGEND32(pName->pString, pName->stringLen - 4);

            status = MOC_MEMCPY(pName->pString + 4, mHostKeySuites[index].pHostKeyName, pName->stringLen - 4);
            if (OK != status)
                return NULL;

            status = SSH_QS_getQsIdsByName((const sshStringBuffer *) pName, &qsAlgoId);
            if (OK != status)
                return NULL;
        }
        else if (CERT_STORE_AUTH_TYPE_HYBRID == mHostKeySuites[index].authType)
        {
            status = SSH_STR_makeStringBuffer(&pName, mHostKeySuites[index].hostKeyNameLength + 4);
            if (OK != status)
                return NULL;

            BIGEND32(pName->pString, pName->stringLen - 4);

            status = MOC_MEMCPY(pName->pString + 4, mHostKeySuites[index].pHostKeyName, pName->stringLen - 4);
            if (OK != status)
                return NULL;

            status = SSH_HYBRID_getHybridIdsByName((const sshStringBuffer *) pName, &curveId, &qsAlgoId);
            if (OK != status)
                return NULL;
        }
#endif


        if (OK > SSH_CERT_convertAuthTypeToKeyAlgo(mHostKeySuites[index].authType, qsAlgoId, mHostKeySuites[index].minAlgoDetail,
                                                   &pubKeyType, &pAlgoIdList, &algoIdListLen))
        {
            return NULL;  /* allocation failing is only possiblitity so ok to return, nothing to free */
        }

        status = CERT_STORE_findIdentityCertChainFirstFromList(pCookie, pubKeyType, 0, pAlgoIdList, algoIdListLen, NULL, 0,
                                                        (const AsymmetricKey **)&pKey, &pRetCertificates, &numberCertificates, NULL);
        /* done with pAlgoIdList, free now so we can cleanly return on errors */
        (void) MOC_FREE((void **) &pAlgoIdList);

        if (OK != status)
            return NULL;

        if ((NULL == pKey) || (NULL == pRetCertificates))
            return NULL;

    }

    if (NULL != pRetStringLength)
        *pRetStringLength = mHostKeySuites[index].hostKeyNameLength;

    return mHostKeySuites[index].pHostKeyName;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_TRANS_allocClassicDH(struct sshContext *pContextSSH)
{
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_DH_allocateServer(MOC_DH(pContextSSH->hwAccelCookie) g_pRandomContext, &SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), pContextSSH->pKeyExSuiteInfo->keyExHint);
#else
    return DH_allocateServer(MOC_DH(pContextSSH->hwAccelCookie) g_pRandomContext, &SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), pContextSSH->pKeyExSuiteInfo->keyExHint);
#endif
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_TRANS_freeClassicDH(struct sshContext *pContextSSH)
{
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_DH_freeDhContext(&SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), NULL);
#else
    return DH_freeDhContext(&SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), NULL);
#endif
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
static MSTATUS
SSH_TRANS_allocGroupDH(struct sshContext *pContextSSH)
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
SSH_TRANS_freeGroupDH(struct sshContext *pContextSSH)
{
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    return CRYPTO_INTERFACE_DH_freeDhContext(&pContextSSH->sshKeyExCtx.p_dhContext, NULL);
#else
    return DH_freeDhContext(&pContextSSH->sshKeyExCtx.p_dhContext, NULL);
#endif
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static MSTATUS
SSH_TRANS_allocRSA(struct sshContext *pContextSSH)
{
    AsymmetricKey*  srcKey;
    MSTATUS         status;

    if ((NULL == pContextSSH) || (NULL == pContextSSH->pKeyExSuiteInfo))
        return ERR_NULL_POINTER;

#ifdef __ENABLE_MOCANA_RSA_ALL_KEYSIZE__
    if (1024 == pContextSSH->pKeyExSuiteInfo->keyExHint)
        srcKey = &m_transientRsaKey1024;
    else
#endif
        srcKey = &m_transientRsaKey2048;

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_copyAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, srcKey);
#else
    status = CRYPTO_copyAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, srcKey);
#endif

    DEBUG_RELABEL_MEMORY(pContextSSH->sshKeyExCtx.transientKey.key.pRSA);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
static MSTATUS
SSH_TRANS_freeRSA(struct sshContext *pContextSSH)
{
    return CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS
SSH_TRANS_allocECDH(struct sshContext *pContextSSH)
{
    return CRYPTO_initAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey);
}
#endif /* (defined(__ENABLE_MOCANA_ECC__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS
SSH_TRANS_freeECDH(struct sshContext *pContextSSH)
{
    return CRYPTO_uninitAsymmetricKey(&pContextSSH->sshKeyExCtx.transientKey, NULL);
}
#endif


/*------------------------------------------------------------------*/


#if (!defined(__DISABLE_AES_CIPHERS__))
static BulkCtx
SSH_TRANS_createAESCTRCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* keyMaterial,
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
SSH_TRANS_doAESCTR(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
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
#endif /* __DISABLE_AES_CIPHERS__ */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_CHACHA20__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
/* IV is used as the nonce for chacha20, for SSH protocol, the nonce is the sequence number
 * of the packet */
static MSTATUS
SSH_TRANS_doChaCha20(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data,
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
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_TRANS_setMessageTimer(sshContext *pContextSSH, ubyte4 msTimeToExpire)
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
    DEBUG_ERROR(DEBUG_SSH_TRANSPORT, ", time to expire = ", msTimeToExpire);
#endif

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    if (NULL != SSH_sshSettings()->funcPtrStartTimer)
    {
        if (kOpenState <= SSH_UPPER_STATE(pContextSSH))
            SSH_sshSettings()->funcPtrStartTimer(CONNECTION_INSTANCE(pContextSSH), msTimeToExpire, 1);  /* authentication completed */
        else
            SSH_sshSettings()->funcPtrStartTimer(CONNECTION_INSTANCE(pContextSSH), msTimeToExpire, 0);  /* authentication not completed */
    }
#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
tcpWrite(sshContext *pContextSSH, ubyte *pData, ubyte4 dataLen)
{
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

#ifndef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    status = TCP_WRITE(SOCKET(pContextSSH), (sbyte *)pData, dataLen, &numBytesWritten);
#else
    status = MOC_STREAM_write(pContextSSH->pSocketOutStreamDescr, pData, dataLen, &numBytesWritten);
#endif

    if ((OK <= status) && (dataLen != numBytesWritten))
        status = ERR_TCP_WRITE_BLOCK_FAIL;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
digestString(sshContext *pContextSSH, BulkCtx *pKeyExHash, ubyte *pRawData, ubyte4 rawLength)
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

    DUMP((ubyte *)"update:", pLength, 4);
    DUMP((ubyte *)"update:", pRawData, rawLength);

exit:
    MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pLength));

    return status;
}


/*------------------------------------------------------------------*/

/* 
 * This function takes a byte string, converts it to Mpint byte string, and adds the result of that 
 * conversion to the hash context with an update call.
 */
static MSTATUS
digestMpintFromByteString(sshContext *pContextSSH, BulkCtx *pKeyExHash, ubyte *pRawBytes, ubyte4 rawBytesLen)
{
    ubyte*  pAsciiVlong = NULL;
    sbyte4  asciiLength = 0;
    MSTATUS status;

    status = SSH_mpintByteStringFromByteString(pRawBytes, rawBytesLen, 0, &pAsciiVlong, &asciiLength); 
    if (OK != status)
        goto exit;

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pKeyExHash, pAsciiVlong, (ubyte4)asciiLength);

exit:

    if (NULL != pAsciiVlong)
        FREE(pAsciiVlong);

    return status;
}


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
digestMpint(sshContext *pContextSSH, BulkCtx *pKeyExHash, vlong *pRawVlong)
{
    ubyte*  pAsciiVlong = NULL;
    ubyte*  pAsciiVlongClone = NULL;
    sbyte4  asciiLength;
    MSTATUS status;

    if (OK > (status = VLONG_mpintByteStringFromVlong(pRawVlong, &pAsciiVlong, &asciiLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pAsciiVlong);

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, asciiLength, TRUE, &pAsciiVlongClone)))
        goto exit;

    MOC_MEMCPY(pAsciiVlongClone, pAsciiVlong, asciiLength);

    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pKeyExHash, pAsciiVlongClone, (ubyte4)asciiLength);

    DUMP((ubyte *)"update:", pAsciiVlongClone, asciiLength);

exit:
    if (NULL != pAsciiVlongClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, (void **)(&pAsciiVlongClone));

    if (NULL != pAsciiVlong)
        FREE(pAsciiVlong);

    return status;
}
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */


/*------------------------------------------------------------------*/

extern void
SSH_TRANS_sendDisconnectMesg(sshContext *pContextSSH, ubyte4 sshError)
{
    ubyte4  errorMesgLen = 0;
    ubyte*  pErrorMesg = NULL;
    ubyte4  payloadLength = 0;
    ubyte*  pPayload = NULL;
    ubyte4  dummy;

    switch (pContextSSH->errorCode)
    {
        case ERR_AUTH_FAILED:
        {
            pErrorMesg = ssh_disconnectAuthMesg.pString;
            errorMesgLen = ssh_disconnectAuthMesg.stringLen;
            break;
        }

        default:
        {
            pErrorMesg = ssh_disconnectMesg.pString;
            errorMesgLen = ssh_disconnectMesg.stringLen;
            break;
        }
    }


    payloadLength = 5 + errorMesgLen + ssh_languageTag.stringLen;
    pPayload = MALLOC(payloadLength);

    if (NULL == pPayload)
        goto exit;

    pPayload[0] = SSH_MSG_DISCONNECT;

    pPayload[1] = (ubyte)(sshError >> 24);
    pPayload[2] = (ubyte)(sshError >> 16);
    pPayload[3] = (ubyte)(sshError >>  8);
    pPayload[4] = (ubyte)(sshError);

    MOC_MEMCPY(pPayload + 5, pErrorMesg, errorMesgLen);
    MOC_MEMCPY(pPayload + 5 + errorMesgLen, ssh_languageTag.pString, ssh_languageTag.stringLen);

    SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, payloadLength, &dummy);

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


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_TRANS_sendServerHello(sshContext *pContextSSH)
{
    ubyte*  pHelloString = NULL;
    MSTATUS status;

    if (OK != (status = MOC_MALLOC((void **)(&pHelloString), SERVER_HELLO_COMMENT_LEN(pContextSSH) + sizeof(CRLF))))
        goto exit;

    MOC_MEMCPY(pHelloString, (ubyte *)SERVER_HELLO_COMMENT(pContextSSH), SERVER_HELLO_COMMENT_LEN(pContextSSH));
    MOC_MEMCPY(pHelloString + SERVER_HELLO_COMMENT_LEN(pContextSSH), (ubyte *)CRLF, sizeof(CRLF)-1);

    /* send server hello message to client */
    if (OK > (status = tcpWrite(pContextSSH, pHelloString, (SERVER_HELLO_COMMENT_LEN(pContextSSH) + sizeof(CRLF)-1))))
        goto exit;

exit:
    MOC_FREE((void **)(&pHelloString));

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_TRANS_sendServerAlgorithms(sshContext *pContextSSH)
{
    intBoolean  copyToBuffer = FALSE;
    ubyte*      pPayload = NULL;
    ubyte4      index, i;
    ubyte4      numBytesWritten;
    MSTATUS     status;

    index = 0;

    if (NULL == pContextSSH->useThisList[HOST_KEY_ALGO].pString)
    {
        if (NULL == pContextSSH->pCertStore)
        {
            status = ERR_SSH_NO_ASSIGNED_CERT_STORE;
            goto exit;
        }

        if (OK > (status = SSH_STR_HOUSE_createFromList1(&pContextSSH->useThisList[HOST_KEY_ALGO], NUM_SSH_HOST_KEY_SUITES, SSH_TRANS_hostKeyList1, pContextSSH->pCertStore)))
            goto exit;

        if (4 >= pContextSSH->useThisList[HOST_KEY_ALGO].stringLen)
        {
            status = ERR_SSH_CONFIG;
            goto exit;
        }
    }

    do
    {
        for (i = 0; i < NUM_ALGORITHM_METHODS; i++)
        {
            if ((NULL != pContextSSH->useThisList[i].pString) && (0 != pContextSSH->useThisList[i].stringLen))
            {
                status = SSH_STR_copyFromString(pPayload, &index, &(pContextSSH->useThisList[i]), copyToBuffer);
                if (OK > status)
                    goto exit;
            }
            else
            {
                status = SSH_STR_copyFromString(pPayload, &index, ssh_algorithmMethods[i], copyToBuffer);

                if (OK > status)
                    goto exit;
            }
        }

        if (FALSE == copyToBuffer)
        {
            if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, (index + SSH2_KEXINIT_PAYLOAD_HEADER + SSH2_KEXINIT_PAYLOAD_TAIL) , TRUE, &pPayload)))
                goto exit;

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

    status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, index, &numBytesWritten);

    if ((OK <= status) && (index != numBytesWritten))
    {
        status = ERR_PAYLOAD_TOO_LARGE;
        goto exit;
    }

    /* save payload here */
    SERVER_KEX_INIT_PAYLOAD(pContextSSH)     = pPayload;
    SERVER_KEX_INIT_PAYLOAD_LEN(pContextSSH) = numBytesWritten;
    pPayload = NULL;

exit:
    if (NULL != pPayload)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, (void **)(&pPayload));

    return status;

} /* SSH_TRANS_sendServerAlgorithms */


/*------------------------------------------------------------------*/

static MSTATUS
generateHostCert(sshContext *pContextSSH)
{
    AsymmetricKey*  pTempKey = NULL;
    ubyte*          pCertificate;
    ubyte4          certificateLength;
    void*           pDummyHint;
    MSTATUS         status;

    if (OK > (status = CRYPTO_initAsymmetricKey(&pContextSSH->hostKey)))
        return status;

    if ((NULL == pContextSSH->pHostKeySuites) ||
        (NULL == pContextSSH->pHostKeySuites->pFuncBuildCert) ||
        (NULL == pContextSSH->pHostKeySuites->pFuncBuildSig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }

    if (OK > (status = CERT_STORE_findIdentityByTypeFirst(pContextSSH->pCertStore,
                                                          pContextSSH->pHostKeySuites->authType,
                                                          pContextSSH->pHostKeySuites->identityType,
                                                          (const AsymmetricKey **)&pTempKey,
                                                          (const ubyte **)&pCertificate,
                                                          &certificateLength, &pDummyHint)))
    {
        goto exit;
    }

    if (NULL == pTempKey)
    {
        status = ERR_SSH_MALFORMED_CERTIFICATE;
        goto exit;
    }

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_copyAsymmetricKey(&pContextSSH->hostKey, pTempKey);
#else
    status = CRYPTO_copyAsymmetricKey(&pContextSSH->hostKey, pTempKey);
#endif
    if (OK > status)
        goto exit;

    DEBUG_RELABEL_MEMORY(pContextSSH->hostKey.key.pRSA);

    if (OK > (status = pContextSSH->pHostKeySuites->pFuncBuildCert(pContextSSH, pCertificate, certificateLength)))
        goto exit;

    /* add K_S to the hash */
    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pContextSSH->pHostBlob, pContextSSH->hostBlobLength);
    DUMP((ubyte *)"update:", pContextSSH->pHostBlob, pContextSSH->hostBlobLength);

exit:
    return status;

} /* generateHostCert */


/*------------------------------------------------------------------*/

static MSTATUS
generateHostNewCert(sshContext *pContextSSH)
{
    AsymmetricKey*  pTempKey = NULL;
    ubyte4          pubKeyType;
    SizedBuffer*    pCertificates = NULL;
    ubyte4          numCertificates;
    void*           pDummyHint = NULL;
    sshStringBuffer *pName = NULL;
    ubyte4          curveId;
    ubyte4          qsAlgoId = 0;
    MSTATUS         status;
    ubyte4          *pAlgoIdList = NULL;
    ubyte4          algoIdListLen = 0;

    if (OK > (status = CRYPTO_initAsymmetricKey(&pContextSSH->hostKey)))
        return status;

    if ((NULL == pContextSSH->pHostKeySuites) ||
        (NULL == pContextSSH->pHostKeySuites->pFuncBuildCertChain) ||
        (NULL == pContextSSH->pHostKeySuites->pFuncBuildSig))
    {
        status = ERR_SSH_BAD_CALLBACK;
        goto exit;
    }

#if 0
    if (OK > (status = CERT_STORE_convertCertStoreKeyTypeToPubKeyType(pContextSSH->pHostKeySuites->authType, &pubKeyType)))
        goto exit;
#endif

#ifdef __ENABLE_MOCANA_PQC__
    if (CERT_STORE_AUTH_TYPE_QS == pContextSSH->pHostKeySuites->authType)
    {
        status = SSH_STR_makeStringBuffer(&pName, pContextSSH->pHostKeySuites->hostKeyNameLength + 4);
        if (OK != status)
            goto exit;

        BIGEND32(pName->pString, pName->stringLen - 4);

        status = MOC_MEMCPY(pName->pString + 4, pContextSSH->pHostKeySuites->pHostKeyName, pName->stringLen - 4);
        if (OK != status)
            goto exit;

        status = SSH_QS_getQsIdsByName((const sshStringBuffer *) pName, &qsAlgoId);
        if (OK != status)
            goto exit;
    }
    else if (CERT_STORE_AUTH_TYPE_HYBRID == pContextSSH->pHostKeySuites->authType)
    {
        status = SSH_STR_makeStringBuffer(&pName, pContextSSH->pHostKeySuites->hostKeyNameLength + 4);
        if (OK != status)
            goto exit;

        BIGEND32(pName->pString, pName->stringLen - 4);

        status = MOC_MEMCPY(pName->pString + 4, pContextSSH->pHostKeySuites->pHostKeyName, pName->stringLen - 4);
        if (OK != status)
            goto exit;

        status = SSH_HYBRID_getHybridIdsByName((const sshStringBuffer *) pName, &curveId, &qsAlgoId);
        if (OK != status)
            goto exit;
    }
#endif
    
    /* for certificate authentication in NanoSSH, minKeySize and maxKeySize are the same value for ECC, and only used for ECC */
    if (OK > (status = SSH_CERT_convertAuthTypeToKeyAlgo(pContextSSH->pHostKeySuites->authType, qsAlgoId, pContextSSH->pHostKeySuites->minAlgoDetail,
                                                         &pubKeyType, &pAlgoIdList, &algoIdListLen)) )
    {
        goto exit;
    }

    if (OK > (status = CERT_STORE_findIdentityCertChainFirstFromList(pContextSSH->pCertStore, pubKeyType, 0, pAlgoIdList, algoIdListLen, NULL, 0,
        (const AsymmetricKey **) &pTempKey, (const SizedBuffer **)&pCertificates, &numCertificates, &pDummyHint)) )
    {
        goto exit;
    }

    if (NULL == pCertificates)
    {
        /* no identity found */
        status = ERR_SSH_NO_IDENTITY_FOUND;
        goto exit;
    }

    if (NULL == pTempKey)
    {
        status = ERR_SSH_MALFORMED_CERTIFICATE;
        goto exit;
    }

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_copyAsymmetricKey(&pContextSSH->hostKey, pTempKey);
#else
    status = CRYPTO_copyAsymmetricKey(&pContextSSH->hostKey, pTempKey);
#endif
    if (OK > status)
        goto exit;

    DEBUG_RELABEL_MEMORY(pContextSSH->hostKey.key.pRSA);

    if (OK > (status = pContextSSH->pHostKeySuites->pFuncBuildCertChain(pContextSSH, pCertificates, numCertificates)))
        goto exit;

    /* add K_S to the hash */
    status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pContextSSH->pHostBlob, pContextSSH->hostBlobLength);
    DUMP((ubyte *)"update:", pContextSSH->pHostBlob, pContextSSH->hostBlobLength);

exit:

    if(NULL != pAlgoIdList)
    {
        (void) MOC_FREE((void **) &pAlgoIdList);
    }

    return status;

} /* generateHostNewCert */


/*------------------------------------------------------------------*/

static MSTATUS
rematchAeadAlgorithms(sshContext *pContextSSH, ubyte *pOptionsSelected,
                      ubyte4 cipherIndex, ubyte4 hmacIndex)
{
    intBoolean  inString;
    ubyte4      optionIndex;
    MSTATUS     status;

    /* AEAD algorithms MUST match their HMAC algorithm */
    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "rematchAeadAlgorithms: AEAD mismatch, cipher chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName);
    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "rematchAeadAlgorithms: AEAD mismatch, hmac chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName);

    if (NULL != mCipherSuites[pOptionsSelected[cipherIndex] - 1].pAeadSuiteInfo)
    {
        /* aead symmetric takes precedence over (any [aead | hmac]) hmac */
        if (OK > (status = SSH_STR_findOption(((NULL == pContextSSH->useThisList[hmacIndex].pString) ?
                                                    ssh_algorithmMethods[hmacIndex] : &pContextSSH->useThisList[hmacIndex] ),
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
         if (NULL != pContextSSH->useThisList[hmacIndex].pString)
         {
            if (OK > (status = SSH_STR_findOption( ssh_algorithmMethods[hmacIndex],
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

        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "rematchAeadAlgorithms: AEAD rematch, cipher chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName);
        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "rematchAeadAlgorithms: AEAD rematch, hmac chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName);
    }
    else
    {
        /* hmac takes precedence over non-aead symmetric */
        if (OK > (status = SSH_STR_findOption(((NULL == pContextSSH->useThisList[cipherIndex].pString) ?
                                                    ssh_algorithmMethods[cipherIndex] : &pContextSSH->useThisList[cipherIndex]),
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
         if (NULL != pContextSSH->useThisList[cipherIndex].pString)
         {
            if (OK > (status = SSH_STR_findOption( ssh_algorithmMethods[cipherIndex],
                                (ubyte *)mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName,
                                         mHmacSuites[pOptionsSelected[hmacIndex] - 1].hmacNameLength,
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
        pOptionsSelected[cipherIndex] = optionIndex;

        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "rematchAeadAlgorithms: AEAD rematch, cipher chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName);
        DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "rematchAeadAlgorithms: AEAD rematch, hmac chosen = ");
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, mHmacSuites[pOptionsSelected[hmacIndex] - 1].pHmacName);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*
 * OpenSSH GCM handling:
 * AES-GCM is only negotiated as the cipher algorithms
 * "aes128-gcm@openssh.com" or "aes256-gcm@openssh.com" and never as
 * an MAC algorithm. Additionally, if AES-GCM is selected as the cipher
 * the exchanged MAC algorithms are ignored and there doesn't have to be
 * a matching MAC.
 */
static sbyte4
handleGcmAtOpenssh(sbyte4 cipherIndex, sbyte4 macIndex, ubyte *pOptionsSelected)
{
    MSTATUS status;
    sbyte4 wordIndex = 0;
    intBoolean inString = FALSE;

    if (0 >= pOptionsSelected[cipherIndex])
        return 0;

    if (0 == MOC_STRCMP("aes128-gcm@openssh.com", mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName) ||
        0 == MOC_STRCMP("aes256-gcm@openssh.com", mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName))
    {
        /* corresponding mac algorithm list for selected cipher is always 2 entries ahead. */
        status = SSH_STR_findOption(ssh_algorithmMethods[macIndex],
            mCipherSuites[pOptionsSelected[cipherIndex] - 1].pCipherName,
            mCipherSuites[pOptionsSelected[cipherIndex] - 1].cipherNameLength,
            &inString, &wordIndex);
        if (OK > status)
            return 0;

        if (FALSE == inString)
            return 0;
    }

    return wordIndex;
}

/*------------------------------------------------------------------*/

static MSTATUS
receiveClientAlgorithms(sshContext *pContextSSH, ubyte *pOptionsSelected,
                        ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*                    pClientAlgorithm[NUM_ALGORITHM_METHODS];
    ubyte4                              optionIndex;
    ubyte*                              pClonedMesg = NULL;
    ubyte4                              index, i, count;
    MSTATUS                             status = OK;
    intBoolean                          firstKexPacketFollows = FALSE;
    sbyte4                              wordIndex;
    intBoolean                          inString = FALSE;

    /* init array of pointers */
    for (index = 0; index < NUM_ALGORITHM_METHODS; index++)
        pClientAlgorithm[index] = NULL;

    if (SSH_MSG_KEXINIT != (*pNewMesg))
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    index = SSH2_KEXINIT_PAYLOAD_HEADER;

    for (i = 0; i < NUM_ALGORITHM_METHODS; i++)
    {
        status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &(pClientAlgorithm[i]));
        if (OK > status)
            goto exit;
    }

    count = 0;

    /* check the remaining bytes */
    if (5 != (newMesgLen - index))
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if (0x01 == pNewMesg[index])
        firstKexPacketFollows = TRUE;

    for (i = 0; i < NUM_ALGORITHM_METHODS; i++)
    {
        if ((NULL != pContextSSH->useThisList[i].pString) && (0 != pContextSSH->useThisList[i].stringLen))
        {
            /* find option in custom list */
            SSH_STR_locateOption(pClientAlgorithm[i], &(pContextSSH->useThisList[i]), &optionIndex);

            if (optionIndex)
            {
                ubyte*      pOption = NULL;
                ubyte4      optionLen;
                ubyte4      stringIndex = 4;

                /* extract option from custom list */
                do
                {
                    status = SSH_STR_getOption(&(pContextSSH->useThisList[i]), &stringIndex, &pOption, &optionLen);
                    if (OK > status)
                        goto exit;

                    if (!(--optionIndex))
                        break;

                    FREE(pOption);
                    pOption = NULL;
                }
                while (optionIndex);

                optionIndex = 0;

                /* verify custom option available(/map to) in larger list */
                if (NULL != pOption)
                {
                    status = SSH_STR_findOption(ssh_algorithmMethods[i], pOption, optionLen, &inString, &optionIndex);

                    FREE(pOption);
                    pOption = NULL;

                    if (OK > status)
                        goto exit;
                }
            }
        }
        else
        {
            optionIndex = 0;
            switch (i)
            {
                case HOST_KEY_ALGO:
                    break;
                case MAC_C2S_ALGO:
                case MAC_S2C_ALGO:
                    /* if cipher algorithm are *gcm@openssh.com, we ignore mac algorithms */
                    optionIndex = handleGcmAtOpenssh(i - 2, i, pOptionsSelected);
                    break;
            };

            if (0 == optionIndex)
            {
                status = SSH_STR_locateOption(pClientAlgorithm[i], ssh_algorithmMethods[i], &optionIndex);
                if (OK > status)
                    goto exit;
            }

            switch (i)
            {
                case KEX_ALGO:
                    if (TRUE == firstKexPacketFollows)
                    {
                        /* RFC 4253 Section 7.1 
                            first_kex_packet_follows
                                Indicates whether a guessed key exchange packet follows.  If a
                                guessed packet will be sent, this MUST be TRUE.  If no guessed
                                packet will be sent, this MUST be FALSE.

                                After receiving the SSH_MSG_KEXINIT packet from the other side,
                                each party will know whether their guess was right.  If the
                                other party's guess was wrong, and this field was TRUE, the
                                next packet MUST be silently ignored, and both sides MUST then
                                act as determined by the negotiated key exchange method. 
                        */
                        pContextSSH->kexGuessMismatch = FALSE;
                        if (1 == optionIndex)
                        {
                            status = SSH_STR_findOption(pClientAlgorithm[i],
                            mKeyExSuites[optionIndex - 1].pKeyExName,
                            mKeyExSuites[optionIndex - 1].keyExNameLength,
                            &inString, &wordIndex);
                            if (OK != status)
                                goto exit;

                            if (FALSE == inString || 1 != wordIndex)
                            {
                                pContextSSH->kexGuessMismatch = TRUE;
                            }
                        }
                        else
                        {
                            pContextSSH->kexGuessMismatch = TRUE;
                        }
                    }

#ifndef __DISABLE_DIGICERT_RFC_8308__
                    status = SSH_STR_findOption(pClientAlgorithm[i],
                        "ext-info-s", MOC_STRLEN("ext-info-s"), &inString, &wordIndex);
                    if (OK != status)
                        goto exit;

                    if (TRUE == inString)
                    {
                        /*
                            Section 2.2. Enabling Criteria
                            Implementations MUST NOT send an incorrect indicator name for their
                            role.  Implementations MAY disconnect if the counterparty sends an
                            incorrect indicator.  If "ext-info-c" or "ext-info-s" ends up being
                            negotiated as a key exchange method, the parties MUST disconnect.
                        */
                        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
                        goto exit;
                    }

                    /*
                      Section 2.2. Enabling Criteria
                      If a server receives an "ext-info-c", or a client receives an
                      "ext-info-s", it MAY send an SSH_MSG_EXT_INFO message but is not
                      required to do so.
                    */
                    status = SSH_STR_findOption(pClientAlgorithm[i],
                        "ext-info-c", MOC_STRLEN("ext-info-c"), &inString, &wordIndex);
                    if (OK != status)
                        goto exit;

                    if (TRUE == inString)
                    {
                        pContextSSH->msgExtInfoEnabled = TRUE;
                    }
#endif
                    break;
            }
        }

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

    if (OK > (status = MOC_MEMCPY(pClonedMesg, pNewMesg, (sbyte4)newMesgLen)))
        goto exit;

    CLIENT_KEX_INIT_PAYLOAD(pContextSSH)     = pClonedMesg;
    CLIENT_KEX_INIT_PAYLOAD_LEN(pContextSSH) = newMesgLen;
    pClonedMesg = NULL;

    /* ---------------------------- */
    /* handle key exchange algorithm */
    if (NULL != pContextSSH->pKeyExSuiteInfo)
    {
        if (NULL != pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx)
        {
            /* free key exchange context (dh, rsa, ecdh, etc) to avoid memory leak when client sends key re-exchange message */
            pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx(pContextSSH);
        }

        if ((NULL != pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo) && (NULL != pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc))
        {
            /* free hash context to avoid memory leak when we re-key */
            if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
                pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &(pContextSSH->sshKeyExCtx.pKeyExHash));
        }

        if (NULL != SSH_HASH_H(pContextSSH))
        {
            if (OK > (status = CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &SSH_HASH_H(pContextSSH))))
                goto exit;

            SSH_HASH_H(pContextSSH) = NULL;
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

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "receiveClientAlgorithms: keyEx algo chosen = ");
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
    pContextSSH->pHostKeySuites = &(mHostKeySuites[pOptionsSelected[1] - 1]);

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "receiveClientAlgorithms: hostAuth algo chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pContextSSH->pHostKeySuites->pHostKeyName);

    if (CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 != pContextSSH->pHostKeySuites->identityType)
    {
        /* Classic SSH */
        if (OK > (status = generateHostCert(pContextSSH)))
            goto exit;
    }
    else
    {
       /* RFC 6187 */
       if (OK > (status = generateHostNewCert(pContextSSH)))
            goto exit;
    }

    /* ---------------------------------------------------------- */
    /* handle AEAD algorithm (RFC-5647, Section 5.1, Paragraph 2) */
    if ((NULL != mCipherSuites[pOptionsSelected[2] - 1].pAeadSuiteInfo) ||
        (NULL != mHmacSuites[pOptionsSelected[4] - 1].pAeadSuiteInfo))
    {
        /* AEAD algorithms MUST match their HMAC algorithm */
        if ((mCipherSuites[pOptionsSelected[2] - 1].cipherNameLength != mHmacSuites[pOptionsSelected[4] - 1].hmacNameLength) ||
            (0 != MOC_STRCMP(mCipherSuites[pOptionsSelected[2] - 1].pCipherName, mHmacSuites[pOptionsSelected[4] - 1].pHmacName)) )
        {
            if (OK > (status = rematchAeadAlgorithms(pContextSSH, pOptionsSelected, 2, 4)))
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
            if (OK > (status = rematchAeadAlgorithms(pContextSSH, pOptionsSelected, 3, 5)))
                goto exit;
        }
    }

exit:
    /* free array of pointers */
    for (index = 0; index < NUM_ALGORITHM_METHODS; index++)
        if (NULL != pClientAlgorithm[index])
            SSH_STR_freeStringBuffer(&pClientAlgorithm[index]);

    if (NULL != pClonedMesg)
    {
        FREE(pClonedMesg);
    }

    return status;

} /* receiveClientAlgorithms */


/*------------------------------------------------------------------*/

static MSTATUS
receiveClientKeyExchange(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    vlong*  pVlongQueue = NULL;
    ubyte4  bytesUsed;
    MSTATUS status;
    ubyte*  pE = NULL;
    ubyte*  pSharedSecret = NULL;
    ubyte4  sharedSecretLen = 0, offset;
    sshKeyExDescr*          pKeyEx = NULL;

    /* will be used to offset leading 0x00 bytes in generated secret */
    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (SSH_MSG_KEXDH_INIT != (*pNewMesg))
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    status = SSH_getByteStringFromMpintBytes(pNewMesg+1, newMesgLen-1, &pE, &bytesUsed);
    if (OK != status)
        goto exit;

    if (4 + bytesUsed != newMesgLen-1)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* add e to the hash */
    /*!!!! need to clone e */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg+1, newMesgLen-1))) 
    goto exit;

    DUMP((ubyte *)"update:", pNewMesg+1, newMesgLen-1);

    offset = 0;
    while ((offset < bytesUsed) && (0x00 == pE[offset])) offset++;

    /* Perform DH computations, based on the incoming e */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_computeKeyExchangeEx(MOC_DH(pContextSSH->hwAccelCookie) SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), g_pRandomContext, pE + offset, bytesUsed - offset, &pSharedSecret, &sharedSecretLen);
    if (OK != status)
        goto exit;
#else
    status = DH_computeKeyExchangeEx(MOC_DH(pContextSSH->hwAccelCookie) SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), g_pRandomContext, pE, bytesUsed, &pSharedSecret, &sharedSecretLen);
    if (OK != status)
        goto exit;
#endif

    offset = 0;
    /* Move past padding */
    while ((offset < sharedSecretLen) && (0x00 == pSharedSecret[offset])) offset++;

    /* store shared secret (K) for later consumption */
    pKeyEx->bytesSharedSecretLen = sharedSecretLen - offset;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pKeyEx->pBytesSharedSecret, pSharedSecret + offset, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;
exit:
    VLONG_freeVlongQueue(&pVlongQueue);

    if (NULL != pE)
        MOC_FREE((void**)&pE);

    if (NULL != pSharedSecret)
    {
        MOC_MEMSET(pSharedSecret, 0x00, sharedSecretLen);
        MOC_FREE((void**)&pSharedSecret);
    }

    return status;

} /* receiveClientKeyExchange */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
receiveClientDHGKeyExchangeRequest(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte*  pTempClone = NULL;
    ubyte4  min;
    ubyte4  preferred;
    ubyte4  max;
    MSTATUS status = OK;

    if ((SSH_MSG_KEY_DH_GEX_REQUEST != (*pNewMesg)) && (SSH_MSG_KEX_DH_GEX_REQUEST_OLD != (*pNewMesg)))
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if ((SSH_MSG_KEY_DH_GEX_REQUEST == *pNewMesg) && (13 != newMesgLen))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if ((SSH_MSG_KEX_DH_GEX_REQUEST_OLD == *pNewMesg) && (5 != newMesgLen))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)(&pTempClone))))
        goto exit;

    if (13 == newMesgLen)
    {
        min =       MOC_NTOHL(1 + pNewMesg);
        preferred = MOC_NTOHL(5 + pNewMesg);
        max =       MOC_NTOHL(9 + pNewMesg);
    }
    else
    {
        min =       1024;
        preferred = MOC_NTOHL(1 + pNewMesg);
        max =       8192;
    }

    if (!((min <= preferred) && (preferred <= max)))
    {
        status = ERR_SSH_KEYEX_BAD_INPUT;
        goto exit;
    }

    /* Here SSH_TRANS_findSafePrimesDHG() was used to get P and G for the key exchange,
     * and use that to set values for diffie hellman context.
     * Using mapping functions we generate P and G at allocation time. */
    /* set P and G, then generate the the key */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_freeDhContext(&SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), NULL);
#else
    status = DH_freeDhContext(&SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), NULL);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_allocateServer(MOC_DH(pContextSSH->hwAccelCookie) g_pRandomContext, &SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), DH_GROUP_14);
#else
    status = DH_allocateServer(MOC_DH(pContextSSH->hwAccelCookie) g_pRandomContext, &SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), DH_GROUP_14);
#endif
    if (OK != status)
        goto exit;

    if (13 == newMesgLen)
    {
        /* save variables here */
        MOC_MEMCPY(pTempClone, 1 + pNewMesg, 12);

        /* add min, n(preferred), max to the hash */
        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pTempClone, 12)))
            goto exit;

        DUMP((ubyte *)"update:", pTempClone, 12);
    }
    else
    {
        /* save variables here */
        MOC_MEMCPY(pTempClone, 1 + pNewMesg, 4);

        /* add min, n(preferred), max to the hash */
        if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pTempClone, 4)))
            goto exit;

        DUMP((ubyte *)"update:", pTempClone, 4);
    }

exit:
    MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&pTempClone));

    return status;

} /* receiveClientDHGKeyExchangeRequest */

#endif /* (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
sendDHGSafePrimeKeyExchange(sshContext *pContextSSH)
{
    ubyte*  pBufP = NULL;
    ubyte*  pBufG = NULL;
    ubyte*  pReplyMesg = NULL;
    sbyte4  LenP;
    sbyte4  LenG;
    ubyte4  replyMesgLen;
    ubyte4  bytesWritten;
    MSTATUS status;
    MDhKeyTemplate  template = {0};

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_getKeyParametersAlloc(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), MOC_GET_PUBLIC_KEY_DATA);
#else
    status = DH_getKeyParametersAlloc(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(template.pP, template.pLen, 0, &pBufP, &LenP); 
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(template.pG, template.gLen, 0, &pBufG, &LenG); 
    if (OK != status)
        goto exit;
    replyMesgLen = 1 + LenP + LenG;
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, replyMesgLen, TRUE, (void **)&pReplyMesg)))
        goto exit;

    /* form message */
    *pReplyMesg = SSH_MSG_KEX_DH_GEX_GROUP;
    MOC_MEMCPY(1 + pReplyMesg, pBufP, LenP);
    MOC_MEMCPY(1 + LenP + pReplyMesg, pBufG, LenG);

    /* add p(safe prime) and g (generator) to the hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, 1 + pReplyMesg, replyMesgLen - 1)))
        goto exit;

    DUMP((ubyte *)"update:", 1 + pReplyMesg, replyMesgLen - 1);

    /* send message */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pReplyMesg, replyMesgLen, &bytesWritten)))
        goto exit;

    if (bytesWritten != replyMesgLen)
        status = ERR_PAYLOAD_TOO_LARGE;

exit:
    if (NULL != pReplyMesg)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, (void **)&pReplyMesg);

    if (NULL != pBufG)
        FREE(pBufG);

    if (NULL != pBufP)
        FREE(pBufP);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplate(NULL, &template);
#else
    DH_freeKeyTemplate(NULL, &template);
#endif

    return status;
}

#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))

static MSTATUS
receiveClientDHGKeyExchangeInit(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte4  bytesUsed;
    MSTATUS status;
    ubyte*  pE = NULL;
    ubyte*  pSharedSecret = NULL;
    ubyte4  sharedSecretLen = 0;
    diffieHellmanContext*   pCtx = NULL;

    /* will be used to move past leading 0x00 bytes in pSharedSecret */
    ubyte4 offset = 0;
    sshKeyExDescr*          pKeyEx = NULL;
    if (SSH_MSG_KEX_DH_GEX_INIT != *pNewMesg)
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }
    pCtx = SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH);
    if (NULL == pCtx)
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

    status = SSH_getByteStringFromMpintBytes(pNewMesg+1, newMesgLen-1, &pE, &bytesUsed);
    if (OK != status)
        goto exit;

    if(pE)
    {
        while ((offset < bytesUsed) && (0x00 == pE[offset])) offset++;
    }

    /* first 4 bytes are length */
    if (4 + bytesUsed != newMesgLen-1)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* add e to the hash */
    /*!!!!! clone e */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg+1, newMesgLen-1)))
        goto exit;
    DUMP((ubyte *)"update:", 1 + pNewMesg, newMesgLen - 1);
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_computeKeyExchangeEx(MOC_DH(pContextSSH->hwAccelCookie) SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), g_pRandomContext, pE + offset, bytesUsed - offset, &pSharedSecret, &sharedSecretLen);
#else
    status = DH_computeKeyExchangeEx(MOC_DH(pContextSSH->hwAccelCookie) SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), g_pRandomContext, pE, bytesUsed, &pSharedSecret, &sharedSecretLen);
#endif
    if (OK != status)
        goto exit;

    /* reset offset, then count leading 0x00 bytes in pSharedSecret */
    offset = 0;
    while ((offset < sharedSecretLen) && (0x00 == pSharedSecret[offset])) offset++;
    pKeyEx->bytesSharedSecretLen = sharedSecretLen - offset;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pKeyEx->pBytesSharedSecret, pSharedSecret + offset, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;
exit:

    if (NULL != pSharedSecret)
    {
        MOC_MEMSET(pSharedSecret, 0x00, sharedSecretLen);
        MOC_FREE((void**)&pSharedSecret);
    }

    if (NULL != pE)
        MOC_FREE((void**)&pE);

    return status;

} /* receiveClientDHGKeyExchangeInit */

#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))

static MSTATUS
SSH_TRANS_sendKexRsaPubKey(struct sshContext *pContextSSH)
{
    ubyte*          pReplyMesg = NULL;
    ubyte4          replyMesgLen;
    ubyte4          bytesWritten;
    ubyte4          index;
    ubyte*          K_T    = NULL;
    ubyte4          K_Tlen = 0;
    MSTATUS         status;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = SSH_RSA_buildRsaCertificate(MOC_RSA(pContextSSH->hwAccelCookie) &(pContextSSH->sshKeyExCtx.transientKey), TRUE, &K_T, &K_Tlen)))
        goto exit;

    DEBUG_RELABEL_MEMORY(K_T);

    /* Send RFC 4432::SSH_MSG_KEXRSA_PUBKEY message K_S + K_T */
    replyMesgLen = 1 + pContextSSH->hostBlobLength + K_Tlen;

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, 1 + pContextSSH->hostBlobLength + K_Tlen, TRUE, &pReplyMesg)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pReplyMesg);

    /* set message type */
    pReplyMesg[0] = SSH_MSG_KEXRSA_PUBKEY;
    index = 1;

    /* store certificate & public host key length */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pContextSSH->pHostBlob, pContextSSH->hostBlobLength)))
        goto exit;
    index += pContextSSH->hostBlobLength;

    /* store transient public RSA key (K_T) */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, K_T, K_Tlen)))
        goto exit;

    /* add K_T to the hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pReplyMesg + index, K_Tlen)))
        goto exit;
    DUMP((ubyte *)"update:", pReplyMesg + index, K_Tlen);

    /* send it out */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pReplyMesg, replyMesgLen, &bytesWritten)))
        goto exit;

    if (bytesWritten != replyMesgLen)
        status = ERR_PAYLOAD_TOO_LARGE;

exit:
    if (NULL != pReplyMesg)
        FREE(pReplyMesg);

    if (NULL != K_T)
        FREE(K_T);

    return status;

} /* SSH_TRANS_sendKexRsaPubKey */

#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
SSH_TRANS_receiveKexRsaSecret(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pEncryptedSecret = NULL;
    ubyte*              pSecret = NULL;
    ubyte4              secretLength;
    ubyte4              index;
    ubyte4              bytesUsed;
    ubyte               H_rsaAlgoId;
    vlong*              pVlongQueue = NULL;
    MSTATUS             status;

    if (SSH_MSG_KEXRSA_SECRET != *pNewMesg)
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* RFC 4432: only two RSA-SHA methods defined */
    H_rsaAlgoId = (2048 == pContextSSH->pKeyExSuiteInfo->keyExHint) ? sha256withRSAEncryption : sha1withRSAEncryption;

    index = 1;

    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pEncryptedSecret)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEncryptedSecret);

    if (index != newMesgLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* add encrypted secret to the hash */
    /*!!!!! clone encrypted secret */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg+1, newMesgLen-1)))
        goto exit;
    DUMP((ubyte *)"update:", 1 + pNewMesg, newMesgLen - 1);

    /*!!!! hack: need to check length field and properly extract */
    if (OK > (status = PKCS1_rsaesOaepDecrypt(MOC_RSA(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.transientKey.key.pRSA, H_rsaAlgoId, PKCS1_MGF1_FUNC, 5 + pNewMesg, newMesgLen - 5, NULL, 0, &pSecret, &secretLength)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSecret);

    /* add secret to the hash */
    /*!!!!! clone secret */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pSecret, secretLength)))
        goto exit;
    DUMP((ubyte *)"update:", pSecret, secretLength);

    /*!!!!! since pSecret is really an encoding for mpint, we need to test here to make sure the length is okay */

    if (OK > (status = VLONG_newFromMpintBytes(pSecret, secretLength, &(SSH_K(pContextSSH)), &bytesUsed, &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(SSH_K(pContextSSH));

    if (secretLength != bytesUsed)
    {
        status = ERR_SSH_KEYEX_MESG_FORMAT;
        goto exit;
    }

exit:
    SSH_STR_freeStringBuffer(&pEncryptedSecret);

    if (NULL != pSecret)
        FREE(pSecret);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSH_TRANS_receiveKexRsaSecret */
#endif /* __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))

static MSTATUS
SSH_TRANS_sendKexRsaDone(sshContext *pContextSSH)
{
    ubyte*          pReplyMesg    = NULL;
    ubyte4          replyMesgLen;
    ubyte4          bytesWritten;
    ubyte4          index;
    ubyte*          pSignature        = NULL;
    ubyte4          signatureLength   = 0;
    MSTATUS         status;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* compute H */
    /* save hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;

    DUMP((ubyte *)"final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &SSH_SESSION_ID(pContextSSH))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    /* create signature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncBuildSig(pContextSSH, SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, &pSignature, &signatureLength, &pContextSSH->hostKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSignature);
    DEBUG_RELABEL_MEMORY(pContextSSH->hostKey.key.pRSA);

    /* Send SSH_MSG_KEXRSA_DONE message */
    replyMesgLen = 1 + signatureLength;

    if (NULL == (pReplyMesg = MALLOC(replyMesgLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set message type */
    pReplyMesg[0] = SSH_MSG_KEXRSA_DONE;
    index = 1;

    /* store signature blob */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pSignature, signatureLength)))
        goto exit;
    index += signatureLength;

    /* send it out */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pReplyMesg, replyMesgLen, &bytesWritten)))
        goto exit;

    if (bytesWritten != replyMesgLen)
        status = ERR_PAYLOAD_TOO_LARGE;

exit:
    if (NULL != pReplyMesg)
        FREE(pReplyMesg);

    if (NULL != pContextSSH) {
        if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

        if (NULL != pContextSSH->pHostBlob)
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &pContextSSH->pHostBlob);

        if (NULL != pSignature)
            FREE(pSignature);

        if (NULL != CLIENT_KEX_INIT_PAYLOAD(pContextSSH))
        {
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(CLIENT_KEX_INIT_PAYLOAD(pContextSSH)));
            CLIENT_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
        }

        if (NULL != SERVER_KEX_INIT_PAYLOAD(pContextSSH))
        {
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(SERVER_KEX_INIT_PAYLOAD(pContextSSH)));
            SERVER_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
        }

        /* clear out the cloned key */
        CRYPTO_uninitAsymmetricKey(&pContextSSH->hostKey, NULL);
    }

    return status;

} /* SSH_TRANS_sendKexRsaDone */

#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSH_TRANS_receiveClientKexHybridInit(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pEphemeralKey = NULL;
    ubyte4              pubKeyLen;
    ubyte4              qsPubLen;
    ubyte4              index;
    MSTATUS             status;

    if ((SSH_MSG_KEX_HYBRID_INIT != *pNewMesg) || (5 > newMesgLen))
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    index = 1;

    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pEphemeralKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEphemeralKey);

    if (index != newMesgLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* add ephemeral key to the hash */
    /*!!!!! clone ephemeral key */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg+1, newMesgLen-1)))
        goto exit;
    DUMP((ubyte *)"update:", 1 + pNewMesg, newMesgLen - 1);

    /* do a simple sanity check for now... */
    if (4 >= pEphemeralKey->stringLen)
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* initialize the ephemeral key */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(pContextSSH->hwAccelCookie) &(pContextSSH->sshKeyExCtx.transientKey.pQsCtx), pContextSSH->pKeyExSuiteInfo->qsKeyExHint);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pContextSSH->sshKeyExCtx.transientKey.pQsCtx, &qsPubLen);
    if (OK != status)
        goto exit;
    
    pubKeyLen = MOC_NTOHL(pEphemeralKey->pString);

    /* validate we have at least more than a qs pub*/
    if (pubKeyLen <= qsPubLen)
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_setPublicKey(pContextSSH->sshKeyExCtx.transientKey.pQsCtx, pEphemeralKey->pString + 4, qsPubLen);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_setECCParameters(MOC_ECC(pContextSSH->hwAccelCookie) &(pContextSSH->sshKeyExCtx.transientKey),
                                     pContextSSH->pKeyExSuiteInfo->keyExHint,
                                     pEphemeralKey->pString + 4 + qsPubLen, pubKeyLen - qsPubLen, NULL, 0);
exit:

    if (NULL != pEphemeralKey)
    {
        SSH_STR_freeStringBuffer(&pEphemeralKey);
    }

    return status;

} /* SSH_TRANS_receiveClientKexHybridInit */
#endif /* __ENABLE_MOCANA_PQC__ */

static MSTATUS
SSH_TRANS_receiveClientKexEcdhInit(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer*    pEphemeralKey = NULL;
    ubyte4              index;
    MSTATUS             status;

    if ((SSH_MSG_KEX_ECDH_INIT != *pNewMesg) || (5 > newMesgLen))
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    index = 1;

    if (OK > (status = SSH_STR_copyStringFromPayload(pNewMesg, newMesgLen, &index, &pEphemeralKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEphemeralKey);

    if (index != newMesgLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* add ephemeral key to the hash */
    /*!!!!! clone ephemeral key */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pNewMesg+1, newMesgLen-1)))
        goto exit;
    DUMP((ubyte *)"update:", 1 + pNewMesg, newMesgLen - 1);

    /* do a simple sanity check for now... */
    if (4 >= pEphemeralKey->stringLen)
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    /* initialize the ephemeral key */
    if (OK > (status = CRYPTO_setECCParameters(MOC_ECC(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.transientKey,
                                               pContextSSH->pKeyExSuiteInfo->keyExHint,
                                               4 + pEphemeralKey->pString, pEphemeralKey->stringLen - 4, NULL, 0)))
    {
        goto exit;
    }
exit:
    SSH_STR_freeStringBuffer(&pEphemeralKey);

    return status;

} /* SSH_TRANS_receiveClientKexEcdhInit */

#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))

#if (defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSH_TRANS_sendClientKexHybridReply(sshContext *pContextSSH)
{
    ECCKey*         pECCKey = NULL;
    ECCKey*         pECCPubKey = NULL;
    QS_CTX*         pQsCtx = NULL;
    ubyte*          pCombinedKey = NULL;
    ubyte4          combinedKeyLen;
    ubyte4          ephemeralEccKeyLen;
    ubyte*          pEccSharedSecret = NULL;
    sbyte4          eccSharedSecretLen;
    ubyte*          pQsSharedSecret = NULL;
    sbyte4          qsSharedSecretLen;
    ubyte*          pCipherSS = NULL;
    sbyte4          cipherSSLen;
    ubyte*          pReplyMesg = NULL;
    ubyte4          replyMesgLen;
    ubyte4          bytesWritten;
    ubyte4          index;
    ubyte*          pSignature = NULL;
    ubyte4          signatureLength;
    MSTATUS         status;
    ubyte4          curveID;
    ubyte4          start;
    BulkCtx         ssHashCtx = NULL;

    sshKeyExDescr*          pKeyEx = NULL;

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pECCKey = pContextSSH->sshKeyExCtx.transientKey.key.pECC;
    pQsCtx  = pContextSSH->sshKeyExCtx.transientKey.pQsCtx;

    status = ERR_NULL_POINTER;
    if (NULL == pECCKey)
        goto exit;

    /* get the length of the ECDH point */
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &ephemeralEccKeyLen);
    if (OK != status)
        goto exit;

    /* pCipher is the encrypted public key used by the responder, in this case SSH server */
    status = CRYPTO_INTERFACE_QS_KEM_encapsulateAlloc(pQsCtx, RANDOM_rngFun, g_pRandomContext, &pCipherSS, &cipherSSLen, &pQsSharedSecret, &qsSharedSecretLen);
    if (ERR_BAD_KEY == status)
    {
        SSH_TRANS_sendDisconnectMesg(pContextSSH, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }
    else if (OK != status)
        goto exit;

    combinedKeyLen = 4 + ephemeralEccKeyLen + cipherSSLen;
    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, combinedKeyLen, TRUE, &pCombinedKey)))
        goto exit;

    /* get curve ID */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveID);
    if(OK != status)
        goto exit;

    /* generate a key with the given curveID */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(MOC_ECC(pContextSSH->hwAccelCookie) curveID, &pECCPubKey, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* set buffer up */
    pCombinedKey[0] = (((ephemeralEccKeyLen + cipherSSLen) >> 24) & 0xff);
    pCombinedKey[1] = (((ephemeralEccKeyLen + cipherSSLen) >> 16) & 0xff);
    pCombinedKey[2] = (((ephemeralEccKeyLen + cipherSSLen) >>  8) & 0xff);
    pCombinedKey[3] = ((ephemeralEccKeyLen + cipherSSLen)       & 0xff);

    status = MOC_MEMCPY(pCombinedKey + 4, pCipherSS, cipherSSLen);
    if (OK != status)
        goto exit;

    index = 4 + cipherSSLen;
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCPubKey, pCombinedKey + index, ephemeralEccKeyLen);
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(pCombinedKey);

    /* add S_REPLY = S_CT2 || S_PK1 to the hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pCombinedKey, combinedKeyLen)))
        goto exit;

    DUMP((ubyte *)"update:", pCombinedKey, combinedKeyLen);

    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCPubKey, pECCKey, &pEccSharedSecret, &eccSharedSecretLen, 1, NULL); 
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

    DEBUG_RELABEL_MEMORY(pKeyEx->pBytesSharedSecret);
    DUMP((ubyte *)"shared secret:", pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);

    /* add combined shared secret to hash H */
    status = digestString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;
    
    /* compute H */
    /* save hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;

    DUMP((ubyte *)"final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &SSH_SESSION_ID(pContextSSH))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    /* create signature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncBuildSig(pContextSSH, SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, &pSignature, &signatureLength, &pContextSSH->hostKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSignature);
    DEBUG_RELABEL_MEMORY(pContextSSH->hostKey.key.pECC);

    /* Send SSH_MSG_KEX_ECDH_REPLY message */
    replyMesgLen = 1 + pContextSSH->hostBlobLength + combinedKeyLen + signatureLength;

    status = MOC_MALLOC((void **) &pReplyMesg, replyMesgLen);
    if (OK != status)
        goto exit;

    /* set message type */
    pReplyMesg[0] = SSH_MSG_KEX_HYBRID_REPLY;
    index = 1;

    /* store certificate (K_S) & public host key length */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pContextSSH->pHostBlob, pContextSSH->hostBlobLength)))
        goto exit;
    index += pContextSSH->hostBlobLength;
    start = index;

    /* store ephemeral public key */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pCombinedKey, combinedKeyLen)))
        goto exit;

    index += combinedKeyLen;
    /* store signature blob */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pSignature, signatureLength)))
        goto exit;
    index += signatureLength;

    /* send it out */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pReplyMesg, replyMesgLen, &bytesWritten)))
        goto exit;

    if (bytesWritten != replyMesgLen)
        status = ERR_PAYLOAD_TOO_LARGE;

exit:

    if (NULL != pReplyMesg)
        FREE(pReplyMesg);

    if (NULL != pSignature)
        FREE(pSignature);

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

    if (NULL != pCipherSS)
    {
        MOC_FREE((void **) &pCipherSS);
    }

    if(NULL != pContextSSH)
    {
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pCombinedKey);

        if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

        if (NULL != ssHashCtx)
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &ssHashCtx);

        if (NULL != pContextSSH->sshKeyExCtx.transientKey.pQsCtx)
            CRYPTO_INTERFACE_QS_deleteCtx(&pContextSSH->sshKeyExCtx.transientKey.pQsCtx);

        if (NULL != pContextSSH->pHostBlob)
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &pContextSSH->pHostBlob);

        if (NULL != CLIENT_KEX_INIT_PAYLOAD(pContextSSH))
        {
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(CLIENT_KEX_INIT_PAYLOAD(pContextSSH)));
            CLIENT_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
        }
    
        if (NULL != SERVER_KEX_INIT_PAYLOAD(pContextSSH))
        {
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(SERVER_KEX_INIT_PAYLOAD(pContextSSH)));
            SERVER_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
        }
    
        /* clear out the cloned key */
        CRYPTO_uninitAsymmetricKey(&pContextSSH->hostKey, NULL);
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pECCPubKey);
#else
    EC_deleteKey(&pECCPubKey);
#endif
    return status;
} /* SSH_TRANS_sendClientKexHybridReply */
#endif /* __ENABLE_MOCANA_PQC__ */

static MSTATUS
SSH_TRANS_sendClientKexEcdhReply(sshContext *pContextSSH)
{
    ECCKey*         pECCKey = NULL;
    ECCKey*         pECCPubKey = NULL;
    ubyte*          pEphemeralKey = NULL;
    ubyte4          ephemeralKeyLen;
    ubyte*          sharedSecret = NULL;
    sbyte4          sharedSecretLen;
    ubyte*          pReplyMesg = NULL;
    ubyte4          replyMesgLen;
    ubyte4          bytesWritten;
    ubyte4          index;
    ubyte*          pSignature = NULL;
    ubyte4          signatureLength;
    MSTATUS         status;
    ubyte4          curveID;

    /* used to move past leading 0x00 bytes in sharedSecret */
    ubyte4 offset = 0;

    sshKeyExDescr*          pKeyEx = NULL;

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pECCKey = pContextSSH->sshKeyExCtx.transientKey.key.pECC ;

    status = ERR_NULL_POINTER;
    if (NULL == pECCKey)
        goto exit;

    /* get the length of the ECDH point */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &ephemeralKeyLen);
    if (OK != status)
        goto exit;
#else
    status = EC_getPointByteStringLenEx(pECCKey, &ephemeralKeyLen);
    if (OK != status)
        goto exit;
#endif

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, 4 + ephemeralKeyLen, TRUE, &pEphemeralKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pEphemeralKey);

    /* get curve ID */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveID);
    if(OK != status)
        goto exit;
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveID);
    if (OK != status)
        goto exit;
#endif
    /* generate a key with the given curveID */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(MOC_ECC(pContextSSH->hwAccelCookie) curveID, &pECCPubKey, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;
#else
    status = EC_generateKeyPairAlloc(MOC_ECC(pContextSSH->hwAccelCookie) curveID, &pECCPubKey, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;
#endif

    /* set buffer up */
    pEphemeralKey[0] = ((ephemeralKeyLen >> 24) & 0xff);
    pEphemeralKey[1] = ((ephemeralKeyLen >> 16) & 0xff);
    pEphemeralKey[2] = ((ephemeralKeyLen >>  8) & 0xff);
    pEphemeralKey[3] = ((ephemeralKeyLen)       & 0xff);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCPubKey, 4 + pEphemeralKey, ephemeralKeyLen);
    if (OK != status)
        goto exit;
#else
    status = EC_writePublicKeyToBuffer(MOC_ECC(pContextSSH->hwAccelCookie) pECCPubKey, 4 + pEphemeralKey, ephemeralKeyLen);
    if (OK != status)
        goto exit;
#endif

    /*!!!! clone it */
    /* add public emphermal point to hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, pEphemeralKey, 4 + ephemeralKeyLen)))
        goto exit;

    DUMP((ubyte *)"update:", pEphemeralKey, 4 + ephemeralKeyLen);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux(MOC_ECC(pContextSSH->hwAccelCookie) pECCPubKey, pECCKey, &sharedSecret, (ubyte4 *) &sharedSecretLen, 1, NULL); 
    if (OK != status)
        goto exit;
#else
    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(pContextSSH->hwAccelCookie) pECCPubKey, pECCKey, &sharedSecret, (ubyte4 *) &sharedSecretLen, 1, NULL); 
    if (OK != status)
        goto exit;
#endif

    /* move past 0x00 bytes in sharedSecret */
    while (((sbyte4) offset < sharedSecretLen) && (0x00 == sharedSecret[offset])) offset++;

    pKeyEx->bytesSharedSecretLen = sharedSecretLen - offset;
    status = MOC_MALLOC((void**)&(pKeyEx->pBytesSharedSecret), pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pKeyEx->pBytesSharedSecret, sharedSecret + offset, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(sharedSecret);

    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;

    /* compute H */
    /* save hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;

    DUMP((ubyte *)"final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &SSH_SESSION_ID(pContextSSH))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    /* create signature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncBuildSig(pContextSSH, SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, &pSignature, &signatureLength, &pContextSSH->hostKey)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pSignature);
    DEBUG_RELABEL_MEMORY(pContextSSH->hostKey.key.pECC);

    /* Send SSH_MSG_KEX_ECDH_REPLY message */
    replyMesgLen = 1 + pContextSSH->hostBlobLength + 4 + ephemeralKeyLen + signatureLength;

    if (NULL == (pReplyMesg = MALLOC(replyMesgLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set message type */
    pReplyMesg[0] = SSH_MSG_KEX_ECDH_REPLY;
    index = 1;

    /* store certificate (K_S) & public host key length */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pContextSSH->pHostBlob, pContextSSH->hostBlobLength)))
        goto exit;
    index += pContextSSH->hostBlobLength;

    /* store ephemeral public key */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pEphemeralKey, 4 + ephemeralKeyLen)))
        goto exit;
    index += 4 + ephemeralKeyLen;

    /* store signature blob */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pSignature, signatureLength)))
        goto exit;
    index += signatureLength;

    /* send it out */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pReplyMesg, replyMesgLen, &bytesWritten)))
        goto exit;

    if (bytesWritten != replyMesgLen)
        status = ERR_PAYLOAD_TOO_LARGE;


exit:

    if (NULL != pReplyMesg)
        FREE(pReplyMesg);

    if (NULL != pSignature)
        FREE(pSignature);

    if (NULL != sharedSecret)
    {
        MOC_MEMSET(sharedSecret, 0x00, sharedSecretLen);
        FREE(sharedSecret);
    }

    if(NULL != pContextSSH)
    {
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pEphemeralKey);

        if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

        if (NULL != pContextSSH->pHostBlob)
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &pContextSSH->pHostBlob);

        if (NULL != CLIENT_KEX_INIT_PAYLOAD(pContextSSH))
        {
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(CLIENT_KEX_INIT_PAYLOAD(pContextSSH)));
            CLIENT_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
        }
    
        if (NULL != SERVER_KEX_INIT_PAYLOAD(pContextSSH))
        {
            CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(SERVER_KEX_INIT_PAYLOAD(pContextSSH)));
            SERVER_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
        }
    
        /* clear out the cloned key */
        CRYPTO_uninitAsymmetricKey(&pContextSSH->hostKey, NULL);
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pECCPubKey);
#else
    EC_deleteKey(&pECCPubKey);
#endif
    return status;

} /* SSH_TRANS_sendClientKexEcdhReply */

#endif


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_MOCANA_ECC__)) && (defined(__ENABLE_MOCANA_PQC__)))
static MSTATUS
SSH_TRANS_buildHybridKey(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength)
{
    MSTATUS status;

    if (akt_hybrid != (pContextSSH->hostKey.type & 0xff))
    {
        status = ERR_SSH_EXPECTED_HYBRID_KEY;
        goto exit;
    }

    status = SSH_HYBRID_buildHybridKey(MOC_ASYM(pContextSSH->hwAccelCookie) &pContextSSH->hostKey, FALSE,
                                       TRUE, &(pContextSSH->pHostBlob), &(pContextSSH->hostBlobLength));
exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PQC__
static MSTATUS
SSH_TRANS_buildQsKey(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength)
{
    MSTATUS status;

    if (akt_qs != (pContextSSH->hostKey.type & 0xff))
    {
        status = ERR_SSH_EXPECTED_QS_KEY;
        goto exit;
    }

    status = SSH_QS_buildQsKey(&pContextSSH->hostKey, FALSE, TRUE, &(pContextSSH->pHostBlob), &(pContextSSH->hostBlobLength));
exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
static MSTATUS
SSH_TRANS_buildDsaSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey)
{
    ubyte*  kBuf = NULL;
    vlong*  pM = NULL;
    vlong*  pVlongQueue = NULL;
    MSTATUS status;

    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->mediumPool, (void **)&(kBuf))))
        goto exit;

    /* compute signature */
    if (OK > (status = SHA1_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, kBuf)))
        goto exit;
    DUMP((ubyte *)"SHA1_completeDigest:", kBuf, SHA_HASH_RESULT_SIZE);

    if (OK > (status = VLONG_vlongFromByteString(kBuf, SHA_HASH_RESULT_SIZE, &pM, &pVlongQueue)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pM);

    status = SSH_DSS_buildDssSignature(MOC_DSA(pContextSSH->hwAccelCookie) pKey, TRUE, pM, ppSignature, pSignatureLength, &pVlongQueue);

    if(NULL != ppSignature)
        DEBUG_RELABEL_MEMORY(*ppSignature);

exit:
    VLONG_freeVlong(&pM, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    if (NULL != kBuf)
        MEM_POOL_putPoolObject(&pContextSSH->mediumPool, (void **)(&kBuf));

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
static MSTATUS
SSH_TRANS_buildRsaSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey)
{
    ubyte*  dataToSign = NULL;
    MSTATUS status;

    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_rsa != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->smallPool, (void **)&(dataToSign))))
        goto exit;

#ifndef __DISABLE_MOCANA_SHA512__
    if (pContextSSH->pHostKeySuites->hashLen == SHA512_RESULT_SIZE)
    {
        if (OK > (status = SHA512_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, dataToSign)))
            goto exit;
        DUMP((ubyte *)"SHA512_completeDigest:", dataToSign, SHA512_RESULT_SIZE);
    }
    else
#endif /* __DISABLE_MOCANA_SHA512__ */
#ifndef __DISABLE_MOCANA_SHA256__
    if (pContextSSH->pHostKeySuites->hashLen == SHA256_RESULT_SIZE)
    {
        if (OK > (status = SHA256_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, dataToSign)))
            goto exit;
        DUMP((ubyte *)"SHA256_completeDigest:", dataToSign, SHA256_RESULT_SIZE);
    }
    else
#endif
    {
        if (OK > (status = SHA1_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, dataToSign)))
            goto exit;
        DUMP((ubyte *)"SHA1_completeDigest:", dataToSign, SHA_HASH_RESULT_SIZE);
    }

    status = SSH_RSA_buildRsaSignature(MOC_RSA(pContextSSH->hwAccelCookie) pKey, TRUE, ppSignature, pSignatureLength, dataToSign, pContextSSH->pHostKeySuites->hashLen, (ubyte *) pContextSSH->pHostKeySuites->pHostKeyName, pContextSSH->pHostKeySuites->hostKeyNameLength);

exit:
    if( dataToSign != NULL )
    {
        MEM_POOL_putPoolObject(&pContextSSH->smallPool, (void **)(&dataToSign));
    }
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__))
static MSTATUS
SSH_TRANS_buildEcdsaSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte4 hashAlgo = 0;
    ubyte*  kBuf = NULL;
    ubyte4 hashSize = 20;

    if (NULL == pKey)
    {
        return ERR_NULL_POINTER;
    }
    
    if (akt_ecc_ed == (pKey->type & 0xff))
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

        status = SSH_ECDSA_buildEcdsaSignatureEx(MOC_ECC(pContextSSH->hwAccelCookie) pKey, hashAlgo, pDigestData, digestLen, ppSignature, pSignatureLength);
    }
    else
    {
        if (OK > (status = MEM_POOL_getPoolObject(&pContextSSH->mediumPool, (void **)&(kBuf))))
            goto exit;

        /* compute signature */
        hashSize = pContextSSH->pHostKeySuites->hashLen;
        switch (hashSize) {
#ifndef __DISABLE_MOCANA_SHA256__
            case SHA256_RESULT_SIZE: if (OK > (status = SHA256_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, kBuf)))
                                              {
                                                goto exit;
                                              }
                                              break;
#endif
#ifndef __DISABLE_MOCANA_SHA384__
            case SHA384_RESULT_SIZE: if (OK > (status = SHA384_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, kBuf)))
                                              {
                                                goto exit;
                                              }
                                              break;
#endif
#ifndef __DISABLE_MOCANA_SHA512__
            case SHA512_RESULT_SIZE: if (OK > (status = SHA512_completeDigest(MOC_HASH(pContextSSH->hwAccelCookie) pDigestData, digestLen, kBuf)))
                                              {
                                                goto exit;
                                              }
                                              break;
#endif
            default : status = ERR_CERT_UNSUPPORTED_DIGEST;
                      goto exit;
          }

        status = SSH_ECDSA_buildEcdsaSignature(MOC_ECC(pContextSSH->hwAccelCookie) pKey, TRUE, kBuf, hashSize, ppSignature, pSignatureLength);
    }

    if(NULL != ppSignature)
        DEBUG_RELABEL_MEMORY(*ppSignature);
exit:
    if (NULL != kBuf)
        MEM_POOL_putPoolObject(&pContextSSH->mediumPool, (void **)(&kBuf));

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_ECC__) && defined(__ENABLE_MOCANA_PQC__))
static MSTATUS
SSH_TRANS_buildHybridSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey)
{
    MSTATUS status;

    if (NULL == pKey)
    {
        return ERR_NULL_POINTER;
    }

    /* compute signature */
    status = SSH_HYBRID_buildHybridSignature(MOC_ASYM(pContextSSH->hwAccelCookie) pKey, FALSE, TRUE, pDigestData, digestLen, ppSignature, pSignatureLength);
    if (OK != status)
        goto exit;

    if(NULL != ppSignature)
        DEBUG_RELABEL_MEMORY(*ppSignature);
exit:

    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PQC__
static MSTATUS
SSH_TRANS_buildQsSignature(sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey)
{
    MSTATUS status;

    if (NULL == pKey)
    {
        return ERR_NULL_POINTER;
    }

    /* compute signature */
    status = SSH_QS_buildQsSignature(pKey, FALSE, TRUE, pDigestData, digestLen, ppSignature, pSignatureLength);
    if (OK != status)
        goto exit;

    if(NULL != ppSignature)
        DEBUG_RELABEL_MEMORY(*ppSignature);
exit:

    return status;
}
#endif /* __ENABLE_MOCANA_PQC__ */

/*------------------------------------------------------------------*/

static MSTATUS
replyToClientKeyExchange(sshContext *pContextSSH, ubyte replyCode)
{
    ubyte*          pStringMpintF = NULL;
    ubyte4          stringLenF;
    ubyte*          pReplyMesg    = NULL;
    ubyte4          replyMesgLen;
    ubyte4          bytesWritten;
    ubyte4          index;
    ubyte*          pSignature        = NULL;
    ubyte4          signatureLength   = 0;
    MSTATUS         status;
    MDhKeyTemplate  template = {0};
    sshKeyExDescr*          pKeyEx = NULL;

    pKeyEx = &(pContextSSH->sshKeyExCtx);
    if (NULL == pKeyEx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContextSSH)
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_getKeyParametersAlloc(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), MOC_GET_PUBLIC_KEY_DATA);
#else
    status = DH_getKeyParametersAlloc(MOC_DH(pContextSSH->hwAccelCookie) &template, SSH_DIFFIEHELLMAN_CONTEXT(pContextSSH), MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(template.pF, template.fLen, 0, &pStringMpintF, (sbyte4 *)&stringLenF);
    if (OK != status)
        goto exit;

    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, template.pF, template.fLen);
    if (OK != status)
        goto exit;

    status = digestMpintFromByteString(pContextSSH, pContextSSH->sshKeyExCtx.pKeyExHash, pKeyEx->pBytesSharedSecret, pKeyEx->bytesSharedSecretLen);
    if (OK != status)
        goto exit;
    /* save hash */
    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pContextSSH->sshKeyExCtx.pKeyExHash, SSH_HASH_H(pContextSSH))))
        goto exit;

    DUMP((ubyte *)"final:", SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    /* save first copy of hash as session identifier */
    if (NULL == SSH_SESSION_ID(pContextSSH))
    {
        if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, TRUE, &SSH_SESSION_ID(pContextSSH))))
            goto exit;

        DEBUG_RELABEL_MEMORY(SSH_SESSION_ID(pContextSSH));

        MOC_MEMCPY(SSH_SESSION_ID(pContextSSH), SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

        pContextSSH->sessionIdLength = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize;
    }

    /* create signature */
    if (OK > (status = pContextSSH->pHostKeySuites->pFuncBuildSig(pContextSSH, SSH_HASH_H(pContextSSH), pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize, &pSignature, &signatureLength, &pContextSSH->hostKey)))
        goto exit;

    /* Send SSH_MSG_KEXDH_REPLY message */
    replyMesgLen = 1 + pContextSSH->hostBlobLength + stringLenF + signatureLength;

    if (NULL == (pReplyMesg = MALLOC(replyMesgLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* set message type */
    pReplyMesg[0] = replyCode;
    index = 1;

    /* store certificate & public host key length */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pContextSSH->pHostBlob, pContextSSH->hostBlobLength)))
        goto exit;
    index += pContextSSH->hostBlobLength;

    /* copy f mpint string */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pStringMpintF, stringLenF)))
        goto exit;
    index += stringLenF;

    /* store signature blob */
    if (OK > (status = MOC_MEMCPY(pReplyMesg + index, pSignature, signatureLength)))
        goto exit;

    /* send it out */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pReplyMesg, replyMesgLen, &bytesWritten)))
        goto exit;

    if (bytesWritten != replyMesgLen)
        status = ERR_PAYLOAD_TOO_LARGE;

exit:
    if (NULL != pReplyMesg)
        FREE(pReplyMesg);

    if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &pContextSSH->sshKeyExCtx.pKeyExHash);

    if (NULL != pContextSSH->pHostBlob)
        CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &pContextSSH->pHostBlob);

    if (NULL != pSignature)
        FREE(pSignature);

    if (NULL != pStringMpintF)
        FREE(pStringMpintF);

    if (NULL != CLIENT_KEX_INIT_PAYLOAD(pContextSSH))
    {
        CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(CLIENT_KEX_INIT_PAYLOAD(pContextSSH)));
        CLIENT_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
    }

    if (NULL != SERVER_KEX_INIT_PAYLOAD(pContextSSH))
    {
        CRYPTO_FREE((pContextSSH)->hwAccelCookie, TRUE, &(SERVER_KEX_INIT_PAYLOAD(pContextSSH)));
        SERVER_KEX_INIT_PAYLOAD(pContextSSH) = NULL;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplate(NULL, &template);
#else
    DH_freeKeyTemplate(NULL, &template);
#endif

    /* clear out the cloned key */
    CRYPTO_uninitAsymmetricKey(&pContextSSH->hostKey, NULL);

    return status;

} /* replyToClientKeyExchange */

/*------------------------------------------------------------------*/

static MSTATUS
makeKeyFromByteString(sshContext *pContextSSH, BulkCtx* pHashContext, ubyte *k, ubyte4 kLen, ubyte *H, ubyte chr,
        ubyte *pSessionId, ubyte *pKeyBuffer, ubyte4 keyBufferSize)
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
    DEBUG_RELABEL_MEMORY(stringK);

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

    DUMP((ubyte *)"makeKeyFromByteString update:", stringKClone, stringLenK);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize /* SHA_HASH_RESULT_SIZE */)))
        goto exit;

    DUMP((ubyte *)"makeKeyFromByteString update:", H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pChr, 1)))
        goto exit;

    DUMP((ubyte *)"makeKeyFromByteString update:", pChr, 1);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pSessionId, pContextSSH->sessionIdLength)))
        goto exit;

    DUMP((ubyte *)"makeKeyFromByteString update:", pSessionId, pContextSSH->sessionIdLength);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer)))
        goto exit;

    DUMP((ubyte *)"makeKeyFromByteString final:", pTempKeyBuffer, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    m = 1;
    /* add as much key material as required for the key */
    while (keyBufferSize > m*pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize)
    {
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

} /* makeKeyFromByteString */


/*------------------------------------------------------------------*/

#ifndef __ENABLE_MOCANA_CRYPTO_INTERFACE__
static MSTATUS
makeKey(sshContext *pContextSSH, BulkCtx* pHashContext, vlong *k, ubyte *H, ubyte chr,
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

    DEBUG_RELABEL_MEMORY(stringK);

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

    DUMP((ubyte *)"makeKey update:", stringKClone, stringLenK);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize /* SHA_HASH_RESULT_SIZE */)))
        goto exit;

    DUMP((ubyte *)"makeKey update:", H, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pChr, 1)))
        goto exit;

    DUMP((ubyte *)"makeKey update:", pChr, 1);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pUpdateFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pSessionId, pContextSSH->sessionIdLength)))
        goto exit;

    DUMP((ubyte *)"makeKey update:", pSessionId, pContextSSH->sessionIdLength);

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFinalFunc(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pTempKeyBuffer)))
        goto exit;

    DUMP((ubyte *)"makeKey final:", pTempKeyBuffer, pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->hashResultSize);

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
sendNewKeysMessage(sshContext *pContextSSH)
{
    ubyte       payload = (ubyte)SSH_MSG_NEWKEYS;
    ubyte4      length;
    MSTATUS     status;

    /* zero out bytes transmitted each time we send out NEWKEYS */
    ZERO_U8(pContextSSH->bytesTransmitted);

    /* send SSH_MSG_NEWKEYS message */
    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, &payload, 1, &length)))
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

#ifdef __ENABLE_MOCANA_SP800_135_ACVP__
extern MSTATUS
#else
static MSTATUS
#endif
receiveNewKeysMessage(sshContext *pContextSSH, ubyte *pOptionsSelected,
                      ubyte *pNewMesg, ubyte4 newMesgLen)
{
    PATCH_CONST SSH_CipherSuiteInfo*    pCipherSuite;
    PATCH_CONST SSH_hmacSuiteInfo*      pHmacSuite;
    BulkCtx                             hashContext = NULL;
    ubyte*                              pKeyBuffer = NULL;
    MSTATUS                             status = OK;

    if ((1 != newMesgLen) || (SSH_MSG_NEWKEYS != *pNewMesg))
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

    if (OK > (status = pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pAllocFunc(MOC_HASH(pContextSSH->hwAccelCookie) &hashContext)))
        goto exit;

     pHmacSuite = &(mHmacSuites[pOptionsSelected[4] - 1]);

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, 4 * pHmacSuite->hmacDigestLength , TRUE, &pKeyBuffer)))
        goto exit;

    /* switch to the new algorithms */
    /* ---------------------------- */
    /* handle client --> server decryption */
    pCipherSuite =  &(mCipherSuites[pOptionsSelected[2] - 1]);

    INBOUND_CIPHER_TYPE(pContextSSH) = pOptionsSelected[2] - 1;

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "receiveNewKeysMessage: decrypt cipher chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pCipherSuite->pCipherName);

    /* free previous context */
    if (NULL != INBOUND_CIPHER_CONTEXT_FREE(pContextSSH))
        (INBOUND_CIPHER_CONTEXT_FREE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) &INBOUND_CIPHER_CONTEXT(pContextSSH));

    /* init inbound iv key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'A', SSH_SESSION_ID(pContextSSH),
                               INBOUND_CIPHER_IV(pContextSSH), pCipherSuite->ivSize)))
    {
        goto exit;
    }

    if ((NULL == (INBOUND_CIPHER_SUITE_INFO(pContextSSH) = pCipherSuite)) || (NULL == pCipherSuite->pBEAlgo))
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    if (CHACHA20_POLY1305_OPENSSH == INBOUND_CIPHER_TYPE(pContextSSH))
    {
        /* init inbound decipher key */
        if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                                   pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                                   pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                                   SSH_HASH_H(pContextSSH),
                                   'C', SSH_SESSION_ID(pContextSSH),
                                   pKeyBuffer, 2*pCipherSuite->keySize)))
        {
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT,(sbyte *) "DECRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, 2*pCipherSuite->keySize);

        /* K_2 context is used to decrypt payload */
        if (NULL == (INBOUND_CIPHER_CONTEXT(pContextSSH) = (INBOUND_CIPHER_CREATE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 0)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* K_1 context for decrypting payload length bytes */
        if (NULL == (INBOUND_CIPHER_CONTEXT2(pContextSSH) = (INBOUND_CIPHER_CREATE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer + pCipherSuite->keySize, pCipherSuite->keySize, 0)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
#endif
#endif /* (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)) */
    {
        /* init inbound decipher key */
        if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                                   pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                                   pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                                   SSH_HASH_H(pContextSSH),
                                   'C', SSH_SESSION_ID(pContextSSH),
                                   pKeyBuffer, pCipherSuite->keySize)))
        {
            goto exit;
        }

        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT,(sbyte *) "DECRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, pCipherSuite->keySize);

        if (NULL == (INBOUND_CIPHER_CONTEXT(pContextSSH) = (INBOUND_CIPHER_CREATE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 0)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    /* block / iv size */
    /* ----------------------------------- */
    /* handle server --> client encryption */
    pCipherSuite =  &(mCipherSuites[pOptionsSelected[3] - 1]);
    OUTBOUND_CIPHER_TYPE(pContextSSH) = pOptionsSelected[3] - 1;

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "receiveNewKeysMessage: encrypt cipher chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pCipherSuite->pCipherName);

    /* free previous context */
    if (NULL != OUTBOUND_CIPHER_CONTEXT_FREE(pContextSSH))
        (OUTBOUND_CIPHER_CONTEXT_FREE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) &OUTBOUND_CIPHER_CONTEXT(pContextSSH));

    /* init outbound iv key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'B', SSH_SESSION_ID(pContextSSH),
                               OUTBOUND_CIPHER_IV(pContextSSH), pCipherSuite->ivSize)))
    {
        goto exit;
    }

    if ((NULL == (OUTBOUND_CIPHER_SUITE_INFO(pContextSSH) = pCipherSuite)) || (NULL == pCipherSuite->pBEAlgo))
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    if (CHACHA20_POLY1305_OPENSSH == OUTBOUND_CIPHER_TYPE(pContextSSH))
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
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, (sbyte *)"ENCRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, 2*pCipherSuite->keySize);

        /* K_2 context is used to encrypt payload */
        if (NULL == (OUTBOUND_CIPHER_CONTEXT(pContextSSH) = (OUTBOUND_CIPHER_CREATE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* K_1 context is used to encrypt payload length bytes */
        if (NULL == (OUTBOUND_CIPHER_CONTEXT2(pContextSSH) = (OUTBOUND_CIPHER_CREATE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer + pCipherSuite->keySize, pCipherSuite->keySize, 1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
#endif
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
        DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, (sbyte *)"ENCRYPT KEY");
        DEBUG_HEXDUMP(DEBUG_SSH_TRANSPORT, pKeyBuffer, pCipherSuite->keySize);

        if (NULL == (OUTBOUND_CIPHER_CONTEXT(pContextSSH) = (OUTBOUND_CIPHER_CREATE(pContextSSH))(MOC_SYM(pContextSSH->hwAccelCookie) pKeyBuffer, pCipherSuite->keySize, 1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    /* block / iv size */
    /* ---------------------------------------- */
    /* configure for client to server hmac-sha1 */
    /* free inbound hmac buffer */
    if (NULL != INBOUND_MAC_BUFFER(pContextSSH))
    {
        FREE(INBOUND_MAC_BUFFER(pContextSSH));
        INBOUND_MAC_BUFFER(pContextSSH) = NULL;
    }

    /* free inbound key data */
    if (NULL != INBOUND_KEY_DATA(pContextSSH))
    {
        CRYPTO_FREE( (pContextSSH)->hwAccelCookie, TRUE, &(INBOUND_KEY_DATA(pContextSSH)) ) ;
        INBOUND_KEY_DATA(pContextSSH) = NULL;
    }

    // Moved to beginning of the function
    // pHmacSuite = &(mHmacSuites[pOptionsSelected[4] - 1]);

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "receiveNewKeysMessage: inbound hmac chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pHmacSuite->pHmacName);

    /* inbound hmac-sha1 buffer */
    if (NULL == (INBOUND_MAC_BUFFER(pContextSSH) = MALLOC(pHmacSuite->hmacDigestLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'E', SSH_SESSION_ID(pContextSSH),
                               pKeyBuffer, pHmacSuite->hmacDigestLength)))
    {
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pHmacSuite->hmacDigestLength, TRUE, &(INBOUND_KEY_DATA(pContextSSH)))))
        goto exit;

    MOC_MEMCPY(INBOUND_KEY_DATA(pContextSSH), pKeyBuffer, pHmacSuite->hmacDigestLength);

    INBOUND_KEY_DATA_LEN(pContextSSH)  = pHmacSuite->hmacKeyLength;

    /* inbound hmac methods */
    INBOUND_MAC_INFO(pContextSSH)      = pHmacSuite;

    /* ---------------------------------------- */
    /* configure for server to client hmac-sha1/2 */
    /* free outbound key data */
    if (NULL != OUTBOUND_KEY_DATA(pContextSSH))
    {
        CRYPTO_FREE( pContextSSH->hwAccelCookie, TRUE, &(OUTBOUND_KEY_DATA(pContextSSH)) ) ;
        OUTBOUND_KEY_DATA(pContextSSH) = NULL;
    }

    pHmacSuite = &(mHmacSuites[pOptionsSelected[5] - 1]);

    DEBUG_PRINT(DEBUG_SSH_TRANSPORT, "receiveNewKeysMessage: outbound hmac chosen = ");
    DEBUG_PRINTNL(DEBUG_SSH_TRANSPORT, pHmacSuite->pHmacName);

    /* init outbound hmac key */
    if (OK > (status = makeKeyFromByteString(pContextSSH, hashContext,
                               pContextSSH->sshKeyExCtx.pBytesSharedSecret,
                               pContextSSH->sshKeyExCtx.bytesSharedSecretLen,
                               SSH_HASH_H(pContextSSH),
                               'F', SSH_SESSION_ID(pContextSSH),
                               pKeyBuffer, pHmacSuite->hmacDigestLength)))
    {
        goto exit;
    }

    if ( OK > (status = CRYPTO_ALLOC(pContextSSH->hwAccelCookie, pHmacSuite->hmacDigestLength, TRUE, &(OUTBOUND_KEY_DATA(pContextSSH)))))
        goto exit;

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

    if (NULL != pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx)
    {
        /* free key exchange context (dh, rsa, ecdh, etc) to avoid memory leak when client sends key re-exchange message */
        pContextSSH->pKeyExSuiteInfo->pKeyExMethods->freeCtx(pContextSSH);
    }

    if (NULL != SSH_HASH_H(pContextSSH))
    {
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &SSH_HASH_H(pContextSSH));
        SSH_HASH_H(pContextSSH) = NULL;
    }

    if (NULL != pContextSSH->sshKeyExCtx.pKeyExHash)
        pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH(pContextSSH->hwAccelCookie) &(pContextSSH->sshKeyExCtx.pKeyExHash));

    VLONG_freeVlong(&SSH_K(pContextSSH), NULL);

    return status;

} /* receiveNewKeysMessage */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_TRANS_versionExchange(sshContext *pContextSSH)
{
    ubyte*  pTempServerHelloClone = NULL;
    MSTATUS status;

    /* copy default server hello string */
    if ( OK > (status = CRYPTO_ALLOC ( pContextSSH->hwAccelCookie, (sizeof(SERVER_HELLO_STRING)-1) , TRUE, &pTempServerHelloClone ) ) )
        goto exit;

    MOC_MEMCPY(pTempServerHelloClone, (ubyte *)SERVER_HELLO_STRING, sizeof(SERVER_HELLO_STRING)-1);

    SERVER_HELLO_COMMENT_LEN(pContextSSH) = sizeof(SERVER_HELLO_STRING)-1;
    SERVER_HELLO_COMMENT(pContextSSH) = pTempServerHelloClone;
    pTempServerHelloClone = NULL;

    if (OK > (status = SSH_TRANS_sendServerHello(pContextSSH)))
        goto exit;

    /* set initial state to listen for client hello string */
    INBOUND_STATE(pContextSSH) = kReceiveInitClientHelloListen;

exit:
    if (NULL != pTempServerHelloClone)
        CRYPTO_FREE(pContextSSH->hwAccelCookie, TRUE, &pTempServerHelloClone);

    return status;
}

#ifndef __DISABLE_DIGICERT_RFC_8308__
/*
    3.1.  "server-sig-algs"

   This extension is sent with the following extension name and value:

     string      "server-sig-algs"
     name-list   public-key-algorithms-accepted

   The name-list type is a strict subset of the string type and is thus
   permissible as an extension-value.  See [RFC4251] for more
   information.

   This extension is sent by the server and contains a list of public
   key algorithms that the server is able to process as part of a
   "publickey" authentication request.  If a client sends this
   extension, the server MAY ignore it and MAY disconnect.

   In this extension, a server MUST enumerate all public key algorithms
   it might accept during user authentication.
*/
extern sshStringBuffer* getPubKeyAuthAlgorithms();
static MSTATUS sendMsgExtInfo(sshContext *pContextSSH)
{
    MSTATUS             status;
    ubyte*              pPayload = NULL;
    sbyte*              pTmp;
    ubyte4              length;
    sbyte4              payloadLen;
    sshStringBuffer*    pAlgorithms = NULL;
    sbyte4              extNameLen;

    pAlgorithms = getPubKeyAuthAlgorithms();
    /* type byte + extension count + length of extension name */
    payloadLen = 1 + sizeof(ubyte4) + sizeof(ubyte4);
    payloadLen += MOC_STRLEN("server-sig-algs") + pAlgorithms->stringLen;

    status = MOC_MALLOC((void **) &pPayload, payloadLen);
    if (OK != status)
        goto exit;

    pPayload[0] = SSH_MSG_EXT_INFO;
    pPayload[1] = 0;
    pPayload[2] = 0;
    pPayload[3] = 0;
    pPayload[4] = 1;

    extNameLen = MOC_STRLEN("server-sig-algs");

    pPayload[5] = 0;
    pPayload[6] = 0;
    pPayload[7] = 0;
    pPayload[8] = extNameLen;

    pTmp = pPayload + 9;

    status = MOC_MEMCPY(pTmp, "server-sig-algs", extNameLen);
    if (OK != status)
        goto exit;

    pTmp += extNameLen;

    status = MOC_MEMCPY(pTmp, pAlgorithms->pString, pAlgorithms->stringLen);
    if (OK != status)
        goto exit;

    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, payloadLen, &length)))
        goto exit;

    if (payloadLen != length)
    {
        status = ERR_SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
        goto exit;
    }

exit:
    SSH_STR_freeStringBuffer(&pAlgorithms);
    MOC_FREE((void **) &pPayload);

    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_TRANS_doProtocol(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
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

            /* return specific disconnect reason */
            status = ERR_SSH_DISCONNECT - status;
        }

        goto exit;
    }

#ifdef __DEBUG_SSH_TRANS_STATE__
    DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_TRANS_doProtocol: incoming state = ", SSH_UPPER_STATE(pContextSSH));
#endif
    switch (SSH_UPPER_STATE(pContextSSH))
    {
        case kTransAlgorithmExchange:
        case kReduxTransAlgorithmExchange:
        {
            if (OK > (status = receiveClientAlgorithms(pContextSSH, optionsSelected, pNewMesg, newMesgLen)))
                break;

            pContextSSH->keyExInitReceived = TRUE;

            if ((NULL == pContextSSH->pKeyExSuiteInfo) ||
                (NULL == pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo))
            {
                /* this should never happen */
                status = ERR_SSH_KEYEX_HASH_ALGO_NULL;
                break;
            }

            /* using table lookup for next state adds flexibility for new exchange mechanisms */
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
            if (TRUE == pContextSSH->kexGuessMismatch && TRUE == pContextSSH->keyExInitReceived)
            {
                pContextSSH->kexGuessMismatch = FALSE;
                goto exit;
            }

            /* handle original DH group"1"/14 Key Exchange */
            if (OK > (status = receiveClientKeyExchange(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveDiffieHellmanClassic == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = replyToClientKeyExchange(pContextSSH, SSH_MSG_KEXDH_REPLY)))
                break;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
            break;
        }

#if (defined(__ENABLE_MOCANA_DHG_KEY_EXCHANGE__))
        case kTransReceiveDiffieHellmanGroup1:
        case kReduxTransReceiveDiffieHellmanGroup1:
        {
            if (TRUE == pContextSSH->kexGuessMismatch && TRUE == pContextSSH->keyExInitReceived)
            {
                pContextSSH->kexGuessMismatch = FALSE;
                goto exit;
            }

            /* handle DH Group Key Exchange Step 1 */
            if (OK > (status = receiveClientDHGKeyExchangeRequest(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveDiffieHellmanGroup1 == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransReceiveDiffieHellmanGroup2;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransReceiveDiffieHellmanGroup2;

            if (OK > (status = sendDHGSafePrimeKeyExchange(pContextSSH)))
                break;

            status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
            break;
        }

        case kTransReceiveDiffieHellmanGroup2:
        case kReduxTransReceiveDiffieHellmanGroup2:
        {
            if (TRUE == pContextSSH->kexGuessMismatch && TRUE == pContextSSH->keyExInitReceived)
            {
                pContextSSH->kexGuessMismatch = FALSE;
                goto exit;
            }

            /* handle DH Group Key Exchange Step 2 */
            if (OK > (status = receiveClientDHGKeyExchangeInit(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveDiffieHellmanGroup2 == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = replyToClientKeyExchange(pContextSSH, SSH_MSG_KEX_DH_GEX_REPLY)))
                break;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
            break;
        }
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_PQC__))
        case kTransReceiveHybrid:
        case kReduxTransReceiveHybrid:
        {
            if (TRUE == pContextSSH->kexGuessMismatch && TRUE == pContextSSH->keyExInitReceived)
            {
                pContextSSH->kexGuessMismatch = FALSE;
                goto exit;
            }

            /* handle EC-DH Key Exchange */
            if (OK > (status = SSH_TRANS_receiveClientKexHybridInit(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveHybrid == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = SSH_TRANS_sendClientKexHybridReply(pContextSSH)))
                break;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
            break;
        }
#endif /* __ENABLE_MOCANA_PQC__ */
        case kTransReceiveECDH:
        case kReduxTransReceiveECDH:
        {
            if (TRUE == pContextSSH->kexGuessMismatch && TRUE == pContextSSH->keyExInitReceived)
            {
                pContextSSH->kexGuessMismatch = FALSE;
                goto exit;
            }

            /* handle EC-DH Key Exchange */
            if (OK > (status = SSH_TRANS_receiveClientKexEcdhInit(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveECDH == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = SSH_TRANS_sendClientKexEcdhReply(pContextSSH)))
                break;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
            break;
        }
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_RSA_PKCS1_SUPPORT__) && defined(__ENABLE_MOCANA_PKCS1__))
        case kTransReceiveRSA:
        case kReduxTransReceiveRSA:
        {
            if (TRUE == pContextSSH->kexGuessMismatch && TRUE == pContextSSH->keyExInitReceived)
            {
                pContextSSH->kexGuessMismatch = FALSE;
                goto exit;
            }

            /* handle RSA Key Exchange */
            if (OK > (status = SSH_TRANS_receiveKexRsaSecret(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (kTransReceiveRSA == SSH_UPPER_STATE(pContextSSH))
                SSH_UPPER_STATE(pContextSSH) = kTransNewKeys;
            else
                SSH_UPPER_STATE(pContextSSH) = kReduxTransNewKeys;

            if (OK > (status = SSH_TRANS_sendKexRsaDone(pContextSSH)))
                break;

            if (OK > (status = sendNewKeysMessage(pContextSSH)))
                break;

            status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
            break;
        }
#endif

        case kTransNewKeys:
        case kReduxTransNewKeys:
        {
            if (OK > (status = receiveNewKeysMessage(pContextSSH, optionsSelected, pNewMesg, newMesgLen)))
                break;

#ifndef __DISABLE_DIGICERT_RFC_8308__
            if (TRUE == pContextSSH->msgExtInfoEnabled)
            {
                if (OK > (status = sendMsgExtInfo(pContextSSH)))
                    break;
            }
#endif

            if (kTransNewKeys == SSH_UPPER_STATE(pContextSSH))
            {
                SSH_UPPER_STATE(pContextSSH) = kAuthServiceRequest;
                status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutServiceRequest);
            }
            else
            {
                SSH_UPPER_STATE(pContextSSH) = kOpenState;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
		status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutNewKeys);
#else
                status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutDefaultOpenState);
#endif
            }

            /* allow non-key messages to flow again */
            pContextSSH->isReKeyOccuring = FALSE;

            break;
        }

        case kAuthServiceRequest:
        case kAuthReceiveMessage:
        {
            status = SSH_AUTH_doProtocol(pContextSSH, pNewMesg, newMesgLen);
            break;
        }

        case kOpenState:
        {
            status = SSH_SESSION_receiveMessage(pContextSSH, pNewMesg, newMesgLen);
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

#ifdef __DEBUG_SSH_TRANS_STATE__
    DEBUG_ERROR(DEBUG_SSH_TRANSPORT, "SSH_TRANS_doProtocol: exit state = ", SSH_UPPER_STATE(pContextSSH));
#endif

    return status;
}

#ifdef __ENABLE_MOCANA_SP800_135_ACVP__
#include "../ssh/nist/ssh_nist.inc"
#endif

#endif /* __ENABLE_MOCANA_SSH_SERVER__ */
