/*
 * sslsock.c
 *
 * SSL implementation
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
#include "../common/moc_net_system.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../ssl/ssl.h"

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__))
#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
/* these are used for getpid() in ssl_server.inc */
#include <sys/types.h>
#include <unistd.h>
#endif /*  defined(__RTOS_LINUX__) */
#include "../common/mdefs.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../common/mem_pool.h"
#include "../common/memory_debug.h"
#include "../common/datetime.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/aes.h"
#include "../crypto/nil.h"
#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
#include "../crypto/chacha20.h"
#endif
#if defined(__ENABLE_DIGICERT_GCM__)
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"
#endif
#include "../crypto/srp.h"
/* aes_ccm.h does not include the ci priv file, include it here
   Next time FIPS layer is modified we can change that */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes_ccm_priv.h"
#endif
#include "../crypto/aes_ccm.h"
#include "../crypto/hmac.h"
#include "../crypto/hmac_kdf.h"
#include "../crypto/dh.h"
#include "../crypto/ca_mgmt.h"
#include "../harness/harness.h"
/* certificate business */
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../crypto/cert_store.h"
#include "../crypto/cert_chain.h"
#include "../crypto/pkcs1.h"
#include "../ssl/ssl_priv.h"
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#include "../dtls/dtls.h"
#include "../common/timer.h"
#if (defined(__ENABLE_DIGICERT_DTLS_SRTP__))
#include "../dtls/dtls_srtp.h"
#endif
#endif
#include "../ssl/sslsock.h"
#include "../ssl/sslsock_priv.h"
/* the ECDHE ECDSA signature is a DER encoded ASN1. sequence ... */
#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
#include "../asn1/derencoder.h"
#endif
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/oiddefs.h"
#include "../common/moc_net.h"

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"
#include "../ocsp/ocsp_store.h"
#include "../ssl/ssl_ocsp.h"
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_CRYPTO__)
#include "../ssl/hardware_accel_crypto.h"
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
#include "../smp/smp_cc.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_md5.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#include "../crypto_interface/crypto_interface_dh.h"
#include "../crypto_interface/crypto_interface_hmac.h"
#include "../crypto_interface/crypto_interface_hmac_kdf.h"
#include "../crypto_interface/crypto_interface_chacha20.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"
#include "../crypto_interface/crypto_interface_aes.h"

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
#include "../crypto_interface/crypto_interface_dsa.h"
#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto/pubcrypto_data.h"
#include "../crypto_interface/crypto_interface_qs_kem.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_composite.h"
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
#include "../crypto_interface/crypto_interface_rsa_tap.h"
#endif /* !__DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */
#if defined(__ENABLE_DIGICERT_ECC__)
#include "../crypto_interface/crypto_interface_ecc_tap.h"
#endif /* __ENABLE_DIGICERT_ECC__ */
#endif /* __ENABLE_DIGICERT_TAP__ */

#else /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_DIGICERT_PQC__
#error Must define __ENABLE_DIGICERT_CRYPTO_INTERFACE__ if __ENABLE_DIGICERT_PQC__ is defined
#endif
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__
#ifdef __ENABLE_DIGICERT_INNER_APP__
#error __ENABLE_DIGICERT_INNER_APP__ and __ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__ are mutually exclusive
#endif
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#define DTLS_RECORD_SIZE(X)          ((((ubyte2)X[11]) << 8) | ((ubyte2)X[12]))
#endif

/* This is the static key type; Will have to provide an API to set this */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static ubyte4 g_keyType = akt_ecc;
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
static tapKeyHandle   *g_pTapKeyList;
#endif
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
static void SSLSOCK_clearKeyShare(SSLSocket *pSSLSock);
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
static MSTATUS handshakeTimerCallbackFunc(void *s, ubyte* type);
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_OCSP_STORE__)
extern ocspStorePtr              gpOcspStore;
#endif

#ifdef __ENABLE_DIGICERT_SSL_KEYLOG_FILE__
#define SERVER_KEYFILENAME "./server_keys.txt"
#define CLIENT_KEYFILENAME "./client_keys.txt"
static void appendToKeyLogFile(
    SSLSocket *pSSLSock, ubyte *pOut, ubyte4 outLen, intBoolean byteBuffer,
    intBoolean newLine);
#include <stdio.h>
#if defined(__ENABLE_DIGICERT_SSL_KEYLOG_ENV_VAR__)
#include "../common/mfmgmt.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
static MSTATUS validateExtension(
    SSLSocket *pSSLSock, ubyte4 handshakeType, ubyte2 extensionType,
    ubyte2 extensionSize, sbyte4 extensionsLen, ubyte4 extensionMask[2]);
static MSTATUS processKeyUpdateRequest(SSLSocket *pSSLSock, ubyte *pMsg, ubyte2 msgLen);
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
static MSTATUS SSLSOCK_pskCalcBinderKey(MOC_HASH(hwAccelDescr hwAccelCtx) SSLSocket* pSSLSock, ubyte *pPsk, ubyte2 pskLength, ubyte pskType,
    const BulkHashAlgo *pDigest, ubyte **ppRetBinderKey, ubyte4 *pRetBinderKeyLen);
static MSTATUS
SSLSOCK_pskBinderEntry(MOC_HASH(hwAccelDescr hwAccelCtx)
    SSLSocket* pSSLSock,
    ubyte *pPartialClientHello, ubyte4 partialClientHelloLen,
    ubyte *pPsk, ubyte2 pskLength, ubyte pskType,
    const BulkHashAlgo *pDigestAlgo, ubyte **ppRetBinderEntry,
    ubyte4 *pRetBinderEntryLen);

static MSTATUS
SSLSOCK_generatePSKFromTicket(SSLSocket *pSSLSock,
                              ubyte *pNonce, ubyte nonceLen,
                              const BulkHashAlgo *pDigestAlgo,
                              ubyte* pResumptionMasterSecret,
                              ubyte **ppPSK, ubyte4 *pPSKLen);
#endif
static MSTATUS
SSLSOCK_setServerTrafficKeyMaterial(SSLSocket *pSSLSock, ubyte *pSecret);
static MSTATUS SSLSOCK_computeHandshakeSecret(SSLSocket *pSSLSock);
static MSTATUS
SSLSOCK_calcTranscriptHash(SSLSocket *pSSLSock, ubyte **ppRetDigest);
static MSTATUS
SSLSOCK_pskCalcApplicationTrafficSecret(SSLSocket *pSSLSock);
static MSTATUS
SSLSOCK_calcFinishedVerifyData(
    SSLSocket *pSSLSock, ubyte *pSecret, ubyte **ppVerifyData,
    ubyte4 *pVerifyDataLen);
static MSTATUS
SSLSOCK_pskHandshakeSecretDerive(SSLSocket *pSSLSock, const BulkHashAlgo *pDigest,
                                 ubyte *pSharedSecret, ubyte4 sharedSecretLen);
static MSTATUS
SSLSOCK_pskEarlySecretDerive(SSLSocket *pSSLSock, ubyte *pPsk, ubyte2 pskLength, const BulkHashAlgo *pDigest);
static MSTATUS
SSLSOCK_hmacKdfExpandLabel(SSLSocket *pSSLSock, ubyte *pSecret, ubyte4 secretLen, ubyte *pLabel,
                           ubyte labelLen, ubyte *pContext, ubyte contextLen, ubyte2 length,
                           ubyte **ppRetKey, ubyte4 *pRetKeyLen);
static MSTATUS SSLSOCK_pskUpdateClientTrafficSecret(SSLSocket *pSSLSock);
static MSTATUS SSLSOCK_pskUpdateServerTrafficSecret(SSLSocket *pSSLSock);
static MSTATUS SSLSOCK_calcTranscriptHashForBuffer(MOC_HASH(hwAccelDescr hwAccelCtx) const BulkHashAlgo *pDigest, ubyte *in, ubyte4 inLen, ubyte *pOutBuffer);
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
static MSTATUS SSLSOCK_pskCalcResumptionMasterSecret(SSLSocket *pSSLSock, const BulkHashAlgo *pDigest);
#endif
#endif
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
static MSTATUS swapEpochKeys(SSLSocket *pSSLSock);
#endif

#if ((defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_TLS13__)) || \
    (defined(__ENABLE_DIGICERT_SSL_CLIENT__)))
static MSTATUS constructTLSExtSupportedGroup(
    SSLSocket *pSSLSock, ubyte **ppPacket, ubyte2 numECCurves, ubyte4 eccCurves);
#endif

#ifndef SSL_SESSION_RESUME_TIMEOUT
#define SSL_SESSION_RESUME_TIMEOUT      (24 * (60 * (60 * 1000)))
#endif

static ubyte4 gSessionResumeTimeout = SSL_SESSION_RESUME_TIMEOUT;

#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS getNamedGroupCipherTextLen(ubyte4 namedGroup, ubyte4 *pLength);
#endif
static MSTATUS getNamedGroupLength(ubyte4 namedGroup, ubyte4 *pLength);
static MSTATUS getPublicKeyFromSharedKeyEntry(MOC_DH(hwAccelDescr hwAccelCtx1) MOC_ECC(hwAccelDescr hwAccelCtx2) sharedKey *pSharedKey, ubyte *pPubKey, ubyte4 pubKeyLen, ubyte4 namedGroup);
static MSTATUS getLengthFromSharedKeyEntry(sharedKey *pSharedKey, ubyte4 *pPubKeyLen);
#ifdef __ENABLE_DIGICERT_ECC__
static MSTATUS generateKeyShareEntryECDHE(ubyte4 namedGroup, AsymmetricKey **ppAsymKey,
    SSLSocket *pSSLSock);
#endif
static MSTATUS generateKeyShareEntryFFDH(MOC_DH(hwAccelDescr hwAccelCtx) ubyte4 namedGroup, diffieHellmanContext **ppDHContext);
static MSTATUS deleteSharedKey(sharedKey* pSharedKey);
static MSTATUS generateSharedKey(SSLSocket* pSSLSock, ubyte4 namedGroup, sharedKey* pSharedKey);
#endif

static MSTATUS
flushPendingBytes(SSLSocket *pSSLSock);

/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/

MSTATUS
SSL_SOCK_constructTLSExtSupportedVersions(SSLSocket* pSSLSock, ubyte** ppVersionBuffer,ubyte versionMask);

enum tlsClientCertType
{
    tlsClientCertType_rsa_sign = 1,
    tlsClientCertType_dsa_sign = 2,
    tlsClientCertType_ecdsa_sign = 64,
    tlsClientCertType_rsa_fixed_ecdh = 65,
    tlsClientCertType_ecdsa_fixed_ecdh = 66,
};

#ifdef __ENABLE_DIGICERT_ECC__
#define NUM_CLIENT_CERT_TYPES_ECC (3)
#else
#define NUM_CLIENT_CERT_TYPES_ECC (0)
#endif

#ifdef __ENABLE_DIGICERT_SSL_DSA_SUPPORT__
#define NUM_CLIENT_CERT_TYPES_DSA (1)
#else
#define NUM_CLIENT_CERT_TYPES_DSA (0)
#endif

#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
#define NUM_CLIENT_CERT_TYPES_RSA (1)
#else
#define NUM_CLIENT_CERT_TYPES_RSA (0)
#endif

#define NUM_CLIENT_CERT_TYPES (NUM_CLIENT_CERT_TYPES_ECC + NUM_CLIENT_CERT_TYPES_DSA + NUM_CLIENT_CERT_TYPES_RSA)

#define SSL_MEDIUM_SIZE 3

#define SSL_DH_CUSTOM_GROUP_PRI_LEN (32)

#if (defined(__ENABLE_DIGICERT_TLS13__))
#define RECORD_LAYER_LENGTH 5
#define RECORD_LAYER_LENGTH_DTLS 13
#define BINDER_LENGTH_VARIABLE 2
#endif

enum tlsExtECPointFormat
{
     tlsExtECPointFormat_uncompressed = 0,
     tlsExtECPointFormat_ansiX962_compressed_prime = 1,
     tlsExtECPointFormat_ansiX962_compressed_char2 = 2
};

enum tlsECCurveType
{
    tlsECCurveType_explicit_prime = 1,
    tlsECCurveType_explicit_char2 = 2,
    tlsECCurveType_named_curve = 3
};

/*------------------------------------------------------------------*/
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION

/* static variables */
static const ubyte gHashPad36[SSL_MAX_PADDINGSIZE] =
{
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

static const ubyte gHashPad5C[SSL_MAX_PADDINGSIZE] =
{
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C
};

#endif

#ifdef __ENABLE_DIGICERT_TLS13__
#define TLS13_MAX_LABEL_LEN             246
#define EVP_MAX_MD_SIZE                 64
#define MAX_HASH_SIZE                   32
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static MSTATUS fillClientRsaKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
#endif
#if (defined(__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
static MSTATUS fillClientEcdhKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
#endif
#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))
static MSTATUS fillClientEcdheKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS processServerEcdheKeyExchange( SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen);
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS fillClientDiffieHellmanKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS processServerKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen);
#endif

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS fillClientDiffieHellmanPskKeyExchange(SSLSocket* pSSLSockArg, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS processServerDiffieHellmanPskKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen);
#endif

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__))
static MSTATUS fillClientEcdhePskKeyExchange(SSLSocket* pSSLSockArg, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS processServerEcdhePskKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen);
#endif

#if defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)
static MSTATUS fillClientPskKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS fillClientRsaPskKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS processServerPskKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen);
#endif

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
static MSTATUS fillClientSrpKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, vlong **ppVlongQueue);
static MSTATUS processServerSrpKeyExchange(SSLSocket *pSSLSock, ubyte* pMesg, ubyte2 mesgLen);
#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
extern MSTATUS SSL_OCSP_addCertificates(SSLSocket* pSSLSock);
#endif

#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
static MSTATUS processClientRsaKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);

#if (defined(__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
static MSTATUS processClientEcdhKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
#endif

#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
static MSTATUS processClientEcdheKeyExchange(SSLSocket* pSSLSock, ubyte *pBuffer, ubyte2 length, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
static MSTATUS fillServerEcdheKeyExchange(SSLSocket* pSSLSock, ubyte *pHSH, ubyte *pHint, ubyte4 hintLength);
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
static MSTATUS processClientDiffieHellmanKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
static MSTATUS fillServerKeyExchange(SSLSocket* pSSLSock, ubyte *pHSH, ubyte *pHint, ubyte4 hintLength);
#endif

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
static MSTATUS processClientEcdhePskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
#endif
#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
static MSTATUS processClientDiffieHellmanPskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
#endif
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static MSTATUS processClientRsaPskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
#endif
static MSTATUS processClientPskKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
static MSTATUS fillServerPskKeyExchange(SSLSocket* pSSLSockTemp, ubyte *pHSH, ubyte *pPskHint, ubyte4 pskHintLength);
#endif

#ifdef __ENABLE_DIGICERT_SSL_SRP__
static MSTATUS processClientSrpKeyExchange(SSLSocket* pSSLSock, ubyte* pMessage, ubyte2 recLen, ubyte **pSecret, ubyte4 *pSecretLength, vlong **ppVlongQueue);
static MSTATUS fillServerSrpKeyExchange(SSLSocket* pSSLSockTemp, ubyte *pHSH, ubyte *pHint, ubyte4 hintLength);
#endif

#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

/*------------------------------------------------------------------*/
#if ((defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) ||\
     (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)))
static MSTATUS
processCertificateVerify(SSLSocket *pSSLSock, AsymmetricKey key, ubyte* pSHSH, ubyte2 recLen, vlong **ppVlongQueue);

#if defined(__ENABLE_DIGICERT_ECC__)
static MSTATUS
processCertificateVerifyECC(const ubyte* pHashResult, ubyte4 hashLen,
                                  SSLSocket *pSSLSock,
                                  AsymmetricKey key,
                                  ubyte* pSignature, ubyte4 signatureLen,
                                  ubyte2 signAlgo,
                                  vlong **ppVlongQueue);
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__))
static MSTATUS
processCertificateVerifyRSA(const ubyte* pHashResult, ubyte4 hashLen,
                                  const ubyte* hashOID, SSLSocket *pSSLSock,
                                  AsymmetricKey key,
                                  ubyte* pSignature, ubyte4 signatureLen,
                                  vlong **ppVlongQueue);
#endif
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
#define KEYEX_DESCR(CIPHER_ID,FILL_SERVER_KEX,PROCESS_SERVER_KEX,FILL_CLIENT_KEX,PROCESS_CLIENT_KEX, K_USAGE) { CIPHER_ID,FILL_SERVER_KEX,PROCESS_SERVER_KEX,FILL_CLIENT_KEX,PROCESS_CLIENT_KEX, K_USAGE }
#elif defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#define KEYEX_DESCR(CIPHER_ID,FILL_SERVER_KEX,PROCESS_SERVER_KEX,FILL_CLIENT_KEX,PROCESS_CLIENT_KEX, K_USAGE) { CIPHER_ID,PROCESS_SERVER_KEX,FILL_CLIENT_KEX, K_USAGE }
#else
#define KEYEX_DESCR(CIPHER_ID,FILL_SERVER_KEX,PROCESS_SERVER_KEX,FILL_CLIENT_KEX,PROCESS_CLIENT_KEX, K_USAGE) { CIPHER_ID,FILL_SERVER_KEX,PROCESS_CLIENT_KEX, K_USAGE }
#endif



/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static KeyExAuthSuiteInfo RsaSuite =                KEYEX_DESCR( SSL_RSA,                    /* cipher flags */
                                                                NULL,                        /* server-side:FillServerKEX */
                                                                NULL,                        /* client-side:ProcessServerKEX */
                                                                fillClientRsaKeyExchange,    /* client-side:FillClientKEX */
                                                                processClientRsaKeyExchange, /* server-side:ProcessClientKEX */
                                                                (1<<keyEncipherment) );      /* key usage for server certificate */
#endif
#ifdef __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static KeyExAuthSuiteInfo EcdhRsaSuite =            KEYEX_DESCR( SSL_ECDH_RSA,
                                                                NULL,
                                                                NULL,
                                                                fillClientEcdhKeyExchange,
                                                                processClientEcdhKeyExchange,
                                                                (1<<keyAgreement));
#endif
#endif
#ifdef __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
static KeyExAuthSuiteInfo EcdhEcdsaSuite =          KEYEX_DESCR( SSL_ECDH_ECDSA,
                                                                NULL,
                                                                NULL,
                                                                fillClientEcdhKeyExchange,
                                                                processClientEcdhKeyExchange,
                                                                (1<<keyAgreement));
#endif
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static KeyExAuthSuiteInfo EcdheRsaSuite =           KEYEX_DESCR( SSL_ECDHE_RSA,
                                                                fillServerEcdheKeyExchange,
                                                                processServerEcdheKeyExchange,
                                                                fillClientEcdheKeyExchange,
                                                                processClientEcdheKeyExchange,
                                                                (1<<digitalSignature));
#endif
#endif
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
static KeyExAuthSuiteInfo EcdheEcdsaSuite =         KEYEX_DESCR( SSL_ECDHE_ECDSA,
                                                                fillServerEcdheKeyExchange,
                                                                processServerEcdheKeyExchange,
                                                                fillClientEcdheKeyExchange,
                                                                processClientEcdheKeyExchange,
                                                                (1<<digitalSignature));
#endif
#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
static KeyExAuthSuiteInfo EcdheAnonSuite =          KEYEX_DESCR( SSL_ECDH_ANON,
                                                                fillServerEcdheKeyExchange,
                                                                processServerEcdheKeyExchange,
                                                                fillClientEcdheKeyExchange,
                                                                processClientEcdheKeyExchange,
                                                                0);
#endif
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
static KeyExAuthSuiteInfo DiffieHellmanRsaSuite =   KEYEX_DESCR( SSL_DHE_RSA,
                                                                fillServerKeyExchange,
                                                                processServerKeyExchange,
                                                                fillClientDiffieHellmanKeyExchange,
                                                                processClientDiffieHellmanKeyExchange,
                                                                (1 << digitalSignature));
#endif

#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
static KeyExAuthSuiteInfo DiffieHellmanDsaSuite =   KEYEX_DESCR( SSL_DHE_DSA,
                                                                fillServerKeyExchange,
                                                                processServerKeyExchange,
                                                                fillClientDiffieHellmanKeyExchange,
                                                                processClientDiffieHellmanKeyExchange,
                                                                (1 << digitalSignature));
#endif

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
static KeyExAuthSuiteInfo DiffieHellmanAnonSuite =  KEYEX_DESCR( SSL_DH_ANON,
                                                                fillServerKeyExchange,
                                                                processServerKeyExchange,
                                                                fillClientDiffieHellmanKeyExchange,
                                                                processClientDiffieHellmanKeyExchange,
                                                                0);
#endif

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
static KeyExAuthSuiteInfo PskSuite =                KEYEX_DESCR( SSL_PSK,
                                                                fillServerPskKeyExchange,
                                                                processServerPskKeyExchange,
                                                                fillClientPskKeyExchange,
                                                                processClientPskKeyExchange,
                                                                0);

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static KeyExAuthSuiteInfo RsaPskSuite =             KEYEX_DESCR( SSL_RSA_PSK,
                                                                fillServerPskKeyExchange,
                                                                processServerPskKeyExchange,
                                                                fillClientRsaPskKeyExchange,
                                                                processClientRsaPskKeyExchange,
                                                                (1 << keyEncipherment));
#endif /* !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && __ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
static KeyExAuthSuiteInfo DiffieHellmanPskSuite =   KEYEX_DESCR( SSL_DH_PSK,
                                                                fillServerKeyExchange,
                                                                processServerDiffieHellmanPskKeyExchange,
                                                                fillClientDiffieHellmanPskKeyExchange,
                                                                processClientDiffieHellmanPskKeyExchange,
                                                                0);
#endif /* __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
static KeyExAuthSuiteInfo EcdhePskSuite =           KEYEX_DESCR( SSL_ECDH_PSK,
                                                                fillServerEcdheKeyExchange,
                                                                processServerEcdhePskKeyExchange,
                                                                fillClientEcdhePskKeyExchange,
                                                                processClientEcdhePskKeyExchange,
                                                                0);
#endif /* __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__ */

#endif /* __ENABLE_DIGICERT_SSL_PSK_SUPPORT__ */


#ifdef __ENABLE_DIGICERT_SSL_SRP__

static KeyExAuthSuiteInfo SrpSuite =                KEYEX_DESCR(SSL_SRP,
                                                                fillServerSrpKeyExchange,
                                                                processServerSrpKeyExchange,
                                                                fillClientSrpKeyExchange,
                                                                processClientSrpKeyExchange,
                                                                0);

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
static KeyExAuthSuiteInfo RsaSrpSuite =             KEYEX_DESCR(SSL_RSA_SRP,
                                                                fillServerSrpKeyExchange,
                                                                processServerSrpKeyExchange,
                                                                fillClientSrpKeyExchange,
                                                                processClientSrpKeyExchange,
                                                                (1 << digitalSignature));
#endif

#endif

#if (defined(__ENABLE_DIGICERT_TLS13__))
#if (defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))

static KeyExAuthSuiteInfo EcdheAllSuite =           KEYEX_DESCR( SSL_ECDHE_ALL,
                                                                 fillServerEcdheKeyExchange,
                                                                 processServerEcdheKeyExchange,
                                                                 fillClientEcdheKeyExchange,
                                                                 processClientEcdheKeyExchange,
                                                                 (1<<digitalSignature));
#endif
#if defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)
static KeyExAuthSuiteInfo DheAllSuite =            KEYEX_DESCR( SSL_DHE_RSA,
                                                                fillServerKeyExchange,
                                                                processServerKeyExchange,
                                                                fillClientDiffieHellmanKeyExchange,
                                                                processClientDiffieHellmanKeyExchange,
                                                                (1 << digitalSignature));
#endif
#endif /* __ENABLE_DIGICERT_TLS13__ */

/* Bulk Hash Algorithms */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkHashAlgo MD5Suite =
    { MD5_RESULT_SIZE, MD5_BLOCK_SIZE, CRYPTO_INTERFACE_MD5Alloc_m, CRYPTO_INTERFACE_MD5Free_m,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_MD5Init_m, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_MD5Update_m,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_MD5Final_m, NULL, NULL, NULL, ht_md5 };
#else
static const BulkHashAlgo MD5Suite =
    { MD5_RESULT_SIZE, MD5_BLOCK_SIZE, MD5Alloc_m, MD5Free_m, (BulkCtxInitFunc)MD5Init_m,
    (BulkCtxUpdateFunc)MD5Update_m, (BulkCtxFinalFunc)MD5Final_m, NULL, NULL, NULL, ht_md5 };
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, CRYPTO_INTERFACE_SHA1_allocDigest, CRYPTO_INTERFACE_SHA1_freeDigest,
      (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA1_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA1_updateDigest,
      (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };
#else
static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest, (BulkCtxInitFunc)SHA1_initDigest,
    (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };
#endif

#ifndef __DISABLE_DIGICERT_SHA224__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkHashAlgo SHA224Suite =
    { SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, CRYPTO_INTERFACE_SHA256_allocDigest, CRYPTO_INTERFACE_SHA256_freeDigest,
        (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA224_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA256_updateDigest,
        (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA224_finalDigest, NULL, NULL, NULL, ht_sha224 };
#else
static const BulkHashAlgo SHA224Suite =
    { SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, SHA224_allocDigest, SHA224_freeDigest,
        (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA224_updateDigest,
        (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224 };
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, CRYPTO_INTERFACE_SHA256_allocDigest, CRYPTO_INTERFACE_SHA256_freeDigest,
        (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA256_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA256_updateDigest,
        (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#else
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
        (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest,
        (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, CRYPTO_INTERFACE_SHA512_allocDigest, CRYPTO_INTERFACE_SHA512_freeDigest,
        (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA384_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA512_updateDigest,
        (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#else
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
        (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest,
        (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, CRYPTO_INTERFACE_SHA512_allocDigest, CRYPTO_INTERFACE_SHA512_freeDigest,
        (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA512_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA512_updateDigest,
        (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#else
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
        (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest,
        (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif
#endif

/*------------------------------------------------------------------*/

#if defined(__SSL_SINGLE_PASS_SUPPORT__)
#define SSL_CIPHER_DEF(CIPHER_ID,CIPHER_ENABLE,MINSSLVER,KEY_SIZE,SYM_CIPHER,KEYEX,PRFHASH,HASH_ID, HW_IN,HW_OUT) { CIPHER_ID, CIPHER_ENABLE, MINSSLVER, KEY_SIZE, SYM_CIPHER, KEYEX, PRFHASH, HASH_ID, HW_IN, HW_OUT }
#else
#define SSL_CIPHER_DEF(CIPHER_ID,CIPHER_ENABLE,MINSSLVER,KEY_SIZE,SYM_CIPHER,KEYEX,PRFHASH, HASH_ID, HW_IN,HW_OUT) { CIPHER_ID, CIPHER_ENABLE, MINSSLVER, KEY_SIZE, SYM_CIPHER, KEYEX, PRFHASH, HASH_ID}
#endif


/*------------------------------------------------------------------*/

/* used for combo algo only, i.e. encryption algo + hash algo */
typedef struct ComboAlgo
{
    const BulkEncryptionAlgo *pBEAlgo;
    const BulkHashAlgo *pBHAlgo;
} ComboAlgo;

/* Encryption Layer */
static BulkCtx SSLComboCipher_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, ubyte4 keySize, sbyte4 encrypt, const ComboAlgo *pComboAlgo);
static MSTATUS SSLComboCipher_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx, const ComboAlgo *pComboAlgo);
static MSTATUS SSLComboCipher_decryptVerifyRecord(SSLSocket* pSSLSock, ubyte protocol, const ComboAlgo *pComboAlgo);
static MSTATUS SSLComboCipher_formEncryptedRecord(SSLSocket* pSSLSock, ubyte* data, ubyte2 dataSize, sbyte padLen, const ComboAlgo *pComboAlgo);

#if defined(__ENABLE_DIGICERT_AEAD_CIPHER__)
static BulkCtx SSLAeadCipher_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, ubyte4 keySize, sbyte4 encrypt, const AeadAlgo *pAeadAlgo);
static MSTATUS SSLAeadCipher_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx, const AeadAlgo *pAeadAlgo);
static MSTATUS SSLAeadCipher_decryptVerifyRecord(SSLSocket* pSSLSock, ubyte protocol, ubyte nonceStyle, const AeadAlgo *pAeadAlgo);
static MSTATUS SSLAeadCipher_formEncryptedRecord(SSLSocket* pSSLSock, ubyte* data, ubyte2 dataSize, sbyte padLen, ubyte nonceStyle, const AeadAlgo *pAeadAlgo);
#endif
static MSTATUS sendData(SSLSocket* pSSLSock, ubyte protocol, const sbyte* data, sbyte4 dataSize, intBoolean skipEmptyMesg);


#ifdef __ENABLE_DIGICERT_SSL_SRP__
static MSTATUS SSL_SOCK_SRPConcatPadSha( SSLSocket* pSSLSock,
                                        const ubyte* first, sbyte4 firstSize,
                                        const ubyte* second, sbyte4 secondSize,
                                        sbyte4 padSize, ubyte* shaResult);

static MSTATUS SSL_SOCK_SerializeVLong(const vlong* src,
                                       ubyte** dest, sbyte4* destLen);
#endif

/* Crypto Helpers */
static void    addToHandshakeHash(SSLSocket* pSSLSock, ubyte* data, sbyte4 size);
static sbyte4  computePadLength(sbyte4 msgSize, sbyte4 blockSize);
#if (defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || MIN_SSL_MINORVERSION <= SSL3_MINORVERSION)
static MSTATUS calculateSSLTLSHashes(SSLSocket *pSSLSock, sbyte4 client, ubyte* result, enum hashTypes hashType);
#endif
static MSTATUS calculateTLSFinishedVerify(SSLSocket *pSSLSock, sbyte4 client, ubyte result[TLS_VERIFYDATASIZE]);
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
static MSTATUS SHAMD5Rounds(SSLSocket *pSSLSock, const ubyte* pPresecret, ubyte4 presecretLength, const ubyte data[2 * SSL_RANDOMSIZE], sbyte4 numRounds, ubyte* dest);
extern MSTATUS SSL_SOCK_computeSSLMAC(SSLSocket *pSSLSock, ubyte* secret, sbyte4 macSize,
                                      ubyte *pSequence, ubyte2 mesgLen,
                                      ubyte result[SSL_MAXDIGESTSIZE]);
#endif
extern MSTATUS SSL_SOCK_computeTLSMAC(MOC_HASH(SSLSocket *pSSLSock) ubyte* secret,
                                      ubyte *pMesg, ubyte2 mesgLen,
                                      ubyte *pMesgOpt, ubyte2 mesgOptLen,
                                      ubyte result[SSL_MAXDIGESTSIZE], const BulkHashAlgo *pBHAlgo);
extern MSTATUS SSL_SOCK_generateKeyMaterial(SSLSocket* pSSLSock, ubyte* preMasterSecret, ubyte4 preMasterSecretLength);
extern MSTATUS SSL_SOCK_setClientKeyMaterial(SSLSocket *pSSLSock);
extern MSTATUS SSL_SOCK_setServerKeyMaterial(SSLSocket *pSSLSock);
static void    resetCipher(SSLSocket* pSSLSock, intBoolean clientSide, intBoolean serverSide);
/* HMAC implementations for TLS */
static void    P_hash(SSLSocket *pSSLSock, const ubyte* secret, sbyte4 secretLen,
                      const ubyte* seed, sbyte4 seedLen,
                      ubyte* result, sbyte4 resultLen, const BulkHashAlgo *pBHAlgo);
static MSTATUS PRF(SSLSocket *pSSLSock, const ubyte* secret, sbyte4 secretLen,
                   const ubyte* labelSeed, sbyte4 labelSeedLen,
                   ubyte* result, sbyte4 resultLen);

/*------------------------------------------------------------------*/
/* MACROs for creating encryption + hash combination ciphers: bSize = blockSize, hSize = hashSize */
#define MAKE_COMBO_CIPHER(e,h, bSize, hSize)   \
    static const ComboAlgo k##e##h##_comboAlgo = {&CRYPTO_##e##Suite, &h##Suite}; \
    static BulkCtx  e##h##_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, ubyte4 keySize, sbyte4 encrypt) \
    { return SSLComboCipher_createCtx(MOC_SYM(hwAccelCtx)  key, keySize, encrypt, &k##e##h##_comboAlgo); } \
    \
    static MSTATUS e##h##_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* pCtx) \
    { return SSLComboCipher_deleteCtx(MOC_SYM(hwAccelCtx) pCtx, &k##e##h##_comboAlgo); } \
    \
    static MSTATUS e##h##_encrypt(SSLSocket *pSSLSock, ubyte* pData, ubyte2 dataLength, sbyte padLength) \
    { return SSLComboCipher_formEncryptedRecord(pSSLSock, pData, dataLength, padLength, &k##e##h##_comboAlgo); } \
    \
    static MSTATUS e##h##_decrypt(SSLSocket *pSSLSock, ubyte protocol) \
    { return SSLComboCipher_decryptVerifyRecord(pSSLSock, protocol, &k##e##h##_comboAlgo); } \
    \
    static sbyte4 e##h##_getField(CipherField type) \
    { return (Block_Size == type? bSize : (Hash_Size == type? hSize : 0)); } \
    \
    static SSLCipherAlgo e##h = {bSize, hSize, 0, e##h##_createCtx, e##h##_deleteCtx, e##h##_encrypt, e##h##_decrypt, e##h##_getField };

#ifndef __DISABLE_AES_CIPHERS__
MAKE_COMBO_CIPHER( AES, SHA1,  AES_BLOCK_SIZE, SHA1_RESULT_SIZE )
#ifndef __DISABLE_DIGICERT_SHA256__
MAKE_COMBO_CIPHER( AES, SHA256,  AES_BLOCK_SIZE, SHA256_RESULT_SIZE )
#endif
#if ((defined __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || (defined __ENABLE_DIGICERT_SSL_PSK_SUPPORT__) || \
     (defined __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))
#ifndef __DISABLE_DIGICERT_SHA384__
MAKE_COMBO_CIPHER( AES, SHA384,  AES_BLOCK_SIZE, SHA384_RESULT_SIZE )
#endif
#endif
#endif

#ifndef __DISABLE_3DES_CIPHERS__
MAKE_COMBO_CIPHER( TripleDES, SHA1, THREE_DES_BLOCK_SIZE, SHA1_RESULT_SIZE )
#endif

#if MIN_SSL_MINORVERSION==SSL3_MINORVERSION
#ifndef __DISABLE_ARC4_CIPHERS__
/* no support for RC4 MD5 */
MAKE_COMBO_CIPHER( RC4, SHA1, 0, SHA1_RESULT_SIZE )
#endif
#endif

#ifdef __ENABLE_DES_CIPHER__
MAKE_COMBO_CIPHER( DES, SHA1, DES_BLOCK_SIZE, SHA1_RESULT_SIZE )
#endif

#ifdef __ENABLE_NIL_CIPHER__
#ifndef __DISABLE_NULL_MD5_CIPHER__
MAKE_COMBO_CIPHER( Nil, MD5, 0, MD5_RESULT_SIZE )
#endif
MAKE_COMBO_CIPHER( Nil, SHA1, 0, SHA1_RESULT_SIZE )
#ifndef __DISABLE_DIGICERT_SHA256__
MAKE_COMBO_CIPHER( Nil, SHA256, 0, SHA256_RESULT_SIZE )
#endif
/* this is used only for PSK ciphers as of 06/22/2015 */
#if !defined(__DISABLE_DIGICERT_SHA384__) && defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__)
MAKE_COMBO_CIPHER( Nil, SHA384, 0, SHA384_RESULT_SIZE )
#endif
#endif

#if defined(__ENABLE_DIGICERT_AEAD_CIPHER__)

#define MAX_AEAD_NONCE_LEN  (12)

/* MACROs for creating AEAD ciphers:  fIVSize = fixedIVSize, rIVSize = recordIVSize, tSize = tagSize */
#define MAKE_AEAD_CIPHER(aead, fIVSize, rIVSize, tSize, nonceStyle)   \
    static BulkCtx  aead##_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, ubyte4 keySize, sbyte4 encrypt) \
    { return SSLAeadCipher_createCtx(MOC_SYM(hwAccelCtx) key, keySize, encrypt, &aead##Suite); } \
    \
    static MSTATUS aead##_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* pCtx) \
    { return SSLAeadCipher_deleteCtx(MOC_SYM(hwAccelCtx) pCtx, &aead##Suite); } \
    \
    static MSTATUS aead##_encrypt(SSLSocket *pSSLSock, ubyte* pData, ubyte2 dataLength, sbyte padLength) \
    { return SSLAeadCipher_formEncryptedRecord(pSSLSock, pData, dataLength, padLength, nonceStyle, &aead##Suite); } \
    \
    static MSTATUS aead##_decrypt(SSLSocket *pSSLSock, ubyte protocol) \
    { return SSLAeadCipher_decryptVerifyRecord(pSSLSock, protocol, nonceStyle, &aead##Suite); } \
    \
    static sbyte4 aead##_getField(CipherField type) \
    { return (FixedIV_Size == type?  fIVSize : (RecordIV_Size == type? rIVSize : (TagLen == type?  tSize : 0))); } \
    \
    static SSLCipherAlgo aead = {fIVSize, rIVSize, tSize, aead##_createCtx, aead##_deleteCtx, aead##_encrypt, aead##_decrypt, aead##_getField };

/* GCM */
#if defined(__ENABLE_DIGICERT_GCM__)
#define GCM_FIXED_IV_LENGTH 4
#define GCM_RECORD_IV_LENGTH 8
#ifdef __ENABLE_DIGICERT_GCM_64K__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo GCMSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, CRYPTO_INTERFACE_GCM_cipher_64k, NULL };
#else
static AeadAlgo GCMSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_createCtx_64k, GCM_deleteCtx_64k, GCM_cipher_64k, NULL };
#endif
#endif /* __ENABLE_DIGICERT_GCM_64K__ */
#ifdef __ENABLE_DIGICERT_GCM_4K__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo GCMSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, CRYPTO_INTERFACE_GCM_cipher_4k, NULL };
#else
static AeadAlgo GCMSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_createCtx_4k, GCM_deleteCtx_4k, GCM_cipher_4k, NULL };
#endif
#endif /* __ENABLE_DIGICERT_GCM_4K__ */
#ifdef __ENABLE_DIGICERT_GCM_256B__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo GCMSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, CRYPTO_INTERFACE_GCM_cipher_256b, NULL };
#else
static AeadAlgo GCMSuite =
    { GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_createCtx_256b, GCM_deleteCtx_256b, GCM_cipher_256b, NULL };
#endif
#endif /* __ENABLE_DIGICERT_GCM_256B__ */
MAKE_AEAD_CIPHER( GCM, GCM_FIXED_IV_LENGTH, GCM_RECORD_IV_LENGTH, AES_BLOCK_SIZE, TLS12_MINORVERSION )

#if (defined(__ENABLE_DIGICERT_TLS13__))
#define GCM_TLS13_FIXED_IV_LENGTH 12
#define GCM_TLS13_RECORD_IV_LENGTH 0
#ifdef __ENABLE_DIGICERT_GCM_64K__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo GCM_TLS13Suite =
    {  GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_64k, CRYPTO_INTERFACE_GCM_deleteCtx_64k, CRYPTO_INTERFACE_GCM_cipher_64k, NULL };
#else
static AeadAlgo GCM_TLS13Suite =
    { GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_createCtx_64k, GCM_deleteCtx_64k, GCM_cipher_64k, NULL };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo GCM_TLS13Suite =
    {  GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_4k, CRYPTO_INTERFACE_GCM_deleteCtx_4k, CRYPTO_INTERFACE_GCM_cipher_4k, NULL };
#else
static AeadAlgo GCM_TLS13Suite =
    { GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_createCtx_4k, GCM_deleteCtx_4k, GCM_cipher_4k, NULL };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif
#ifdef __ENABLE_DIGICERT_GCM_256B__
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo GCM_TLS13Suite =
    {  GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, CRYPTO_INTERFACE_GCM_createCtx_256b, CRYPTO_INTERFACE_GCM_deleteCtx_256b, CRYPTO_INTERFACE_GCM_cipher_256b, NULL };
#else
static AeadAlgo GCM_TLS13Suite =
    { GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, GCM_createCtx_256b, GCM_deleteCtx_256b, GCM_cipher_256b, NULL };
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif
MAKE_AEAD_CIPHER( GCM_TLS13, GCM_TLS13_FIXED_IV_LENGTH, GCM_TLS13_RECORD_IV_LENGTH, AES_BLOCK_SIZE, TLS13_MINORVERSION )
#endif /* __ENABLE_DIGICERT_TLS13__ */

#endif

/* CCM */
#if defined(__ENABLE_DIGICERT_CCM__) || defined(__ENABLE_DIGICERT_CCM_8__)
#define AESCCM_FIXED_IV_LENGTH   4
#define AESCCM_RECORD_IV_LENGTH  8
#ifdef __ENABLE_DIGICERT_TLS13__
#define AESCCM_TLS13_FIXED_IV_LENGTH   12
#define AESCCM_TLS13_RECORD_IV_LENGTH  0
#endif

#ifdef __ENABLE_DIGICERT_CCM_8__
#define AESCCM_8_TAGSIZE         8

static AeadAlgo AESCCM8Suite =
    { AESCCM_FIXED_IV_LENGTH, AESCCM_RECORD_IV_LENGTH, AESCCM_8_TAGSIZE, AESCCM_createCtx, AESCCM_deleteCtx, AESCCM_cipher, NULL };

MAKE_AEAD_CIPHER( AESCCM8, AESCCM_FIXED_IV_LENGTH, AESCCM_RECORD_IV_LENGTH, AESCCM_8_TAGSIZE, TLS12_MINORVERSION )

#ifdef __ENABLE_DIGICERT_TLS13__
static AeadAlgo AESCCM8_TLS13Suite =
    { AESCCM_TLS13_FIXED_IV_LENGTH, AESCCM_TLS13_RECORD_IV_LENGTH, AESCCM_8_TAGSIZE, AESCCM_createCtx, AESCCM_deleteCtx, AESCCM_cipher, NULL };

MAKE_AEAD_CIPHER( AESCCM8_TLS13, AESCCM_TLS13_FIXED_IV_LENGTH, AESCCM_TLS13_RECORD_IV_LENGTH, AESCCM_8_TAGSIZE, TLS13_MINORVERSION )
#endif /* __ENABLE_DIGICERT_TLS13__ */

#endif /* __ENABLE_DIGICERT_CCM_8__ */

#ifdef __ENABLE_DIGICERT_CCM__
#define AESCCM_TAGSIZE         16

static AeadAlgo AESCCM16Suite =
{ AESCCM_FIXED_IV_LENGTH, AESCCM_RECORD_IV_LENGTH, AESCCM_TAGSIZE, AESCCM_createCtx, AESCCM_deleteCtx, AESCCM_cipher, NULL };

MAKE_AEAD_CIPHER( AESCCM16, AESCCM_FIXED_IV_LENGTH, AESCCM_RECORD_IV_LENGTH, AESCCM_TAGSIZE, TLS12_MINORVERSION )

#ifdef __ENABLE_DIGICERT_TLS13__
static AeadAlgo AESCCM16_TLS13Suite =
    { AESCCM_TLS13_FIXED_IV_LENGTH, AESCCM_TLS13_RECORD_IV_LENGTH, AESCCM_TAGSIZE, AESCCM_createCtx, AESCCM_deleteCtx, AESCCM_cipher, NULL };

MAKE_AEAD_CIPHER( AESCCM16_TLS13, AESCCM_TLS13_FIXED_IV_LENGTH, AESCCM_TLS13_RECORD_IV_LENGTH, AESCCM_TAGSIZE, TLS13_MINORVERSION )
#endif /* __ENABLE_DIGICERT_TLS13__ */

#endif /* __ENABLE_DIGICERT_CCM__ */

#endif /* __ENABLE_DIGICERT_CCM__ || __ENABLE_DIGICERT_CCM_8__  */

/* CHACHA20POLY1305 */
#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)

#define CHACHA20POLY1305_FIXED_IV_LENGTH 12
#define CHACHA20POLY1305_RECORD_IV_LENGTH 0
#define CHACHA20POLY1305_TAGSIZE 16
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static AeadAlgo CHACHA20POLY1305Suite =
{
    CHACHA20POLY1305_FIXED_IV_LENGTH,  /* implicitNonceSize */
    CHACHA20POLY1305_RECORD_IV_LENGTH, /* explicitNonceSize */
    CHACHA20POLY1305_TAGSIZE,          /* tagSize */
    CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx, CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx, CRYPTO_INTERFACE_ChaCha20Poly1305_cipher, NULL
};
#else
static AeadAlgo CHACHA20POLY1305Suite =
{
    CHACHA20POLY1305_FIXED_IV_LENGTH,  /* implicitNonceSize */
    CHACHA20POLY1305_RECORD_IV_LENGTH, /* explicitNonceSize */
    CHACHA20POLY1305_TAGSIZE,          /* tagSize */
    ChaCha20Poly1305_createCtx, ChaCha20Poly1305_deleteCtx, ChaCha20Poly1305_cipher, NULL
};
#endif
/* Nonce style for POLY-CHACHA is TLS13 (for TLS1.2, TLS1.3 and DTLS 1.2 versions)
 * RFC 7905, section 2
 */
MAKE_AEAD_CIPHER( CHACHA20POLY1305, CHACHA20POLY1305_FIXED_IV_LENGTH, CHACHA20POLY1305_RECORD_IV_LENGTH, CHACHA20POLY1305_TAGSIZE, TLS13_MINORVERSION )

#endif


#endif /* __ENABLE_DIGICERT_AEAD_CIPHER__ */

#define SUPPORTED_VERSION_TLS13            (  1 << TLS13_MINORVERSION)
#define SUPPORTED_VERSION_TLS12            (  1 << TLS12_MINORVERSION)
#define SUPPORTED_VERSION_TLS11_TO_TLS12   (( 1 << TLS12_MINORVERSION) | ( 1 << TLS11_MINORVERSION))
#define SUPPORTED_VERSION_TLS10_TO_TLS12   (( 1 << TLS12_MINORVERSION) | ( 1 << TLS11_MINORVERSION) | \
                                            ( 1 << TLS10_MINORVERSION))
#define SUPPORTED_VERSION_SSL3_TO_TLS12    (( 1 << TLS12_MINORVERSION) | ( 1 << TLS11_MINORVERSION) | \
                                            ( 1 << TLS10_MINORVERSION) | ( 1 << SSL3_MINORVERSION))

/* table with infos about the ssl cipher suites
 *   THIS IS IN ORDER OF PREFERENCE
 */
#if !defined(__ENABLE_DIGICERT_DTLS_SERVER__)
static
#endif
CipherSuiteInfo gCipherSuites[] = {     /*cipherIndex supported keysize ivsize cipherFun hashtype*/

    /******************************************************************************/
    /*                                                                            */
    /*               ************ SRP CIPHERS ***********                         */
    /*  First in order of preference, since a client proposing it and others      */
    /*  probably prefers it                                                       */
    /*                                                                            */
    /******************************************************************************/

#if (defined(__ENABLE_DIGICERT_TLS13__)) && (defined(__ENABLE_DIGICERT_GCM__))
#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)
    /* 0x1302 TLS_AES_256_GCM_SHA384 */
    SSL_CIPHER_DEF( 0x1302, 1, SUPPORTED_VERSION_TLS13, 32, &GCM_TLS13, &EcdheAllSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),

    /* 0x1301 TLS_AES_128_GCM_SHA256 */
    SSL_CIPHER_DEF( 0x1301, 1, SUPPORTED_VERSION_TLS13, 16, &GCM_TLS13, &EcdheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
    /* 0x1303 TLS_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF(0x1303, 1, SUPPORTED_VERSION_TLS13, 32, &CHACHA20POLY1305, &EcdheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif /* __ENABLE_DIGICERT_CHACHA20__ && __ENABLE_DIGICERT_POLY1305__ */

#ifndef __DISABLE_AES128_CIPHER__
#ifdef __ENABLE_DIGICERT_CCM__
    /* 0x1304 TLS_AES_128_CCM_SHA256 */
    SSL_CIPHER_DEF( 0x1304, 1, SUPPORTED_VERSION_TLS13, 16, &AESCCM16_TLS13, &EcdheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),

#ifdef __ENABLE_DIGICERT_CCM_8__
    /* 0x1305 TLS_AES_128_CCM_8_SHA256 */
    SSL_CIPHER_DEF( 0x1305, 1, SUPPORTED_VERSION_TLS13, 16, &AESCCM8_TLS13, &EcdheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __ENABLE_DIGICERT_CCM_8__  */
#endif /* __ENABLE_DIGICERT_CCM__    */
#endif /* __DISABLE_AES128_CIPHER__*/
#endif /* __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
    /* 0x1302 TLS_AES_256_GCM_SHA384 */
    SSL_CIPHER_DEF( 0x1302, 1, SUPPORTED_VERSION_TLS13, 32, &GCM_TLS13, &DheAllSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),

    /* 0x1301 TLS_AES_128_GCM_SHA256 */
    SSL_CIPHER_DEF( 0x1301, 1, SUPPORTED_VERSION_TLS13, 16, &GCM_TLS13, &DheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),

#ifndef __DISABLE_AES128_CIPHER__
#ifdef __ENABLE_DIGICERT_CCM__
    /* 0x1304 TLS_AES_128_CCM_SHA256 */
    SSL_CIPHER_DEF( 0x1304, 1, SUPPORTED_VERSION_TLS13, 16, &AESCCM16_TLS13, &DheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),

#ifdef __ENABLE_DIGICERT_CCM_8__
    /* 0x1305 TLS_AES_128_CCM_8_SHA256 */
    SSL_CIPHER_DEF( 0x1305, 1, SUPPORTED_VERSION_TLS13, 16, &AESCCM8_TLS13, &DheAllSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __ENABLE_DIGICERT_CCM_8__  */
#endif /* __ENABLE_DIGICERT_CCM__    */
#endif /* __DISABLE_AES128_CIPHER__*/
#endif /* __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__ */

#endif /* __ENABLE_DIGICERT_TLS13__  */

#ifdef __ENABLE_DIGICERT_SSL_SRP__

#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES_CIPHERS__

#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC021 TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA */
    SSL_CIPHER_DEF( 0xC021, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &RsaSrpSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC01E TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA */
    SSL_CIPHER_DEF( 0xC01E, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &RsaSrpSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#endif  /* __DISABLE_AES_CIPHERS__ */

#ifndef __DISABLE_3DES_CIPHERS__
    /* 0xC01B TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA */
    SSL_CIPHER_DEF( 0xC01B, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &RsaSrpSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif /* !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && __ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES_CIPHERS__

#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC020 TLS_SRP_SHA_WITH_AES_256_CBC_SHA */
    SSL_CIPHER_DEF( 0xC020, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &SrpSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC01D TLS_SRP_SHA_WITH_AES_128_CBC_SHA */
    SSL_CIPHER_DEF( 0xC01D, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &SrpSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#endif  /* __DISABLE_AES_CIPHERS__ */

#ifndef __DISABLE_3DES_CIPHERS__
    /* 0xC01A TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA */
    SSL_CIPHER_DEF( 0xC01A, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &SrpSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif /*__DISABLE_DIGICERT_SSL_WEAK_CIPHERS__*/

#endif/***************  __ENABLE_DIGICERT_SSL_SRP__ *****************************/

/*****************************************************************************/
/*                                ECDHE                                      */
/*****************************************************************************/
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) && !defined(__DISABLE_DIGICERT_TLS12_CHACHA20_POLY1035__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF( 0xCCA9, 1, SUPPORTED_VERSION_TLS12, 32, &CHACHA20POLY1305, &EcdheEcdsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
    /* 0xCCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    SSL_CIPHER_DEF( 0xCCA8, 1, SUPPORTED_VERSION_TLS12, 32, &CHACHA20POLY1305, &EcdheRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#endif

#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0xC02C TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0xC02C, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &EcdheEcdsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0xC030, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &EcdheRsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0xC02B, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &EcdheEcdsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0xC02F, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &EcdheRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#ifdef __ENABLE_DIGICERT_CCM__

#ifndef __DISABLE_AES_256_CIPHER__
    /* 0xC0AD TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
    SSL_CIPHER_DEF( 0xC0AD, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM16, &EcdheEcdsaSuite, NULL, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES_128_CIPHER__
    /* 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    SSL_CIPHER_DEF( 0xC0AC, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM16, &EcdheEcdsaSuite, NULL, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#endif /* __ENABLE_DIGICERT_CCM__ */

#ifdef __ENABLE_DIGICERT_CCM_8__

#ifndef __DISABLE_AES_256_CIPHER__
    /* 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
    SSL_CIPHER_DEF( 0xC0AF, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM8, &EcdheEcdsaSuite, NULL, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES_128_CIPHER__
    /* 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
    SSL_CIPHER_DEF( 0xC0AE, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM8, &EcdheEcdsaSuite, NULL, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#endif /* __ENABLE_DIGICERT_CCM_8__ */

#ifndef __DISABLE_AES256_CIPHER__
#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0xC024 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384*/
    SSL_CIPHER_DEF( 0xC024, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA384, &EcdheEcdsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384*/
    SSL_CIPHER_DEF( 0xC028, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA384, &EcdheRsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC00A TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC00A, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &EcdheEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC014, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &EcdheRsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif


#ifndef __DISABLE_AES128_CIPHER__
#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0xC023, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &EcdheEcdsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0xC027, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &EcdheRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC009 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC009, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &EcdheEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC013, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &EcdheRsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif

#endif /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC008 SSL_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC008, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &EcdheEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC012 SSL_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC012, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &EcdheRsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__ */

/*****************************************************************************/
/*                                  DHE                                      */
/*****************************************************************************/
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) && !defined(__DISABLE_DIGICERT_TLS12_CHACHA20_POLY1035__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xCCAA TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF( 0xCCAA, 1, SUPPORTED_VERSION_TLS12, 32, &CHACHA20POLY1305, &DiffieHellmanRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#ifndef __DISABLE_AES_CIPHERS__
#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x009F TLS_DHE_RSA_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0x009F, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &DiffieHellmanRsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x009E TLS_DHE_RSA_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0x009E, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &DiffieHellmanRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#ifdef __ENABLE_DIGICERT_CCM__
#ifndef __DISABLE_DIGICERT_SHA256__
#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC09F TLS_RSA_WITH_AES_256_CCM */
    SSL_CIPHER_DEF( 0xC09F, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM16, &DiffieHellmanRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC09E TLS_RSA_WITH_AES_128_CCM */
    SSL_CIPHER_DEF( 0xC09E, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM16, &DiffieHellmanRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SHA256__ */
#endif /* __ENABLE_DIGICERT_CCM__ */

#ifdef __ENABLE_DIGICERT_CCM_8__
#ifndef __DISABLE_DIGICERT_SHA256__
#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC0A3 TLS_RSA_WITH_AES_256_CCM_8 */
    SSL_CIPHER_DEF( 0xC0A3, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM8, &DiffieHellmanRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC0A2 TLS_RSA_WITH_AES_128_CCM_8 */
    SSL_CIPHER_DEF( 0xC0A2, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM8, &DiffieHellmanRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /*  __DISABLE_DIGICERT_SHA256__ */
#endif /* __ENABLE_DIGICERT_CCM_8__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x006B TLS_DHE_RSA_WITH_AES_256_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x006B, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA256, &DiffieHellmanRsaSuite, NULL, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /*  0x0039 TLS_DHE_RSA_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0039, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA1, &DiffieHellmanRsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x0067 TLS_DHE_RSA_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x0067, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &DiffieHellmanRsaSuite, NULL, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
   /*  0x0033 TLS_DHE_RSA_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0033, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &DiffieHellmanRsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0016 SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0016, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &DiffieHellmanRsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && __ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__) && __ENABLE_DIGICERT_SSL_DHE_SUPPORT__ */

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__)
#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0032 SSL_DHE_DSS_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0032, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &DiffieHellmanDsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x0040 SSL_DHE_DSS_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x0040, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &DiffieHellmanDsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif

/*****************************************************************************/
/*                                  ECDH                                     */
/*****************************************************************************/
#ifdef __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0xC02E TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0xC02E, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &EcdhEcdsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC032 TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0xC032, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &EcdhRsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC02D TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0xC02D, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &EcdhEcdsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC031 TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0xC031, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &EcdhRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0xC026 TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384*/
    SSL_CIPHER_DEF( 0xC026, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA384, &EcdhEcdsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC02A TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384*/
    SSL_CIPHER_DEF( 0xC02A, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA384, &EcdhRsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC005 TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC005, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &EcdhEcdsaSuite,  NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC00F TLS_ECDH_RSA_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC00F, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &EcdhRsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC025 TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0xC025, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &EcdhEcdsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC029 TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0xC029, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &EcdhRsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC004 TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC004, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &EcdhEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC00E TLS_ECDH_RSA_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC00E, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &EcdhRsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC003 SSL_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC003, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &EcdhEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC00D SSL_ECDH_RSA_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC00D, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &EcdhRsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__ */


/*****************************************************************************/
/*                                  RSA                                      */
/*****************************************************************************/
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))

#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x009D TLS_RSA_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0x009D, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &RsaSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x009C TLS_RSA_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0x009C, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x003D TLS_RSA_WITH_AES_256_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x003D, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA256, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
   /* 0x0035 TLS_RSA_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0035, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA1, &RsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x003C TLS_RSA_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x003C, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x002F TLS_RSA_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x002F, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &RsaSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#ifdef __ENABLE_DIGICERT_CCM__
#ifndef __DISABLE_DIGICERT_SHA256__
#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC09D TLS_RSA_WITH_AES_256_CCM */
    SSL_CIPHER_DEF( 0xC09D, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM16, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC09C TLS_RSA_WITH_AES_128_CCM */
    SSL_CIPHER_DEF( 0xC09C, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM16, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SHA256__ */
#endif /* __ENABLE_DIGICERT_CCM__ */

#ifdef __ENABLE_DIGICERT_CCM_8__
#ifndef __DISABLE_DIGICERT_SHA256__
#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC0A1 TLS_RSA_WITH_AES_256_CCM_8 */
    SSL_CIPHER_DEF( 0xC0A1, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM8, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC0A0 TLS_RSA_WITH_AES_128_CCM_8 */
    SSL_CIPHER_DEF( 0xC0A0, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM8, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif /*  __DISABLE_DIGICERT_SHA256__ */
#endif /* __ENABLE_DIGICERT_CCM_8__ */
#endif  /* __DISABLE_AES_CIPHERS__ */

    /* pick ARC4 over 3DES CBC if SSL3 is enabled, there's no real good choice here anyway */
#if ((MIN_SSL_MINORVERSION==SSL3_MINORVERSION) && (MAX_SSL_MINORVERSION<TLS13_MINORVERSION))
#if (!defined(__DISABLE_ARC4_CIPHERS__) && !defined(__DISABLE_DIGICERT_SSL_WEAK_CIPHERS__))
    /*  5 SSL_RSA_WITH_RC4_128_SHA*/
    SSL_CIPHER_DEF( 0x0005, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &RC4SHA1, &RsaSuite, NULL, ht_sha1, SINGLE_PASS_RC4_SHA1_IN, SINGLE_PASS_RC4_SHA1_OUT ),
#endif
#endif

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x000A SSL_RSA_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x000A, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &RsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif

/*****************************************************************************/
/*                                  ECDH_ANON                                */
/*****************************************************************************/
#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES_CIPHERS__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC019 TLS_ECDH_anon_WITH_AES_256_CBC_SHA  */
    SSL_CIPHER_DEF( 0xC019, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &EcdheAnonSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC018 TLS_ECDH_anon_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC018, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &EcdheAnonSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_AES_CIPHERS__ */

#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC017 SSL_ECDH_anon_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0xC017, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &EcdheAnonSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif /* __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__ */


/*****************************************************************************/
/*                                  DH_ANON                                  */
/*****************************************************************************/

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__

#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00A7 TLS_DH_ANON_WITH_AES_256_GCM_SHA384*/
    SSL_CIPHER_DEF( 0x00A7, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &DiffieHellmanAnonSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00A6 TLS_DH_ANON_WITH_AES_128_GCM_SHA256*/
    SSL_CIPHER_DEF( 0x00A6, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &DiffieHellmanAnonSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x006D TLS_DH_ANON_WITH_AES_256_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x006D, 1, SUPPORTED_VERSION_TLS12, 32, &AESSHA256, &DiffieHellmanAnonSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x003A TLS_DH_ANON_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0x003A, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA1, &DiffieHellmanAnonSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x006C TLS_DH_ANON_WITH_AES_128_CBC_SHA256*/
    SSL_CIPHER_DEF( 0x006C, 1, SUPPORTED_VERSION_TLS12, 16, &AESSHA256, &DiffieHellmanAnonSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
   /* 0x0034 TLS_DH_ANON_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0034, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &DiffieHellmanAnonSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif   /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x001B SSL_DH_ANON_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x001B, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &DiffieHellmanAnonSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__ */

/*****************************************************************************/
/*                                                                           */
/*          ******** PRESHARED KEY **********                                */
/*                                                                           */
/*****************************************************************************/
#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__

/*****************************************************************************/
/*                                ECDHE                                      */
/*****************************************************************************/
#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) && !defined(__DISABLE_DIGICERT_TLS12_CHACHA20_POLY1035__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xCCAC TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF(0xCCAC, 1, SUPPORTED_VERSION_TLS11_TO_TLS12, 32, &CHACHA20POLY1305, &EcdhePskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES_CIPHERS__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0xC038 TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    SSL_CIPHER_DEF(0xC038, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA384, &EcdhePskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC037 TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    SSL_CIPHER_DEF(0xC037, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA256, &EcdhePskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC036 TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF(0xC036, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA1, &EcdhePskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC035 TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF(0xC035, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA1, &EcdhePskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_AES_CIPHERS__ */

#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC034 TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF(0xC034, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 24, &TripleDESSHA1, &EcdhePskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif /* __DISABLE_3DES_CIPHERS__ */
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */


#endif /*__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__ */

/*****************************************************************************/
/*                                  DHE                                      */
/*****************************************************************************/
#if defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) && !defined(__DISABLE_DIGICERT_TLS12_CHACHA20_POLY1035__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xCCAD TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF(0xCCAD, 1, SUPPORTED_VERSION_TLS11_TO_TLS12, 32, &CHACHA20POLY1305, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00AB TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
    SSL_CIPHER_DEF( 0x00AB, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &DiffieHellmanPskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00AA TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
    SSL_CIPHER_DEF( 0x00AA, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#ifdef __ENABLE_DIGICERT_CCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC0A7 TLS_DHE_PSK_WITH_AES_256_CCM */
    SSL_CIPHER_DEF( 0xC0A7, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM16, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC0A6 TLS_DHE_PSK_WITH_AES_128_CCM */
    SSL_CIPHER_DEF( 0xC0A6, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM16, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#endif /* __ENABLE_DIGICERT_CCM__ */

#ifdef __ENABLE_DIGICERT_CCM_8__

#ifndef __DISABLE_AES256_CIPHER__
    /* 0xC0AB TLS_DHE_PSK_WITH_AES_256_CCM_8 */
    SSL_CIPHER_DEF( 0xC0AB, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM8, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif

#ifndef __DISABLE_AES128_CIPHER__
    /* 0xC0AA TLS_DHE_PSK_WITH_AES_128_CCM_8 */
    SSL_CIPHER_DEF( 0xC0AA, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM8, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif

#endif /* __ENABLE_DIGICERT_CCM_8__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_DIGICERT_SHA384__
#ifndef __DISABLE_AES256_CIPHER__
    /* 0x00B3 TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    SSL_CIPHER_DEF( 0x00B3, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA384, &DiffieHellmanPskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00B2 TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    SSL_CIPHER_DEF( 0x00B2, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA256, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0091 TLS_DHE_PSK_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0091, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA1, &DiffieHellmanPskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0090 TLS_DHE_PSK_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0090, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &DiffieHellmanPskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x008F SSL_DHE_PSK_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x008F, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &DiffieHellmanPskSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

#endif /* __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__ */


/*****************************************************************************/
/*                                  RSA                                      */
/*****************************************************************************/
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) && !defined(__DISABLE_DIGICERT_TLS12_CHACHA20_POLY1035__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xCCAE TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF(0xCCAE, 1, SUPPORTED_VERSION_TLS11_TO_TLS12, 32, &CHACHA20POLY1305, &RsaPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00AD TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    SSL_CIPHER_DEF( 0x00AD, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &RsaPskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00AC TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    SSL_CIPHER_DEF( 0x00AC, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &RsaPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */


#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00B7 TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    SSL_CIPHER_DEF( 0x00B7, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA384, &RsaPskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00B6 TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    SSL_CIPHER_DEF( 0x00B6, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA256, &RsaPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0095 TLS_RSA_PSK_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0095, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA1, &RsaPskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0094 TLS_RSA_PSK_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0094, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &RsaPskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x0093 TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0093, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &RsaPskSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */


#endif /* !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && __ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__ */

/*****************************************************************************/
/*                                  PSK                                      */
/*****************************************************************************/

#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__) && !defined(__DISABLE_DIGICERT_TLS12_CHACHA20_POLY1035__)
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xCCAB TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    SSL_CIPHER_DEF(0xCCAB, 1, SUPPORTED_VERSION_TLS11_TO_TLS12, 32, &CHACHA20POLY1305, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES_CIPHERS__

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00A9 TLS_PSK_WITH_AES_256_GCM_SHA384 */
    SSL_CIPHER_DEF( 0x00A9, 1, SUPPORTED_VERSION_TLS12, 32, &GCM, &PskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00A8 TLS_PSK_WITH_AES_128_GCM_SHA256 */
    SSL_CIPHER_DEF( 0x00A8, 1, SUPPORTED_VERSION_TLS12, 16, &GCM, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#endif /* __ENABLE_DIGICERT_GCM__ */

#ifdef __ENABLE_DIGICERT_CCM__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC0A5 TLS_PSK_WITH_AES_256_CCM */
    SSL_CIPHER_DEF( 0xC0A5, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM16, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC0A4 TLS_PSK_WITH_AES_128_CCM */
    SSL_CIPHER_DEF( 0xC0A4, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM16, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#endif /* __ENABLE_DIGICERT_CCM__ */

#ifdef __ENABLE_DIGICERT_CCM_8__

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC0A9 TLS_PSK_WITH_AES_256_CCM_8 */
    SSL_CIPHER_DEF( 0xC0A9, 1, SUPPORTED_VERSION_TLS12, 32, &AESCCM8, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC0A8 TLS_PSK_WITH_AES_128_CCM_8 */
    SSL_CIPHER_DEF( 0xC0A8, 1, SUPPORTED_VERSION_TLS12, 16, &AESCCM8, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#endif /* __ENABLE_DIGICERT_CCM_8__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00AF TLS_PSK_WITH_AES_256_CBC_SHA384 */
    SSL_CIPHER_DEF( 0x00AF, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 32, &AESSHA384, &PskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00AE TLS_PSK_WITH_AES_128_CBC_SHA256 */
    SSL_CIPHER_DEF( 0x00AE, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 16, &AESSHA256, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif
#endif

#ifndef __DISABLE_AES256_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x008D TLS_PSK_WITH_AES_256_CBC_SHA*/
    SSL_CIPHER_DEF( 0x008D, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 32, &AESSHA1, &PskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#ifndef __DISABLE_AES128_CIPHER__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x008C TLS_PSK_WITH_AES_128_CBC_SHA*/
    SSL_CIPHER_DEF( 0x008C, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 16, &AESSHA1, &PskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif

#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */
#endif /* __DISABLE_AES_CIPHERS__ */

#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0x008B TLS_PSK_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x008B, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &PskSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

/******************************************************************************/
/*                              NIL CIPHER                                    */
/******************************************************************************/
#ifdef __ENABLE_NIL_CIPHER__

    /******* ECDHE **********/
#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__

#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0xC03B TLS_ECDHE_PSK_WITH_NULL_SHA384*/
    SSL_CIPHER_DEF(0xC03B, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 0, &NilSHA384, &EcdhePskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0xC03A TLS_ECDHE_PSK_WITH_NULL_SHA256*/
    SSL_CIPHER_DEF(0xC03A, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 0, &NilSHA256, &EcdhePskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif

#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
    /* 0xC039 TLS_ECDHE_PSK_WITH_NULL_SHA*/
    SSL_CIPHER_DEF(0xC039, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 0, &NilSHA1, &EcdhePskSuite, NULL, ht_sha1, SINGLE_PASS_AES_SHA1_IN, SINGLE_PASS_AES_SHA1_OUT),
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */

#endif /* __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__ */

    /*******+** DHE **********/

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__

#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00B5 TLS_DHE_PSK_WITH_NULL_SHA384 */
    SSL_CIPHER_DEF( 0x00B5, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA384, &DiffieHellmanPskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT),
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00B4 TLS_DHE_PSK_WITH_NULL_SHA256 */
    SSL_CIPHER_DEF( 0x00B4, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA256, &DiffieHellmanPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT),
#endif

#endif /* __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__ */

    /*******+** RSA **********/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))

#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00B9 TLS_RSA_PSK_WITH_NULL_SHA384 */
    SSL_CIPHER_DEF( 0x00B9, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA384, &RsaPskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT),
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00B8 TLS_RSA_PSK_WITH_NULL_SHA256 */
    SSL_CIPHER_DEF( 0x00B8, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA256, &RsaPskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT),
#endif

#endif /* !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && __ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__ */

    /******** PSK *********/

#ifndef __DISABLE_DIGICERT_SHA384__
    /* 0x00B1 TLS_PSK_WITH_NULL_SHA384 */
    SSL_CIPHER_DEF( 0x00B1, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA384, &PskSuite, &SHA384Suite, ht_sha384, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT),
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x00B0 TLS_PSK_WITH_NULL_SHA256 */
    SSL_CIPHER_DEF( 0x00B0, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA256, &PskSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT),
#endif

#endif /* __ENABLE_NIL_CIPHER__ */

#endif /************* __ENABLE_DIGICERT_SSL_PSK_SUPPORT__ ***********************/


/******************************************************************************/
/*                                                                            */
/*              ********* VERY WEAK CIPHERS ******                            */
/*                                                                            */
/******************************************************************************/

/********* DES cipher *************/
#if !defined(__DISABLE_DIGICERT_SSL_CBC_CIPHERS__)
#ifdef __ENABLE_DES_CIPHER__

#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
    /* 0x0015 SSL_DHE_RSA_WITH_DES_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0015, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 8, &DESSHA1, &DiffieHellmanRsaSuite, NULL, ht_sha1, SINGLE_PASS_DES_SHA1_IN, SINGLE_PASS_DES_SHA1_OUT ),
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /*  0x0009 SSL_RSA_WITH_DES_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0009, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 8, &DESSHA1, &RsaSuite, NULL, ht_sha1, SINGLE_PASS_DES_SHA1_IN, SINGLE_PASS_DES_SHA1_OUT ),
#endif

#ifdef __ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__
    /* 0x001A SSL_DH_ANON_WITH_DES_CBC_SHA*/
    SSL_CIPHER_DEF( 0x001A, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 8, &DESSHA1, &DiffieHellmanAnonSuite, NULL, ht_sha1, SINGLE_PASS_DES_SHA1_IN, SINGLE_PASS_DES_SHA1_OUT ),
#endif

#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif /* __ENABLE_DES_CIPHER__ */

#ifndef __DISABLE_3DES_CIPHERS__
#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
    /* 0x0013 SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA*/
    SSL_CIPHER_DEF( 0x0013, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 24, &TripleDESSHA1, &DiffieHellmanDsaSuite, NULL, ht_sha1, SINGLE_PASS_3DES_SHA1_IN, SINGLE_PASS_3DES_SHA1_OUT ),
#endif
#endif /* __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__ */
#endif /*  !__DISABLE_3DES_CIPHERS__ */
#endif /* __DISABLE_DIGICERT_SSL_CBC_CIPHERS__ */

/********* No Cipher **************/
#ifdef __ENABLE_NIL_CIPHER__

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
#ifndef __DISABLE_DIGICERT_SHA256__
    /* 0x003B SSL_RSA_WITH_NULL_SHA256 */
    SSL_CIPHER_DEF( 0x003B, 1, SUPPORTED_VERSION_TLS12, 0, &NilSHA256, &RsaSuite, &SHA256Suite, ht_sha256, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#endif
#endif /* !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__) */

#ifndef __DISABLE_DIGICERT_SSL_WEAK_CIPHERS__
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
    /* 0xC006 TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    SSL_CIPHER_DEF( 0xC006, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA1, &EcdheEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC010 TLS_ECDHE_RSA_WITH_NULL_SHA */
    SSL_CIPHER_DEF( 0xC010, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA1, &EcdheRsaSuite, NULL, ht_sha1, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#endif
#endif

#ifdef __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
    /* 0xC001 TLS_ECDH_ECDSA_WITH_NULL_SHA */
    SSL_CIPHER_DEF( 0xC001, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 0, &NilSHA1, &EcdhEcdsaSuite, NULL, ht_sha1, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0xC00B TLS_ECDH_RSA_WITH_NULL_SHA */
    SSL_CIPHER_DEF( 0xC00B, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 0, &NilSHA1, &EcdhRsaSuite, NULL, ht_sha1, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#endif
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
    /* 0x0002 SSL_RSA_WITH_NULL_SHA*/
    SSL_CIPHER_DEF( 0x0002, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilSHA1, &RsaSuite, NULL, ht_sha1, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#endif /* !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__) */


#ifdef __ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
    /* 0xC015 TLS_ECDH_anon_WITH_NULL_SHA */
    SSL_CIPHER_DEF( 0xC015, 1, SUPPORTED_VERSION_TLS10_TO_TLS12, 0, &NilSHA1, &EcdheAnonSuite, NULL, ht_sha1, SINGLE_PASS_NULL_SHA1_IN, SINGLE_PASS_NULL_SHA1_OUT ),
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
#if (!defined(__DISABLE_NULL_MD5_CIPHER__) && !defined(__DISABLE_DIGICERT_SSL_WEAK_CIPHERS__))
    /*  0x0001 SSL_RSA_WITH_NULL_MD5*/
    SSL_CIPHER_DEF( 0x0001, 1, SUPPORTED_VERSION_SSL3_TO_TLS12, 0, &NilMD5, &RsaSuite, NULL, ht_md5, SINGLE_PASS_NULL_MD5_IN, SINGLE_PASS_NULL_MD5_OUT ),
#endif
#endif
#endif /*__DISABLE_DIGICERT_SSL_WEAK_CIPHERS__*/
#endif /* __ENABLE_NIL_CIPHER___ */
};

#define NUM_CIPHER_SUITES    (COUNTOF(gCipherSuites))

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
#if !defined(__ENABLE_DIGICERT_DTLS_SERVER__)
static
#endif
const ubyte2 gCipherIdFIPSExclusion[] = {
    /* RC4 */
    0x0005, /* SSL_RSA_WITH_RC4_128_SHA */
    0xC03B, /* SSL_RSA_WITH_RC4_128_SHA384 */

    /* Nil */
    0xC03A, /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    0xC039, /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    0x00B5, /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    0x00B4, /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    0x00B9, /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    0x00B8, /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    0x00B1, /* TLS_PSK_WITH_NULL_SHA384 */
    0x00B0, /* TLS_PSK_WITH_NULL_SHA256 */
    0xC006, /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    0xC010, /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    0xC001, /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    0xC00B, /* TLS_ECDH_RSA_WITH_NULL_SHA */
    0x003B, /* SSL_RSA_WITH_NULL_SHA256 */
    0x0002, /* SSL_RSA_WITH_NULL_SHA */
    0xC015, /* TLS_ECDH_anon_WITH_NULL_SHA */

    /* MD5 */
    0x0001, /* SSL_RSA_WITH_NULL_MD5 */

    /* ChaCha20-Poly1305 */
    0xCCA9, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCA8, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCAA, /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCAC, /* TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCAD, /* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCAE, /* TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCAB, /* TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */

    /* DES */
    0x0015, /* SSL_DHE_RSA_WITH_DES_CBC_SHA */
    0x0009, /* SSL_RSA_WITH_DES_CBC_SHA */
    0x001A  /* SSL_DH_ANON_WITH_DES_CBC_SHA */
};

#define NUM_CIPHERID_FIPS_EXCLUSION (COUNTOF(gCipherIdFIPSExclusion))
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
static const ubyte2 gCipherIdDTLSExclusion[] =
{
    0xC002, 0xC00C, 0xC007, 0xC011, 0x0004, 0x0005, 0x0018, 0xC016,
    0x008A, 0x0092, 0x008E
};

#define NUM_CIPHERID_DTLS_EXCLUSION (COUNTOF(gCipherIdDTLSExclusion))
#endif

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
static const ubyte2 gCipherIdDSA[] = {
    0x0032, /* SSL_DHE_DSS_WITH_AES_128_CBC_SHA */
    0x0040, /* SSL_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    0x0013, /* SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
};

#define NUM_CIPHERID_DSA (COUNTOF(gCipherIdDSA))
#endif

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)  || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) || \
    (!(defined(__DISABLE_DIGICERT_DH_RFC7919_GROUPS__))))

/* List of supported groups
 *
 *   THIS IS IN ORDER OF PREFERENCE
 */
ubyte2 gSupportedNamedGroup[] = {
#ifndef __DISABLE_DIGICERT_ECC_P256__
    tlsExtNamedCurves_secp256r1,
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    tlsExtNamedCurves_secp384r1,
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    tlsExtNamedCurves_secp521r1,
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    tlsExtNamedCurves_secp224r1,
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
    tlsExtNamedCurves_secp192r1,
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    tlsExtNamedCurves_x25519,
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    tlsExtNamedCurves_x448,
#endif
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
    tlsExtNamedCurves_ffdhe2048,
    tlsExtNamedCurves_ffdhe3072,
    tlsExtNamedCurves_ffdhe4096,
    tlsExtNamedCurves_ffdhe6144,
    tlsExtNamedCurves_ffdhe8192,
#endif
#ifdef __ENABLE_DIGICERT_PQC__
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    tlsExtHybrid_X25519MLKEM768,
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    tlsExtHybrid_SecP256r1MLKEM768,
#endif
#endif
};

#define GROUP_BIT_MASK(group) (1 << (group & 0x1F))
#define SUPPORTED_GROUP_MASK        (0xFF00)
#define ECDH_SUPPORTED_GROUP_MASK   (0x0000)
#define FFDH_SUPPORTED_GROUP_MASK   (0x0100)
#define HYBRID_SUPPORTED_GROUP_MASK (0x1100)

/* so far tlsExtHybrid_X25519MLKEM768 is only group with PQC sig/key followed by the ECC one */
#define HYBRID_IS_PQC_FIRST( x) (tlsExtHybrid_X25519MLKEM768 == x ? TRUE : FALSE)

#define NUM_SSL_SUPPORTED_NAMED_GROUP (COUNTOF( gSupportedNamedGroup))

#ifndef __ENABLE_DIGICERT_ECC_P192__
#define EC_P192_FLAG    0
#else
#define EC_P192_FLAG    (1 << tlsExtNamedCurves_secp192r1)
#endif

#ifdef __DISABLE_DIGICERT_ECC_P224__
#define EC_P224_FLAG    0
#else
#define EC_P224_FLAG    (1 << tlsExtNamedCurves_secp224r1)
#endif

#ifdef __DISABLE_DIGICERT_ECC_P256__
#define EC_P256_FLAG    0
#else
#define EC_P256_FLAG    (1 << tlsExtNamedCurves_secp256r1)
#endif

#ifdef __DISABLE_DIGICERT_ECC_P384__
#define EC_P384_FLAG    0
#else
#define EC_P384_FLAG    (1 << tlsExtNamedCurves_secp384r1)
#endif

#ifdef __DISABLE_DIGICERT_ECC_P521__
#define EC_P521_FLAG    0
#else
#define EC_P521_FLAG    (1 << tlsExtNamedCurves_secp521r1)
#endif

#ifndef __ENABLE_DIGICERT_ECC_EDDH_25519__
#define EC_X25519_FLAG    0
#else
#define EC_X25519_FLAG  (1 << tlsExtNamedCurves_x25519)
#endif

#ifndef __ENABLE_DIGICERT_ECC_EDDH_448__
#define EC_X448_FLAG    0
#else
#define EC_X448_FLAG    (1 << tlsExtNamedCurves_x448)
#endif

/* FFDHE group values start at 256 and end at 260, in order to,
 * store values in an 32 bit integer mask all but the last bits. */
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
#define DH_FFDHE2048_FLAG   (1 << (tlsExtNamedCurves_ffdhe2048 & 0x1F))
#define DH_FFDHE3072_FLAG   (1 << (tlsExtNamedCurves_ffdhe3072 & 0x1F))
#define DH_FFDHE4096_FLAG   (1 << (tlsExtNamedCurves_ffdhe4096 & 0x1F))
#define DH_FFDHE6144_FLAG   (1 << (tlsExtNamedCurves_ffdhe6144 & 0x1F))
#define DH_FFDHE8192_FLAG   (1 << (tlsExtNamedCurves_ffdhe8192 & 0x1F))
#else
#define DH_FFDHE2048_FLAG   0
#define DH_FFDHE3072_FLAG   0
#define DH_FFDHE4096_FLAG   0
#define DH_FFDHE6144_FLAG   0
#define DH_FFDHE8192_FLAG   0
#endif

#if defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
#define HYBRID_MLKEM768_X25519_FLAG        (1 << (tlsExtHybrid_X25519MLKEM768 & 0x1F))
#else
#define HYBRID_MLKEM768_X25519_FLAG        0
#endif

#if defined(__ENABLE_DIGICERT_PQC__) && !defined(__DISABLE_DIGICERT_ECC_P256__)
#define HYBRID_SECP256R1_MLKEM768_FLAG     (1 << (tlsExtHybrid_SecP256r1MLKEM768 & 0x1F))
#else
#define HYBRID_SECP256R1_MLKEM768_FLAG     0
#endif

#define HYBRID_FLAG (HYBRID_MLKEM768_X25519_FLAG | \
                     HYBRID_SECP256R1_MLKEM768_FLAG )

#ifndef SUPPORTED_GROUPS_FLAGS
#define SUPPORTED_GROUPS_FLAGS \
    (EC_P192_FLAG | \
     EC_P224_FLAG | \
     EC_P256_FLAG | \
     EC_P384_FLAG | \
     EC_P521_FLAG | \
     EC_X25519_FLAG | \
     EC_X448_FLAG | \
     DH_FFDHE2048_FLAG | \
     DH_FFDHE3072_FLAG | \
     DH_FFDHE4096_FLAG | \
     DH_FFDHE6144_FLAG | \
     DH_FFDHE8192_FLAG | \
     HYBRID_FLAG )
#endif

#ifndef SUPPORTED_GROUPS_FLAGS_TLS12
#define SUPPORTED_GROUPS_FLAGS_TLS12 \
    (EC_P192_FLAG | \
     EC_P224_FLAG | \
     EC_P256_FLAG | \
     EC_P384_FLAG | \
     EC_P521_FLAG)
#endif

#ifndef SUPPORTED_GROUPS_FLAGS_TLS13
#define SUPPORTED_GROUPS_FLAGS_TLS13 \
    (EC_P256_FLAG | \
     EC_P384_FLAG | \
     EC_P521_FLAG | \
     EC_X25519_FLAG | \
     EC_X448_FLAG | \
     DH_FFDHE2048_FLAG | \
     DH_FFDHE3072_FLAG | \
     DH_FFDHE4096_FLAG | \
     DH_FFDHE6144_FLAG | \
     DH_FFDHE8192_FLAG | \
     HYBRID_FLAG )
#endif

#else

#define SUPPORTED_GROUPS_FLAGS 0

#define SUPPORTED_GROUPS_FLAGS_TLS12 0

#define SUPPORTED_GROUPS_FLAGS_TLS13 0

#endif  /* defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) ||
            defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)||
            defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)*/

enum TLS13_SignatureAlgorithm
{
    TLS_13_RSA_PSS_RSAE_SHA256 = 0x04,
    TLS_13_RSA_PSS_RSAE_SHA384 = 0x05,
    TLS_13_RSA_PSS_RSAE_SHA512 = 0x06,
    TLS_13_RSA_PSS_PSS_SHA256  = 0x09,
    TLS_13_RSA_PSS_PSS_SHA384  = 0x0A,
    TLS_13_RSA_PSS_PSS_SHA512  = 0x0B
};

enum TLS_SignatureAlgorithm
{
    TLS_ANONYMOUS               = 0,
    TLS_RSA                     = 1,
    TLS_DSA                     = 2,
    TLS_ECDSA                   = 3,
    TLS_EDDSA25519              = 7,
    TLS_EDDSA448                = 8,
#ifdef __ENABLE_DIGICERT_PQC__
    TLS_MLDSA_44                     = 4,
    TLS_MLDSA_65                     = 5,
    TLS_MLDSA_87                     = 6,      
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    TLS_MLDSA_44_ECDSA_P256_SHA256   = 7, /* ok to have duplicate values */
    TLS_MLDSA_65_ECDSA_P384_SHA384   = 8,
    TLS_MLDSA_87_ECDSA_P384_SHA384   = 9,
    TLS_MLDSA_44_EDDSA_25519         = 10,
    TLS_MLDSA_65_EDDSA_25519         = 11,
    TLS_MLDSA_44_RSA_2048_SHA256     = 12,
    TLS_MLDSA_65_RSA_3072_SHA256     = 13,
    TLS_MLDSA_65_RSA_4096_SHA384     = 14,
    TLS_MLDSA_44_RSA_2048_PSS_SHA256 = 15,
    TLS_MLDSA_65_RSA_3072_PSS_SHA256 = 16,
    TLS_MLDSA_65_RSA_4096_PSS_SHA384 = 17,
    TLS_MLDSA_87_EDDSA_448           = 18,
#endif
#endif
    TLS_SIGNATURE_MAX                = 255
};

ubyte2 gSupportedVersions[] =
{
    SSL3_MAJORVERSION << 8 | TLS13_MINORVERSION,
    SSL3_MAJORVERSION << 8 | TLS12_MINORVERSION,
    SSL3_MAJORVERSION << 8 | TLS11_MINORVERSION,
    SSL3_MAJORVERSION << 8 | TLS10_MINORVERSION,
};

#define NUM_SUPPORTED_VERSIONS (COUNTOF( gSupportedVersions ))

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
ubyte2 gSupportedVersionsDTLS[] =
{
    DTLS1_MAJORVERSION << 8 | DTLS13_MINORVERSION,
    DTLS1_MAJORVERSION << 8 | DTLS12_MINORVERSION,
    DTLS1_MAJORVERSION << 8 | DTLS10_MINORVERSION,
};

#define NUM_SUPPORTED_VERSIONS_DTLS (COUNTOF( gSupportedVersionsDTLS ))
#endif

enum TLS13_cipherAlgorithmType
{
    TLS13_cipher                         = 0,
    TLS13_supportedGroups                = 1,
    TLS13_signatureAlgorithms            = 2,
    TLS13_certificateSignatureAlgorithms = 3
};

/* List of all cert store hash algorithms that can be set. */
static ubyte4 gAllCertStoreHashAlgorithms[] =
{
    ht_sha512,
    ht_sha384,
    ht_sha256,
    ht_sha224,
    ht_sha1,
    ht_md5
};

#define NUM_SSL_ALL_CERT_STORE_HASH_ALGORITHMS (COUNTOF(gAllCertStoreHashAlgorithms))

static ubyte2 gSupportedSignatureAlgorithms[] =
{
#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))
#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_SHA512 << 8 |TLS_ECDSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_SHA384 << 8 |TLS_ECDSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_SHA256 << 8 |TLS_ECDSA,
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    TLS_INTRINSIC << 8 |TLS_EDDSA25519,
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    TLS_INTRINSIC << 8 |TLS_EDDSA448,
#endif
#else /* __ENABLE_DIGICERT_TLS13__ */
#ifndef __DISABLE_DIGICERT_SHA224__
    TLS_SHA224 << 8 |TLS_ECDSA,
#endif
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
    TLS_SHA1   << 8 |TLS_ECDSA,
#endif
#endif /* __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__ or __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__ */

/* TODO Do we disable ECDSA or RSA composite groups ever */
#ifdef __ENABLE_DIGICERT_PQC__
    TLS_QS << 8 |TLS_MLDSA_44,
    TLS_QS << 8 |TLS_MLDSA_65,
    TLS_QS << 8 |TLS_MLDSA_87,
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    TLS_QS << 8 |TLS_MLDSA_44_ECDSA_P256_SHA256,
    TLS_QS << 8 |TLS_MLDSA_65_ECDSA_P384_SHA384,
    TLS_QS << 8 |TLS_MLDSA_87_ECDSA_P384_SHA384,
    TLS_QS << 8 |TLS_MLDSA_44_EDDSA_25519,
    TLS_QS << 8 |TLS_MLDSA_65_EDDSA_25519,
    TLS_QS << 8 |TLS_MLDSA_44_RSA_2048_PSS_SHA256,
    TLS_QS << 8 |TLS_MLDSA_65_RSA_3072_PSS_SHA256,
    TLS_QS << 8 |TLS_MLDSA_65_RSA_4096_PSS_SHA384,
    TLS_QS << 8 |TLS_MLDSA_87_EDDSA_448,
#endif
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
#if defined(__ENABLE_DIGICERT_TLS13__)
#ifdef __ENABLE_DIGICERT_PKCS1__
#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_PSS_SHA512,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_PSS_SHA384,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_PSS_SHA256,
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_RSAE_SHA512,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_RSAE_SHA384,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_RSAE_SHA256,
#endif
#endif
#endif /* __ENABLE_DIGICERT_TLS13__ */

#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_SHA512 << 8 |TLS_RSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_SHA384 << 8 |TLS_RSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_SHA256 << 8 |TLS_RSA,
#endif
#ifndef __ENABLE_DIGICERT_TLS13__
#ifndef __DISABLE_DIGICERT_SHA224__
    TLS_SHA224 << 8 |TLS_RSA,
#endif
#endif

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
    TLS_SHA1   << 8 |TLS_RSA,
#if !defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_MD5__)
    TLS_MD5    << 8 |TLS_RSA,
#endif
#endif

#endif

#ifdef __ENABLE_DIGICERT_SSL_DSA_SUPPORT__
#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_SHA512 << 8 |TLS_DSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_SHA384 << 8 |TLS_DSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_SHA256 << 8 | TLS_DSA,
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
    TLS_SHA224 << 8 | TLS_DSA,
#endif
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
    TLS_SHA1 << 8 | TLS_DSA,
#endif
#endif
};

#define NUM_SSL_SUPPORTED_SIGNATURE_ALGORITHMS (COUNTOF( gSupportedSignatureAlgorithms))

#define TLS_EXT_SIG_ALGO_IS_PQC(_x) (TLS_QS == (_x >> 8) ? TRUE : FALSE)

#if defined(__ENABLE_DIGICERT_PKCS1__) && defined(__ENABLE_DIGICERT_TLS13__) && \
    (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && \
    defined(__ENABLE_DIGICERT_SSL_SERVER__)
    ubyte2 gServerExcludedSignatureAlgorithms[] = {
#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_PSS_SHA512,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_PSS_SHA384,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_PSS_SHA256,
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_RSAE_SHA512,
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_RSAE_SHA384,
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    TLS_INTRINSIC     << 8 |TLS_13_RSA_PSS_RSAE_SHA256,
#endif
    };
#endif

typedef struct hashSuite
{
    ubyte hashType;
    const ubyte* oid;
    ubyte4 ctxSize;
    const BulkHashAlgo *algo;
} hashSuite;


static hashSuite gSupportedHashAlgorithms[] =
{
#ifndef __DISABLE_DIGICERT_SHA512__
    {TLS_SHA512, sha512_OID, sizeof(SHA512_CTX), &SHA512Suite},
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    {TLS_SHA384, sha384_OID, sizeof(SHA384_CTX), &SHA384Suite},
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
    {TLS_SHA256, sha256_OID, sizeof(SHA256_CTX), &SHA256Suite},
#endif
#ifndef __DISABLE_DIGICERT_SHA224__
    {TLS_SHA224, sha224_OID, sizeof(SHA224_CTX), &SHA224Suite},
#endif

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
    {TLS_SHA1, sha1_OID, sizeof(SHA1_CTX), &SHA1Suite},
#if !defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_MD5__)
    {TLS_MD5, md5_OID, sizeof(MD5_CTX), &MD5Suite}
#endif
#endif
};

#define NUM_SSL_SUPPORTED_HASH_ALGORITHMS (COUNTOF( gSupportedHashAlgorithms))

#ifdef __ENABLE_DIGICERT_TLS12_UNSECURE_HASH__
#define NUM_SSL_SUPPORTED_HASH_ALGORITHMS_EXT (SSL_SOCK_getSupportedHashAlgorithmCount())
#else
#define NUM_SSL_SUPPORTED_HASH_ALGORITHMS_EXT (NUM_SSL_SUPPORTED_HASH_ALGORITHMS)
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#define DTLS_RECORD_SIZE(X)          ((((ubyte2)X[11]) << 8) | ((ubyte2)X[12]))
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
/* SSL Alerts */

typedef struct
{
    sbyte4  sslAlertId;         /* the alert */
    sbyte4  sslAlertClass;      /* warning or error */
    sbyte4  sslProtocol;        /* SSL, TLS, combos, etc */
    MSTATUS mocErrorCode;       /* map error codes to alerts */

} sslAlertsInfo;

#define ALERT_SSL           (0x01)
#define ALERT_TLS           (0x02)
#define ALERT_SSL_TLS       (ALERT_SSL | ALERT_TLS)

static sslAlertsInfo mAlertsSSL[] = {
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL,     ERR_SSL_INVALID_PRESECRET },
    { SSL_ALERT_NO_CERTIFICATE,          SSLALERTLEVEL_FATAL,   ALERT_SSL,     ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE },
    { SSL_ALERT_UNKNOWN_CA,              SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_CERT_CHAIN_NO_TRUST_ANCHOR },
    { SSL_ALERT_ACCESS_DENIED,           SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_SSL_MUTUAL_AUTHENTICATION_REQUEST_IGNORED },
    { SSL_ALERT_DECODE_ERROR,            SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_SSL_PROTOCOL },
    { SSL_ALERT_PROTOCOL_VERSION,        SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_SSL_PROTOCOL_VERSION },
    { SSL_ALERT_INTERNAL_ERROR,          SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_MEM_ALLOC_FAIL },
    { SSL_ALERT_INTERNAL_ERROR,          SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_SSL_CONFIG },
    { SSL_ALERT_INAPPROPRIATE_FALLBACK,  SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_SSL_SERVER_INAPPROPRIATE_FALLBACK_SCSV },
    { SSL_ALERT_UNRECOGNIZED_NAME,       SSLALERTLEVEL_FATAL,   ALERT_TLS,     ERR_SSL_EXTENSION_UNRECOGNIZED_NAME },
    { SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE,
                                         SSLALERTLEVEL_FATAL, ALERT_TLS,       ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE },
    { SSL_ALERT_NO_RENEGOTIATION,        SSLALERTLEVEL_WARNING, ALERT_TLS,     ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED },
    { SSL_ALERT_NO_RENEGOTIATION,        SSLALERTLEVEL_WARNING, ALERT_TLS,     ERR_SSL_CLIENT_RENEGOTIATE_NOT_ALLOWED },
    { SSL_ALERT_CLOSE_NOTIFY,            SSLALERTLEVEL_WARNING, ALERT_SSL_TLS, OK },
    { SSL_ALERT_BAD_RECORD_MAC,          SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CRYPT_BLOCK_SIZE },
    { SSL_ALERT_BAD_RECORD_MAC,          SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_INVALID_PADDING },
    { SSL_ALERT_BAD_RECORD_MAC,          SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CRYPT_BLOCK_SIZE },
    { SSL_ALERT_UNEXPECTED_MESSAGE,      SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_PROTOCOL_BAD_STATE },
    { SSL_ALERT_BAD_RECORD_MAC,          SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_INVALID_MAC },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_NO_CIPHER_MATCH },
    { SSL_ALERT_BAD_CERTIFICATE,         SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CERT_VALIDATION_FAILED },
    { SSL_ALERT_BAD_CERTIFICATE,         SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_CERT_INVALID_SIGNATURE },
    { SSL_ALERT_CERTIFICATE_REVOKED,     SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_CERT_REVOKED },
    { SSL_ALERT_CERTIFICATE_EXPIRED,     SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_CERT_EXPIRED },
    { SSL_ALERT_CERTIFICATE_UNKNOWN,     SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_CERT_INVALID_STRUCT },
    { SSL_ALERT_ILLEGAL_PARAMETER,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_PROTOCOL },
    { SSL_ALERT_CERTIFICATE_REQUIRED,    SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_EMPTY_CERTIFICATE_MESSAGE},
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_SERVER_RENEGOTIATE_LENGTH },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_SERVER_RENEGOTIATE_CLIENT_VERIFY },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_SERVER_RENEGOTIATE_ILLEGAL_SCSV },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_SERVER_RENEGOTIATE_ILLEGAL_EXTENSION },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CLIENT_RENEGOTIATE_LENGTH },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CLIENT_RENEGOTIATE_CLIENT_VERIFY },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CLIENT_RENEGOTIATE_SERVER_VERIFY },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_CLIENT_RENEGOTIATE_ILLEGAL_EXTENSION },
    { SSL_ALERT_HANDSHAKE_FAILURE,       SSLALERTLEVEL_FATAL,   ALERT_SSL_TLS, ERR_SSL_EXTENDED_MASTERSECRET_NOT_SUPPORTED }
};

#define NUM_ALERTS  ((sizeof(mAlertsSSL)/sizeof(mAlertsSSL[0])))

/* End SSL Alerts */
#endif

/* DTLS_SRTP_BUSINESS */
#if defined (__ENABLE_DIGICERT_DTLS_SRTP__)
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)

#define DTLS_SRTP_EXTRACTOR         "EXTRACTOR-dtls_srtp"
#define DTLS_SRTP_EXTRACTOR_SIZE    (19)

#define SRTP_PROFILE_DEF(CIPHER_ID, PROFILE_ENABLE, KEY_SIZE, SALT_SIZE) { CIPHER_ID, PROFILE_ENABLE, KEY_SIZE, SALT_SIZE }

/* table with infos about the SRTP profiles
 *   THIS IS IN ORDER OF PREFERENCE
 */

/* __ENABLE_DIGICERT_ITERATE_DTLS_SRTP_PROFILES__ is used to expose globals for unit testing */
#ifndef __ENABLE_DIGICERT_ITERATE_DTLS_SRTP_PROFILES__
static
#endif
const SrtpProfileInfo gSrtpProfiles[] = {

    /*   ################# remember to update dtls_srtp.h ################
    #define SRTP_MAX_KEY_SIZE           (32)
    #define SRTP_MAX_SALT_SIZE          (14)
    if necessary ########################################################## */

#ifdef __ENABLE_DIGICERT_GCM__

#ifndef __DISABLE_AES128_CIPHER__
    SRTP_PROFILE_DEF( E_SRTP_AES_128_GCM_8,  1,  16, 12 ),
    SRTP_PROFILE_DEF( E_SRTP_AES_128_GCM_12, 1,  16, 12 ),
#endif
#ifndef __DISABLE_AES256_CIPHER__
    SRTP_PROFILE_DEF( E_SRTP_AES_256_GCM_8,  1,  32, 12 ),
    SRTP_PROFILE_DEF( E_SRTP_AES_256_GCM_12, 1,  32, 12 ),
#endif

#endif

#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES128_CIPHER__
    SRTP_PROFILE_DEF( E_SRTP_AES_128_CM_SHA1_80, 1,  16, 14 ),
    SRTP_PROFILE_DEF( E_SRTP_AES_128_CM_SHA1_32, 1,  16, 14 ),
#endif
#endif /* __DISABLE_AES_CIPHERS__ */
    SRTP_PROFILE_DEF( E_SRTP_NULL_SHA1_80, 1,  0, 0 ),
    SRTP_PROFILE_DEF( E_SRTP_NULL_SHA1_32, 1,  0, 0 )
};

#define NUM_SRTP_PROFILES    (COUNTOF(gSrtpProfiles))

#ifdef __ENABLE_DIGICERT_ITERATE_DTLS_SRTP_PROFILES__
const ubyte4 gNumSrtpProfiles = NUM_SRTP_PROFILES;
#endif



#endif /* defined (__ENABLE_DIGICERT_DTLS_SRTP__) */
#endif /* defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__) */

/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_TLS13__)
extern ubyte4 getSupportedGroups(){
    return SUPPORTED_GROUPS_FLAGS_TLS13;
}
#endif

static MSTATUS
SSLSOCK_findPascalStringInList( const ubyte* pstr, const ubyte* list,
                               int listLen, const ubyte** found)
{
    int j = 0;
    int len = *pstr;
    intBoolean differ;

    while (j < listLen)
    {
        /* current index (j) + length (alpnList[j]) < total length */
        if ( j + list[j] >= listLen)
        {
            return ERR_INDEX_OOB;
        }

        /* match for length? */
        if (list[j] == len)
        {
            /* match for the rest? */
            DIGI_CTIME_MATCH(list+j+1, pstr + 1, len, &differ);

            if (!differ)
            {
                *found = list + j;
                return OK;
            }
        }

        /* increment index */
        j += 1 + list[j];
    }
    return ERR_NOT_FOUND;
}

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) ||\
     defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_TLS13__))
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_PQC__)
static MSTATUS
SSL_SOCK_getCurveIdFromNameQS(ubyte4 tlsExtNamedCurve, ubyte4 *pECCCurve, ubyte4 *pCurve, ubyte4 *pQSAlgo)
{
    switch (tlsExtNamedCurve)
    {
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtHybrid_SecP256r1MLKEM768:
            *pECCCurve = tlsExtNamedCurves_secp256r1;
            *pCurve    = cid_EC_P256;
            *pQSAlgo   = cid_PQC_MLKEM_768;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtHybrid_X25519MLKEM768:
            *pECCCurve = tlsExtNamedCurves_x25519;
            *pCurve  = cid_EC_X25519;
            *pQSAlgo = cid_PQC_MLKEM_768;
            break;
#endif
    }
    return OK;
}
#endif/* __ENABLE_DIGICERT_PQC__ */
static ubyte4
SSL_SOCK_getCurveIdFromName( ubyte4 tlsExtNamedCurve)
{
    switch (tlsExtNamedCurve)
    {
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtNamedCurves_secp256r1:
            return cid_EC_P256;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case tlsExtNamedCurves_secp384r1:
            return cid_EC_P384;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case tlsExtNamedCurves_secp521r1:
            return cid_EC_P521;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case tlsExtNamedCurves_secp224r1:
            return cid_EC_P224;
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case tlsExtNamedCurves_secp192r1:
            return cid_EC_P192;
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtNamedCurves_x25519:
            return cid_EC_X25519;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
        case tlsExtNamedCurves_x448:
            return cid_EC_X448;
#endif
#endif
    }

    return 0;
}
#else /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
static PEllipticCurvePtr
SSL_SOCK_getCurveFromName( ubyte4 tlsExtNamedCurve)
{
    switch (tlsExtNamedCurve)
    {
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtNamedCurves_secp256r1:
            return EC_P256;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case tlsExtNamedCurves_secp384r1:
            return EC_P384;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case tlsExtNamedCurves_secp521r1:
            return EC_P521;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case tlsExtNamedCurves_secp224r1:
            return EC_P224;
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case tlsExtNamedCurves_secp192r1:
            return EC_P192;
#endif
    }

    return 0;
}
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
static ubyte4
SSL_SOCK_getSupportedHashAlgorithmCount()
{
    ubyte4 i = 0;
    ubyte4 count = COUNTOF(gSupportedHashAlgorithms);

    if (SSL_sslSettings()->allowSha1SigAlg == FALSE)
    {
        for (i = 0; i < count; i++)
        {
            if (TLS_SHA1 == (gSupportedHashAlgorithms[i].hashType))
            {
                count--;
            }
        }
    }

    return count;
}

/*------------------------------------------------------------------*/

static intBoolean
isHashAlgoSupported(ubyte hashType)
{
    if (FALSE == SSL_sslSettings()->allowSha1SigAlg && TLS_SHA1 == hashType)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

#endif /* __ENABLE_DIGICERT_TLS12_UNSECURE_HASH__ */

/*------------------------------------------------------------------*/

/* Add the keytype to each hash index. */
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
static void setKeyTypeForAllHashes(ubyte4 *pAlgoList, ubyte4 *pCounter, ubyte4 keyType)
{
    /* internal method, NULL checks not necc */
    ubyte4 counter = *pCounter;
    ubyte4 i;

    for (i = 0; i < NUM_SSL_ALL_CERT_STORE_HASH_ALGORITHMS; i++)
    {
        pAlgoList[counter] = CERT_STORE_ALGO_ID_HASH_MASK & pAlgoList[counter];
        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter++], keyType );
    }

    *pCounter = counter;

    return;
}
#endif

/*------------------------------------------------------------------*/

/* Set all hash algorithms the cert store can take. This API is equivalent to
 * setting all the hash bits using CERT_STORE_ALGO_FLAG_HASHALGO */
static void setAllHashes(ubyte4 *pAlgoList, ubyte4 *pCounter)
{
   /* internal method, NULL checks not necc */
    /* Save a copy of the algo id built up so far to be used for each hash */
    ubyte4 counter = *pCounter;
    ubyte4 temp = pAlgoList[counter];
    ubyte4 i;

    for (i = 0; i < NUM_SSL_ALL_CERT_STORE_HASH_ALGORITHMS; i++)
    {
        pAlgoList[counter] = temp;
        CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter++], gAllCertStoreHashAlgorithms[i] );
    }

    *pCounter = counter;

    return;
}

/*------------------------------------------------------------------*/

/* convert ecCurveFlags, and signatureAlgoList into CertStore algorithm id list */
static MSTATUS convertToCertStoreAlgoIdList(
    SSLSocket *pSSLSock, ubyte *pSignatureAlgoList,
    ubyte4 signatureAlgoListLength, ubyte4 **ppAlgoIds, ubyte4 *pAlgoIdsLen)
{
    MSTATUS status = OK;
    ubyte4 *pAlgoIds = NULL;
    ubyte4 maxAlgoId = 0;
    ubyte4 counter = 0;
    ubyte4 i = 0;
    ubyte4 numHashes = NUM_SSL_ALL_CERT_STORE_HASH_ALGORITHMS; /* Max digests possible */

    /* Number of hashes into the 3 different asymmetric algorithms
     * (DSA, RSA, ECC) */
    maxAlgoId = numHashes * 3;

    /* sanity check though that this is indeed big enough, recall each sigAlg takes up 2 bytes in pSignatureAlgoList */
    if (signatureAlgoListLength/2 > maxAlgoId)
        maxAlgoId = signatureAlgoListLength/2;

    status = DIGI_CALLOC((void **) &pAlgoIds, maxAlgoId, sizeof(ubyte4));
    if (OK != status)
    {
        goto exit;
    }

    if (0 < signatureAlgoListLength)
    {
        for (i = 0; i < signatureAlgoListLength; i += 2)
        {
            ubyte2 sigAlgo = (ubyte2) (pSignatureAlgoList[i] << 8 | pSignatureAlgoList[i+1]);

            /* hash algo */
            switch (sigAlgo >> 8)
            {
#if !defined(__ENABLE_DIGICERT_TLS13__)
                case TLS_MD5:
                    CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter], ht_md5 );
                    break;
#endif
                case TLS_SHA1:
                    if (TRUE == SSL_sslSettings()->allowSha1SigAlg)
                        CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter], ht_sha1 );
                    break;
                case TLS_SHA224:
                    CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter], ht_sha224 );
                    break;
                case TLS_SHA256:
                    CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter], ht_sha256 );
                    break;
                case TLS_SHA384:
                    CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter], ht_sha384 );
                    break;
                case TLS_SHA512:
                    CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter], ht_sha512 );
                    break;
                default:
                    /* unknown algo, ignore */
                    break;
            }

            /* sign algo */
            /* List Provided - Choose based on list */
            switch (sigAlgo & 0xff)
            {
                case TLS_RSA:
                    CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_rsa );
                    break;
                case TLS_ECDSA:
                    /* ECDH_RSA* ciphers enforce that Signature Algorithm of the certificate is RSA */
                    if (!((pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT) &&
                      (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDH_BIT)))
                    {
                        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_ecc );
                    }
                    break;
                case TLS_DSA:
                    /* ECDH_RSA* ciphers enforce that Signature Algorithm of the certificate is RSA */
                    if (!((pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_AUTH_RSA_BIT) &&
                      (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_KEYEX_ECDH_BIT)))
                    {
                        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_dsa );
                    }
                    break;
                default:
                    /* unknown algo, ignore */
                    break;
            }

            /* If a the signature algorithm is recognized then both the keytype
             * and hash should be set. In that case move to the next index,
             * otherwise reset the current index */
            if (CERT_STORE_ALGO_ID_GET_KEYTYPE(pAlgoIds[counter]) &&
                CERT_STORE_ALGO_ID_GET_HASH(pAlgoIds[counter]))
            {
                counter++;
            }
            else
            {
                pAlgoIds[counter] = 0;
            }
        }
    }
    else
    {
        const struct KeyExAuthSuiteInfo   *pKeyExAuthAlgo;
        pKeyExAuthAlgo = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo;

        if (pSSLSock->server &&
            (pKeyExAuthAlgo->flags & SSL_KEYEX_ECDHE_BIT))
        {
            if (pKeyExAuthAlgo->flags & SSL_AUTH_ECDSA_BIT)
            {
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_ecc );
                setAllHashes(pAlgoIds, &counter);
            }
            if (pKeyExAuthAlgo->flags & SSL_AUTH_DSA_BIT)
            {
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_dsa );
                setAllHashes(pAlgoIds, &counter);
            }
            else
            {
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_rsa );
                setAllHashes(pAlgoIds, &counter);
            }
        }
        else
        {
            if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
                (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION) )
            {
                /* change in tls1.2 only default are allowed */
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_dsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter++], ht_sha1 );

                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_dsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter++], ht_md5 );

                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_rsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter++], ht_sha1 );

                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_rsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter++], ht_md5 );

                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_ecc );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter++], ht_sha1 );

                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_ecc );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoIds[counter++], ht_md5 );
            }
            else
            {
                /* all hash and sign algos are good if they are supported */
                /* Backward compatibility:
                * when <= TLS11MINORVERSION, if ECDH_RSA, cert has to be signed by RSA;
                * if ECDH_ECDSA, cert has to be signed by ECDSA */
                if (pSSLSock->server &&
                    (pKeyExAuthAlgo->flags & SSL_KEYEX_ECDH_BIT))
                {
                    if (pKeyExAuthAlgo->flags & SSL_AUTH_ECDSA_BIT)
                    {
                        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_ecc );
                    }
                    else if (pKeyExAuthAlgo->flags & SSL_AUTH_DSA_BIT)
                    {
                        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_dsa );
                    }
                    else
                    {
                        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_rsa );
                    }
                    setAllHashes(pAlgoIds, &counter);
                }
                else
                {
                    /* Set everything */
                    CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_ecc );
                    setAllHashes(pAlgoIds, &counter);

                    CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_dsa );
                    setAllHashes(pAlgoIds, &counter);

                    CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIds[counter], akt_rsa );
                    setAllHashes(pAlgoIds, &counter);
                }
            }
        }
    }

    *ppAlgoIds = pAlgoIds;
    *pAlgoIdsLen = counter;

exit:

    /* DIGI_CALLOC is only thing that can fail, no cleanup needed */

    return status;
}

/*------------------------------------------------------------------*/

static void convertEcGroupsToKeyIdList(
    ubyte4 supportedGroups, ubyte4 *pList, ubyte4 *pListLen)
{
    ubyte4 curveIdsLen = *pListLen;
    
#if defined(__ENABLE_DIGICERT_ECC_P192__)
    if (supportedGroups & EC_P192_FLAG)
    {
        CERT_STORE_ALGO_ID_SET_KEYTYPE(pList[curveIdsLen], akt_ecc);
        CERT_STORE_ALGO_ID_SET_CURVE(pList[curveIdsLen], cid_EC_P192);
        curveIdsLen++;
    }
#endif

#if !defined(__DISABLE_DIGICERT_ECC_P224__)
    if (supportedGroups & EC_P224_FLAG)
    {
        CERT_STORE_ALGO_ID_SET_KEYTYPE(pList[curveIdsLen], akt_ecc);
        CERT_STORE_ALGO_ID_SET_CURVE(pList[curveIdsLen], cid_EC_P224);
        curveIdsLen++;
    }
#endif

#if !defined(__DISABLE_DIGICERT_ECC_P256__)
    if (supportedGroups & EC_P256_FLAG)
    {
        CERT_STORE_ALGO_ID_SET_KEYTYPE(pList[curveIdsLen], akt_ecc);
        CERT_STORE_ALGO_ID_SET_CURVE(pList[curveIdsLen], cid_EC_P256);
        curveIdsLen++;
    }
#endif

#if !defined(__DISABLE_DIGICERT_ECC_P384__)
    if (supportedGroups & EC_P384_FLAG)
    {
        CERT_STORE_ALGO_ID_SET_KEYTYPE(pList[curveIdsLen], akt_ecc);
        CERT_STORE_ALGO_ID_SET_CURVE(pList[curveIdsLen], cid_EC_P384);
        curveIdsLen++;
    }
#endif

#if !defined(__DISABLE_DIGICERT_ECC_P521__)
    if (supportedGroups & EC_P521_FLAG)
    {
        CERT_STORE_ALGO_ID_SET_KEYTYPE(pList[curveIdsLen], akt_ecc);
        CERT_STORE_ALGO_ID_SET_CURVE(pList[curveIdsLen], cid_EC_P521);
        curveIdsLen++;
    }
#endif

    *pListLen = curveIdsLen;
}

/*------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__) &&\
    (defined(__ENABLE_DIGICERT_ENFORCE_CERT_SIG_ALGO__) || defined(__ENABLE_DIGICERT_TLS13__) || defined (__ENABLE_DIGICERT_SSL_SERVER__))
static MSTATUS
getCertSigAlgo(ubyte* pCertificate, ubyte4 certLen, ubyte2* pRetCertSigAlgo)
{
    MSTATUS         status;
    ASN1_ITEM*      pCert = NULL;
    ASN1_ITEM*      pSignAlgoId = NULL;
    MemFile         certMemFile;
    CStream         cs;
    ubyte4          hashType = 0;
    ubyte4          pubKeyType = 0;
    ubyte4          classicalType = 0;
    ubyte4          qsType = 0;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    byteBoolean isPss = FALSE;
    CV_CERT *pCertData = NULL;
    AsymmetricKey key = {0};
#endif

    static WalkerStep signatureAlgoWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { GoNthChild, 2, 0},
        { VerifyType, SEQUENCE, 0 },
        { Complete, 0, 0}
    };

    if (NULL == pCertificate)
        return ERR_NULL_POINTER;

    if (0 == certLen)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    *pRetCertSigAlgo = 0;

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (0x7F == pCertificate[0])
    {
        status = CV_CERT_parseCert (
            (ubyte *)pCertificate, certLen, &pCertData);
        if (OK != status)
        {
            goto exit;
        }

        status = CV_CERT_parseKey (
            pCertData->pCvcKey, pCertData->cvcKeyLen, &key, &hashType, &isPss);
        if (OK != status)
        {
            goto exit;
        }

        if (TRUE == isPss)
        {
            hashType = rsaSsaPss;
        }

        pubKeyType = key.type;
    }
    else
    {
#endif
        MF_attach(&certMemFile, certLen, (ubyte *)pCertificate);
        CS_AttachMemFile(&cs, &certMemFile);

        if (OK > (status = ASN1_Parse( cs, &pCert)))
            goto exit;

        if ( OK > ASN1_WalkTree( pCert, cs, signatureAlgoWalkInstructions, &pSignAlgoId))
        {
            return ERR_CERT_INVALID_STRUCT;
        }

        status = X509_getCertSignAlgoTypeEx( pSignAlgoId, cs, &hashType, &pubKeyType, &classicalType, &qsType);
        if (OK > status)
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }
#ifdef __ENABLE_DIGICERT_CV_CERT__
    }
#endif

    switch (hashType)
    {
#if !defined(__ENABLE_DIGICERT_TLS13__)
    case ht_md5:
        hashType = TLS_MD5;
        break;
#endif
    case ht_sha1:
        hashType = TLS_SHA1;
        break;

#ifndef __DISABLE_DIGICERT_SHA224__
    case ht_sha224:
        hashType = TLS_SHA224;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    case ht_sha256:
        hashType = TLS_SHA256;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    case ht_sha384:
        hashType = TLS_SHA384;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    case ht_sha512:
        hashType = TLS_SHA512;
        break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    case ht_none:
        hashType = TLS_INTRINSIC;
        break;
#endif

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_PKCS1__)
    case rsaSsaPss:
        hashType = TLS_INTRINSIC;
        break;
#endif

    default:
        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
        goto exit;
    }

    switch (pubKeyType)
    {
    case akt_rsa:
        pubKeyType = TLS_RSA;
        break;

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    case akt_dsa:
        pubKeyType = TLS_DSA;
        break;
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
        pubKeyType = TLS_ECDSA;
        break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    case akt_ecc_ed:
        if (cid_EC_Ed25519 == classicalType)
        {
            pubKeyType = TLS_EDDSA25519;
        }
        else if(cid_EC_Ed448 == classicalType)
        {
            pubKeyType = TLS_EDDSA448;
        }
        break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    case akt_hybrid:

        /* override what was chosen by X509_getCertSignAlgoTypeEx */
        hashType = TLS_QS;

        switch(qsType)
        {
            case cid_PQC_MLDSA_44:

                switch(classicalType)
                {
                    case cid_EC_P256:
                        pubKeyType = TLS_MLDSA_44_ECDSA_P256_SHA256;
                        break;
                    case cid_EC_Ed25519:
                        pubKeyType = TLS_MLDSA_44_EDDSA_25519;
                        break;
                    case cid_RSA_2048_PKCS15:
                        pubKeyType = TLS_MLDSA_44_RSA_2048_SHA256;
                        break;
                    case cid_RSA_2048_PSS:
                        pubKeyType = TLS_MLDSA_44_RSA_2048_PSS_SHA256;
                        break;
                    default:
                        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                        goto exit;
                }
                break;

            case cid_PQC_MLDSA_65:

                switch(classicalType)
                {
                    case cid_EC_P384:
                        pubKeyType = TLS_MLDSA_65_ECDSA_P384_SHA384;
                        break;
                    case cid_EC_Ed25519:
                        pubKeyType = TLS_MLDSA_65_EDDSA_25519;
                        break;
                    case cid_RSA_3072_PKCS15:
                        pubKeyType = TLS_MLDSA_65_RSA_3072_SHA256;
                        break;
                    case cid_RSA_4096_PKCS15:
                        pubKeyType = TLS_MLDSA_65_RSA_4096_SHA384;
                        break;                   
                    case cid_RSA_3072_PSS:
                        pubKeyType = TLS_MLDSA_65_RSA_3072_PSS_SHA256;
                        break;
                    case cid_RSA_4096_PSS:
                        pubKeyType = TLS_MLDSA_65_RSA_4096_PSS_SHA384;
                        break;
                    default:
                        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                        goto exit;
                }
                break;

            case cid_PQC_MLDSA_87:

                switch(classicalType)
                {
                    case cid_EC_P384:
                        pubKeyType = TLS_MLDSA_87_ECDSA_P384_SHA384;
                        break;
                    case cid_EC_Ed448:
                        pubKeyType = TLS_MLDSA_87_EDDSA_448;
                        break;
                    default:
                        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                        goto exit;
                }
                break;
            
            default:
                status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                goto exit;
        }

        break;
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */

    case akt_qs:

        /* override what was chosen by X509_getCertSignAlgoTypeEx */
        hashType = TLS_QS;
    
        if (cid_PQC_MLDSA_44 == qsType)
        {
            pubKeyType = TLS_MLDSA_44;
        }
        else if (cid_PQC_MLDSA_65 == qsType)
        {
            pubKeyType = TLS_MLDSA_65;
        }
        else if (cid_PQC_MLDSA_87 == qsType)
        {
            pubKeyType = TLS_MLDSA_87;
        }
        else
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }
        break;
#endif
    default:
        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
        goto exit;
    }

    *pRetCertSigAlgo = (ubyte2) (hashType << 8 | pubKeyType);

exit:
    if (pCert)
        TREE_DeleteTreeItem((TreeItem*)pCert);
    
#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }
    CRYPTO_uninitAsymmetricKey(&key, NULL);
#endif

    return status;
}
#endif /* !__DISABLE_DIGICERT_CERTIFICATE_PARSING__ */

#if defined(__ENABLE_DIGICERT_TLS13__)
static const BulkHashAlgo*
getHashSuite(ubyte4 hash)
{
    const struct BulkHashAlgo *hashSuite = NULL;

    switch(hash)
    {
#ifndef __DISABLE_DIGICERT_SHA256__
        case TLS_SHA256:
            hashSuite = &SHA256Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case TLS_SHA384:
            hashSuite = &SHA384Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case TLS_SHA512:
            hashSuite = &SHA512Suite;
            break;
#endif
        default:
            break;
    }

    return hashSuite;
}

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__)

static ubyte
getHashIdFromSuite(const BulkHashAlgo *pHashAlgo)
{
    ubyte hashId = 0;

#ifndef __DISABLE_DIGICERT_SHA256__
    if (&SHA256Suite == pHashAlgo)
    {
        hashId = TLS_SHA256;
    }
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    if (&SHA384Suite == pHashAlgo)
    {
        hashId = TLS_SHA384;
    }
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    if (&SHA512Suite == pHashAlgo)
    {
        hashId = TLS_SHA512;
    }
#endif
    return hashId;
}

#endif /* defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) */

#endif
/*------------------------------------------------------------------*/
static intBoolean
isSignatureAlgoSupported(ubyte algo)
{
    intBoolean retValue = FALSE;
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    if (TLS_DSA == algo)
    {
        if (TRUE == SSL_sslSettings()->allowDSASigAlg)
        {
            /* If DSA algo is enabled, return TRUE */
            retValue = TRUE;
        }
    }
    else
#endif
    {
        retValue = TRUE;
    }

    return retValue;
}

/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_SRP__) ))
static MSTATUS
calculateTLS12KeyExchangeRSASignature(SSLSocket* pSSLSock,
                                    ubyte* pData, ubyte4 dataLen,
                                    ubyte2 signatureAlgo, ubyte* pHashResult, ubyte4 *pHashLen)
{
    MSTATUS     status = OK;
    BulkCtx     pHashCtx = NULL;
    hashSuite  *pHashSuite = NULL;
    ubyte4      offset;
    ubyte4      hashLen;
    ubyte4      hashResultLen;
    ubyte4      i;

    /* verify we are indeed using the 1.2 versions */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        status = ERR_SSL;
        goto exit;
    }

    /* for tls1.2 and above, the struct to sign is
    DigestInfo ::= SEQUENCE {
    digestAlgorithm AlgorithmIdentifier,
    digest OCTET STRING
    }
    0x30 XX (length=YY+1 (tag) +1 (len) + digestLen+1 (tag) +1(len)) 0x30 YY (len=OID_len+2+2 (NULL)) 06 (OID tag) OID 05 00 (NULL) 04 ZZ (digestLen) digest
    */
    for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++)
    {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
        if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
        {
            if (gSupportedHashAlgorithms[i].hashType == ((signatureAlgo >> 8) & 0xff))
            {
                pHashSuite = &gSupportedHashAlgorithms[i];
                break;
            }
        }
    }

    if (!pHashSuite)
    {
        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
        goto exit;
    }

    offset = 0;
    hashResultLen = 2+2+2+pHashSuite->oid[0]+2+2+pHashSuite->algo->digestSize;
    DIGI_MEMSET(pHashResult, 0x00, hashResultLen);
    pHashResult[offset++] = 0x30; /* SEQUENCE */
    pHashResult[offset++] = (ubyte) (hashResultLen - 2);
    pHashResult[offset++] = 0x30; /* SEQUENCE */
    pHashResult[offset++] = 2 + pHashSuite->oid[0] + 2;
    pHashResult[offset++] = 0x06; /* OID */
    pHashResult[offset++] = pHashSuite->oid[0];
    DIGI_MEMCPY(pHashResult+offset, pHashSuite->oid+1, pHashSuite->oid[0]); /* oid */
    offset += pHashSuite->oid[0];
    pHashResult[offset++] = 0x05; /* NULL */
    pHashResult[offset++] = 0x00; /* NULL */
    pHashResult[offset++] = 0x04; /* OCTETSTRING */
    pHashResult[offset++] = (ubyte) (pHashSuite->algo->digestSize);

    hashLen = pHashSuite->algo->digestSize;

    if (OK > (status = pHashSuite->algo->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx )))
        goto exit;

    /* compute the hash of the data */
    if (OK > (status = pHashSuite->algo->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx)))
        goto exit;

    if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pSSLSock->pClientRandHello, SSL_RANDOMSIZE)))
        goto exit;

    if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pSSLSock->pServerRandHello, SSL_RANDOMSIZE)))
        goto exit;

    if (OK > (status = pHashSuite->algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pData, dataLen)))
        goto exit;

    if (OK > (status = pHashSuite->algo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pHashResult+offset)))
        goto exit;
    *pHashLen = offset + hashLen;
exit:
    if (pHashCtx)
        status = pHashSuite->algo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
    return status;
}
#endif
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TLS13__
/*
 * CertificateVerify message for TLS 1.3;
 * This message will be sent by both client and/or server,
 * immediately after Certificate message.
 *
 *  struct {
 *      SignatureScheme algorithm;
 *      opaque signature<0..2^16-1>;
 *  } CertificateVerify;
 *
 *  The digital signature is then computed over the concatenation of:
 *      -  A string that consists of octet 32 (0x20) repeated 64 times
 *      -  The context string
 *          * Server Handshake Context String : "TLS 1.3, server CertificateVerify"
 *          * Client Handshake Context String : "TLS 1.3, client CertificateVerify"
 *      -  A single 0 byte which serves as the separator
 *      -  The content to be signed : Transcript-Hash(Handshake Context, Certificate)
 *          * Handshake Context : hash of all the previous handshake messages
 *
 * Steps
 *   1) Create the data to digest which the data concatenated above
 */
static MSTATUS
calculateTLS13CertificateVerifyHash(ubyte2 signAlgo, SSLSocket *pSSLSock,
                                    ubyte* pContent, ubyte4 *pLen,
                                    const ubyte** ppHashOID,
                                    ubyte *pContextString, ubyte4 contextStringLen,
                                    AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte4 i;
    const ubyte *pOid = NULL;
    ubyte4 contentLen = 0;
    ubyte *pTranscriptHash = NULL;
    intBoolean calculateHash = FALSE;
    ubyte *pBuffer = NULL;
    BulkCtx pHashCtx = NULL;
    const BulkHashAlgo *pHashSuite = NULL;

    /* Select the digest algorithm based on the signature algorithm.
     */
    switch (signAlgo)
    {
#ifndef __DISABLE_DIGICERT_SHA256__
        case SSL_RSA_PSS_RSAE_SHA256:
        case SSL_RSA_PSS_PSS_SHA256:
            pOid = sha256_OID;
            break;

        case SSL_ECDSA_SECP256R1_SHA256:
            pOid = sha256_OID;
            calculateHash = TRUE;
            pHashSuite = &SHA256Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case SSL_RSA_PSS_RSAE_SHA384:
        case SSL_RSA_PSS_PSS_SHA384:
            pOid = sha384_OID;
            break;

        case SSL_ECDSA_SECP384R1_SHA384:
            pOid = sha384_OID;
            calculateHash = TRUE;
            pHashSuite = &SHA384Suite;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case SSL_RSA_PSS_RSAE_SHA512:
        case SSL_RSA_PSS_PSS_SHA512:
            pOid = sha512_OID;
            break;

        case SSL_ECDSA_SECP521R1_SHA521:
            pOid = sha512_OID;
            calculateHash = TRUE;
            pHashSuite = &SHA512Suite;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
        case SSL_ED25519:
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
        case SSL_ED448:
            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case SSL_MLDSA_44_ECDSA_P256_SHA256:
        case SSL_MLDSA_65_ECDSA_P384_SHA384:
        case SSL_MLDSA_87_ECDSA_P384_SHA384:
        case SSL_MLDSA_44_ED25519:
        case SSL_MLDSA_65_ED25519:
        case SSL_MLDSA_44_RSA2048_PKCS15_SHA256:
        case SSL_MLDSA_65_RSA3072_PKCS15_SHA256:
        case SSL_MLDSA_65_RSA4096_PKCS15_SHA384:
        case SSL_MLDSA_44_RSA2048_PSS_SHA256:
        case SSL_MLDSA_65_RSA3072_PSS_SHA256:
        case SSL_MLDSA_65_RSA4096_PSS_SHA384:
        case SSL_MLDSA_87_ED448:
        case SSL_MLDSA_44:
        case SSL_MLDSA_65:
        case SSL_MLDSA_87:
            break;
#endif
        default:
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
    }

    contentLen = CERT_VERIFY_OCTET_SIZE;
    contentLen += contextStringLen + 1;
    contentLen += pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize;

    status = DIGI_MALLOC((void **) &pBuffer, contentLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pBuffer, 0x20, CERT_VERIFY_OCTET_SIZE);
    if (OK != status)
        goto exit;

    i = CERT_VERIFY_OCTET_SIZE;

    status = DIGI_MEMCPY(pBuffer + i, pContextString, contextStringLen);
    if (OK != status)
        goto exit;

    i += contextStringLen;
    pBuffer[i++] = 0x00;

    status = SSLSOCK_calcTranscriptHash(pSSLSock, &pTranscriptHash);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(
        pBuffer + i, pTranscriptHash,
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize);
    if (OK != status)
        goto exit;

    if (TRUE == calculateHash)
    {
        status = pHashSuite->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
        if (OK != status)
            goto exit;

        status = pHashSuite->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx);
        if (OK != status)
            goto exit;

        status = pHashSuite->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pBuffer, contentLen);
        if (OK != status)
            goto exit;

        status = pHashSuite->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pContent);
        if (OK != status)
            goto exit;

        *pLen = pHashSuite->digestSize;
    }
    else
    {
        status = DIGI_MEMCPY(pContent, pBuffer, contentLen);
        if (OK != status)
        {
            goto exit;
        }

        *pLen = contentLen;
    }

    *ppHashOID = pOid;

exit:

    if ((NULL != pHashCtx) && (NULL != pHashSuite))
    {
        pHashSuite->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
    }

    if (NULL != pTranscriptHash)
    {
        DIGI_FREE((void **) &pTranscriptHash);
    }

    if (NULL != pBuffer)
    {
        DIGI_FREE((void **)&pBuffer);
    }
    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13__)

static void SSLSOCK_freeHashCtxList(SSLSocket *pSSLSock)
{
    ubyte4 i;
    BulkCtx pHashCtx;
    const BulkHashAlgo *pHashAlgo;

    if (NULL != pSSLSock->pHashCtxList)
    {
        for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++)
        {
            pHashCtx = pSSLSock->pHashCtxList[i];
            pHashAlgo = gSupportedHashAlgorithms[i].algo;

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
            if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
            {
                if (NULL != pHashCtx)
                {
                    pHashAlgo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pHashCtx);
                }
            }
        }

        DIGI_FREE((void **) &(pSSLSock->pHashCtxList));
    }
}

#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ || __ENABLE_DIGICERT_TLS13__ */

/*------------------------------------------------------------------*/
#if ((defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)) || \
     (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__)))
static MSTATUS SSLSOCK_extractAsn1Integer(
    ASN1_ITEMPTR pItem, CStream cs, ubyte4 *pRetVal)
{
    MSTATUS status;
    const ubyte *pTemp;

    status = ASN1_VerifyType(pItem, INTEGER);
    if (OK != status)
    {
        goto exit;
    }

    if (4 >= pItem->length)
    {
        *pRetVal = pItem->data.m_intVal;
    }
    else
    {
        if (5 < pItem->length)
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        pTemp = CS_memaccess(cs, pItem->dataOffset, pItem->length);
        if (0x00 != *pTemp)
        {
            status = ERR_ASN_INVALID_DATA;
            goto exit;
        }

        *pRetVal = DIGI_NTOHL(pTemp + 1);
    }

exit:

    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
/*
 * Serialize sessionTicket structure
 *
 * SEQUENCE:
 *  INTEGER     version
 *  INTEGER     cipherID
 *  OCTETSTRING pMasterSecret
 *  INTEGER     lifeTimeHintInSec
 *  UTCTIME     startTime
 *  INTEGER     ticketLen
 *  OCTETSTRING pTicket
 *
 */
extern MSTATUS SSLSOCK_serializeSessionTicket(sessionTicket *pTicket,
                                              ubyte **ppRetTicket,
                                              ubyte4 *pRetTicketLen)
{
    MSTATUS status = OK;
    DER_ITEMPTR pRoot= NULL;
    sbyte pTimeBuf[16];
    if ((NULL == pTicket) || (NULL == ppRetTicket) || (NULL == pRetTicketLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Create the root node. All values will be immediate children of this node.
     */
    status = DER_AddSequence(NULL, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    /* Add version value. This value is internal to the ASN.1 structure and it
     * is not stored in the Session Ticket structure.
     */
    status = DER_AddIntegerEx(pRoot, sslASN1EncodeTicket, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pTicket->cipherId, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, OCTETSTRING, SSL_MASTERSECRETSIZE, pTicket->masterSecret, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pTicket->lifeTimeHintInSec, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DATETIME_convertToValidityString(&(pTicket->startTime), pTimeBuf);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, UTCTIME, DIGI_STRLEN(pTimeBuf), (ubyte *) pTimeBuf, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pTicket->ticketLen, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, OCTETSTRING, pTicket->ticketLen, pTicket->pTicket, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_Serialize(pRoot, ppRetTicket, pRetTicketLen);

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

extern MSTATUS SSLSOCK_deserializeSessionTicket(
    ubyte *pTicket, ubyte4 ticketLen, sessionTicket **ppRetTicket)
{
    MSTATUS status;
    ASN1_ITEMPTR pRoot = NULL, pItem;
    CStream cs;
    MemFile mf;
    sessionTicket *pNewTicket = NULL;

    if ( (NULL == pTicket) || (NULL == ppRetTicket) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    MF_attach(&mf, ticketLen, pTicket);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pNewTicket, 1, sizeof(sessionTicket));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD(pRoot);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, SEQUENCE);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( !((UNIVERSAL == (pItem->id & CLASS_MASK)) &&
           (pItem->tag == INTEGER) &&
           (pItem->length <= sizeof(sbyte4)) &&
           (sslASN1EncodeTicket == pItem->data.m_intVal)) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (UNIVERSAL == (pItem->id & CLASS_MASK)) &&
         (pItem->tag == INTEGER) &&
         (pItem->length <= sizeof(sbyte4)) )
    {
        pNewTicket->cipherId = pItem->data.m_intVal;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, OCTETSTRING);
    if (OK != status)
    {
        goto exit;
    }

    if (SSL_MASTERSECRETSIZE != pItem->length)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MEMCPY(
        pNewTicket->masterSecret,
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = SSLSOCK_extractAsn1Integer(
        pItem, cs, &(pNewTicket->lifeTimeHintInSec));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DATETIME_convertFromValidityString2(
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length,
        &(pNewTicket->startTime));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    status = SSLSOCK_extractAsn1Integer(
        pItem, cs, &(pNewTicket->ticketLen));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, OCTETSTRING);
    if (OK != status)
    {
        goto exit;
    }

    if (pNewTicket->ticketLen != pItem->length)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* If application provided a ticket with 0 length,
     * it cannot be used for resumption
     */
    if (0 == pNewTicket->ticketLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &(pNewTicket->pTicket), 1, pNewTicket->ticketLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pNewTicket->pTicket,
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length);
    if (OK != status)
    {
        goto exit;
    }

    *ppRetTicket = pNewTicket;
    pNewTicket = NULL;
    status = OK;

exit:

    if (NULL != pNewTicket)
    {
        if (NULL != pNewTicket->pTicket)
        {
            DIGI_FREE((void **) &(pNewTicket->pTicket));
        }
        DIGI_FREE((void **) &pNewTicket);
    }

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__)

/*------------------------------------------------------------------*/

/* Serialize a tls13Psk structure. The structure will be encoded into an ASN.1
 * format defined as follows.
 *
 * SEQUENCE
 *   INTEGER      version
 *   INTEGER      isExternal
 *   INTEGER      isPSKavailable
 *   INTEGER      pskTLS13LifetimeHint
 *   INTEGER      pskTLS13AgeAdd
 *   OCTETSTRING  ticketNonce
 *   OCTETSTRING  pskTLS13
 *   INTEGER      obfuscatedTicketAge
 *   INTEGER      hashAlgo
 *   UTCTIME      startTime
 *   INTEGER      maxEarlyDataSize
 *   INTEGER      pSelectedTlsVersion
 *   OCTETSTRING  selectedALPN
 *   INTEGER      selectedCipherSuiteId
 *
 * Note that the version field is internal and will not be stored in the PSK
 * structure when it is deserialized.
 */
extern MSTATUS SSLSOCK_tls13SerializePsk(
    tls13PSK *pPsk, ubyte **ppRetPsk, ubyte4 *pRetPskLen)
{
    MSTATUS status;
    DER_ITEMPTR pRoot = NULL;
    sbyte pTimeBuf[14];

    if ( (NULL == pPsk) || (NULL == ppRetPsk) || (NULL == pRetPskLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Create the root node. All values will be immediate children of this node.
     */
    status = DER_AddSequence(NULL, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    /* Add version value. This value is internal to the ASN.1 structure and it
     * is not stored in the TLS 1.3 PSK structure.
     */
    status = DER_AddIntegerEx(pRoot, sslASN1EncodePSK, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->isExternal, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->isPSKavailable, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->pskTLS13LifetimeHint, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->pskTLS13AgeAdd, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, OCTETSTRING, sizeof(pPsk->ticketNonce), pPsk->ticketNonce, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, OCTETSTRING, pPsk->pskTLS13Length, pPsk->pskTLS13, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, OCTETSTRING, pPsk->pskTLS13IdentityLength,
        pPsk->pskTLS13Identity, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->obfuscatedTicketAge, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->hashAlgo, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DATETIME_convertToValidityString(&(pPsk->startTime), pTimeBuf);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, UTCTIME, DIGI_STRLEN(pTimeBuf), (ubyte *) pTimeBuf, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->maxEarlyDataSize, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->pSelectedTlsVersion, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pRoot, OCTETSTRING, sizeof(pPsk->selectedALPN), pPsk->selectedALPN,
        NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddIntegerEx(pRoot, pPsk->selectedCipherSuiteId, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_Serialize(pRoot, ppRetPsk, pRetPskLen);

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SSLSOCK_tls13DeserializePsk(
    ubyte *pPsk, ubyte4 pskLen, tls13PSK **ppRetPsk)
{
    MSTATUS status;
    ASN1_ITEMPTR pRoot = NULL, pItem;
    CStream cs;
    MemFile mf;
    tls13PSK *pNewPsk = NULL;

    if ( (NULL == pPsk) || (NULL == ppRetPsk) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    MF_attach(&mf, pskLen, pPsk);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pNewPsk, 1, sizeof(tls13PSK));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD(pRoot);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, SEQUENCE);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( !((UNIVERSAL == (pItem->id & CLASS_MASK)) &&
           (pItem->tag == INTEGER) &&
           (pItem->length <= sizeof(sbyte4)) &&
           (sslASN1EncodePSK == pItem->data.m_intVal)) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (UNIVERSAL == (pItem->id & CLASS_MASK)) &&
         (pItem->tag == INTEGER) &&
         (pItem->length <= sizeof(sbyte4)) )
    {
        pNewPsk->isExternal = pItem->data.m_intVal;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (UNIVERSAL == (pItem->id & CLASS_MASK)) &&
         (pItem->tag == INTEGER) &&
         (pItem->length <= sizeof(sbyte4)) )
    {
        pNewPsk->isPSKavailable = pItem->data.m_intVal;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = SSLSOCK_extractAsn1Integer(
        pItem, cs, &(pNewPsk->pskTLS13LifetimeHint));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = SSLSOCK_extractAsn1Integer(
        pItem, cs, &(pNewPsk->pskTLS13AgeAdd));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, OCTETSTRING);
    if (OK != status)
    {
        goto exit;
    }

    if (SSL_SESSION_TICKET_NONCE_SIZE != pItem->length)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MEMCPY(
        pNewPsk->ticketNonce,
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, OCTETSTRING);
    if (OK != status)
    {
        goto exit;
    }

    if (SSL_PSK_TLS13_MAX_LENGTH < pItem->length)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MEMCPY(
        pNewPsk->pskTLS13,
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length);
    if (OK != status)
    {
        goto exit;
    }
    pNewPsk->pskTLS13Length = pItem->length;

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, OCTETSTRING);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC(
        (void **) &(pNewPsk->pskTLS13Identity), pItem->length);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pNewPsk->pskTLS13Identity,
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length);
    if (OK != status)
    {
        goto exit;
    }
    pNewPsk->pskTLS13IdentityLength = pItem->length;

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = SSLSOCK_extractAsn1Integer(
        pItem, cs, &(pNewPsk->obfuscatedTicketAge));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (UNIVERSAL == (pItem->id & CLASS_MASK)) &&
         (pItem->tag == INTEGER) &&
         (pItem->length <= sizeof(sbyte4)) )
    {
        pNewPsk->hashAlgo = pItem->data.m_intVal;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DATETIME_convertFromValidityString2(
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length,
        &(pNewPsk->startTime));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = SSLSOCK_extractAsn1Integer(
        pItem, cs, &(pNewPsk->maxEarlyDataSize));
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (UNIVERSAL == (pItem->id & CLASS_MASK)) &&
         (pItem->tag == INTEGER) &&
         (pItem->length <= sizeof(sbyte4)) )
    {
        pNewPsk->pSelectedTlsVersion = pItem->data.m_intVal;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pItem, OCTETSTRING);
    if (OK != status)
    {
        goto exit;
    }

    if (SSL_ALPN_MAX_SIZE != pItem->length)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MEMCPY(
        pNewPsk->selectedALPN,
        CS_memaccess(cs, pItem->dataOffset, pItem->length), pItem->length);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_NEXT_SIBLING(pItem);
    if (NULL == pItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (UNIVERSAL == (pItem->id & CLASS_MASK)) &&
         (pItem->tag == INTEGER) &&
         (pItem->length <= sizeof(sbyte4)) )
    {
        pNewPsk->selectedCipherSuiteId = pItem->data.m_intVal;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *ppRetPsk = pNewPsk;
    pNewPsk = NULL;
    status = OK;

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    if (pNewPsk != NULL)
    {
        SSLSOCK_freePSK(&pNewPsk);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS SSLSOCK_computePartialDigests(
    SSLSocket *pSSLSock, ubyte **ppPartialDigests, ubyte4 partialDigestsCount,
    ubyte *pPartialClientHello, ubyte4 partialClientHelloLength,
    const BulkHashAlgo *pHashAlgo, ubyte4 *pRetIndex)
{
    MSTATUS status;
    ubyte i;

    if (NUM_SSL_SUPPORTED_HASH_ALGORITHMS != partialDigestsCount)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    for (i = 0; i < partialDigestsCount; i++)
    {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
        if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
        {
            if (gSupportedHashAlgorithms[i].algo == pHashAlgo)
            {
                break;
            }
        }
    }

    if (i == partialDigestsCount)
    {
        status = ERR_SSL_HASH_ALGO_NULL;
        goto exit;
    }

    if (NULL == ppPartialDigests[i])
    {
        status = DIGI_MALLOC(
            (void **) &(ppPartialDigests[i]), pHashAlgo->digestSize);
        if (OK > status)
        {
            goto exit;
        }

        if (NULL != pSSLSock->pHashCtxList)
        {

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) && defined(__ENABLE_DIGICERT_TLS13__)

            if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                status = pHashAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie)
                    pSSLSock->pHashCtxList[i], pPartialClientHello, 4);
                if (OK > status)
                {
                    goto exit;
                }

                status = pHashAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie)
                    pSSLSock->pHashCtxList[i], pPartialClientHello + 12,
                    partialClientHelloLength - 12);
                if (OK > status)
                {
                    goto exit;
                }
            }
            else
#endif
            if (!pSSLSock->isDTLS)
            {
                status = pHashAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie)
                    pSSLSock->pHashCtxList[i], pPartialClientHello,
                    partialClientHelloLength);
                if (OK > status)
                {
                    goto exit;
                }
            }

            status = pHashAlgo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie)
                pSSLSock->pHashCtxList[i], ppPartialDigests[i]);
            if (OK > status)
            {
                goto exit;
            }
        }
        else
        {
            status = SSLSOCK_calcTranscriptHashForBuffer(MOC_HASH(pSSLSock->hwAccelCookie)
                pHashAlgo, pPartialClientHello, partialClientHelloLength,
                ppPartialDigests[i]);
            if (OK > status)
            {
                goto exit;
            }
        }
    }

    *pRetIndex = i;
    status = OK;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13__ && __ENABLE_DIGICERT_TLS13_PSK__ */

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13__))
static MSTATUS
calculateTLS12CertificateVerifyHash(ubyte2 signAlgo, SSLSocket *pSSLSock,
                                    ubyte* pHashResult, ubyte4 *pLen,
                                    const ubyte** ppHashOID)
{
    MSTATUS status = OK;
    ubyte4 i;
    const hashSuite *pHashSuite = NULL;
    BulkCtx              pHashCtx  = NULL;
    const BulkHashAlgo  *pHashAlgo = NULL;

    for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++)
    {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
        if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
        {
            if (gSupportedHashAlgorithms[i].hashType == ((signAlgo >> 8) & 0xff))
            {
                pHashSuite = &gSupportedHashAlgorithms[i];
                break;
            }
        }
    }

    if (!pHashSuite)
    {
        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
        goto exit;
    }

    /* find the signatureAlgo in the supported list */
    for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++)
    {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
        if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
        {
            if (gSupportedHashAlgorithms[i].hashType == ((signAlgo >> 8) & 0xff))
            {
                pHashCtx = pSSLSock->pHashCtxList[i];
                pHashAlgo = gSupportedHashAlgorithms[i].algo;
                break;
            }
        }
    }

    /* put the signature into digestData area */
    if (signAlgo && pHashAlgo && pHashCtx)
    {
        pHashAlgo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtx, pHashResult);
        *pLen = pHashSuite->algo->digestSize;
        *ppHashOID = pHashSuite->oid;
    }
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13__))
    /* done: clean the list now */
    SSLSOCK_freeHashCtxList(pSSLSock);
#endif
exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ || __ENABLE_DIGICERT_TLS13__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) &&\
    (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined( __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__) || defined(__ENABLE_DIGICERT_EAP_FAST__))
static intBoolean
isCipherIdExcludedForDTLS(ubyte2 cipherId)
{
    ubyte4 count;

    for (count = 0; count < NUM_CIPHERID_DTLS_EXCLUSION; count++)
    {
        if (cipherId == gCipherIdDTLSExclusion[count])
            return TRUE;
    }

    return FALSE;
}

#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__)
static void
PrintBytes( ubyte* buffer, sbyte4 len)
{
    sbyte4 i;

    for ( i = 0; i < len; ++i)
    {
        DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, buffer[i]);
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" ");

        if ( i % 16 == 15)
        {
            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
        }
    }

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
}
#endif

/*------------------------------------------------------------------*/

/* static functions */
static void    setMediumValue(ubyte medium[SSL_MEDIUMSIZE], ubyte2 val);
static ubyte2  getMediumValue(const ubyte* medium);
static void    setShortValue(ubyte shortBuff[2], ubyte2 val);
static ubyte2  getShortValue(const ubyte* medium);

/* TCP helpers */
static MSTATUS recvAll(SSLSocket* pSSLSock, sbyte* pBuffer, sbyte4 toReceive, const enum sslAsyncStates curAsyncState, const enum sslAsyncStates nextAsyncState, ubyte **ppPacketPayload, ubyte4 *pPacketLength);


#if defined(__ENABLE_DIGICERT_EAP_FAST__)
static MSTATUS T_PRF(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte* secret, sbyte4 secretLen, ubyte* labelSeed, sbyte4 labelSeedLen,
                    ubyte* result, sbyte4 resultLen);
static MSTATUS SSL_SOCK_generateEAPFASTMasterSecret(SSLSocket *pSSLSock);
#endif


/* Handshake */
extern MSTATUS SSL_INTERNAL_setConnectionState(sbyte4 connectionInstance, sbyte4 connectionState);
static MSTATUS SSLSOCK_doOpenUpcalls(SSLSocket* pSSLSock);

/* server specific */
#ifdef    __ENABLE_DIGICERT_SSL_SERVER__
static MSTATUS processClientHello2(SSLSocket* pSSLSock);
static MSTATUS processClientHello3(SSLSocket* pSSLSock);

static MSTATUS fillServerHello(SSLSocket* pSSLSock, ubyte* pHSRec, ubyte versionMask, intBoolean sendCookie);
static ubyte*  fillCertificate(SSLSocket* pSSLSock, ubyte* pHSRec);

static MSTATUS SSL_SERVER_sendServerHello(SSLSocket* pSSLSock);

static MSTATUS handleServerHandshakeMessages(SSLSocket* pSSLSock);
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

/* client specific */
#ifdef    __ENABLE_DIGICERT_SSL_CLIENT__
static MSTATUS SSL_CLIENT_sendClientHello(SSLSocket* pSSLSock);
static MSTATUS processServerHello(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 recLen);
static MSTATUS handleClientHandshakeMessages(SSLSocket* pSSLSock);
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)) || (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined (__ENABLE_DIGICERT_ECC__))
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
SSL_SOCK_getECCSignatureLength( ECCKey* pECCKey, sbyte4* signatureLen, ubyte4 keyType);
#else
static MSTATUS
SSL_SOCK_getECCSignatureLength( ECCKey* pECCKey, sbyte4* signatureLen);
#endif
#endif

/* shared */
static MSTATUS sendChangeCipherSpec(SSLSocket* pSSLSock);
static MSTATUS sendFinished(SSLSocket* pSSLSock);

static MSTATUS processFinished(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 recLen);
static MSTATUS handleAlertMessage(SSLSocket* pSSLSock);
static MSTATUS handleInnerAppMessage(SSLSocket* pSSLSock);
static MSTATUS SSL_SOCK_receiveV23Record(SSLSocket* pSSLSock, ubyte* pSRH,
                                         ubyte **ppPacketPayload,
                                         ubyte4 *pPacketLength);

#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
static MSTATUS SSL_SOCK_receiveDTLS13Record(SSLSocket* pSSLSock, ubyte* pSRH,
                                            ubyte2 *pSRHLen,
                                            ubyte **ppPacketPayload,
                                            ubyte4 *pPacketLength);

static MSTATUS freeMsgBufferDescrRecords(msgBufferDescr *pMsg);
#endif
                                         
static MSTATUS handleFragmentedRecord(SSLSocket* pSSLSock,
                                         ubyte **ppPacketPayload,
                                         ubyte4 *pPacketLength);
static MSTATUS checkBuffer(SSLSocket* pSSLSock, sbyte4 requestedSize, ubyte4 sizeofRecordHeader);

static MSTATUS processHelloExtensions(SSLSocket* pSSLSock, ubyte *pExtensions,
                                      sbyte4 extensionsLen, ubyte4 handshakeType);

#if defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
static MSTATUS resetTicket(SSLSocket* pSSLSock);
#endif /* defined(__ENABLE_DIGICERT_SSL_CLIENT__) */

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__))
static MSTATUS processCertificate(SSLSocket* pSSLSock, ubyte* pSHSH,
                                  ubyte2 recLen, intBoolean isCertRequired);
#endif
#if ((defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) ||\
     (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)))
static MSTATUS
SSLSOCK_fillCertificateVerify(ubyte2 signAlgo, SSLSocket* pSSLSock, AsymmetricKey key,
                      ubyte *pBuffer, ubyte2* pLength, vlong **ppVlongQueue);

#if defined(__ENABLE_DIGICERT_ECC__)
static MSTATUS
SSLSOCK_fillCertificateVerifyECC(ubyte2 signAlgo, SSLSocket* pSSLSock,
                         AsymmetricKey key,
                         ubyte *pBuffer, ubyte2* pLength,
                         const ubyte* pHash, ubyte4 hashLen);
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__))
/* if a hashOID is specified, then this is TLS 1.2 and we need to
build a DER structure that is the signature input */
static MSTATUS
SSLSOCK_fillCertificateVerifyRSA(ubyte2 signAlgo, SSLSocket* pSSLSock,
                         AsymmetricKey key,
                         ubyte *pBuffer, ubyte2 length,
                         const ubyte* pHash, ubyte4 hashLen,
                         const ubyte* hashOID, vlong **ppVlongQueue);
#endif
#if defined (__ENABLE_DIGICERT_ECC__)
static MSTATUS
SSL_SOCK_GenerateECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey* pECCKey,
                                  RNGFun rngFun, void* rngArg,
                                  const ubyte* hash, ubyte4 hashLen,
                                  ubyte* pSignature, ubyte4* pSignatureLen,
                                  ubyte4 sslMinorVersion);
#endif
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)

/* verify that pLeafCert matches the server name indication if any */

static MSTATUS
SSL_SOCK_validateServerName(SSLSocket *pSSLSock, const SizedBuffer* pLeafCert)
{
    MSTATUS status = OK;
    MemFile      mf;
    CStream      cs;
    ASN1_ITEMPTR pCertRoot   = NULL;

    if (!pSSLSock->serverNameIndication)
    {
        return OK;
    }

    /* &mf will always be valid, so function will always return 0, no test needed */
    (void) MF_attach(&mf, pLeafCert->length, pLeafCert->data);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pCertRoot)))
        goto exit;

    if (OK > (status = X509_matchName( ASN1_FIRST_CHILD(pCertRoot), cs,
                                      (sbyte*) pSSLSock->serverNameIndication)))
    {
        goto exit;
    }

exit:

    /* clean up */
    if (pCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pCertRoot);
        pCertRoot = NULL;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

#if defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
static MSTATUS
SSL_SOCK_getCertificateSerialNumber(const SizedBuffer *pCert, ubyte **ppSerialNum, ubyte4 *pSerialNumLength)
{
    MSTATUS status = OK;
    MemFile      mf;
    CStream      cs;
    ASN1_ITEMPTR pRoot   = NULL;

    /* &mf will always be valid, so function will always return 0, no test needed */
    (void) MF_attach(&mf, pCert->length, pCert->data);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRoot)))
    {
        goto exit;
    }

    if (OK > (status = X509_extractSerialNum(ASN1_FIRST_CHILD(pRoot), cs, ppSerialNum, pSerialNumLength)))
    {
        goto exit;
    }

exit:
    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
        pRoot = NULL;
    }
    return status;
}

static MSTATUS
SSL_SOCK_getCertificateSerialNumberHash(MOC_HASH(hwAccelDescr hwAccelCtx) const SizedBuffer *pCert, ubyte **ppHashOut)
{
    ubyte  *pSerialNum  = NULL;
    ubyte4 serialNumLen = 0;
    ubyte  *pHash       = NULL;
    MSTATUS status = OK;

    if (OK > (status = SSL_SOCK_getCertificateSerialNumber(pCert, &pSerialNum, &serialNumLen)))
    {
        goto exit;
    }

    if ((pSerialNum != NULL) && (serialNumLen > 0))
    {
        if (OK > (status = DIGI_CALLOC((void **)&pHash, 1, 32))) /* 32 bytes for sha256 */
        {
            goto exit;
        }

        if (OK > (status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(hwAccelCtx) pSerialNum, serialNumLen, pHash)))
        {
            goto exit;
        }
    }

    *ppHashOut = pHash;
exit:
    if (OK > status)
    {
        if (pHash != NULL)
        {
            DIGI_FREE((void **)&pHash);
        }
    }

    if (pSerialNum != NULL)
    {
        DIGI_FREE((void **)&pSerialNum);
    }
    return status;
}
#endif
/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_getSharedSignatureAlgorithm(SSLSocket *pSSLSock, ubyte4 index, ubyte2 *pSigAlgo, ubyte isPeer)
{
    MSTATUS status = OK;
    ubyte2 *pSupportedSignatureAlgoList = NULL;
    ubyte4 supportedSignatureAlgoListLength = 0;

    if (isPeer)
    {
        pSupportedSignatureAlgoList = (ubyte2 *)pSSLSock->signatureAlgoList;
        /* signatureAlgoListLength contains the byte length, not the number of
         * signature algorithms so divide by 2 here */
        supportedSignatureAlgoListLength = pSSLSock->signatureAlgoListLength / 2;
    }
    else
    {
        pSupportedSignatureAlgoList      = pSSLSock->pSupportedSignatureAlgoList;
        supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;
    }

    if (index >= supportedSignatureAlgoListLength)
    {
        status = ERR_SSL; /*  */
        goto exit;
    }

    *pSigAlgo = pSupportedSignatureAlgoList[index];

exit:

    if (status >= OK)
    {
        /* If status is OK, return the total number of supported signature algorithms */
        status = supportedSignatureAlgoListLength;
    }
    return status;
}
#if !defined(__ENABLE_DIGICERT_TLS13__)
extern MSTATUS
SSL_SOCK_setSupportedAlgorithm(SSLSocket *pSSLSock, ubyte2 *pList, ubyte4 listLength)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    for (i = 0; i < listLength; i++)
    {
        sbyte4 j = 0;
        sbyte supported = 0;

        for (j = 0; j < (sbyte4) NUM_SSL_SUPPORTED_SIGNATURE_ALGORITHMS; j++)
        {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
            if (isHashAlgoSupported((gSupportedSignatureAlgorithms[j] >> 8) & 0xFF))
#endif
            {
                if (isSignatureAlgoSupported(gSupportedSignatureAlgorithms[j] & 0xFF))
                {
                    if (pList[i] ==  gSupportedSignatureAlgorithms[j])
                    {
                        supported = 1;
                        break;
                    }
                }
            }
        }

        if (0 == supported)
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }
    }

    if (pSSLSock->pSupportedSignatureAlgoList != NULL)
    {
        DIGI_FREE((void **)&(pSSLSock->pSupportedSignatureAlgoList));
        pSSLSock->supportedSignatureAlgoListLength = 0;
    }

    if (OK > (status = DIGI_CALLOC((void **) &pSSLSock->pSupportedSignatureAlgoList, 1, listLength * sizeof(ubyte2))))
    {
        goto exit;
    }

    DIGI_MEMCPY(pSSLSock->pSupportedSignatureAlgoList, pList, listLength * sizeof(ubyte2));
    pSSLSock->supportedSignatureAlgoListLength = listLength;

exit:
    return status;
}
#endif

MOC_EXTERN sbyte4 SSL_SOCK_enableECCCurves(
    SSLSocket *pSSLSock, enum tlsExtNamedCurves *pECCCurvesList,
    ubyte4 listLength)
{
    MSTATUS status;
    ubyte4 count, i;
    ubyte2 *pNewGroupList = NULL;
    ubyte4 newGroupListLen = 0;

    for (count = 0; count < listLength; count++)
    {
        for (i = 0; i < COUNTOF(gSupportedNamedGroup); i++)
        {
            if (gSupportedNamedGroup[i] == pECCCurvesList[count])
            {
                newGroupListLen++;
            }
        }
    }

    /* If no shared groups can be set then exit with an error. Note that the
     * original list is untouched */
    if (!newGroupListLen)
    {
        status = ERR_SSL_CONFIG;
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &pNewGroupList, newGroupListLen, sizeof(ubyte2));
    if (OK != status)
    {
        goto exit;
    }

    newGroupListLen = 0;
    for (count = 0; count < listLength; count++)
    {
        for (i = 0; i < COUNTOF(gSupportedNamedGroup); i++)
        {
            if (gSupportedNamedGroup[i] == pECCCurvesList[count])
            {
                pNewGroupList[newGroupListLen] = pECCCurvesList[count];
                newGroupListLen++;
            }
        }
    }

    /* DIGI_FREE performs NULL check */
    DIGI_FREE((void **) &(pSSLSock->pSupportedGroupList));

    pSSLSock->pSupportedGroupList = pNewGroupList;
    pSSLSock->supportedGroupListLength = newGroupListLen;

exit:
    /* No need to free pNewGroupList in case of error */
    return status;
}

void SSL_SOCK_filterSupportedGroups(SSLSocket *pSSLSock)
{
    ubyte4 i, supportedGroups, offset;
#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        supportedGroups = SUPPORTED_GROUPS_FLAGS_TLS13;
    }
    else
#endif
    {
        supportedGroups = SUPPORTED_GROUPS_FLAGS_TLS12;
    }

    pSSLSock->supportedGroups = 0;
    offset = 0;
    for (i = 0; i < pSSLSock->supportedGroupListLength; i++)
    {
        pSSLSock->pSupportedGroupList[i - offset] = pSSLSock->pSupportedGroupList[i];

        if (!(GROUP_BIT_MASK(pSSLSock->pSupportedGroupList[i - offset]) & supportedGroups))
        {
            offset++;
        }
        else
        {
            pSSLSock->supportedGroups |= GROUP_BIT_MASK(pSSLSock->pSupportedGroupList[i - offset]);
        }
    }

    pSSLSock->supportedGroupListLength -= offset;
}

#if defined(__ENABLE_DIGICERT_PKCS1__) && defined(__ENABLE_DIGICERT_TLS13__) && (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
intBoolean isSignatureAlgorithmExcluded(ubyte2 sigAlgo)
{
    ubyte4 i = 0;
    ubyte4 count = COUNTOF(gServerExcludedSignatureAlgorithms);
    intBoolean isExcluded = FALSE;

    for (i = 0; i < count; i++)
    {
        if (sigAlgo == gServerExcludedSignatureAlgorithms[i])
        {
            isExcluded = TRUE;
            break;
        }
    }

    return isExcluded;
}
#endif

MSTATUS SSL_SOCK_filterSupportedSignatureAlgorithm(SSLSocket *pSSLSock, intBoolean isVersionNegotiated)
{
    MSTATUS status = OK;
    ubyte4 supportedSignatureAlgoListLength = 0;
    ubyte4 i       = 0;
    ubyte4 offset  = 0;
    intBoolean isSHA1 = FALSE;
    intBoolean isDSA  = FALSE;
    intBoolean sha1Allowed = SSL_sslSettings()->allowSha1SigAlg;
    intBoolean dsaAllowed  = SSL_sslSettings()->allowDSASigAlg;
    ubyte2 *pSupportedSignatureAlgoList = NULL;

    if (pSSLSock == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pSupportedSignatureAlgoList      = pSSLSock->pSupportedSignatureAlgoList;
    supportedSignatureAlgoListLength = pSSLSock->supportedSignatureAlgoListLength;

    /* Loop through all the gSupportedSignatureAlgorithms and calculate the count of negotiable algorithms */
    for (i = 0; i < supportedSignatureAlgoListLength; i++)
    {
        isSHA1 = ((pSupportedSignatureAlgoList[i] >> 8) == TLS_SHA1) ? TRUE : FALSE;
        isDSA  = ((pSupportedSignatureAlgoList[i] & 0xFF) == TLS_DSA) ? TRUE : FALSE;

        pSupportedSignatureAlgoList[i - offset] = pSupportedSignatureAlgoList[i];
        /* Check if this algo is allowed
         * if SHA1, sha1Allowed should be set
         * if DSA, dsaAllowed flag should be set
         * If version is negotiated check the following two conditions :
         * if TLS 1.3, SHA1 and DSA are not allowed
         * if TLS 1.2 or lower, RSA-PSS are not allowed
         */
        if ((!sha1Allowed && isSHA1) || (!dsaAllowed && isDSA) ||
            (isVersionNegotiated && ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion && isDSA)
#if defined(__ENABLE_DIGICERT_PKCS1__) && defined(__ENABLE_DIGICERT_TLS13__) && (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
            || ((pSSLSock->server) && ((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) || (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)) && isSignatureAlgorithmExcluded(pSupportedSignatureAlgoList[i]))
#endif
            )))
        {
            offset++;
        }
    }

    pSSLSock->supportedSignatureAlgoListLength -= offset;

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_TLS13__
extern MSTATUS
SSL_SOCK_setCipherAlgorithm(SSLSocket *pSSLSock, ubyte2 *pList, ubyte4 listLength, ubyte4 listType)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    sbyte4 cipherIndex;

    if ((NULL == pList) || (0 == listLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(listType)
    {
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
        case TLS13_cipher:
            for (i = 0; i < listLength; i++)
            {
                if (0 <= (cipherIndex = SSL_SOCK_getCipherTableIndex(pSSLSock, pList[i])))
                {
                    /* mark the cipher as active */
                    pSSLSock->isCipherTableInit = TRUE;
                    pSSLSock->isCipherEnabled[cipherIndex] = TRUE;

                    status = OK;
                }
            }
            break;
#endif

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)  || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
        case TLS13_supportedGroups:
            for (i = 0; i < listLength; i++)
            {
                ubyte4 j = 0;
                ubyte supported = 0;

                for (j = 0; j < NUM_SSL_SUPPORTED_NAMED_GROUP; j++)
                {
                    if (pList[i] == gSupportedNamedGroup[j])
                    {
                        supported = 1;
                        break;
                    }
                }

                /* If the curve is not in the global list of supported curves,
                 * throw and error and exit
                 */
                if (0 == supported)
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }
            }

            DIGI_FREE((void ** ) &(pSSLSock->pSupportedGroupList));
            pSSLSock->supportedGroupListLength = 0;
            /* This API is similar to SSL_enableECCCurves but it allows the
             * caller to set the order of the groups as well.
             */
            if (OK > (status = DIGI_CALLOC((void **) &pSSLSock->pSupportedGroupList, 1, listLength * sizeof(ubyte2))))
            {
                goto exit;
            }

            DIGI_MEMCPY(pSSLSock->pSupportedGroupList, pList, listLength * sizeof(ubyte2));
            pSSLSock->supportedGroupListLength = listLength;
            break;
#endif

        case TLS13_signatureAlgorithms:
            for (i = 0; i < listLength; i++)
            {
                ubyte4 j = 0;
                sbyte supported = 0;

                for (j = 0; j <  NUM_SSL_SUPPORTED_SIGNATURE_ALGORITHMS; j++)
                {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
                    if (isHashAlgoSupported((gSupportedSignatureAlgorithms[j] >> 8) & 0xFF))
#endif
                    {
                        if (isSignatureAlgoSupported(gSupportedSignatureAlgorithms[j] & 0xFF))
                        {
                            if (pList[i] ==  gSupportedSignatureAlgorithms[j])
                            {
                                supported = 1;
                                break;
                            }
                        }
                    }
                }

                if (0 == supported)
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }
            }

            if (pSSLSock->pSupportedSignatureAlgoList != NULL)
            {
                DIGI_FREE((void **)&(pSSLSock->pSupportedSignatureAlgoList));
                pSSLSock->supportedSignatureAlgoListLength = 0;
            }

            if (OK > (status = DIGI_CALLOC((void **) &pSSLSock->pSupportedSignatureAlgoList, 1, listLength * sizeof(ubyte2))))
            {
                goto exit;
            }

            DIGI_MEMCPY(pSSLSock->pSupportedSignatureAlgoList, pList, listLength * sizeof(ubyte2));
            pSSLSock->supportedSignatureAlgoListLength = listLength;

            break;

        case TLS13_certificateSignatureAlgorithms:
            for (i = 0; i < listLength; i++)
            {
                ubyte4 j = 0;
                sbyte supported = 0;

                for (j = 0; j < NUM_SSL_SUPPORTED_SIGNATURE_ALGORITHMS; j++)
                {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
                    if (isHashAlgoSupported((gSupportedSignatureAlgorithms[j] >> 8) & 0xFF))
#endif
                    {
                        if (isSignatureAlgoSupported(gSupportedSignatureAlgorithms[j] & 0xFF))
                        {
                            if (pList[i] == gSupportedSignatureAlgorithms[j])
                            {
                                supported = 1;
                                break;
                            }
                        }
                    }
                }

                if (0 == supported)
                {
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                    goto exit;
                }
            }

            if (OK > (status = DIGI_CALLOC((void **) &(pSSLSock->pConfiguredSignatureCertAlgoList), 1, listLength * sizeof(ubyte2))))
            {
                goto exit;
            }

            DIGI_MEMCPY(pSSLSock->pConfiguredSignatureCertAlgoList, pList, listLength * sizeof(ubyte2));
            pSSLSock->configuredSignatureCertAlgoListLength = listLength;

            break;

        default:
            status = ERR_SSL;
            break;
    }

exit:
    return status;
}

#if defined(__ENABLE_DIGICERT_PQC__)

extern MSTATUS
SSL_SOCK_enforcePQCAlgorithm(SSLSocket *pSSLSock)
{
    MSTATUS status;
    ubyte4 i;
    ubyte2 pPQCKeyExchangeList[COUNTOF(gSupportedNamedGroup)] = { 0 };
    ubyte4 pqcKeyExchangeListLength = 0;
    ubyte2 pPQCSignatureAlgorithmList[COUNTOF(gSupportedNamedGroup)] = { 0 };
    ubyte4 pqcSignatureAlgorithmLength = 0;

    for (i = 0; i < COUNTOF(gSupportedNamedGroup); i++)
    {
        if (TLS_EXT_NAMED_CURVE_IS_PQC(gSupportedNamedGroup[i]))
        {
            pPQCKeyExchangeList[pqcKeyExchangeListLength] = gSupportedNamedGroup[i];
            pqcKeyExchangeListLength++;
        }
    }

    status = SSL_SOCK_setCipherAlgorithm(
        pSSLSock, pPQCKeyExchangeList, pqcKeyExchangeListLength,
        TLS13_supportedGroups);
    if (OK > status)
    {
        goto exit;
    }

    for (i = 0; i < COUNTOF(gSupportedSignatureAlgorithms); i++)
    {
        if (TLS_EXT_SIG_ALGO_IS_PQC(gSupportedSignatureAlgorithms[i]))
        {
            pPQCSignatureAlgorithmList[pqcSignatureAlgorithmLength] = gSupportedSignatureAlgorithms[i];
            pqcSignatureAlgorithmLength++;
        }
    }

    status = SSL_SOCK_setCipherAlgorithm(
        pSSLSock, pPQCSignatureAlgorithmList, pqcSignatureAlgorithmLength,
        TLS13_signatureAlgorithms);

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_PQC__ */

/* Convert the "signature_algorithms" or "signature_algorithms_cert" extension
 * into the list of certificate signature algo id's for the cert store.
 */
static MSTATUS convertToCertStoreListTls13SigAlgoCerts(
    ubyte *pList, ubyte4 listLen, ubyte4 **ppAlgoList, ubyte4 *pAlgoListLen,
    byteBoolean *pValidateNotSha1, ubyte2 curSigAlg)
{
    MSTATUS status;
    ubyte4 i, counter = 0;
    ubyte2 sigAlg;
    ubyte4 *pAlgoList = NULL;
    byteBoolean rsaPssFound = FALSE;
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_PKCS1__)
    byteBoolean allowRsaPssPss = FALSE;
#endif

    *pValidateNotSha1 = TRUE;

    /* listLen is in bytes, 2 bytes per algo */
    status = DIGI_CALLOC((void **) &pAlgoList, listLen/2, sizeof(ubyte4));
    if (OK != status)
        goto exit;

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_PKCS1__)
    /* curSigAlg is the current signature_algorithm that is being processed.
     * The signature_algorithm determines the certificates public key OID.
     *
     * If the public key OID is rsaPss (SSL_RSA_PSS_PSS_*), then allow the
     * SSL_RSA_PSS_PSS_* algorithms in signature_algorithm_certs to search
     * for a certificate signed with RSA-PSS. */
    switch (curSigAlg)
    {
        case SSL_RSA_PSS_PSS_SHA256:
        case SSL_RSA_PSS_PSS_SHA384:
        case SSL_RSA_PSS_PSS_SHA512:
            allowRsaPssPss = TRUE;
            break;
    }
#endif

    for (i = 0; i < listLen; i += 2, counter++)
    {
        sigAlg = getShortValue(pList + i);

        switch (sigAlg)
        {
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__))
            case SSL_RSA_PKCS1_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_rsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha256 );
                break;
            case SSL_RSA_PKCS1_SHA384:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_rsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha384 );
                break;
            case SSL_RSA_PKCS1_SHA512:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_rsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha512 );
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
            case SSL_ECDSA_SECP256R1_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_ecc );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha256 );
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoList[counter], cid_EC_P256 );
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
            case SSL_ECDSA_SECP384R1_SHA384:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_ecc );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha384 );
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoList[counter], cid_EC_P384 );
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
            case SSL_ECDSA_SECP521R1_SHA521:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_ecc );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha512 );
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoList[counter], cid_EC_P521 );
                break;
#endif
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_PKCS1__)
            case SSL_RSA_PSS_RSAE_SHA256:
            case SSL_RSA_PSS_RSAE_SHA384:
            case SSL_RSA_PSS_RSAE_SHA512:
                /* hashing is intrinsic, don't need to add hash Ids, only add this algo once */
                if (!rsaPssFound)
                {
                    CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_rsa_pss );
                    rsaPssFound = TRUE;
                }
                else
                {
                    counter--;
                }
                break;
            case SSL_RSA_PSS_PSS_SHA256:
            case SSL_RSA_PSS_PSS_SHA384:
            case SSL_RSA_PSS_PSS_SHA512:
                if (TRUE == allowRsaPssPss)
                {
                    /* hashing is intrinsic, don't need to add hash Ids, only add this algo once */
                    if (!rsaPssFound)
                    {
                        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_rsa_pss );
                        rsaPssFound = TRUE;
                    }
                    else
                    {
                        counter--;
                    }
                }
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            case SSL_ED25519:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_ecc_ed );
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoList[counter], cid_EC_Ed25519 );
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            case SSL_ED448:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_ecc_ed );
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoList[counter], cid_EC_Ed448 );
                break;
#endif
#ifndef __DISABLE_DIGICERT_SSL_TLS13_SIG_ALGO_CHECK__
            /* These are legacy algorithms. They will only be used if a
             * certificate chain without these signature algorithms cannot be
             * found.
             */
            case SSL_RSA_PKCS1_SHA1:
                *pValidateNotSha1 = FALSE;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_rsa );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha1 );
                break;
            case SSL_ECDSA_SHA1:
                *pValidateNotSha1 = FALSE;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_ecc );
                CERT_STORE_ALGO_ID_SET_HASH( pAlgoList[counter], ht_sha1 );
                break;
#endif /* __DISABLE_DIGICERT_SSL_TLS13_SIG_ALGO_CHECK__ */
#ifdef __ENABLE_DIGICERT_PQC__
            case SSL_MLDSA_44_ECDSA_P256_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_EC_P256);
                break;
            case SSL_MLDSA_65_ECDSA_P384_SHA384:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_EC_P384);
                break;
            case SSL_MLDSA_87_ECDSA_P384_SHA384:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_87);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_EC_P384);
                break;
            case SSL_MLDSA_44_ED25519:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_EC_Ed25519);
                break;
            case SSL_MLDSA_65_ED25519:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_EC_Ed25519);
                break;
            case SSL_MLDSA_44_RSA2048_PKCS15_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_RSA_2048_PKCS15);
                break;
            case SSL_MLDSA_65_RSA3072_PKCS15_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_RSA_3072_PKCS15);
                break;
            case SSL_MLDSA_65_RSA4096_PKCS15_SHA384:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_RSA_4096_PKCS15);
                break;
            case SSL_MLDSA_44_RSA2048_PSS_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_RSA_2048_PSS);
                break;
            case SSL_MLDSA_65_RSA3072_PSS_SHA256:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_RSA_3072_PSS);
                break;
            case SSL_MLDSA_65_RSA4096_PSS_SHA384:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_RSA_4096_PSS);
                break;
            case SSL_MLDSA_87_ED448:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_87);
                CERT_STORE_ALGO_ID_SET_CLALG( pAlgoList[counter], cid_EC_Ed448);
                break;
            case SSL_MLDSA_44:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_qs);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_44);
                break;
            case SSL_MLDSA_65:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_qs);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_65);
                break;
            case SSL_MLDSA_87:
                CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoList[counter], akt_qs);
                CERT_STORE_ALGO_ID_SET_QSALG( pAlgoList[counter], cid_PQC_MLDSA_87);
                break;
#endif
            default:
                counter--;
                break;
        }
    }

    *ppAlgoList = pAlgoList;
    *pAlgoListLen = counter;

exit:
    return status;
}

/*------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)

/* If a RSA-PSS key is being used then it must fit the proper criteria to sign
 * TLS messages. RFC 8446 section 4.2.3 specifies the RSA-PSS digest and salt
 * length. With the specified digest and salt length, depending on the RSA key
 * size, the RSA-PSS operation might not be able to sign the data.
 */
static MSTATUS validateRsaPssParams( MOC_RSA(hwAccelDescr hwAccelCtx)
    const AsymmetricKey *pKey, ubyte2 sigAlgo, intBoolean *pValid)
{
    MSTATUS status = OK;
    ubyte4 digestLen, saltLen;
    ubyte4 length;
    *pValid = FALSE;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* Get byte length of signature */
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux( MOC_RSA(hwAccelCtx)
        pKey->key.pRSA, (sbyte4 *) &length);
    if (OK != status)
    {
        goto exit;
    }

    length = (8 * length);
#else
    length = VLONG_bitLength(RSA_N(pKey->key.pRSA));
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
    /* RSA TAP keys must be 2048 bits and use SHA-256
     */
    if (akt_tap_rsa == pKey->type)
    {
        if ( ( (SSL_RSA_PSS_PSS_SHA256 != sigAlgo) &&
               (SSL_RSA_PSS_RSAE_SHA256 != sigAlgo) ) || (length != 2048) )
        {
            goto exit;
        }
    }
    else
#endif
    {
        length--;

        if ( (SSL_RSA_PSS_PSS_SHA256 == sigAlgo) ||
             (SSL_RSA_PSS_RSAE_SHA256 == sigAlgo) )
        {
            digestLen = 32;
        }
        else if ( (SSL_RSA_PSS_PSS_SHA384 == sigAlgo) ||
                  (SSL_RSA_PSS_RSAE_SHA384 == sigAlgo) )
        {
            digestLen = 48;
        }
        else if ( (SSL_RSA_PSS_PSS_SHA512 == sigAlgo) ||
                  (SSL_RSA_PSS_RSAE_SHA512 == sigAlgo) )
        {
            digestLen = 64;
        }
        else
        {
            goto exit;
        }
        saltLen = digestLen;

        /* Checks are performed as per RFC 8017 Section 9.1.1 for RSA-PSS.
         *
         * bit length must be at least 8 * digestLen + 8 * saltLen + 9
         */
        if (length < ((8 * digestLen) + (8 * saltLen) + 9))
        {
            goto exit;
        }
    }

    *pValid = TRUE;

exit:

    return status;
}

#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SSL_TLS13_SIG_ALGO_CHECK__
    /* If SHA-1 was not indicated in the certStoreFlags then iterate through
     * each of the certificates and ensure that none of the certificate
     * signatures use SHA-1.
     */

static MSTATUS SSL_SOCK_tls13ValidateNotSha1(const SizedBuffer *pCerts, ubyte4 certCount, intBoolean *pValid)
{
    MSTATUS status = OK;
    ubyte4 i, hashType, pubKeyType;
    ASN1_ITEMPTR pRoot = NULL, pSignAlgoId = NULL;
    static WalkerStep signatureAlgoWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { GoNthChild, 2, 0},
        { VerifyType, SEQUENCE, 0 },
        { Complete, 0, 0}
    };
#ifdef __ENABLE_DIGICERT_CV_CERT__
    CV_CERT *pCertData = NULL;
#endif

    *pValid = FALSE;

    for (i = 0; i < certCount; i++)
    {
        MemFile mf;
        CStream cs;
#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (0x7F == pCerts[i].data[0])
        {
            status = CV_CERT_parseCert (
                pCerts[i].data, pCerts[i].length, &pCertData);
            if (OK != status)
            {
                goto exit;
            }

            status = CV_CERT_parseKey (
                pCertData->pCvcKey, pCertData->cvcKeyLen, NULL, &hashType, NULL);
            if (OK != status)
            {
                goto exit;
            }
        }
        else
        {
#endif
            MF_attach(&mf, pCerts[i].length, pCerts[i].data);
            CS_AttachMemFile(&cs, &mf);

            if (NULL != pRoot)
            {
                TREE_DeleteTreeItem((TreeItem *) pRoot);
                pRoot = NULL;
            }

            status = ASN1_Parse(cs, &pRoot);
            if (OK != status)
            {
                goto exit;
            }

            status = ASN1_WalkTree(
                pRoot, cs, signatureAlgoWalkInstructions, &pSignAlgoId);
            if (OK != status)
            {
                goto exit;
            }

            status = X509_getCertSignAlgoType(
                pSignAlgoId, cs, &hashType, &pubKeyType);
            if (OK != status)
            {
                goto exit;
            }
#ifdef __ENABLE_DIGICERT_CV_CERT__
        }
#endif

        if (hashType == ht_sha1)
        {
            goto exit;
        }
    }

    *pValid = TRUE;

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }
#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }
#endif

    return status;
}

#endif /* __DISABLE_DIGICERT_SSL_TLS13_SIG_ALGO_CHECK__ */

/*------------------------------------------------------------------*/

static MSTATUS SSL_SOCK_tls13ValidateCertSelection(
    SSLSocket *pSSLSock, ubyte4 keyType, ubyte2 sigAlg, byteBoolean validateNotSha1,
    const AsymmetricKey *pPriKey, const SizedBuffer *pCerts, ubyte4 certCount,
    sbyte *pSNI, AsymmetricKey *pRetKey, const SizedBuffer **ppRetCerts,
    ubyte4 *pRetCertCount, intBoolean *pValid, ExtendedDataCallback extDataFunc, sbyte4 extDataIdentifier)
{
    MSTATUS status = OK;
    AsymmetricKey pubKey;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_TAP__)
    sbyte *pCredentials = NULL;
    sbyte4 credentialsLen = 0;
    enum dataType credType;
    enum dataEncoding credEncoding;
#endif

    if (OK > (status = CRYPTO_initAsymmetricKey(&pubKey)))
        goto exit_uninit;

    *pValid = FALSE;

    /* Ensure there is atleast a single certificate.
     */
    if (0 == certCount)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if (!pSSLSock->server && (akt_undefined == pPriKey->type) &&
        (NULL != SSL_sslSettings()->funcPtrMutualAuthCertificateVerify))
    {
        /* Possible that the key is empty. If it is empty then check if
         * the signature callback has been set. If it has been set then
         * store the public key of the certificate as the mutual auth
         * key.
         */
        MemFile mf;
        CStream cs;
        ASN1_ITEMPTR pRoot = NULL;
#ifdef __ENABLE_DIGICERT_CV_CERT__
        CV_CERT *pCertData = NULL;

        if (0x7F == pCerts[0].data[0])
        {
            status = CV_CERT_parseCert (
                pCerts[0].data, pCerts[0].length, &pCertData);
            if (OK != status)
            {
                goto exit1;
            }

            status = CV_CERT_parseKey (
                pCertData->pCvcKey, pCertData->cvcKeyLen, &pubKey, NULL, NULL);
            if (OK != status)
            {
                goto exit1;
            }
        }
        else
        {
#endif
            MF_attach(&mf, pCerts[0].length, pCerts[0].data);
            CS_AttachMemFile(&cs, &mf);

            status = ASN1_Parse(cs, &pRoot);
            if (OK != status)
            {
                goto exit1;
            }

            /* Extract the key into pKey.
            */
            status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(pSSLSock->hwAccelCookie)
                ASN1_FIRST_CHILD(pRoot), cs, &pubKey);
            if (OK != status)
            {
                goto exit1;
            }
#ifdef __ENABLE_DIGICERT_CV_CERT__
        }
#endif

        pPriKey = &pubKey;

exit1:
        if (NULL != pRoot)
        {
            TREE_DeleteTreeItem((TreeItem *) pRoot);
        }
#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (NULL != pCertData)
        {
            DIGI_FREE((void **)&pCertData);
        }
#endif

        if (OK != status)
            goto exit;

    }
#endif

#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
    /* If the key being selected is for RSA-PSS then validate the key can be
     * used to sign TLS messages.
     */
    if ( (akt_rsa == (keyType & 0xFF)) || (akt_rsa_pss == keyType) )
    {
        status = validateRsaPssParams(MOC_RSA(pSSLSock->hwAccelCookie) pPriKey, sigAlg, pValid);
        if ( (OK != status) || (FALSE == *pValid) )
        {
            goto exit;
        }

        *pValid = FALSE;
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
#if !defined(__DISABLE_DIGICERT_SERVERNAME_VALIDATION__) && !defined(__ENABLE_DIGICERT_CV_CERT__)
    /* Validate the server name if it was provided.
     */
    if (NULL != pSNI)
    {
        if (OK != SSL_SOCK_validateServerName(pSSLSock, pCerts))
        {
            goto exit;
        }
    }
#endif
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

    /* Validate the signature algorithms.
     */
#ifndef __DISABLE_DIGICERT_SSL_TLS13_SIG_ALGO_CHECK__
    if (validateNotSha1)
    {
        status = SSL_SOCK_tls13ValidateNotSha1(pCerts, certCount, pValid);
        if ( (OK != status) || (FALSE == *pValid) )
        {
            goto exit;
        }
    }
#endif /* __DISABLE_DIGICERT_SSL_TLS13_SIG_ALGO_CHECK__ */

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_TAP__)
    CRYPTO_INTERFACE_asymmetricKeyRemoveCreds(pRetKey);
#endif
    status = CRYPTO_INTERFACE_copyAsymmetricKey(pRetKey, pPriKey);
#else
    status = CRYPTO_copyAsymmetricKey(pRetKey, pPriKey);
#endif
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != extDataFunc)
    {
        if (0 != extDataFunc(extDataIdentifier, &credType, &credEncoding, &pCredentials, &credentialsLen))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if ((DATA_TYPE_PASSWORD != credType) || (DATA_ENCODE_BYTE_BUFFER != credEncoding))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        status = CRYPTO_INTERFACE_asymmetricKeyAddCreds(pRetKey, pCredentials, credentialsLen);
        DIGI_FREE((void **) &pCredentials);
        if (OK != status)
        {
            goto exit;
        }
    }
#endif

    *ppRetCerts = pCerts;
    *pRetCertCount = certCount;
    *pValid = TRUE;

exit:


    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

exit_uninit:
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS SSL_SOCK_setCertTLS13(
    SSLSocket* pSSLSock, void *pCertStore, ubyte *pSigAlgo, ubyte4 sigAlgoLen,
    ubyte *pSigAlgoCerts, ubyte4 sigAlgoCertLen, sbyte *pSNI,
    AsymmetricKey *pCertKey, const SizedBuffer **ppCerts, ubyte4 *pCertCount,
    ubyte2 *pRetSigAlgo, intBoolean *pFound)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    const AsymmetricKey *pKey = NULL;
    const SizedBuffer *pCerts = NULL;
    ubyte4 certCount = 0;
    ubyte4 certAlgoId;
    ubyte4 *pSigAlgoIds = NULL;
    ubyte4 sigAlgoIdsLen = 0;
    byteBoolean validateNotSha1 = TRUE;
    ExtendedDataCallback extDataFunc = NULL;
    sbyte4 extDataIdentifier = 0;

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    CRYPTO_INTERFACE_asymmetricKeyRemoveCreds(pCertKey);
#endif
    CRYPTO_uninitAsymmetricKey(pCertKey, NULL);

    *ppCerts = NULL;
    *pCertCount = 0;
    *pRetSigAlgo = 0;
    *pFound = FALSE;

    /* Extract the cert store ids for certificate signatures based on
     * "signature_algorithms_cert" or "signature_algorithms" extension.
     */
    if (NULL == pSigAlgoCerts)
    {
        pSigAlgoCerts = pSigAlgo;
        sigAlgoCertLen = sigAlgoLen;
    }

    /* Look for a certificate and key pair.
     */

    for (i = 0; i < sigAlgoLen; i += 2)
    {
        intBoolean valid = FALSE;
#ifdef __DISABLE_DIGICERT_SERVERNAME_VALIDATION__
        intBoolean validWithoutSNI = FALSE;
#endif
        void *pIdentity = NULL;
        ubyte4 keyType = 0;
        ubyte2 sigAlg = getShortValue(pSigAlgo + i);

        certAlgoId = 0;

        DIGI_FREE((void **) &pSigAlgoIds);
        status = convertToCertStoreListTls13SigAlgoCerts(
            pSigAlgoCerts, sigAlgoCertLen, &pSigAlgoIds, &sigAlgoIdsLen,
            &validateNotSha1, sigAlg);
        if (OK != status)
            goto exit;

        switch (sigAlg)
        {
#ifndef __DISABLE_DIGICERT_ECC_P256__
            case SSL_ECDSA_SECP256R1_SHA256:
                keyType = akt_ecc;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_ecc);
                CERT_STORE_ALGO_ID_SET_CURVE(certAlgoId, cid_EC_P256);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
            case SSL_ECDSA_SECP384R1_SHA384:
                keyType = akt_ecc;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_ecc);
                CERT_STORE_ALGO_ID_SET_CURVE(certAlgoId, cid_EC_P384);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
            case SSL_ECDSA_SECP521R1_SHA521:
                keyType = akt_ecc;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_ecc);
                CERT_STORE_ALGO_ID_SET_CURVE(certAlgoId, cid_EC_P521);
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            case SSL_ED25519:
                keyType = akt_ecc_ed;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_ecc_ed);
                CERT_STORE_ALGO_ID_SET_CURVE(certAlgoId, cid_EC_Ed25519);
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            case SSL_ED448:
                keyType = akt_ecc_ed;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_ecc_ed);
                CERT_STORE_ALGO_ID_SET_CURVE(certAlgoId, cid_EC_Ed448);
                break;
#endif
#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_RSA_KEYEX_SUPPORT__)) && defined(__ENABLE_DIGICERT_PKCS1__)
            case SSL_RSA_PSS_RSAE_SHA256:
            case SSL_RSA_PSS_RSAE_SHA384:
            case SSL_RSA_PSS_RSAE_SHA512:
                keyType = akt_rsa;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_rsa);
                break;
            case SSL_RSA_PSS_PSS_SHA256:
            case SSL_RSA_PSS_PSS_SHA384:
            case SSL_RSA_PSS_PSS_SHA512:
                keyType = akt_rsa_pss;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_rsa);
                break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
            case SSL_MLDSA_44_ECDSA_P256_SHA256:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_EC_P256);
                break;
            case SSL_MLDSA_65_ECDSA_P384_SHA384:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_EC_P384);
                break;
            case SSL_MLDSA_87_ECDSA_P384_SHA384:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_87);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_EC_P384);
                break;
            case SSL_MLDSA_44_ED25519:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_EC_Ed25519);
                break;
            case SSL_MLDSA_65_ED25519:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_EC_Ed25519);
                break;
            case SSL_MLDSA_44_RSA2048_PKCS15_SHA256:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_RSA_2048_PKCS15);
                break;
            case SSL_MLDSA_65_RSA3072_PKCS15_SHA256:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_RSA_3072_PKCS15);
                break;
            case SSL_MLDSA_65_RSA4096_PKCS15_SHA384:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_RSA_4096_PKCS15);
                break;
            case SSL_MLDSA_44_RSA2048_PSS_SHA256:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_44);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_RSA_2048_PSS);
                break;
            case SSL_MLDSA_65_RSA3072_PSS_SHA256:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_RSA_3072_PSS);
                break;
            case SSL_MLDSA_65_RSA4096_PSS_SHA384:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_65);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_RSA_4096_PSS);
                break;
            case SSL_MLDSA_87_ED448:
                keyType = akt_hybrid;
                CERT_STORE_ALGO_ID_SET_KEYTYPE( certAlgoId, akt_hybrid);
                CERT_STORE_ALGO_ID_SET_QSALG( certAlgoId, cid_PQC_MLDSA_87);
                CERT_STORE_ALGO_ID_SET_CLALG( certAlgoId, cid_EC_Ed448);
                break;
            case SSL_MLDSA_44:
                keyType = akt_qs;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_qs);
                CERT_STORE_ALGO_ID_SET_QSALG(certAlgoId, cid_PQC_MLDSA_44);
                break;
            case SSL_MLDSA_65:
                keyType = akt_qs;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_qs);
                CERT_STORE_ALGO_ID_SET_QSALG(certAlgoId, cid_PQC_MLDSA_65);
                break;
            case SSL_MLDSA_87:
                keyType = akt_qs;
                CERT_STORE_ALGO_ID_SET_KEYTYPE(certAlgoId, akt_qs);
                CERT_STORE_ALGO_ID_SET_QSALG(certAlgoId, cid_PQC_MLDSA_87);
                break;
#endif
            default:
                continue;
        }

        /* Find a certificate and key pair.
         */
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        /* Application can load a certificate/key pair using an alias.
         * If application wants to use that particular cert/key pair,
         * it sets the cert auth alias and we blindly pick that cert/key pair
         * for this connection.
         */
        if (!pSSLSock->server &&
            (pSSLSock->roleSpecificInfo.client.pCertAuthAlias != NULL) &&
            (pSSLSock->roleSpecificInfo.client.certAuthAliasLen > 0))
        {
            status = CERT_STORE_findIdentityByAliasAndAlgo(pCertStore, keyType, (1 << digitalSignature),
                                                           &certAlgoId, 1, pSigAlgoIds, sigAlgoIdsLen,
                                                           pSSLSock->roleSpecificInfo.client.pCertAuthAlias,
                                                           pSSLSock->roleSpecificInfo.client.certAuthAliasLen,
                                                           (struct AsymmetricKey **)&pKey,
                                                           (struct SizedBuffer **)&pCerts,
                                                           &certCount, &pIdentity);
            if (NULL != pIdentity)
            {
                status = CERT_STORE_getIdentityPairExtData(pIdentity, &extDataFunc, &extDataIdentifier);
                if (OK > status)
                    goto exit;
                /* validateNotSha1 is passed as FALSE explicitly;
                 * The certificate is choosen on the basis of alias,
                 * sha1 check is the best effort check, so we allow it
                 */
                status = SSL_SOCK_tls13ValidateCertSelection(pSSLSock, keyType, sigAlg,
                                                             FALSE, pKey, pCerts,
                                                             certCount, pSNI,
                                                             pCertKey, ppCerts, pCertCount,
                                                             &valid, extDataFunc, extDataIdentifier);
                if (OK > status)
                    goto exit;

                if ((TRUE == valid) && (*ppCerts != NULL) && (*pCertCount > 0))
                {
                    *pRetSigAlgo = sigAlg;
                    *pFound = TRUE;
                    break;
                }
                else
                {
                    /* We found the identity with alias and the algos,
                     * but it does not fit the selection certeria;
                     * Get the next signature Algo, retrieve the cert/key using
                     * the alias and check the selection creteria.
                     */
                    continue;
                }
            }
            else
            {
                continue;
            }
        }
        else
#endif
        {
            status = CERT_STORE_findIdentityCertChainFirstFromList(
                pCertStore, keyType, (1 << digitalSignature), &certAlgoId, 1, pSigAlgoIds, sigAlgoIdsLen,
                &pKey, &pCerts, &certCount, &pIdentity);
        }
        if (OK != status)
            goto exit;

        /* Validate the identity matches the search criteria.
         */
        while (NULL != pIdentity)
        {
            status = CERT_STORE_getIdentityPairExtData(pIdentity, &extDataFunc, &extDataIdentifier);
            if (OK > status)
                goto exit;
            /* This API only sets pCertKey, ppCerts, and pCertCount if the
             * certificate match criteria is met, otherwise they retain their
             * previous values. */
            status = SSL_SOCK_tls13ValidateCertSelection(
                pSSLSock, keyType, sigAlg, validateNotSha1,
                pKey, pCerts, certCount, pSNI, pCertKey, ppCerts, pCertCount,
                &valid, extDataFunc, extDataIdentifier);
            if (OK != status)
            {
                goto exit;
            }
             /* Found a match. Break out */
            if (TRUE == valid)
            {
                DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_setCertTLS13: Found match");
                break;
            }

#ifdef __DISABLE_DIGICERT_SERVERNAME_VALIDATION__
            /* Couldn't find valid entry with SNI. Attempt to validate the
             * entry without SNI - only keep the 1st entry found but keep 
             * parsing the list for other entries with SNI
             */
            if (TRUE != validWithoutSNI)
            {   /* Identifies the 1st Algorithm match only, do not set valid status - allows the subsequent
                   matches against the SNI */
                status = SSL_SOCK_tls13ValidateCertSelection(
                    pSSLSock, keyType, sigAlg, validateNotSha1,
                    pKey, pCerts, certCount, NULL, pCertKey, ppCerts, pCertCount,
                    &validWithoutSNI, extDataFunc, extDataIdentifier);
            }
            if (OK != status)
            {
                goto exit;
            }
#endif

            /* If the certificate did not fit the criteria, then get the next
             * certificate.
             */
            status = CERT_STORE_findIdentityCertChainNextFromList(
                pCertStore, keyType, (1 << digitalSignature), &certAlgoId, 1, pSigAlgoIds, sigAlgoIdsLen,
                &pKey, &pCerts, &certCount, &pIdentity);
            if (OK != status)
            {
                goto exit;
            }
#ifdef __DISABLE_DIGICERT_SERVERNAME_VALIDATION__
            if ((pIdentity == NULL) && (TRUE == validWithoutSNI)) 
            { /* End of the List and Entry without SNI found */
              valid = TRUE;
              break;
            }
#endif

        }

        /* Search for a certificate without the legacy flags (without SHA-1). As
         * per RFC 8446 section 4.2.3 legacy algorithms must not be used in
         * certificate signatures unless no valid certificate chain can be
         * produced without it.
         *
         * If validateNotSha1 flag is TRUE then the above loop is the same as 
         * this loop, therefore no need to loop here. The loop above would have
         * already found a certificate without SHA-1.
         *
         * If validateNotSha1 flag is FALSE then the above loop could've potentially found
         * an identity with SHA-1. Loop through the remaining identities to find
         * one without SHA-1. If we don't find one then the certificate in the
         * above loop will be used even if it contains SHA-1.
         */
        if ((TRUE == valid) && (TRUE != validateNotSha1))
        {
            /* Parse the list again only if atleast a valid entry found above, 
             * and No SHA1 was not already enforced
             */
            status = CERT_STORE_findIdentityCertChainFirstFromList(
              pCertStore, keyType, (1 << digitalSignature), &certAlgoId, 1, pSigAlgoIds, sigAlgoIdsLen,
              &pKey, &pCerts, &certCount, &pIdentity);

            if (OK != status)
              goto exit;

            while (NULL != pIdentity)
            {
                status = CERT_STORE_getIdentityPairExtData(pIdentity, &extDataFunc, &extDataIdentifier);
                if (OK > status)
                    goto exit;
                /* Call SSL_SOCK_tls13ValidateCertSelection before retrieving
                 * the next identity to check if the current identity is valid.
                 *
                 * This API only sets pCertKey, ppCerts, and pCertCount if the
                 * certificate match criteria is met, otherwise they retain their
                 * previous values. */
                status = SSL_SOCK_tls13ValidateCertSelection(
                    pSSLSock, keyType, sigAlg, TRUE, pKey, pCerts,
                    certCount, pSNI, pCertKey, ppCerts, pCertCount, &valid, extDataFunc, extDataIdentifier);
                if (OK != status)
                {
                    goto exit;
                }

                if (TRUE == valid)
                {
                    break;
                }

                /* If the certificate did not fit the criteria, then get the next
                 * certificate.
                 */
                status = CERT_STORE_findIdentityCertChainNextFromList(
                    pCertStore, keyType, (1 << digitalSignature), &certAlgoId, 1, pSigAlgoIds, sigAlgoIdsLen,
                    &pKey, &pCerts, &certCount, &pIdentity);

                if (OK != status)
                {
                    goto exit;
                }
            }
        }

        if ( (NULL != *ppCerts) && (0 != *pCertCount) )
        {
            *pRetSigAlgo = sigAlg;
            *pFound = TRUE;
            break;
        }
    }

exit:

    if (NULL != pSigAlgoIds)
    {
        (void) DIGI_FREE((void **) &pSigAlgoIds);
    }
   
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_setCertTLS13() returns status = ", status);
    }

    if (TRUE == *pFound)
    {
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"MATCHED CLIENT CIPHER ");
        DEBUG_HEXINT(DEBUG_SSL_TRANSPORT,  pSSLSock->signatureAlgo);
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)" ");
    }
    else
    {
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"SSL_SOCK_setCertTLS13(): No certificate found");
    }

    return status;
}

static MSTATUS
addHrrClientHelloToHandshakeHash(
    SSLSocket *pSSLSock, ubyte *pClientHello, ubyte4 clientHelloLen)
{
    MSTATUS status;
    ubyte pBuffer[4 + SHA512_RESULT_SIZE];
#if ((defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))) && (defined(__ENABLE_DIGICERT_TLS13__))
    ubyte *pPtr;
    ubyte *pClientHello1 = NULL;
    ubyte4 clientHello1Len;
    ubyte4 tmpLen;
#endif

    /* RFC 8446 Section 4.4.1
     *
     * The construction of ClientHello1 is
     *   [ message_hash (1 byte) || 0x00 0x00 || digest length (1 byte) ||
     *     digest of client hello ]
     */
    pBuffer[0] = SSL_MESSAGE_HASH;
    pBuffer[1] = 0x00;
    pBuffer[2] = 0x00;
    pBuffer[3] = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize;


#if ((defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))) && (defined(__ENABLE_DIGICERT_TLS13__))
    /* The digest starts at the second byte of the helloCookie */
    if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        /* Add first 4 bytes of recordHeader, then skip
         * DTLS fields message_seq, fragment_offset, fragment_length.
         */
        /* message_seq(2) + fragment_offset(3) + fragment_length(3) */
        clientHello1Len = clientHelloLen - 8;
        status = DIGI_MALLOC((void **) &pClientHello1, clientHello1Len);
        if (OK != status)
            goto exit;

        pPtr = pClientHello1;

        /* msg_type(1) + length(3) */
        tmpLen = 4;
        status = DIGI_MEMCPY(pPtr, pClientHello, tmpLen);
        if (OK != status)
            goto exit;

        pPtr += tmpLen;
        pClientHello += tmpLen + 8; /* 8 associated with DTLS-only fields */
        clientHelloLen -= (tmpLen + 8);

        status = DIGI_MEMCPY(pPtr, pClientHello, clientHelloLen);
        if (OK != status)
            goto exit;

        tmpLen += clientHelloLen; /* add rest of client hello to length calculation */

        if (tmpLen != clientHello1Len)
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }

        pClientHello = pClientHello1;
        clientHelloLen = clientHello1Len;
    }
#endif

    /* Calculate the digest.
    */
    status = SSLSOCK_calcTranscriptHashForBuffer(MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo, (ubyte *) pClientHello,
        clientHelloLen, pBuffer + 4);
    if (OK > status)
    {
        goto exit;
    }

    addToHandshakeHash(
        pSSLSock, pBuffer,
        4 + pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize);

exit:
#if ((defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))) && (defined(__ENABLE_DIGICERT_TLS13__))
    (void)DIGI_FREE((void **) &pClientHello1);
#endif
    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
extern MSTATUS SSL_SOCK_sendHeartbeatMessage(SSLSocket *pSSLSock, ubyte *pPayload, ubyte2 payloadLen, intBoolean isRequest)
{
    MSTATUS status = OK;
    ubyte* pSRH  = NULL;
    ubyte *pTemp = NULL;
    ubyte  pPadding[HEARTBEAT_PADDING_LENGTH] = {0};
    ubyte *pHeartbeatMsg = NULL;
    ubyte4 heartbeatMsgLen = 0;
    ubyte4 sizeofRecordHeader = 0;
    ubyte4 sizeofHandshakeHeader = 0;

    /* Perform this check only if the peer is allowed to send the heartbeat message */
    if (pSSLSock->sendHeartbeatMessage == peerAllowedToSend)
    {
        /* Check if we are already waiting for a heartbeat response */
        if (pSSLSock->heartbeatMessageInFlight == TRUE)
            goto exit;

        pSSLSock->heartbeatMessageInFlight = TRUE;
    }

    heartbeatMsgLen += 1; /* HeartbeatMessageType */
    heartbeatMsgLen += 2; /* payload length */
    heartbeatMsgLen += payloadLen;

    heartbeatMsgLen += HEARTBEAT_PADDING_LENGTH;

    if (OK > (status = DIGI_MALLOC((void **)&pHeartbeatMsg, heartbeatMsgLen)))
    {
        goto exit;
    }

    pTemp = pHeartbeatMsg;
    if (isRequest)
    {
        *pTemp++ = HEARTBEAT_MESSAGE_REQUEST;
    }
    else
    {
        *pTemp++ = HEARTBEAT_MESSAGE_RESPONSE;
    }

    setShortValue(pTemp, payloadLen);
    pTemp += sizeof(ubyte2);

    if (OK > (status = DIGI_MEMCPY(pTemp, pPayload, payloadLen)))
        goto exit;

    pTemp += payloadLen;

    if (OK > (status = pSSLSock->rngFun(pSSLSock->rngFunArg, sizeof(pPadding), pPadding)))
        goto exit;

    if (OK > (status = DIGI_MEMCPY(pTemp, pPadding, sizeof(pPadding))))
        goto exit;

    pTemp += HEARTBEAT_PADDING_LENGTH;

    if (OK > (status = sendData(pSSLSock, SSL_HEARTBEAT, pHeartbeatMsg, heartbeatMsgLen, TRUE)))
    {
        goto exit;
    }

exit:
    return status;
}

extern MSTATUS SSL_SOCK_processHeartbeatMessage(SSLSocket *pSSLSock, ubyte *pMsg, ubyte2 msgLen)
{
    MSTATUS status = OK;
    ubyte *pTemp = NULL;
    ubyte2 tempLen = 0;
    ubyte4 sizeofHandshakeHeader;
    ubyte  heartbeatType = 0;
    ubyte2 payloadLen = 0;
    ubyte* pPayload = NULL;
    ubyte2 paddingLen = 0;

    pTemp = (ubyte *)(pMsg);
    tempLen = msgLen;

    status = ERR_SSL_INVALID_MSG_SIZE;
    if (1 > tempLen)
        goto exit;

    heartbeatType = *pTemp++;
    tempLen--;

    if (2 > tempLen)
        goto exit;

    payloadLen = getShortValue(pTemp);
    pTemp   += 2;
    tempLen -= 2;

    if (payloadLen >= tempLen)
        goto exit;

    if (OK > (status = DIGI_MALLOC((void **)&pPayload, payloadLen)))
        goto exit;

    DIGI_MEMCPY(pPayload, pTemp, payloadLen);

    pTemp   += payloadLen;
    tempLen -= payloadLen;

    if (heartbeatType == HEARTBEAT_MESSAGE_RESPONSE)
    {
        sbyte4 result = -1;
        if (payloadLen != HEARTBEAT_PAYLOAD_LENGTH)
        {
            status = ERR_SSL_INVALID_MSG_SIZE;
            goto exit;
        }

        status = DIGI_MEMCMP(pPayload, pSSLSock->heartbeatPayload, payloadLen, &result);
        if ((OK > status) || (result != 0))
        {
            /* Should fail silently */
            status = OK;
            goto exit;
        }
    }

    /* Padding should be of atleast 16 bytes */
    paddingLen = msgLen - (1 + 2 + payloadLen);
    if (16 > paddingLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    pTemp += paddingLen;
    tempLen -= paddingLen;

    /* Set the status to OK, no errors found */
    status = OK;

    /* Func Callback */
    if (pSSLSock->funcPtrHeatbeatMessageCallback != NULL)
    {
        status = pSSLSock->funcPtrHeatbeatMessageCallback(SSL_findConnectionInstance(pSSLSock),
                                                          status, heartbeatType);
        if (OK > status)
            goto exit;
    }

    if ((heartbeatType == HEARTBEAT_MESSAGE_REQUEST) &&
        (pSSLSock->rxHeartbeatExtension == peerAllowedToSend))
    {
        status = SSL_SOCK_sendHeartbeatMessage(pSSLSock, pPayload, payloadLen, FALSE);
    }

exit:
    if (heartbeatType == HEARTBEAT_MESSAGE_RESPONSE)
        pSSLSock->heartbeatMessageInFlight = FALSE;

    if (pPayload != NULL)
        DIGI_FREE((void **)&pPayload);

    return status;
}
#endif


#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) || \
    (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__))))
static MSTATUS
SSLSOCK_sanityCertificateStatusRequestExtension(SSLSocket *pSSLSock,
                                                ubyte *pCertStatusRequest,
                                                sbyte4 certStatusRequestLen)
{
    MSTATUS status          = OK;
    ubyte2  respIdListLen   = 0;
    ubyte2  ocspReqExtLen   = 0;
    ubyte2  offset          = 0;

    /* We do basic sanity test here */
    if (5 > certStatusRequestLen)
    {
         /* 5 = 1 + 2 byte repId Len + 2 byte Exten Len */
         status = ERR_SSL_EXTENSION_LENGTH;
         goto exit;
    }

    /* Check for CertificateStatusType */
    if (certStatusType_ocsp != (ubyte)(*pCertStatusRequest))
    {
        status = ERR_SSL_EXTENSION_UNKNOWN_FORMAT;
        goto exit;
    }

    offset += 1;

    /* Now check for ResponderId List Length */
    respIdListLen = getShortValue(pCertStatusRequest + offset);
    offset += 2;

    if (respIdListLen > certStatusRequestLen)
    {
        status = ERR_SSL_EXTENSION_LENGTH;
        goto exit;
    }

    /* Ignore responder Ids */
    offset += respIdListLen;

    /* Now check for OCSP extensions length */
    ocspReqExtLen = getShortValue(pCertStatusRequest + offset);
    offset += 2;

    if (ocspReqExtLen > certStatusRequestLen)
    {
        status = ERR_SSL_EXTENSION_LENGTH;
        goto exit;
    }

    if (ocspReqExtLen)
    {
        /* Now extract the extensions */
        if (OK > (status = SSL_OCSP_parseExtensions(pCertStatusRequest + offset,
                    ocspReqExtLen, &pSSLSock->pExts, &pSSLSock->numOfExtension)))
        {
            goto exit;
        }
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

/*------------------------------------------------------------------*/

#ifdef    __ENABLE_DIGICERT_SSL_CLIENT__
#ifdef __DISABLE_INC_FILES__
/* ssl_client.inc is copied as ssl_client_inc.h by install script as IDE
   doesn't support .inc files */
#include "../ssl/client/ssl_client_inc.h"
#else
#include "../ssl/client/ssl_client.inc"
#endif
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

#ifdef    __ENABLE_DIGICERT_SSL_SERVER__
#include "../ssl/server/ssl_server.inc"
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#include "../dtls/dtlssock.inc"
#endif

/*------------------------------------------------------------------*/

static MSTATUS
checkBuffer(SSLSocket* pSSLSock, sbyte4 requestedSize, ubyte4 sizeofRecordHeader)
{
    ubyte   temp[20] = {0}; /* enough for either SSL or DTLS record header */
    MSTATUS status = OK;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        /* For 1.3 we use what's passed in, for 1.2 it's a fixed size */
#if (defined(__ENABLE_DIGICERT_TLS13__))
        if (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion || 0 == sizeofRecordHeader)
#endif
            sizeofRecordHeader = sizeof(DTLSRecordHeader);
    } 
    else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    if ((sbyte4)(SSL_MALLOC_BLOCK_SIZE + requestedSize + sizeofRecordHeader + SSL_MAXMACSECRETSIZE) <= pSSLSock->receiveBufferSize)
        goto exit;

    if (NULL != pSSLSock->pReceiveBufferBase)
    {
        /* copy out SSL record header, if we realloc */
        if (pSSLSock->pReceiveBuffer)
            DIGI_MEMCPY(temp, pSSLSock->pReceiveBuffer - sizeofRecordHeader, sizeofRecordHeader);

        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pSSLSock->pReceiveBufferBase);
    }

    pSSLSock->receiveBufferSize = SSL_MALLOC_BLOCK_SIZE + requestedSize + sizeofRecordHeader + SSL_MAXMACSECRETSIZE ;

    status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, SSL_MALLOC_BLOCK_SIZE + requestedSize + sizeofRecordHeader + SSL_MAXMACSECRETSIZE, TRUE, (void **)&pSSLSock->pReceiveBufferBase);

    if (pSSLSock->pReceiveBufferBase)
    {
        pSSLSock->pReceiveBuffer = pSSLSock->pReceiveBufferBase + SSL_MALLOC_BLOCK_SIZE;
        pSSLSock->pSharedInBuffer = (ubyte *)(pSSLSock->pReceiveBuffer - sizeofRecordHeader);

        DIGI_MEMCPY(pSSLSock->pReceiveBuffer - sizeofRecordHeader, temp, sizeofRecordHeader);
    }
    else
    {
        pSSLSock->receiveBufferSize = 0;
        pSSLSock->pReceiveBuffer = NULL;
        pSSLSock->pSharedInBuffer = NULL;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static void
setMediumValue(ubyte medium[SSL_MEDIUMSIZE], ubyte2 val)
{
    medium[2] = (ubyte)(val & 0xFF);
    medium[1] = (ubyte)((val >> 8) & 0xFF);
    medium[0] = 0;
}


/*------------------------------------------------------------------*/

static ubyte2
getMediumValue(const ubyte* med)
{
    return  (ubyte2)(((ubyte2)med[1] << 8) | (med[2]));
}


/*------------------------------------------------------------------*/

static void
setShortValue(ubyte shortBuff[2], ubyte2 val)
{
    shortBuff[1] = (ubyte)(val & 0xFF);
    shortBuff[0] = (ubyte)((val >> 8) & 0xFF);
}


/*------------------------------------------------------------------*/

static ubyte2
getShortValue(const ubyte* med)
{
    return  (ubyte2)(((ubyte2)med[0] << 8) | (med[1]));
}

MOC_EXTERN MSTATUS
SSL_SOCK_setSessionResumeTimeout(ubyte4 timeout)
{
    gSessionResumeTimeout = timeout;
    return OK;
}

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
extern MSTATUS
getNumBytesSent(SSLSocket *pSSLSock, ubyte *pOutputBuffer, ubyte4 maxLen, ubyte4 *pNumBytesSent)
{
    ubyte *ptr = pOutputBuffer;
    ubyte2 recordSize = 0;

    *pNumBytesSent = 0;

    while (*pNumBytesSent < maxLen)
    {
        if (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION && (DTLS13_PROTOCOL_MIN <= *ptr && *ptr <= DTLS13_PROTOCOL_MAX))
            recordSize = ((((ubyte2)ptr[3]) << 8) | ((ubyte2)ptr[4]));
        else
            recordSize = DTLS_RECORD_SIZE(ptr);


        if (*pNumBytesSent + recordSize > maxLen)
            break;

        if (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION && (DTLS13_PROTOCOL_MIN <= *ptr && *ptr <= DTLS13_PROTOCOL_MAX))
        {
            *pNumBytesSent += recordSize + DTLS13_MOC_RECORD_HEADER_LEN; /* unified_hdr == 5 */
            ptr = ptr + DTLS13_MOC_RECORD_HEADER_LEN + recordSize;
        }
        else
        {
            *pNumBytesSent += recordSize + 13; /* sizeof(DTLSRecordHeader) == 13 */
            ptr = ptr + 13 + recordSize;
        }
    }

    if (0 == *pNumBytesSent)
    {
        /*
         * Possible error conditions:
         * 1. application send buffer is too small to hold a record
         * 2. recordSize is invalid (this is less likely to happen)
         */
        return ERR_DTLS_SEND_BUFFER;
    }

    return OK;
}

extern MSTATUS cleanupOutputBuffer(SSLSocket *pSSLSock)
{
    if (NULL != pSSLSock->pOutputBufferBase)
        FREE(pSSLSock->pOutputBufferBase);

    pSSLSock->pOutputBufferBase = NULL;
    pSSLSock->pOutputBuffer     = NULL;

    return OK;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
extern intBoolean
SSLSOCK_parseAlert(SSLSocket* pSSLSock, sbyte4 alertId,
                    sbyte4 alertClass, sbyte4 *pRetErrorCode)
{
    ubyte4      index;
    intBoolean  isFound = FALSE;

    if ((NULL == pSSLSock) || (NULL == pRetErrorCode))
        goto exit;

    for (index = 0; index < NUM_ALERTS; index++)
    {
        if (alertId == mAlertsSSL[index].sslAlertId &&
            alertClass == mAlertsSSL[index].sslAlertClass)
        {
            if (ALERT_SSL_TLS == mAlertsSSL[index].sslProtocol)
                break;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            if ((ALERT_SSL == mAlertsSSL[index].sslProtocol) && (SSL3_MINORVERSION == pSSLSock->sslMinorVersion))
                break;

            if ((ALERT_TLS == mAlertsSSL[index].sslProtocol) && (SSL3_MINORVERSION < pSSLSock->sslMinorVersion))
                break;
#else
            if ((ALERT_TLS == mAlertsSSL[index].sslProtocol))
                break;
#endif
        }
    }

    if (index < NUM_ALERTS)
    {
        *pRetErrorCode = mAlertsSSL[index].mocErrorCode;
        isFound = TRUE;
    }

exit:
    return isFound;
}

extern intBoolean
SSLSOCK_lookupAlert(SSLSocket* pSSLSock, sbyte4 lookupError,
                    sbyte4 *pRetAlertId, sbyte4 *pAlertClass)
{
    ubyte4      index;
    intBoolean  isFound = FALSE;

    if ((NULL == pSSLSock) || (NULL == pRetAlertId) || (NULL == pAlertClass))
        goto exit;

    for (index = 0; index < NUM_ALERTS; index++)
    {
        if (lookupError == mAlertsSSL[index].mocErrorCode)
        {
            if (ALERT_SSL_TLS == mAlertsSSL[index].sslProtocol)
                break;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            if ((ALERT_SSL == mAlertsSSL[index].sslProtocol) && (SSL3_MINORVERSION == pSSLSock->sslMinorVersion))
                break;

            if ((ALERT_TLS == mAlertsSSL[index].sslProtocol) && (SSL3_MINORVERSION < pSSLSock->sslMinorVersion))
                break;
#else
            if ((ALERT_TLS == mAlertsSSL[index].sslProtocol))
                break;
#endif
        }
    }

    if (index < NUM_ALERTS)
    {
        *pRetAlertId = mAlertsSSL[index].sslAlertId;
        *pAlertClass = mAlertsSSL[index].sslAlertClass;
        isFound = TRUE;
    }

exit:
    return isFound;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
extern MSTATUS
SSLSOCK_sendAlert(SSLSocket* pSSLSock, intBoolean encryptBool, sbyte4 alertId, sbyte4 alertClass)
{
    MSTATUS status = OK, tstatus;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        /* for DTLS, encrypt alert once changeCipherSpec is sent (pActiveOwnCipherSuite is set) */
        /* since epoch is incremented, records sent with the new epoch should be encrypted */
        encryptBool = TRUE;
    }
#endif

    if ((NULL != pSSLSock->pActiveOwnCipherSuite) && (encryptBool))
    {
        sbyte   alertMesg[2];

        alertMesg[0] = (sbyte)alertClass;
        alertMesg[1] = (sbyte)alertId;

        status = sendData(pSSLSock, SSL_ALERT, alertMesg, 2, TRUE);
    }
    else
    {
        sbyte   alertMesg[20]; /* adequate for both SSL and DTLS alertMesg */
        ubyte4  sizeofAlertMesg;
        ubyte4  sizeofRecordHeader;
        ubyte4  numBytesSent = 0;

        /* fill buffer */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            if (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
                sizeofRecordHeader = DTLS13_MOC_RECORD_HEADER_LEN;
            else
                sizeofRecordHeader = sizeof(DTLSRecordHeader);
            DTLS_SET_RECORD_HEADER_EXT(alertMesg,pSSLSock,SSL_ALERT,2);
        } else
#endif
        {
            sizeofRecordHeader = sizeof(SSLRecordHeader);
            SSL_SET_RECORD_HEADER(alertMesg, SSL_ALERT, (pSSLSock->sslMinorVersion == TLS13_MINORVERSION) ?
                TLS12_MINORVERSION : pSSLSock->sslMinorVersion, 2);
        }

        sizeofAlertMesg = sizeofRecordHeader + 2;

        alertMesg[0 + sizeofRecordHeader] = (sbyte)alertClass;
        alertMesg[1 + sizeofRecordHeader] = (sbyte)alertId;

        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            if (NULL != pSSLSock->pOutputBufferBase)
                FREE(pSSLSock->pOutputBufferBase);

            if (NULL == (pSSLSock->pOutputBufferBase = (ubyte*) MALLOC(sizeofAlertMesg)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            pSSLSock->pOutputBuffer     = pSSLSock->pOutputBufferBase;
            DIGI_MEMCPY(pSSLSock->pOutputBuffer, (ubyte *)alertMesg, sizeofAlertMesg);
            pSSLSock->outputBufferSize  = sizeofAlertMesg;
            pSSLSock->numBytesToSend    = sizeofAlertMesg;
            status = (MSTATUS) pSSLSock->numBytesToSend;
#if !defined(__ENABLE_DIGICERT_SSL_ALERT_DIRECTION__)
            goto exit;
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
            if (NULL != pSSLSock->pTransportHandler)
            {
                if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
                {
                    if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId, 
                                                                                         (sbyte *)alertMesg, sizeofAlertMesg, &numBytesSent)))
                    {
                        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                    }
                }
                else
                {
                    status = ERR_INTERNAL_ERROR;
                }
            }
            else
#endif
            {
#ifndef __DIGICERT_IPSTACK__
                status = TCP_WRITE(pSSLSock->tcpSock, alertMesg, sizeofAlertMesg, &numBytesSent);
#else
                status = DIGI_TCP_WRITE(pSSLSock->tcpSock, alertMesg, sizeofAlertMesg, &numBytesSent);
#endif
            }
        }
    }

    if (SSL_sslSettings()->funcPtrAlertCallback != NULL)
    {
#if defined(__ENABLE_DIGICERT_SSL_ALERT_DIRECTION__)
        tstatus = SSL_sslSettings()->funcPtrAlertCallback(SSL_findConnectionInstance(pSSLSock),
                                      alertId, alertClass | SSL_ALERT_DIRECTION_BIT);
#else
        tstatus = SSL_sslSettings()->funcPtrAlertCallback(SSL_findConnectionInstance(pSSLSock),
                                      alertId, alertClass);
#endif
        if (OK > tstatus)
            status = tstatus;
    }

    /* Set the flag to false if stack is sending the close notify alert */
    if ((SSLALERTLEVEL_WARNING == alertClass) && (SSL_ALERT_CLOSE_NOTIFY == alertId))
    {
        pSSLSock->sendCloseNotifyAlert = FALSE;
    }

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    /* on fatal alert, we want to scramble session cache's master secret */
    if (SSLALERTLEVEL_FATAL == alertClass)
    {
        SSLSOCK_clearServerSessionCache(pSSLSock);
    }
#endif
exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
extern MSTATUS
SSLSOCK_sendInnerApp(SSLSocket* pSSLSock, InnerAppType innerApp, ubyte* pMsg, ubyte4 msgLen, ubyte4 * retMsgLen, sbyte4 isClient)
{
    ubyte   *pAppMsg = NULL;
    ubyte4   appMsgLen;
    MSTATUS status = ERR_SSL_NO_CIPHERSUITE;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (SSL_INNER_APPLICATION_DATA == innerApp)
    {
        if (NULL ==  pMsg || 0 == msgLen)
        {
            goto exit;
        }

        pAppMsg = MALLOC(msgLen + 4);

        if (NULL == pAppMsg)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *pAppMsg = innerApp;

        pAppMsg[1] = (msgLen >> 16) & 0xFF ;
        pAppMsg[2] = (msgLen >> 8) & 0xFF ;
        pAppMsg[3] = (msgLen) & 0xFF ;
        DIGI_MEMCPY(pAppMsg + 4,pMsg,msgLen);

        appMsgLen = msgLen + 4;
    }
    else if ((SSL_INNER_INTER_FINISHED == innerApp) ||
             (SSL_INNER_FINAL_FINISHED == innerApp))
    {
        pAppMsg = MALLOC(16);

        if (NULL == pAppMsg)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *pAppMsg = innerApp;
        pAppMsg[1] = 0;
        pAppMsg[2] = 0;
        pAppMsg[3] = 12 ;

        /* Calculate 12 Bytes Verify Data  and Copy it to the pAppMsg*/
        if (  0 < isClient )
            status = PRF(pSSLSock, pSSLSock->innerSecret, SSL_MASTERSECRETSIZE,
                         (const ubyte*)SSL_INNER_APP_CLIENT_PHRASE,SSL_INNER_APP_CLIENT_PHRASE_LEN,
                         pAppMsg+4, 12);
        else
            status = PRF(pSSLSock, pSSLSock->innerSecret, SSL_MASTERSECRETSIZE,
                         (const ubyte*)SSL_INNER_APP_SERVER_PHRASE,SSL_INNER_APP_SERVER_PHRASE_LEN,
                         pAppMsg+4, 12);

        if (OK > status)
            goto exit;

            appMsgLen = 16;
    }
    else
    {
        status = ERR_SSL_INVALID_INNER_TYPE;
        goto exit;
    }

    if ((NULL != pSSLSock->pActiveOwnCipherSuite))
        status = sendData(pSSLSock, SSL_INNER_APPLICATION, (const sbyte*)pAppMsg, appMsgLen, TRUE);
    else
        status = ERR_SSL_NO_CIPHERSUITE;



exit:
    if (pAppMsg)
    {
        FREE(pAppMsg);
        pAppMsg = NULL;
    }
    if (0 < status) /* Return the Length of the Data to be Sent */
    {
        *retMsgLen = status;
        status = OK;
    }
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_INNER_APP__) */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
extern MSTATUS
SSLSOCK_updateInnerAppSecret(SSLSocket* pSSLSock, ubyte* session_key, ubyte4 sessionKeyLen)
{
    ubyte               innerSecret[SSL_MASTERSECRETSIZE];
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];
    sbyte4              i;
    ubyte*              random1;
    ubyte*              random2;
    MSTATUS status = OK;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMCPY(masterSecret, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

    random1 = START_RANDOM( pSSLSock);
    random2 = random1 + SSL_RANDOMSIZE;
    for (i = 0; i < SSL_RANDOMSIZE; ++i)
    {
        ubyte swap = *random1;
        *random1++ = *random2;
        *random2++ = swap;
    }

    /* copy label "inner app permutation" in its special place */
    DIGI_MEMCPY( START_RANDOM( pSSLSock) - SSL_INNER_APP_SECRET_PHRASE_LEN,
            SSL_INNER_APP_SECRET_PHRASE,
            SSL_INNER_APP_SECRET_PHRASE_LEN);

    /* generate innersecret with PRF */
    status = PRF(pSSLSock, pSSLSock->innerSecret, SSL_MASTERSECRETSIZE,
            START_RANDOM( pSSLSock) - SSL_INNER_APP_SECRET_PHRASE_LEN,
            SSL_INNER_APP_SECRET_PHRASE_LEN + 2 * SSL_RANDOMSIZE,
            innerSecret, SSL_MASTERSECRETSIZE);

    /* store master secret in its place after that */
    DIGI_MEMCPY(pSSLSock->pSecretAndRand, masterSecret, SSL_MASTERSECRETSIZE);

    /* update inner secret  */
    if (OK == status)
        DIGI_MEMCPY(pSSLSock->innerSecret, innerSecret, SSL_MASTERSECRETSIZE);

exit:
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_INNER_APP__) */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_INNER_APP__)
extern MSTATUS
SSLSOCK_verifyInnerAppVerifyData(SSLSocket *pSSLSock, ubyte *data, InnerAppType innerAppType, sbyte4 isClient)
{
    ubyte   verifyData[12];
    sbyte4  cmp;
    MSTATUS status = OK;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 < isClient)
    {
        status = PRF(pSSLSock, pSSLSock->innerSecret, SSL_MASTERSECRETSIZE,
                     (const ubyte*)SSL_INNER_APP_CLIENT_PHRASE,SSL_INNER_APP_CLIENT_PHRASE_LEN,
                     verifyData, 12);
    }
    else
    {
        status = PRF(pSSLSock, pSSLSock->innerSecret, SSL_MASTERSECRETSIZE,
                     (const ubyte*)SSL_INNER_APP_SERVER_PHRASE,SSL_INNER_APP_SERVER_PHRASE_LEN,
                     verifyData, 12);
    }

    if (OK > status)
        goto exit;

    DIGI_CTIME_MATCH(verifyData,data,12,&cmp);
    if (cmp)
    {
        status = ERR_SSL_INNER_APP_VERIFY_DATA;
        goto exit;
    }

exit:
    return status;

}
#endif /* defined(__ENABLE_DIGICERT_INNER_APP__) */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS13__)
/* Convert an OID into a hash enumeration and suite. This function uses pointer
 * comparison against the statically defined OID values.
 */
static MSTATUS getHashInfoFromOID(
    const ubyte *pHashOID,
    const BulkHashAlgo **ppHashAlgo,
    ubyte *pHashId
    )
{
    if (EqualOID(pHashOID, sha1_OID))
    {
        *ppHashAlgo = &SHA1Suite;
        *pHashId = ht_sha1;
    }
#ifndef __DISABLE_DIGICERT_SHA224__
    else if (EqualOID(pHashOID, sha224_OID))
    {
        *ppHashAlgo = &SHA224Suite;
        *pHashId = ht_sha224;
    }
#endif /* __DISABLE_DIGICERT_SHA224__ */
#ifndef __DISABLE_DIGICERT_SHA256__
    else if (EqualOID(pHashOID, sha256_OID))
    {
        *ppHashAlgo = &SHA256Suite;
        *pHashId = ht_sha256;
    }
#endif /* __DISABLE_DIGICERT_SHA256__ */
#ifndef __DISABLE_DIGICERT_SHA384__
    else if (EqualOID(pHashOID, sha384_OID))
    {
        *ppHashAlgo = &SHA384Suite;
        *pHashId = ht_sha384;
    }
#endif /* __DISABLE_DIGICERT_SHA384__ */
#ifndef __DISABLE_DIGICERT_SHA512__
    else if (EqualOID(pHashOID, sha512_OID))
    {
        *ppHashAlgo = &SHA512Suite;
        *pHashId = ht_sha512;
    }
#endif /* __DISABLE_DIGICERT_SHA512__ */
    else
    {
        return ERR_INVALID_INPUT;
    }
    return OK;
}
#endif


#if ((defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) ||\
     (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)))

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
static MSTATUS
processCertificateVerifyDSA(ubyte* pHashResult, ubyte4 hashLen, ubyte4 msgLen,
                                  const ubyte2 signatureAlgo, SSLSocket *pSSLSock,
                                  AsymmetricKey key, ubyte* pSig, ubyte4 signatureLen,
                                  vlong **ppVlongQueue)
{
    DSAKey*     pDSAKey;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    struct MDsaKeyTemplate dsaParameters = {0};
#endif
    MSTATUS     status;
    ubyte       *strR = 0, *strS = 0;
    vlong*      pVlongQueue = NULL;
    vlong*  	pM = NULL;
    vlong*  	pR = NULL;
    vlong*  	pS = NULL;
    intBoolean  isGoodSignature;
    ubyte	    lenR = 0, lenS = 0;
    ubyte4      lenDsaQ = 0;

    /* key type should have been verified before calling this function */
    pDSAKey = key.key.pDSA;
    /* Parse DER encoding */
    if ((pSig[0] != 0x30) || ((ubyte4)(2 + pSig[1]) > msgLen) || pSig[2] != 0x2)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    lenR = pSig[3];
    if ((ubyte4) (2 + 2 + lenR) > msgLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    strR = pSig+4;
    if (pSig[4+lenR] != 0x2)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    lenS = pSig[4 + lenR + 1];
    if ((ubyte4) (lenR + 2 + lenS) > msgLen)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    strS = strR + lenR + 2;
    if (0x0 == strR[0])
    {
        ++strR;
        --lenR;
    }

    if (0x0 == strS[0])
    {
        ++strS;
        --lenS;
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(pDSAKey, &dsaParameters, MOC_GET_PUBLIC_KEY_DATA)))
    {
        goto exit;
    }

    lenDsaQ = dsaParameters.qLen;
    if (lenDsaQ < hashLen)
    {
        hashLen = lenDsaQ;
    }

    if (OK > (status = CRYPTO_INTERFACE_DSA_verifySignatureAux(MOC_DSA(hwAccelDescr hwAccelCtx) pDSAKey,
                                              pHashResult, hashLen,
                                              strR, lenR, strS, lenS,
                                              &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = VLONG_vlongFromByteString(strR, lenR, &pR, &pVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_vlongFromByteString(strS, lenS, &pS, &pVlongQueue)))
        goto exit;

    lenDsaQ = ((7 + VLONG_bitLength(DSA_Q(pDSAKey))) / 8);

    if (lenDsaQ < hashLen)
    {
        hashLen = lenDsaQ;
    }

    if (OK > (status = VLONG_vlongFromByteString(pHashResult, hashLen, &pM, &pVlongQueue)))
	{
        goto exit;
    }

    if (OK > (status = DSA_verifySignature(MOC_DSA(hwAccelDescr hwAccelCtx) pDSAKey,
					   pM, pR, pS, &isGoodSignature, &pVlongQueue)))
    {
        goto exit;
    }

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    status = (isGoodSignature) ? OK : ERR_SSL_INVALID_SIGNATURE;

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    DSA_freeKeyTemplate(pDSAKey, &dsaParameters);
#else
    if (pR != NULL)
    {
        VLONG_freeVlong(&pR, &pVlongQueue);
    }
    if (pS != NULL)
    {
        VLONG_freeVlong(&pS, &pVlongQueue);
    }
    if (pM != NULL)
    {
        VLONG_freeVlong(&pM, &pVlongQueue);
    }
#endif

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
} /* processCertificateVerifyDSA */

#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */

/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__))

static MSTATUS
processCertificateVerifyRSA(const ubyte* pHashResult, ubyte4 hashLen,
                                  const ubyte* hashOID, SSLSocket *pSSLSock,
                                  AsymmetricKey key,
                                  ubyte* pSignature, ubyte4 signatureLen,
                                  vlong **ppVlongQueue)
{
    MSTATUS status;
    ubyte4  lenRsaN;
    ubyte*  pDecrypt = NULL;
    ubyte4  decryptLen;
    sbyte4  compareResult;
    ASN1_ITEMPTR pRootItem = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(pSSLSock->hwAccelCookie)
        key.key.pRSA, (sbyte4 *) &lenRsaN, key.type);
    if (OK != status)
    {
        goto exit;
    }
#else
    lenRsaN = ((7 + VLONG_bitLength(RSA_N(key.key.pRSA))) / 8);
#endif

    if (NULL == pHashResult)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (lenRsaN < signatureLen)
    {
        status = ERR_SSL_INVALID_CERT_VERIFY_MSG_SIZE;
        goto exit;
    }

    /* verify signature matches */
    if (NULL == (pDecrypt = MALLOC(lenRsaN)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        ubyte hashId;
        const BulkHashAlgo *pHashAlgo = NULL;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        ubyte4 validSig = 1;
#else
        intBoolean validSig = FALSE;
#endif
        sbyte4 saltLen;

        status = getHashInfoFromOID(hashOID, &pHashAlgo, &hashId);
        if (OK != status)
        {
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_PSS_AUTO_RECOVER__)
        saltLen = -1;
#else
        saltLen = (sbyte4) pHashAlgo->digestSize;
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify(MOC_RSA(pSSLSock->hwAccelCookie)
            key.key.pRSA, hashId, MOC_PKCS1_ALG_MGF1, hashId, pHashResult,
            hashLen, pSignature, signatureLen, (sbyte4) saltLen, &validSig);
        if ( (OK == status) && (0 != validSig) )
        {
            status = ERR_RSA_DECRYPTION;
        }
#else
        status = PKCS1_rsassaPssVerify(MOC_RSA(pSSLSock->hwAccelCookie)
            key.key.pRSA, hashId,
            PKCS1_MGF1_FUNC, pHashResult, hashLen, pSignature,
            signatureLen, (sbyte4) saltLen, &validSig);
        if ( (OK == status) && (TRUE != validSig) )
        {
            status = ERR_RSA_DECRYPTION;
        }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
        goto exit;
    }
    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignatureAux(MOC_RSA(pSSLSock->hwAccelCookie)
                                                    key.key.pRSA, pSignature,
                                                    pDecrypt, &decryptLen, ppVlongQueue)))
#else
        if (OK > (status = RSA_verifySignature(MOC_RSA(pSSLSock->hwAccelCookie)
                                                    key.key.pRSA, pSignature,
                                                    pDecrypt, &decryptLen, ppVlongQueue)))
#endif
        {
            goto exit;
        }
    }

    if (hashOID) /* TLS 1.2 DER struct -> parse and verify the OID and hash matches */
    {
        MemFile mf;
        CStream cs;
        ASN1_ITEMPTR pOctetString;
        const ubyte* digest;

        WalkerStep digestInfoWalkInstructions[] =
        {
            { GoFirstChild, 0, 0},          /* 0: DigestInfo */
            { VerifyType, SEQUENCE, 0 },    /* 1: */
            { GoFirstChild, 0, 0},          /* 2: AlgorithmIdentifier */
            { VerifyType, SEQUENCE, 0 },    /* 3: */
            { GoFirstChild, 0,0 },          /* 4: OID */
            { VerifyOID, 0, 0 },            /* 5: */
            { GoParent, 0, 0 },             /* 6: AlgorithmIdentifier */
            { GoNextSibling, 0, 0},         /* 7: digest */
            { VerifyType, OCTETSTRING, 0},  /* 8: */
            { Complete, 0, 0}
        };

        /* place the hashOID in the WalkerStep s */
#ifdef __UCOS_DIRECT_RTOS__
	digestInfoWalkInstructions[5].extra2 = (ubyte*)hashOID;
#else
        digestInfoWalkInstructions[5].extra2 = (ubyte*)hashOID;
#endif /* __UCOS_DIRECT_RTOS__ */

        status = ERR_SSL_INVALID_SIGNATURE;

        /* &mf will always be valid, so function will always return 0, no test needed */
        (void) MF_attach( &mf, decryptLen, pDecrypt);
        CS_AttachMemFile( &cs, &mf);

        if (OK > ASN1_Parse( cs, &pRootItem))
            goto exit;

        if (OK > ASN1_WalkTree( pRootItem, cs,
                                digestInfoWalkInstructions,
                                &pOctetString))
        {
            goto exit;
        }

        if (pOctetString->length != hashLen)
            goto exit;

        digest = CS_memaccess( cs, pOctetString->dataOffset, pOctetString->length);
        if (!digest)
            goto exit;

        /* all pointer parameters have been validated, function will always return OK */
        (void) DIGI_CTIME_MATCH( digest, pHashResult, hashLen, &compareResult);
        status = (0 == compareResult) ? OK : ERR_SSL_INVALID_SIGNATURE;
        CS_stopaccess( cs, digest);
    }
    else
    {
        if (hashLen != decryptLen)
            goto exit;

        /* all pointer parameters have been validated, function will always return OK */
        (void) DIGI_CTIME_MATCH(pDecrypt, pHashResult, hashLen, &compareResult);
        status = (0 == compareResult) ? OK : ERR_SSL_INVALID_SIGNATURE;
    }

exit:

    FREE(pDecrypt);
    TREE_DeleteTreeItem((TreeItem*) pRootItem);

    return status;
} /* processCertificateVerifyRSA */

#endif /* __DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ECC__)
static MSTATUS
processCertificateVerifyECC(const ubyte* pMessage, ubyte4 messageLen,
                                  SSLSocket *pSSLSock,
                                  AsymmetricKey key,
                                  ubyte* pSignature, ubyte4 signatureLen,
                                  ubyte2 signAlgo,
                                  vlong **ppVlongQueue)
{


    MSTATUS status = OK;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
#ifdef __ENABLE_DIGICERT_TLS13__
    const ubyte* buffer = NULL;
    ASN1_ITEMPTR pItem = NULL;
    ubyte4  verifyFailure = 0;
    ubyte *pSig = NULL;
    ubyte4 elementLen;
    ubyte4 rLen, sLen;
    ubyte4 hashId;
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        if (akt_ecc == (key.type & 0xFF))
        {
            /* signature for ECDSA is a SEQUENCE consisting of two INTEGERs,
             * extract R and S values to byte strings */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(key.key.pECC, &elementLen);
#else
            status = EC_getElementByteStringLen(key.key.pECC, &elementLen);
#endif
            if (OK != status)
                goto exit;

            /* Allocate signature buffer.
             */
            status = DIGI_CALLOC((void **) &pSig, 1, 2 * elementLen);
            if (OK != status)
                goto exit;

            /* &mf will always be valid, so function will always return 0, no test needed */
            (void) MF_attach( &mf, signatureLen, pSignature);
            CS_AttachMemFile( &cs, &mf);

            if (OK > ( status = ASN1_Parse( cs, &pRootItem)))
                goto exit;

            pItem = ASN1_FIRST_CHILD(pRootItem);
            status = ASN1_VerifyType(pItem, SEQUENCE);
            if (OK != status)
            {
                status = ERR_SSL_INVALID_SIGNATURE;
                goto exit;
            }

            pItem = ASN1_FIRST_CHILD(pItem);
            status = ASN1_VerifyType(pItem, INTEGER);
            if (OK != status)
            {
                status = ERR_SSL_INVALID_SIGNATURE;
                goto exit;
            }

            buffer = (const ubyte*) CS_memaccess(cs, pItem->dataOffset, pItem->length);
            if (NULL == buffer)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            rLen = pItem->length;
            while (rLen > elementLen)
            {
                if (0x00 != *(buffer + pItem->length - rLen))
                {
                    status = ERR_SSL_INVALID_SIGNATURE;
                    goto exit;
                }

                rLen--;
            }

            if (OK > (status = DIGI_MEMCPY(
                pSig + elementLen - rLen, buffer + pItem->length - rLen, rLen)))
            {
                goto exit;
            }

            CS_stopaccess(cs, buffer);
            pItem = ASN1_NEXT_SIBLING(pItem);
            status = ASN1_VerifyType(pItem, INTEGER);
            if (OK != status)
            {
                status = ERR_SSL_INVALID_SIGNATURE;
                goto exit;
            }

            buffer = (const ubyte*) CS_memaccess(cs, pItem->dataOffset, pItem->length);
            if (NULL == buffer)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            sLen = pItem->length;
            while (sLen > elementLen)
            {
                if (0x00 != *(buffer + pItem->length - sLen))
                {
                    status = ERR_SSL_INVALID_SIGNATURE;
                    goto exit;
                }

                sLen--;
            }

            if (OK > (status = DIGI_MEMCPY(
                pSig + (2 * elementLen) - sLen, buffer + pItem->length - sLen, sLen)))
            {
                goto exit;
            }

            CS_stopaccess( cs, buffer);
            buffer = 0;

            pSignature = pSig;
            signatureLen = 2*elementLen;
        }

        switch (signAlgo)
        {
#ifndef __DISABLE_DIGICERT_SHA256__
            case SSL_ECDSA_SECP256R1_SHA256:
                hashId = ht_sha256;
                break;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
            case SSL_ECDSA_SECP384R1_SHA384:
                hashId = ht_sha384;
                break;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
            case SSL_ECDSA_SECP521R1_SHA521:
                hashId = ht_sha512;
                break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
            case SSL_ED25519:
            case SSL_ED448:
                hashId = ht_none;
                break;
#endif
            default:
                status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                goto exit;
        }
        if (OK != status)
            goto exit;

        if (ht_none == hashId)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(MOC_ECC(pSSLSock->hwAccelCookie) key.key.pECC, hashId,
                (ubyte *) pMessage, messageLen, pSignature, signatureLen, &verifyFailure, NULL);
#else
            status = ECDSA_verifyMessage(MOC_ECC(pSSLSock->hwAccelCookie) key.key.pECC, hashId,
                (ubyte *) pMessage, messageLen, pSignature, signatureLen, &verifyFailure, NULL);
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux(MOC_ECC(pSSLSock->hwAccelCookie) key.key.pECC,
                        (ubyte *)pMessage, messageLen, pSignature, signatureLen/2,
                        pSignature + (signatureLen/2), signatureLen/2, &verifyFailure);
#else
            status = ECDSA_verifySignatureDigest(MOC_ECC(pSSLSock->hwAccelCookie) key.key.pECC,
                        (ubyte *)pMessage, messageLen, pSignature, signatureLen/2,
                        pSignature + (signatureLen/2), signatureLen/2, &verifyFailure);
#endif
        }
        if (OK != status)
            goto exit;

        if (verifyFailure != 0)
        {
            status = ERR_CERT_INVALID_SIGNATURE;
        }
    }
    else
#endif
    {
        /* &mf will always be valid, so function will always return 0, no test needed */
        (void) MF_attach( &mf, signatureLen, pSignature);
        CS_AttachMemFile( &cs, &mf);

        if (OK > ( status = ASN1_Parse( cs, &pRootItem)))
            goto exit;

        /* key type should have been verified before calling this function*/
        if (OK > ( status = X509_verifyECDSASignature(MOC_ECC(pSSLSock->hwAccelCookie) ASN1_FIRST_CHILD( pRootItem), cs,
                                                        key.key.pECC,
                                                        messageLen, pMessage)))
        {
            goto exit;
        }
    }

exit:

    TREE_DeleteTreeItem( (TreeItem*) pRootItem);
#ifdef __ENABLE_DIGICERT_TLS13__
    if (NULL != pSig)
    {
        DIGI_FREE((void **) &pSig);
    }
#endif
    return status;
} /* processCertificateVerifyECC */
#endif /* __ENABLE_DIGICERT_ECC__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS
processCertificateVerifyHybrid(const ubyte* pMessage, ubyte4 messageLen,
                               SSLSocket *pSSLSock,
                               AsymmetricKey key,
                               ubyte* pSignature, ubyte4 signatureLen,
                               ubyte2 signAlgo,
                               vlong **ppVlongQueue)
{
    MSTATUS status = OK;
    
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte4 verifyFailure = 0;
    ubyte *pDomain = NULL;
    ubyte4 domainLen = 0;

    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        ubyte4 qsAlg = 0;

        status = CRYPTO_INTERFACE_QS_getAlg(key.pQsCtx, &qsAlg);
        if (OK != status)
            goto exit;

        status = CRYPTO_getAlgoOIDAlloc(key.clAlg, qsAlg, &pDomain, &domainLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(pSSLSock->hwAccelCookie) &key, TRUE, pDomain, domainLen,
                                                     (ubyte *) pMessage, messageLen,
                                                     pSignature, signatureLen, &verifyFailure);
        if (OK != status)
            goto exit;
        
        if (verifyFailure)
        {
            status = ERR_CERT_INVALID_SIGNATURE;
        }
        else
        {
            status = OK;
        }
    }

exit:
    
    if (NULL != pDomain)
    {
        (void) DIGI_MEMSET_FREE(&pDomain, domainLen);
    }

#endif
    
    return status;
    
} /* processCertificateVerifyHybrid */

/*------------------------------------------------------------------*/

static MSTATUS
processCertificateVerifyQS(const ubyte* pMessage, ubyte4 messageLen,
                           SSLSocket *pSSLSock,
                           AsymmetricKey key,
                           ubyte* pSignature, ubyte4 signatureLen)
{
    MSTATUS status = OK;
    ubyte4 verifyFailure = 0;
    
#ifdef __ENABLE_DIGICERT_TLS13__
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(pSSLSock->hwAccelCookie) key.pQsCtx, (ubyte *) pMessage, messageLen,
                                                pSignature, signatureLen, &verifyFailure);
        if (OK != status)
            goto exit;
        
        if (verifyFailure)
        {
            status = ERR_CERT_INVALID_SIGNATURE;
        }
        else
        {
            status = OK;
        }
    }
#endif
    
exit:
    
    return status;
    
} /* processCertificateVerifyQS */
#endif

/*------------------------------------------------------------------*/

static MSTATUS
processCertificateVerify(SSLSocket *pSSLSock, AsymmetricKey key, ubyte* pSHSH, ubyte2 recLen, vlong **ppVlongQueue)
{
    ubyte*  pParams;
    ubyte2  lenParams;
    ubyte4  sizeofHandshakeHeader;
    MSTATUS status;
    ubyte2  signatureAlgo=0;
    ubyte   *pHashResult = 0;
    ubyte4  hashLen = 0;
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    ubyte   dsaOffset = 0; /* offset in pHashResult to use for ECDSA and DSA keys */
#endif
    const   ubyte* hashOID = 0; /* for TLS 1.2 */
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte *pContextString = NULL;
    ubyte4 contextStringLen = 0;
#endif

    if (2 > recLen)
    {
        status = ERR_SSL_INVALID_CERT_VERIFY_MSG_SIZE;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    /* start of message */
    pParams = (ubyte *)(pSHSH + sizeofHandshakeHeader);

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        /* extract signature/hash algo */
        signatureAlgo = getShortValue(pParams);
        pParams += 2;
    }

    /* extract length of signature */
    lenParams = getShortValue(pParams);
    pParams += 2;

    if (((signatureAlgo != 0? 2: 0) + 2 + lenParams) != recLen)
    {
        status = ERR_SSL_INVALID_CERT_VERIFY_MSG_SIZE;
        goto exit;
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        if (pSSLSock->server)
        {
            pContextString = (ubyte *) CERT_VERIFY_CLIENT_CONTEXT_STRING;
            contextStringLen = CERT_VERIFY_CLIENT_CONTEXT_STRING_SIZE;
        }
        else
        {
            pContextString = (ubyte *) CERT_VERIFY_SERVER_CONTEXT_STRING;
            contextStringLen = CERT_VERIFY_SERVER_CONTEXT_STRING_SIZE;
        }


        if (OK > (status = calculateTLS13CertificateVerifyHash(signatureAlgo, pSSLSock,
                        pHashResult, &hashLen, &hashOID,
                        pContextString, contextStringLen, &key)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            if (OK > (status = calculateTLS12CertificateVerifyHash(signatureAlgo, pSSLSock,
                            pHashResult, &hashLen, &hashOID)))
            {
                goto exit;
            }
        }
        else
        {
            hashLen = MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE;
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
            dsaOffset = MD5_DIGESTSIZE; /* offset in pHashResult to use for ECDSA and DSA keys */
#endif
            if (OK > (status = calculateSSLTLSHashes(pSSLSock, 0, pHashResult, pSSLSock->sslMinorVersion)))
                goto exit;
        }
    }


    switch ( key.type & 0xFF)
    {
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    case akt_dsa:
        if (TRUE == SSL_sslSettings()->allowDSASigAlg)
        {
            if (OK > (status = processCertificateVerifyDSA(pHashResult + dsaOffset, hashLen - dsaOffset, recLen,
                                                           signatureAlgo, pSSLSock, key, pParams, lenParams, ppVlongQueue)))
            {
                goto exit;
            }
        }
        else
        {
            status = ERR_SSL_INVALID_KEY_TYPE;
        }
        break;
#endif
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
    case akt_rsa:
        if ( OK > (status = processCertificateVerifyRSA( pHashResult, hashLen, hashOID,
                                                                pSSLSock, key, pParams, lenParams, ppVlongQueue)))
        {
            goto exit;
        }
        break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    case akt_ecc_ed:
    case akt_ecc:
        if ( OK > (status = processCertificateVerifyECC( pHashResult + dsaOffset, hashLen - dsaOffset,
                                                                pSSLSock, key, pParams, lenParams, signatureAlgo, ppVlongQueue)))
        {
            goto exit;
        }
        break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case akt_hybrid:
        if (OK > (status = processCertificateVerifyHybrid( pHashResult + dsaOffset, hashLen - dsaOffset,
                                                                pSSLSock, key, pParams, lenParams, signatureAlgo, ppVlongQueue)))
        {
            goto exit;
        }
        break;

    case akt_qs:
        if (OK > (status = processCertificateVerifyQS( pHashResult + dsaOffset, hashLen - dsaOffset,
                                                       pSSLSock, key, pParams, lenParams)))
        {
            goto exit;
        }
        break;
#endif

    default:
        status = ERR_SSL_INVALID_KEY_TYPE;
        goto exit;
        break;
    }

exit:

    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));


    return status;

} /* processCertificateVerify */

#endif /* defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) */

/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) ||\
     (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)))

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
static MSTATUS
SSLSOCK_fillCertificateVerifyDSA(ubyte4 sigAlgo, SSLSocket* pSSLSock, AsymmetricKey key,
                         ubyte *pBuffer, ubyte2 *pLength,
                         ubyte* pHash, ubyte4 hashLen,
                         vlong **ppVlongQueue)
{
    MSTATUS  status;
    ubyte4   lenDsaQ = 0;
    ubyte4   lenSignature = 0;
    ubyte*   pSHSH = NULL;
    ubyte*   pParams = NULL;
    ubyte4   sizeofHandshakeHeader;
    DSAKey*  pDSAKey = NULL;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    ubyte*   pM = NULL;
    ubyte*   pR = NULL;
    ubyte*   pS = NULL;
    ubyte*   pX = NULL;
#else
    vlong*   pM = NULL;
    vlong*   pR = NULL;
    vlong*   pS = NULL;
    vlong*   pX = NULL;
#endif
    ubyte4   rLen = 0, sLen = 0;
    ubyte	 DsaRstr[2*SHA_HASH_BLOCK_SIZE];
    ubyte	 DsaSstr[2*SHA_HASH_BLOCK_SIZE];
    ubyte	 extraRByte=0;
    ubyte	 extraSByte=0;
    struct MDsaKeyTemplate dsaParameters = {0};
    /* TLS 1.2 extra memory */
    ubyte4              actualLen = 0;

    /* set the handshake part */
    pSHSH = pBuffer;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
    }

    pParams = (ubyte*)(pSHSH + sizeofHandshakeHeader);

    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        setShortValue(pParams, (ubyte2)sigAlgo); pParams += 2;
        actualLen += 2;
    }

    pDSAKey = key.key.pDSA;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(pDSAKey, &dsaParameters, MOC_GET_PRIVATE_KEY_DATA)))
    {
        goto exit;
    }
    pX = dsaParameters.pX;
#else
    pX = DSA_X(key.key.pDSA);
#endif

    if (NULL != pX)
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        lenDsaQ = dsaParameters.qLen;

        if (lenDsaQ < hashLen)
        {
            hashLen = lenDsaQ;
        }

        if (OK > (status = CRYPTO_INTERFACE_DSA_computeSignatureAux(g_pRandomContext, pDSAKey, pHash, hashLen,
                                                   NULL, &pR, &rLen, &pS, &sLen, ppVlongQueue)))
        {
            goto exit;
        }

        if ((pR != NULL) && (rLen != 0))
        {
            if (OK > (status = DIGI_MEMCPY(DsaRstr, pR, hashLen)))
            {
                goto exit;
            }
        }

        if ((pS != NULL) && (sLen != 0))
        {
            if (OK > (status = DIGI_MEMCPY(DsaSstr, pS, hashLen)))
            {
                goto exit;
            }
        }
#else
        lenDsaQ = ((7 + VLONG_bitLength(DSA_Q(pDSAKey))) / 8);

        if (lenDsaQ < hashLen)
        {
            hashLen = lenDsaQ;
        }

        if (OK > (status = VLONG_vlongFromByteString(pHash, hashLen, &pM, ppVlongQueue)))
        {
            goto exit;
        }

        if (OK > (status = DSA_computeSignature(MOC_DSA(hwAccelCtx) g_pRandomContext, pDSAKey,
                                                pM, NULL, &pR, &pS, ppVlongQueue)))
        {
            goto exit;
        }


        if (OK > (status = VLONG_fixedByteStringFromVlong(pR, DsaRstr, hashLen)))
        {
            goto exit;
        }

        if (OK > (status = VLONG_fixedByteStringFromVlong(pS, DsaSstr, hashLen)))
        {
            goto exit;
        }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
        lenSignature = 2 /* Seq type + len */ + (2 * 2) /* INT type + len for R and S */ + (2 * hashLen);

        if (DsaRstr[0] & 0x80) {extraRByte = 1; ++lenSignature;} /* insert a 0x0 as leading byte of int value */
        if (DsaSstr[0] & 0x80) {extraSByte = 1; ++lenSignature;} /* insert a 0x0 as leading byte of int value */

        /* store signature */
        setShortValue(pParams, (ubyte2)lenSignature);
        pParams += 2;
        /* insert DER encoded Dss-Sig-Value (RFC 2246, 4.7) */
        *pParams++ = 0x30; /* SEQUENCE */
        *pParams++ = lenSignature-2;
        *pParams++ = 0x2; /* ASN.1 INT */

        /* Copy R value */
        *pParams++ = hashLen + extraRByte;
        if (extraRByte) *pParams++ = 0x0;
        (void) DIGI_MEMCPY(pParams, DsaRstr, hashLen);
        pParams += hashLen;

        /* Copy S value */
        *pParams++ = 0x2; /* ASN.1 INT */
        *pParams++ = hashLen + extraSByte;
        if (extraSByte) *pParams++ = 0x0;
        (void) DIGI_MEMCPY(pParams, DsaSstr, hashLen);

        actualLen += lenSignature;
    }
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    else /* a public key -> the private key was not provided so use the callback  */
    {
        if (!SSL_sslSettings()->funcPtrMutualAuthCertificateVerify)
        {
            status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
            goto exit;
        }

        if (OK > (status = (MSTATUS) SSL_sslSettings()->funcPtrMutualAuthCertificateVerify(
                    SSL_findConnectionInstance(pSSLSock), pHash, hashLen,
                    pParams, lenDsaQ)))
        {
            goto exit;
        }

        actualLen += status;
    }
#endif

    actualLen += 2; /* Length of the signature */

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(actualLen));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }
    else
#endif
    {
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }

    actualLen += sizeofHandshakeHeader;
    *pLength = (ubyte2) actualLen;

exit:
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    DSA_freeKeyTemplate(pDSAKey, &dsaParameters);

    if (NULL != pR)
    {
        DIGI_FREE((void **) &pR);
    }

    if (NULL != pS)
    {
        DIGI_FREE((void **) &pS);
    }
#else
    if (pR != NULL)
    {
        VLONG_freeVlong(&pR, ppVlongQueue);
    }
    if (pS != NULL)
    {
        VLONG_freeVlong(&pS, ppVlongQueue);
    }
    if (pM != NULL)
    {
        VLONG_freeVlong(&pM, ppVlongQueue);
    }

#endif
    return status;

} /* fillCertificateVerifyDSA */
#endif

#if (!defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__))
/* if a hashOID is specified, then this is TLS 1.2 and we need to
build a DER structure that is the signature input */
static MSTATUS
SSLSOCK_fillCertificateVerifyRSA(ubyte2 signAlgo, SSLSocket* pSSLSock,
                                 AsymmetricKey key,
                                 ubyte *pBuffer, ubyte2 length,
                                 const ubyte* pHash, ubyte4 hashLen,
                                 const ubyte* hashOID, vlong **ppVlongQueue)
{
    ubyte4              lenRsaN;
    ubyte*              pSHSH;
    ubyte*              pParams;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
    /* TLS 1.2 extra memory */
    DER_ITEMPTR         pDigestInfo = 0;
    ubyte*              derBuffer = 0;
    ubyte4              derBufferLen;

    /* set the handshake part */
    pSHSH = pBuffer;
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(length - sizeofHandshakeHeader));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;

    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(length - sizeofHandshakeHeader));
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
    }

    pParams = (ubyte*)(pSHSH + sizeofHandshakeHeader);

    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        setShortValue(pParams, (ubyte2) signAlgo); pParams += 2;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(pSSLSock->hwAccelCookie)
        key.key.pRSA, (sbyte4 *) &lenRsaN, key.type);
    if (OK != status)
    {
        goto exit;
    }
#else
    lenRsaN = ((7 + VLONG_bitLength(RSA_N(key.key.pRSA))) / 8);
#endif
    /* store signature length */
    setShortValue(pParams, (ubyte2)lenRsaN);    pParams += 2;

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion == DTLS13_MINORVERSION) ||
       (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION))
    {
        ubyte hashId;
        const BulkHashAlgo *pHashAlgo = NULL;
        ubyte *pSignature = NULL;
        ubyte4 signatureLen;

        if (key.key.pRSA->privateKey)
        {
            status = getHashInfoFromOID(hashOID, &pHashAlgo, &hashId);
            if (OK != status)
            {
                goto exit;
            }

            /* The hash is not really the hash. The RSA-PSS function will perform
             * the digest of the message itself.
             */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_PKCS1_rsaPssSign(MOC_RSA(pSSLSock->hwAccelCookie)
                g_pRandomContext, key.key.pRSA, hashId, MOC_PKCS1_ALG_MGF1, hashId,
                pHash, hashLen, pHashAlgo->digestSize, &pSignature, &signatureLen);
#else
            status = PKCS1_rsassaPssSign(MOC_RSA(pSSLSock->hwAccelCookie)
                g_pRandomContext, key.key.pRSA, hashId,
                PKCS1_MGF1_FUNC, pHash, hashLen, pHashAlgo->digestSize,
                &pSignature, &signatureLen);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
            if ( (OK == status) && (signatureLen != lenRsaN) )
            {
                status = ERR_BAD_LENGTH;
            }
            if (OK != status)
            {
                goto exit;
            }

            if (OK == status)
            {
                status = DIGI_MEMCPY(pParams, pSignature, signatureLen);
            }

            DIGI_FREE((void **) &pSignature);
        }
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        else /* a public key -> the private key was not provided so use the callback  */
        {
            if (!SSL_sslSettings()->funcPtrMutualAuthCertificateVerify)
            {
                status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
                goto exit;
            }

            if (OK > (status = (MSTATUS) SSL_sslSettings()->funcPtrMutualAuthCertificateVerify(
                        SSL_findConnectionInstance(pSSLSock), pHash,hashLen,
                        pParams, lenRsaN)))
            {
                goto exit;
            }
        }
#endif
    }
    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
    {
        /* if a hashOID is specified, this is TLS 1.2 and we need to build and sign a DER structure */
        if (hashOID)
        {
            if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&derBuffer))))
                goto exit;

            if (OK > ( status = DER_AddSequence( NULL, &pDigestInfo)))
                goto exit;

            /* add the whole algorithm identifier sequence */
            if (OK > ( status = DER_StoreAlgoOID( pDigestInfo, hashOID, 1)))
                goto exit;

            /* add the digest */
            if (OK > ( status = DER_AddItem( pDigestInfo, OCTETSTRING, hashLen,
                                                pHash,  NULL)))
            {
                goto exit;
            }

            derBufferLen = SSL_BIGGER_TEMP_BUF_SIZE;
            if (OK > ( status = DER_SerializeInto( pDigestInfo, derBuffer, &derBufferLen)))
                goto exit;

            /* the DER is the thing to sign */
            pHash = derBuffer;
            hashLen = derBufferLen;
        }

        /* if this is a private key, we can do the signature ourselves */
        if (key.key.pRSA->privateKey)
        {
#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
            intBoolean validSig = FALSE;
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessageAux(MOC_RSA(pSSLSock->hwAccelCookie) key.key.pRSA,
                                            pHash, hashLen, pParams, ppVlongQueue)))
#else
            if (OK > (status = RSA_signMessage(MOC_RSA(pSSLSock->hwAccelCookie) key.key.pRSA,
                                            pHash, hashLen, pParams, ppVlongQueue)))
#endif
            {
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(pSSLSock->hwAccelCookie) key.key.pRSA,
                (ubyte *)pHash, hashLen, pParams, lenRsaN, &validSig, NULL);
#else
            status = RSA_verifyDigest(MOC_RSA(pSSLSock->hwAccelCookie) key.key.pRSA,
                (ubyte *)pHash, hashLen, pParams, lenRsaN, &validSig, NULL);
#endif
            if (OK != status)
            {
                goto exit;
            }

            if (validSig == FALSE)
            {
                status = ERR_SSL_INVALID_SIGNATURE;
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
                DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validation failed.");
#endif
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Signature validated.");
#endif
#endif /* __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__ */
        }
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        else /* a public key -> the private key was not provided so use the callback  */
        {
            if (!SSL_sslSettings()->funcPtrMutualAuthCertificateVerify)
            {
                status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
                goto exit;
            }

            if (OK > (status = (MSTATUS) SSL_sslSettings()->funcPtrMutualAuthCertificateVerify(
                        SSL_findConnectionInstance(pSSLSock), pHash,hashLen,
                        pParams, lenRsaN)))
            {
                goto exit;
            }
        }
#endif
    }
exit:

    TREE_DeleteTreeItem( (TreeItem*) pDigestInfo);
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&derBuffer));

    return status;

} /* SSLSOCK_fillCertificateVerifyRSA */

#endif /* __DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ECC__)
static MSTATUS
SSLSOCK_fillCertificateVerifyECC(ubyte2 signAlgo, SSLSocket* pSSLSock,
                         AsymmetricKey key,
                         ubyte *pBuffer, ubyte2* pLength,
                         const ubyte* pHash, ubyte4 hashLen)
{
    ubyte*              pSHSH;
    ubyte*              pParams;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
    ubyte4              actualLen;
    intBoolean          isPrivate = FALSE;

    /* set the handshake part, not the length since we don't know it yet */
    pSHSH = pBuffer;
    actualLen = (ubyte4) *pLength;
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;

    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
    }

    pParams = (ubyte*)(pSHSH + sizeofHandshakeHeader);
    actualLen -= sizeofHandshakeHeader;

    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        setShortValue(pParams, (ubyte2) signAlgo);
        pParams += 2;
        actualLen -= 2;
    }

    /* can't set the length yet */
    pParams += 2;  /* where to put the signature */
    actualLen -= 2;

    /* if this is a private key, we can do the signature ourselves */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_isKeyPrivate(key.key.pECC, &isPrivate);
#else
    status = EC_isKeyPrivate(key.key.pECC, &isPrivate);
#endif
    if (OK != status)
        goto exit;

    if (TRUE == isPrivate)
    {
        if (OK > (status = SSL_SOCK_GenerateECDSASignature(MOC_ECC(pSSLSock->hwAccelCookie) key.key.pECC,
                                            pSSLSock->rngFun, pSSLSock->rngFunArg,
                                            pHash, hashLen, pParams, &actualLen,
                                            pSSLSock->sslMinorVersion)))
        {
            goto exit;
        }
    }
    else /* a public key -> the private key was not provided so use the callback  */
    {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        if (!SSL_sslSettings()->funcPtrMutualAuthCertificateVerify)
        {
            status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
            goto exit;
        }

        /* callback API specify a fixed length, so the return value is
        used to indicate the length of the signature */
        if (OK > (status = (MSTATUS) SSL_sslSettings()->funcPtrMutualAuthCertificateVerify(
                    SSL_findConnectionInstance(pSSLSock), pHash, hashLen,
                    pParams, actualLen)))
        {
            goto exit;
        }
        actualLen = (ubyte4) status;
#endif
    }

    /* actualLen is the length of the signature -- update data */
    /* store signature length */
    pParams -= 2;
    setShortValue(pParams, (ubyte2)actualLen);
    actualLen += 2;

    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        actualLen += 2;
    }

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if (pSSLSock->isDTLS)
    {
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(actualLen));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }
    else
#endif
    {
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }

    actualLen += sizeofHandshakeHeader;
    *pLength = (ubyte2) actualLen;

exit:

    return status;

} /* SSLSOCK_fillCertificateVerifyECC */
#endif /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
/* TO DO this method is very similar to SSLSOCK_fillCertificateVerifyECC so they could be combined at some point with a flag indicating which */
static MSTATUS SSLSOCK_fillCertificateVerifyHybrid(ubyte2 signAlgo, SSLSocket* pSSLSock, AsymmetricKey key,
                                                   ubyte *pBuffer, ubyte2* pLength, const ubyte* pHash, ubyte4 hashLen)
{
    ubyte*              pSHSH;
    ubyte*              pParams;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;
    ubyte4              actualLen;
    ubyte*              pDomain = NULL;
    ubyte4              domainLen = 0;
    
    /* set the handshake part, not the length since we don't know it yet */
    pSHSH = pBuffer;
    actualLen = (ubyte4) *pLength;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
        
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
    }
    
    pParams = (ubyte*)(pSHSH + sizeofHandshakeHeader);
    actualLen -= sizeofHandshakeHeader;
    
    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        setShortValue(pParams, (ubyte2) signAlgo);
        pParams += 2;
        actualLen -= 2;
    }
    
    /* can't set the length yet */
    pParams += 2;  /* where to put the signature */
    actualLen -= 2;

    /* if this is a private key, we can do the signature ourselves */    
    if (TRUE == key.pQsCtx->isPrivate)
    {
        ubyte4 qsAlg = 0;

        if (OK > (status = CRYPTO_INTERFACE_QS_getAlg(key.pQsCtx, &qsAlg)))
            goto exit;

        if (OK > (status = CRYPTO_getAlgoOIDAlloc(key.clAlg, qsAlg, &pDomain, &domainLen)))
            goto exit;

        if (OK > (status = CRYPTO_INTERFACE_QS_compositeSign(MOC_ASYM(pSSLSock->hwAccelCookie) &key, TRUE, pSSLSock->rngFun, pSSLSock->rngFunArg, 
                                                             pDomain, domainLen, (ubyte *) pHash, hashLen, pParams, actualLen, &actualLen)))
            goto exit;
    }
    else /* a public key -> the private key was not provided so use the callback  */
    {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        if (!SSL_sslSettings()->funcPtrMutualAuthCertificateVerify)
        {
            status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
            goto exit;
        }
        
        /* callback API specify a fixed length, so the return value is
         used to indicate the length of the signature */
        if (OK > (status = (MSTATUS) SSL_sslSettings()->funcPtrMutualAuthCertificateVerify(SSL_findConnectionInstance(pSSLSock), pHash, hashLen,
                                                                                           pParams, actualLen)))
        {
            goto exit;
        }
        actualLen = (ubyte4) status;
#endif
    }
    
    /* actualLen is the length of the signature -- update data */
    /* store signature length */
    pParams -= 2;
    setShortValue(pParams, (ubyte2)actualLen);
    actualLen += 2;
    
    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        actualLen += 2;
    }
    
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(actualLen));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }
    else
#endif
    {
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }
    
    actualLen += sizeofHandshakeHeader;
    *pLength = (ubyte2) actualLen;
    
exit:
    
    if (NULL != pDomain)
    {
        (void) DIGI_MEMSET_FREE(&pDomain, domainLen);
    }

    return status;
}

static MSTATUS SSLSOCK_fillCertificateVerifyQS(ubyte2 signAlgo, SSLSocket* pSSLSock, AsymmetricKey key,
                                               ubyte *pBuffer, ubyte2* pLength, const ubyte* pHash, ubyte4 hashLen)
{
    ubyte*              pSHSH;
    ubyte*              pParams;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status;
    ubyte4              actualLen;
    
    /* set the handshake part, not the length since we don't know it yet */
    pSHSH = pBuffer;
    actualLen = (ubyte4) *pLength;
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
        ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
        
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_CLIENT_CERTIFICATE_VERIFY;
    }
    
    pParams = (ubyte*)(pSHSH + sizeofHandshakeHeader);
    actualLen -= sizeofHandshakeHeader;
    
    /* store signature/hash algo   TODO DO WE STILL DO THIS FOR PQC? */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        setShortValue(pParams, (ubyte2) signAlgo);
        pParams += 2;
        actualLen -= 2;
    }
    
    /* can't set the length yet */
    pParams += 2;  /* where to put the signature */
    actualLen -= 2;
    
    /* if this is a private key, we can do the signature ourselves */
    if (TRUE == key.pQsCtx->isPrivate)
    {
        if (OK > (status = CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(pSSLSock->hwAccelCookie) key.pQsCtx, pSSLSock->rngFun, pSSLSock->rngFunArg, 
                                                        (ubyte *) pHash, hashLen, pParams, actualLen, &actualLen)))
        {
            goto exit;
        }
    }
    else /* a public key -> the private key was not provided so use the callback  */
    {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined( __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        if (!SSL_sslSettings()->funcPtrMutualAuthCertificateVerify)
        {
            status = ERR_SSL_UNABLE_TO_SIGN_CERTIFICATE_VERIFY;
            goto exit;
        }
        
        /* callback API specify a fixed length, so the return value is
         used to indicate the length of the signature */
        if (OK > (status = (MSTATUS) SSL_sslSettings()->funcPtrMutualAuthCertificateVerify(SSL_findConnectionInstance(pSSLSock), pHash, hashLen,
                                                                                           pParams, actualLen)))
        {
            goto exit;
        }
        actualLen = (ubyte4) status;
#endif
    }
    
    /* actualLen is the length of the signature -- update data */
    /* store signature length */
    pParams -= 2;
    setShortValue(pParams, (ubyte2)actualLen);
    actualLen += 2;
    
    /* store signature/hash algo */
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        actualLen += 2;
    }
    
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader *)pSHSH), pSSLSock->nextSendSeq++, (ubyte2)(actualLen));
        setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }
    else
#endif
    {
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, (ubyte2)(actualLen));
    }
    
    actualLen += sizeofHandshakeHeader;
    *pLength = (ubyte2) actualLen;
    
exit:
    
    return status;
    
}
#endif

static MSTATUS
SSLSOCK_fillCertificateVerify(ubyte2 signAlgo, SSLSocket* pSSLSock,
                              AsymmetricKey key, ubyte *pBuffer, ubyte2* pLength,
                              vlong **ppVlongQueue)
{
    MSTATUS status;
    ubyte* pHashResult = 0;
    ubyte4 hashLen = 0;
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    ubyte4 dsaOffset = 0;
#endif
    const ubyte* hashOID = 0;
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte *pContextString = NULL;
    ubyte4 contextStringLen = 0;
#endif

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult))))
        goto exit;

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion == TLS13_MINORVERSION))
    {
        if (pSSLSock->server)
        {
            pContextString = (ubyte *) CERT_VERIFY_SERVER_CONTEXT_STRING;
            contextStringLen = CERT_VERIFY_SERVER_CONTEXT_STRING_SIZE;
        }
        else
        {
            pContextString = (ubyte *) CERT_VERIFY_CLIENT_CONTEXT_STRING;
            contextStringLen = CERT_VERIFY_CLIENT_CONTEXT_STRING_SIZE;
        }

        if (OK > (status = calculateTLS13CertificateVerifyHash(signAlgo, pSSLSock,
                        pHashResult, &hashLen,
                        &hashOID,
                        pContextString, contextStringLen, &key)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        if ((pSSLSock->isDTLS && pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION) ||
                (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            if (OK > (status = calculateTLS12CertificateVerifyHash(signAlgo, pSSLSock,
                            pHashResult, &hashLen,
                            &hashOID)))
            {
                goto exit;
            }
        }
        else
        {
            hashLen = MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE;
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
            dsaOffset = MD5_DIGESTSIZE; /* offset in pHashResult to use for ECDSA and DSA keys */
#endif

            if (OK > (status = calculateSSLTLSHashes(pSSLSock, 1, pHashResult,
                            (enum hashTypes) pSSLSock->sslMinorVersion)))
            {
                goto exit;
            }
        }
    }

    switch (key.type & 0xFF)
    {
#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
    case akt_dsa:
        if (TRUE == SSL_sslSettings()->allowDSASigAlg)
        {
            status = SSLSOCK_fillCertificateVerifyDSA(signAlgo, pSSLSock, key, pBuffer, pLength,
                                              pHashResult + dsaOffset, hashLen - dsaOffset, ppVlongQueue);
        }
        else
        {
            status = ERR_SSL_INVALID_KEY_TYPE;
        }
        break;
#endif
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
    case akt_rsa:
        status = SSLSOCK_fillCertificateVerifyRSA(signAlgo, pSSLSock, key,
                                            pBuffer, *pLength, pHashResult, hashLen, hashOID, ppVlongQueue);
        break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    case akt_ecc_ed:
    case akt_ecc:
        status = SSLSOCK_fillCertificateVerifyECC(signAlgo, pSSLSock, key, pBuffer, pLength,
                                            pHashResult + dsaOffset, hashLen - dsaOffset);
        break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case akt_hybrid:
        status = SSLSOCK_fillCertificateVerifyHybrid(signAlgo, pSSLSock, key, pBuffer, pLength,
                                                     pHashResult + dsaOffset, hashLen - dsaOffset);
        break;

    case akt_qs:
        status = SSLSOCK_fillCertificateVerifyQS(signAlgo, pSSLSock, key, pBuffer, pLength,
                                                 pHashResult + dsaOffset, hashLen - dsaOffset);
        break;
#endif

    default:
        status = ERR_SSL_INVALID_KEY_TYPE;
        goto exit;
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLSOCK_fillCertificateVerify() returns status = ", status);
#endif

    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pHashResult));

    return status;

} /* SSLSOCK_fillCertificateVerify */

/*------------------------------------------------------------------*/


#if defined (__ENABLE_DIGICERT_ECC__)

static MSTATUS
SSL_SOCK_GenerateECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey* pECCKey,
                                  RNGFun rngFun, void* rngArg,
                                  const ubyte* hash, ubyte4 hashLen,
                                  ubyte* pSignature, ubyte4* pSignatureLen,
                                  ubyte4 sslMinorVersion)
{
    DER_ITEMPTR pTempSeq = 0;
    ubyte* pSignatureBuffer = NULL;
    ubyte* pSig = NULL;
    ubyte4 sigLength = 0;
    ubyte4 elementLen;
    ubyte* pRBuffer;
    ubyte* pSBuffer;
    MSTATUS status;
    ubyte hashAlgo;
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte4 curveId = 0;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
        pECCKey, &elementLen);
#else
    status = EC_getElementByteStringLen(
        pECCKey, &elementLen);
#endif
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pSig, 2 * elementLen);
    if (OK != status)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    if (TLS13_MINORVERSION == sslMinorVersion
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
     || DTLS13_MINORVERSION == sslMinorVersion
#endif
       )
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
#else
        status = EC_getCurveIdFromKey(pECCKey, &curveId);
#endif
        if (OK != status)
        {
            goto exit;
        }

        switch(curveId)
        {
            case cid_EC_P192:
                hashAlgo = ht_sha1;
                break;
            case cid_EC_P256:
                hashAlgo = ht_sha256;
                break;
            case cid_EC_P224:
                hashAlgo = ht_sha224;
                break;
            case cid_EC_P384:
                hashAlgo = ht_sha384;
                break;
            case cid_EC_P521:
                hashAlgo = ht_sha512;
                break;
            case cid_EC_Ed25519:
            case cid_EC_Ed448:
                hashAlgo = ht_none;
                break;
            default:
                status = ERR_SSL_UNSUPPORTED_CURVE;
                goto exit;
        }

        if ((cid_EC_Ed25519 == curveId) || (cid_EC_Ed448 == curveId))
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDSA_signMessageExt(MOC_ECC(hwAccelCtx)
                pECCKey, rngFun, rngArg, hashAlgo, (ubyte *) hash, hashLen, pSig, elementLen * 2,
                &sigLength, NULL);
#else
            status = ECDSA_signMessage(MOC_ECC(hwAccelCtx)
                pECCKey, rngFun, rngArg, hashAlgo, (ubyte *) hash, hashLen, pSig, elementLen * 2,
                &sigLength, NULL);
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDSA_signDigestAux(MOC_ECC(hwAccelCtx)
                pECCKey, rngFun, rngArg, (ubyte *) hash, hashLen, pSig, elementLen * 2,
                &sigLength);
#else
            status = ECDSA_signDigest(MOC_ECC(hwAccelCtx)
                pECCKey, rngFun, rngArg, (ubyte *) hash, hashLen, pSig, elementLen * 2,
                &sigLength);
#endif
        }
        if (OK != status)
        {
            goto exit;
        }
    }
    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDSA_signDigestAux(MOC_ECC(hwAccelCtx)
            pECCKey, rngFun, rngArg, (ubyte *) hash, hashLen, pSig, elementLen * 2,
            &sigLength);
#else
        status = ECDSA_signDigest(MOC_ECC(hwAccelCtx)
            pECCKey, rngFun, rngArg, (ubyte *) hash, hashLen, pSig, elementLen * 2,
            &sigLength);
#endif
        if (OK != status)
        {
            goto exit;
        }
    }

    if (sigLength > elementLen * 2)
    {
        status = ERR_SSL_INVALID_SIGNATURE; goto exit;
    }

#ifdef __ENABLE_DIGICERT_TLS13__
    if ((cid_EC_Ed25519 == curveId) || (cid_EC_Ed448 == curveId))
    {
        *pSignatureLen = elementLen * 2;
        status = DIGI_MEMCPY(pSignature, pSig, *pSignatureLen);
        /* if we have an ED curve, we can skip rest of function */
        goto exit;
    }
#endif

    /* allocate 2 extra bytes for the possible zero padding */
    status = DIGI_MALLOC((void **) &pSignatureBuffer, 2 + 2 * elementLen);
    if (OK != status)
    {
        goto exit;
    }

    pRBuffer = pSignatureBuffer;
    *pRBuffer = 0x00; /* leading 0 */
    pSBuffer = pSignatureBuffer + 1 + elementLen;
    *pSBuffer = 0x00; /* leading 0 */

    status = DIGI_MEMCPY(pRBuffer + 1, pSig, elementLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pSBuffer + 1, pSig + elementLen, elementLen);
    if (OK != status)
    {
        goto exit;
    }

    /* create a sequence with the two integer -> signature */
    if (OK > ( status = DER_AddSequence( NULL, &pTempSeq)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, elementLen + 1, pRBuffer, NULL)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, elementLen + 1, pSBuffer, NULL)))
        goto exit;

    /* serialize the sequence */
    if (OK > ( status = DER_SerializeInto( pTempSeq, pSignature, pSignatureLen)))
        goto exit;

exit:

    if (pTempSeq)
    {
        TREE_DeleteTreeItem( (TreeItem*) pTempSeq);
    }

    DIGI_FREE((void **) &pSignatureBuffer);

    if (NULL != pSig)
    {
        DIGI_FREE((void **) &pSig);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */
#endif /* ((defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) || (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_SSL_SERVER__))) */

/*------------------------------------------------------------------*/

static MSTATUS
recvAll(SSLSocket* pSSLSock, sbyte* pBuffer, sbyte4 toReceive,
        const enum sslAsyncStates curAsyncState, const enum sslAsyncStates nextAsyncState,
        ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    intBoolean  boolComplete = FALSE;
    intBoolean  moreDataToRead = FALSE;
    ubyte4      numBytesRead;
    MSTATUS     status = OK;

    if ((NULL == pSSLSock) || (NULL == pBuffer) || (NULL == ppPacketPayload) ||
        (NULL == *ppPacketPayload) || (NULL == pPacketLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == toReceive)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if ((curAsyncState != SSL_RX_RECORD_STATE(pSSLSock)) || (FALSE == SSL_RX_RECORD_STATE_INIT(pSSLSock)))
    {
        /* new state */
        SSL_RX_RECORD_STATE(pSSLSock) = curAsyncState;
        SSL_RX_RECORD_BUFFER(pSSLSock) = (ubyte *)pBuffer;
        SSL_RX_RECORD_BYTES_READ(pSSLSock) = 0;
        SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) = toReceive;
        SSL_RX_RECORD_STATE_INIT(pSSLSock) = TRUE;
    }

    if (0 == (SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) - SSL_RX_RECORD_BYTES_READ(pSSLSock)))
    {
        status = ERR_MISSING_STATE_CHANGE;
        goto exit;
    }

    if (SSL_RX_RECORD_BYTES_READ(pSSLSock) > SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock))
    {
        /*!-!-! should never happen */
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

readData:
    if ((SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) - SSL_RX_RECORD_BYTES_READ(pSSLSock)) <= *pPacketLength)
    {
        sbyte4 excessData = 0;

        /* enough bytes available for a complete message */
        numBytesRead = (SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) - SSL_RX_RECORD_BYTES_READ(pSSLSock));
        boolComplete = TRUE;

        /* If are reading data (not header) && there are 5 bytes more than the bytes required,
         * implies the handshake packet length is greater than 16384.
         */
        excessData = *pPacketLength - (SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) - SSL_RX_RECORD_BYTES_READ(pSSLSock));

        /* recvAll called to read the header is with SSL_ASYNC_RECEIVE_RECORD_1;
         * this check fails for recvAll of header */
        if ((kSslReceiveUntil > SSL_HANDSHAKE_STATE(pSSLSock)) &&
            (curAsyncState == SSL_ASYNC_RECEIVE_RECORD_2) &&
            (SSL_RECORDSIZE == pSSLSock->recordSize))
        {
            if (excessData >= 5)
            {
                moreDataToRead = TRUE;
            }
            else
            {
                /* If the TCP packet for excess bytes has not been read */
                boolComplete = FALSE;
            }
        }
    }
    else
        numBytesRead = *pPacketLength;

    if (0 != numBytesRead)
    {
        DIGI_MEMCPY(SSL_RX_RECORD_BYTES_READ(pSSLSock) + SSL_RX_RECORD_BUFFER(pSSLSock), *ppPacketPayload, numBytesRead);

        SSL_RX_RECORD_BYTES_READ(pSSLSock) += numBytesRead;

        /* digest bytes from packet */
        *ppPacketPayload += numBytesRead;
        *pPacketLength   -= numBytesRead;
    }

    if (TRUE == boolComplete)
    {
        if (moreDataToRead == TRUE)
        {
            /* We enter this state only for the packet data recv portion,
             * and pSSLSock->pReceiveBuffer is passed to recvAll;
             * Hence handleFragmentedRecord function manipulates the
             * pSSLSock->pRecieveBuffer when required
             */
            if (OK == (status = handleFragmentedRecord(pSSLSock, ppPacketPayload, pPacketLength)))
            {
                moreDataToRead = FALSE;
                boolComplete = FALSE;
                goto readData;
            }
        }

        SSL_RX_RECORD_STATE_CHANGE(pSSLSock, nextAsyncState)
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"recvAll() returns status = ", status);
#endif

    return status;

} /* recvAll */


/*------------------------------------------------------------------*/

/*******************************************************************************
* addToHandshakeHash
* This routine is used to had all handshakes records to the hashes. These
* hashes are used in the Finished handshake records.
*/
static void
addToHandshakeHash(SSLSocket* pSSLSock, ubyte* data, sbyte4 size)
{
    MSTATUS status = OK;
    SSLHandshakeHeader* pSHSH = (SSLHandshakeHeader*) data;

#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Handshake length = ", size);

    RTOS_sleepMS(200);

    if (pSSLSock->server)
    {
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (SERVER)");
    }
    else
    {
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (CLIENT)");
    }

    switch ( pSHSH->handshakeType)
    {
    case SSL_CLIENT_HELLO:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Client Hello");
        break;

    case SSL_SERVER_HELLO:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Server hello");
        break;

    case SSL_SERVER_HELLO_VERIFY_REQUEST:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Server HelloVerifyRequest");
        break;

    case SSL_CERTIFICATE:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Certificate");
        break;

    case SSL_CERTIFICATE_REQUEST:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Certificate Request");
        break;

    case SSL_SERVER_HELLO_DONE:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Server Hello done");
        break;

    case SSL_CLIENT_CERTIFICATE_VERIFY:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Client Certificate Verify");
        break;

    case SSL_SERVER_KEY_EXCHANGE:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Server Key Exchange");
        break;

    case SSL_CLIENT_KEY_EXCHANGE:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Client Key Exchange");
        break;

    case SSL_FINISHED:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Finished");
        break;

    case SSL_CERTIFICATE_STATUS:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Certificate Status");
        break;

    case SSL_NEW_SESSION_TICKET:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" New Session Ticket");
        break;

#ifdef __ENABLE_DIGICERT_TLS13__
    case SSL_ENCRYPTED_EXTENSIONS:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Encrypted Extensions");
        break;

    /* Key Update is not added to the hash.
     * Process and send KeyUpdate functions print the message
     */
    case SSL_KEY_UPDATE:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Key Update");
        break;

    case SSL_CLIENT_END_OF_EARLY_DATA:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" End Of Early Data");
        break;

    case SSL_MESSAGE_HASH:
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Message Hash");
        break;
#endif
    }
    PrintBytes( data, size);
#endif
    /* Fix some compiler warnings by referencing these vars */
    (void)gSupportedSignatureAlgorithms;
    (void)gSupportedHashAlgorithms;

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        if (OK > (status = CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pMd5Ctx, data, size)))
#else
        if (OK > (status = MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pMd5Ctx, data, size)))
#endif
        {
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        if (OK > (status = CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pShaCtx, data, size)))
#else
        if (OK > (status = SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pShaCtx, data, size)))
#endif
        {
            goto exit;
        }
    }
    else
    {
        const BulkHashAlgo *pHashAlgo = NULL;
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13__))
        intBoolean updateRunningHash = FALSE;
#endif

        if (!pSSLSock->pHandshakeCipherSuite)
            return;

        /* TLS1.2 changes */
        /* the hash is used for finished verify. the hash algo is PRFHashingAlgo */
        pHashAlgo = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo;

#ifndef __DISABLE_DIGICERT_SHA256__
        if (!pHashAlgo)
        {
            pHashAlgo = &SHA256Suite;
        }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) && defined(__ENABLE_DIGICERT_TLS13__)
        if ( /* (SSL_CLIENT_HELLO == pSHSH->handshakeType || SSL_SERVER_HELLO == pSHSH->handshakeType) &&  */ SSL_MESSAGE_HASH != pSHSH->handshakeType &&
             pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            ubyte *pPtr = data;
            ubyte4 tempSize;

            if (size < 12)
            {
                status = ERR_SSL_INVALID_MSG_SIZE;
                goto exit;
            }

            /* first 4 */
            if (OK > (status = pHashAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx, pPtr, 4)))
                goto exit;

            pPtr += 12; /* skip 8 */
            tempSize = size - 12;

            if (OK > (status = pHashAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx, pPtr, tempSize)))
                goto exit;

        }
        else
#endif
        {
            if (OK > (status = pHashAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx, data, size)))
                goto exit;
        }

#if defined(__ENABLE_DIGICERT_TLS13__)
        if ( (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion && pSSLSock->helloRetryRequest) ||
             (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)) 
        {
            updateRunningHash = TRUE;
        }
#endif
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
        if ( (SSL_NO_MUTUAL_AUTH_BIT != (pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo->flags & SSL_NO_MUTUAL_AUTH_BIT)) &&
             (SSL_FLAG_NO_MUTUAL_AUTH_REPLY != (pSSLSock->runtimeFlags & SSL_FLAG_NO_MUTUAL_AUTH_REPLY)) &&
             (pSHSH->handshakeType != SSL_CLIENT_CERTIFICATE_VERIFY) && (pSHSH->handshakeType != SSL_FINISHED) &&
             (pSHSH->handshakeType != SSL_NEW_SESSION_TICKET) &&
             ((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) ||
              (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)))
        {
            updateRunningHash = TRUE;
        }
#endif

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13__))
        /* change in TLS12 calculate for all supported hash algos */
        if (TRUE == updateRunningHash)
        {
            /* allocate memory for BulkCtx if not already done */
                ubyte4 i;
                /* initialize hashCtx */
                if (!pSSLSock->pHashCtxList)
                {
                    pSSLSock->pHashCtxList = (void**) MALLOC(sizeof(BulkCtx)*NUM_SSL_SUPPORTED_HASH_ALGORITHMS_EXT);

                    if (NULL == pSSLSock->pHashCtxList)
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }

                    DIGI_MEMSET((ubyte*)pSSLSock->pHashCtxList, 0x00, sizeof(BulkCtx)*NUM_SSL_SUPPORTED_HASH_ALGORITHMS_EXT);
                }

                for (i = 0; i < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; i++)
                {
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
                    if (isHashAlgoSupported(gSupportedHashAlgorithms[i].hashType))
#endif
                    {
                        if (!pSSLSock->pHashCtxList[i])
                        {
                            if (OK > (status = gSupportedHashAlgorithms[i].algo->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &pSSLSock->pHashCtxList[i])))
                                goto exit;
                            if (OK > (status = gSupportedHashAlgorithms[i].algo->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtxList[i])))
                                goto exit;
                        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) && defined(__ENABLE_DIGICERT_TLS13__)
                        if (SSL_MESSAGE_HASH != pSHSH->handshakeType && pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                        {
                            /* first 4 bytes, handshake type and length */
                            if (OK > (status = gSupportedHashAlgorithms[i].algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtxList[i], data, 4)))
                                goto exit;

                            /* Skip the DTLS specific message sequence, fragment offset, and fragment length,
                            so skip 8 bytes after the 4 processed so far */
                            if (OK > (status = gSupportedHashAlgorithms[i].algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtxList[i], data + 12, size - 12)))
                                goto exit;
                        }
                        else
#endif
                        {
                            if (OK > (status = gSupportedHashAlgorithms[i].algo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtxList[i], data, size)))
                                goto exit;
                        }
                    }
                }
        }
#endif /* #ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ || __ENABLE_DIGICERT_TLS13__ */
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"addToHandshakeHash return error: ", status);
}


/*------------------------------------------------------------------*/

/*******************************************************************************
* computePadLength
* This routine compute the minimum pad length in case of block encryption
*/
static sbyte4
computePadLength(sbyte4 msgSize, sbyte4 blockSize)
{
    if (blockSize)
    {
        sbyte4 retVal = blockSize - (msgSize % blockSize);
        return (0 == retVal) ? blockSize : retVal;
    }
    return 0;
}


/*------------------------------------------------------------------*/

/*******************************************************************************
* calculateTLSFinishedVerify
* this function is called only for the TLS implementation
*/
static MSTATUS
calculateTLSFinishedVerify(SSLSocket *pSSLSock, sbyte4 client, ubyte result[TLS_VERIFYDATASIZE])
{
    /* pSSLSock's pMd5Ctx and pShaCtx contain hash of all the handshake
        messages (see addToHandshakeHash)*/
    /* There are 2 finished messages one sent by server, the other by the client
       one is to be sent, the other is received and we want to verify it */
    ubyte*      pBuffer = NULL;     /* [ TLS_FINISHEDLABELSIZE + MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE] */
    MSTATUS     status;
    ubyte4      hashSize = 0;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)&(pBuffer))))
        goto exit;

    /* put the correct label in the beginning of buffer */
    DIGI_MEMCPY(pBuffer, (ubyte *)(client ? "client finished" : "server finished"), TLS_FINISHEDLABELSIZE);

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        MD5_CTXHS*  pMd5Copy = NULL;
        shaDescrHS* pShaCopy = NULL;
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Copy))))
            goto exit1;

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaCopy))))
            goto exit1;

        /* copy the contexts */
#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_cloneHashCtx ( MOC_HASH(pSSLSock->hwAccelCookie)
            pSSLSock->pMd5Ctx, pMd5Copy, pSSLSock->md5Pool.poolObjectSize)))
        {
            goto exit1;
        }

        if (OK > (status = CRYPTO_INTERFACE_cloneHashCtx ( MOC_HASH(pSSLSock->hwAccelCookie)
            pSSLSock->pShaCtx, pShaCopy, pSSLSock->shaPool.poolObjectSize)))
        {
            goto exit1;
        }
#else
        DIGI_MEMCPY(pMd5Copy, pSSLSock->pMd5Ctx, sizeof(MD5_CTXHS));
        DIGI_MEMCPY(pShaCopy, pSSLSock->pShaCtx, sizeof(shaDescrHS));
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#else
        if (OK > (status = MD5CopyCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pSSLSock->pMd5Ctx)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit1;
        }

        if (OK > (status = SHA1_CopyCtxHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pSSLSock->pShaCtx)))
        {
            MD5FreeCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy);
            status = ERR_MEM_ALLOC_FAIL;
            goto exit1;
        }
#endif

        /* save results in the buffer */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pBuffer + TLS_FINISHEDLABELSIZE);
        CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pBuffer + TLS_FINISHEDLABELSIZE + MD5_DIGESTSIZE);
#else
        MD5final_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pBuffer + TLS_FINISHEDLABELSIZE);
        SHA1_finalDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pBuffer + TLS_FINISHEDLABELSIZE + MD5_DIGESTSIZE);
#endif

        hashSize = MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE;
exit1:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_freeCloneHashCtx(pMd5Copy);
        CRYPTO_INTERFACE_freeCloneHashCtx(pShaCopy);
#endif
        MEM_POOL_putPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Copy));
        MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaCopy));

    }
    else
    {
        BulkCtx pHashCtxCopy = NULL;

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->hashPool, (void **)(&pHashCtxCopy))))
            goto exit2;

        /* TLS1.2 and up */
        /* copy the hashcontext because it needs to be used again for verifying the client's finished message */
#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_cloneHashCtx ( MOC_HASH(pSSLSock->hwAccelCookie)
            pSSLSock->pHashCtx, pHashCtxCopy, pSSLSock->hashPool.poolObjectSize);
        if (OK != status)
            goto exit2;
#else
        DIGI_MEMCPY(pHashCtxCopy, pSSLSock->pHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif
#else
        /* new API for TLS 1.2 */
        CopyCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtxCopy,
                          pSSLSock->pHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif /* ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__ */

        if (pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo)
        {
            pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtxCopy, pBuffer + TLS_FINISHEDLABELSIZE);
            hashSize = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize;
        }
#ifndef __DISABLE_DIGICERT_SHA256__
        else
        {
            SHA256Suite.finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtxCopy, pBuffer + TLS_FINISHEDLABELSIZE);
            hashSize = SHA256Suite.digestSize;
        }
#endif

exit2:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_freeCloneHashCtx(pHashCtxCopy);
#endif
        MEM_POOL_putPoolObject(&pSSLSock->hashPool, (void **)(&pHashCtxCopy));
    }

    {
	int i;
	DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"Master-Key");
	for (i=0;i<48;++i)
	    DEBUG_HEXBYTE(DEBUG_SSL_TRANSPORT, pSSLSock->pSecretAndRand[i]);
	DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte *)"");
    }
    /* call prf with master secret */
    status = PRF(pSSLSock, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE,
        pBuffer, TLS_FINISHEDLABELSIZE + hashSize,
        result, TLS_VERIFYDATASIZE);

    if (client)
    {
        DIGI_MEMCPY(pSSLSock->client_verify_data, result, TLS_VERIFYDATASIZE);
        pSSLSock->client_verify_data_len = TLS_VERIFYDATASIZE;
    }
    else
    {
        DIGI_MEMCPY(pSSLSock->server_verify_data, result, TLS_VERIFYDATASIZE);
        pSSLSock->server_verify_data_len = TLS_VERIFYDATASIZE;
    }

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pBuffer));

    return status;
}


/*--------------------------------------------------------------------------------*/

#if ( defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || MIN_SSL_MINORVERSION <= SSL3_MINORVERSION)

/*******************************************************************************
* calculateFinishedHashes
* see fig. 4-28 of SSL and TLS Essentials, page 91
* This function is used for calculating
* 1. SSL 3.0 FinishedVerify;
* and 2. CertificateVerify for versions prior to TLS1.2 (or DTLS1.2)
*/
static MSTATUS
calculateSSLTLSHashes(SSLSocket *pSSLSock, sbyte4 client,
                      ubyte* result,
                      enum hashTypes hashType)
{
    MSTATUS     status = OK;

    /* pSSLSock's pMd5Ctx and pShaCtx contain hash of all the handshake
        messages (see addToHandshakeHash)*/
    /* There are 2 finished messages one sent by server, the other by the client
       one is to be sent, the other is received and we want to verify it */
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    ubyte* senderRole = (ubyte*) ((client) ? "CLNT" : "SRVR");
#endif
#if ((MIN_SSL_MINORVERSION > SSL3_MINORVERSION) && (!defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__) || defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    MOC_UNUSED(client);
    MOC_UNUSED(hashType);
#endif

    MD5_CTXHS*  pMd5Copy = NULL;
    shaDescrHS* pShaCopy = NULL;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Copy))))
        goto exit1;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pShaCopy))))
        goto exit1;

#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_cloneHashCtx ( MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pMd5Ctx, pMd5Copy, pSSLSock->md5Pool.poolObjectSize)))
    {
        goto exit1;
    }

    if (OK > (status = CRYPTO_INTERFACE_cloneHashCtx ( MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pShaCtx, pShaCopy, pSSLSock->shaPool.poolObjectSize)))
    {
        goto exit1;
    }
#else /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    DIGI_MEMCPY(pMd5Copy, pSSLSock->pMd5Ctx, sizeof(MD5_CTXHS));
    DIGI_MEMCPY(pShaCopy, pSSLSock->pShaCtx, sizeof(shaDescrHS));
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#else
    if ( MD5CopyCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pSSLSock->pMd5Ctx) != OK)
    {
        goto exit1;
    }
    if (SHA1_CopyCtxHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pSSLSock->pShaCtx) != OK)
    {
        MD5FreeCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy);
        goto exit1;
    }
#endif

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    switch (hashType)
    {
        case hashTypeSSLv3Finished:

            /* add sender Role*/
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, senderRole, 4);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, senderRole, 4);
#else
            MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, senderRole, 4);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, senderRole, 4);
#endif
            /* flow-through */

        case hashTypeSSLv3CertificateVerify:
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            /* add master secret */
            CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

            /* add first padding (0x36) */
            CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, gHashPad36, SSL_MD5_PADDINGSIZE);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, gHashPad36, SSL_SHA1_PADDINGSIZE);

            /* save results in the buffer provided as argument */
            CRYPTO_INTERFACE_MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result);
            CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE);

            /* initialize the hashes */
            CRYPTO_INTERFACE_MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy);
            CRYPTO_INTERFACE_SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy);

            /* add master secret */
            CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

            /* add second padding  (0x5C) */
            CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, gHashPad5C, SSL_MD5_PADDINGSIZE);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, gHashPad5C, SSL_SHA1_PADDINGSIZE);

            /* add first hash */
            CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result, MD5_DIGESTSIZE);
            CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE, SHA_HASH_RESULT_SIZE);
            /* flow-through */
#else
            /* add master secret */
            MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

            /* add first padding (0x36) */
            MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, gHashPad36, SSL_MD5_PADDINGSIZE);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, gHashPad36, SSL_SHA1_PADDINGSIZE);

            /* save results in the buffer provided as argument */
            MD5final_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result);
            SHA1_finalDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE);

            /* initialize the hashes */
#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
            MD5init_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy);
            SHA1_initDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy);
#else
            if (OK > MD5init_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy))
                goto exit1;

            if (OK > SHA1_initDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy))
            {
                MD5FreeCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy);
                goto exit1;
            }
#endif

            /* add master secret */
            MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

            /* add second padding  (0x5C) */
            MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, gHashPad5C, SSL_MD5_PADDINGSIZE);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, gHashPad5C, SSL_SHA1_PADDINGSIZE);

            /* add first hash */
            MD5update_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result, MD5_DIGESTSIZE);
            SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE, SHA_HASH_RESULT_SIZE);
            /* flow-through */
#endif

        default:
            /* save results in the buffer provided as argument */
            /* for TLS CertificateVerify, the hash is only calculated on the handshake messages */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            CRYPTO_INTERFACE_MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result);
            CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE);
#else
            MD5final_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result);
            SHA1_finalDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE);
#endif
    }

#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if (hashTypeSSLv3Finished == hashType)
    {
        if (client)
            DIGI_MEMCPY(pSSLSock->client_verify_data, result, SSL_VERIFY_DATA);
        else
            DIGI_MEMCPY(pSSLSock->server_verify_data, result, SSL_VERIFY_DATA);
    }
#endif

#else  /* MIN_SSL_MINORVERSION <= SSL3_MINORVERSION */

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    CRYPTO_INTERFACE_MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result);
    CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE);
#else
    MD5final_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Copy, result);
    SHA1_finalDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pShaCopy, result + MD5_DIGESTSIZE);
#endif

#endif

exit1:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_freeCloneHashCtx(pMd5Copy);
    CRYPTO_INTERFACE_freeCloneHashCtx(pShaCopy);
#endif
    MEM_POOL_putPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Copy));
    MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pShaCopy));

    return status;
}

#endif /* defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || MIN_SSL_MINORVERSION <= SSL3_MINORVERSION */

/*--------------------------------------------------------------------------------*/

/* this is the pseudo random output function for TLS
    output is of length resultLen and is stored in result
    (which should be at least resultLen bytes long!)
*/

static void
P_hash(SSLSocket *pSSLSock, const ubyte* secret, sbyte4 secretLen,
       const ubyte* seed, sbyte4 seedLen,
       ubyte* result, sbyte4 resultLen, const BulkHashAlgo *pBHAlgo)
{
    ubyte*  pA = NULL;
    ubyte*  pB = NULL;
    sbyte4  produced;
    BulkCtx context = NULL;

    if (OK > MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)&(pA)))
        goto exit;

    if (OK > MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)&(pB)))
        goto exit;


    if (OK > pBHAlgo->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &context))
	{
		goto exit;
	}

    /* A(0) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    CRYPTO_INTERFACE_HmacQuickerInline(MOC_HASH(pSSLSock->hwAccelCookie) secret, secretLen, seed, seedLen, pA, pBHAlgo,context);
#else
    HmacQuickerInline(MOC_HASH(pSSLSock->hwAccelCookie) secret, secretLen, seed, seedLen, pA, pBHAlgo,context);
#endif
    for (produced = 0; produced < resultLen; produced += pBHAlgo->digestSize)
    {
        ubyte4 numToCopy;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        CRYPTO_INTERFACE_HmacQuickerInlineEx(MOC_HASH(pSSLSock->hwAccelCookie) secret, secretLen, pA, pBHAlgo->digestSize, seed, seedLen, pB, pBHAlgo,context);
#else
        HmacQuickerInlineEx(MOC_HASH(pSSLSock->hwAccelCookie) secret, secretLen, pA, pBHAlgo->digestSize, seed, seedLen, pB, pBHAlgo,context);
#endif
        /* put in result buffer */
        numToCopy =  resultLen - produced;
        if ( numToCopy > pBHAlgo->digestSize)
        {
            numToCopy = pBHAlgo->digestSize;
        }
        DIGI_MEMCPY( result + produced, pB, numToCopy);

        /* A(i) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        CRYPTO_INTERFACE_HmacQuickerInline(MOC_HASH(pSSLSock->hwAccelCookie) secret, secretLen, pA, pBHAlgo->digestSize, pA, pBHAlgo,context);
#else
        HmacQuickerInline(MOC_HASH(pSSLSock->hwAccelCookie) secret, secretLen, pA, pBHAlgo->digestSize, pA, pBHAlgo,context);
#endif
    }

exit:
	if ( context != NULL )
	{
		pBHAlgo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &context);
	}

    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pB));
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pA));
}

/*--------------------------------------------------------------------------------*/

static MSTATUS
PRF(SSLSocket *pSSLSock, const ubyte* secret, sbyte4 secretLen,
    const ubyte* labelSeed, sbyte4 labelSeedLen,
    ubyte* result, sbyte4 resultLen)
{
    MSTATUS status = OK;

    if ((secret == NULL) || (secretLen < 0))
    {
        status = ERR_NULL_POINTER;
        goto exit1;
    }

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        ubyte*  temp = NULL;   /* temp buffer allocated locally */
        const ubyte*  s2;            /* half secrets */
        sbyte4     i;
        sbyte4     halfSecretLen;  /* length of half secrets */

        /* split the secret in two */
        if ( secretLen & 1) /* odd */
        {
            halfSecretLen = (secretLen + 1) / 2;
        }
        else
        {
            halfSecretLen = secretLen / 2;
        }

        /* start of halfsecret */
        s2 = secret + secretLen - halfSecretLen;

        /* compute both XOR inputs */
        if (NULL == (temp = (ubyte*) MALLOC(resultLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        P_hash(pSSLSock, secret, halfSecretLen, labelSeed, labelSeedLen, result, resultLen, &MD5Suite);
        P_hash(pSSLSock, s2, halfSecretLen, labelSeed, labelSeedLen, temp, resultLen, &SHA1Suite);

        for ( i=0; i < resultLen; ++i)
        {
            result[i] ^= temp[i];
        }

exit:
        if (NULL != temp)
            FREE(temp);
    }
    else
    {
        /* use SHA256 for MD5 and SHA1 ciphers; use cipher specified for new ciphers */
        /* tiny sslcli build disables SHA256 by default, what to do?  not supporting tls1.2? */
        const CipherSuiteInfo *pCS = pSSLSock->pHandshakeCipherSuite;
        if (!pCS->pPRFHashAlgo)
        {
#if defined(__DISABLE_DIGICERT_SHA256__)
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
#else
            P_hash(pSSLSock, secret, secretLen, labelSeed, labelSeedLen, result, resultLen, &SHA256Suite);
#endif
        }
        else
        {
            P_hash(pSSLSock, secret, secretLen, labelSeed, labelSeedLen, result, resultLen, pCS->pPRFHashAlgo);
        }
    }

exit1:
    return status;
}


/*--------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_FAST__)
static MSTATUS
T_PRF(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte* secret, sbyte4 secretLen,
      ubyte* labelSeed, sbyte4 labelSeedLen,
      ubyte* result, sbyte4 resultLen)
{
    ubyte*  texts[3];               /* argument to HMAC_SHA1Ex */
    sbyte4  textLens[3];            /* argument to HMAC_SHA1Ex */
    ubyte   suffix[3];              /* output length + counter */
    sbyte4  numTexts;
    MSTATUS status;

    /* initialize variables for first round */
    suffix[0] = (ubyte) (resultLen >> 8);
    suffix[1] = (ubyte) (resultLen);
    suffix[2] = 1;

    texts[0]= labelSeed;
    textLens[0] = labelSeedLen;
    texts[1] = texts[2] = suffix;
    textLens[1] = textLens[2] = 3;
    numTexts = 2;

    while ( resultLen > SHA1_RESULT_SIZE)
    {
        if ( OK > (status = HMAC_SHA1Ex(MOC_HASH(hwAccelCtx) secret, secretLen,
                                            (const ubyte**)texts, textLens,
                                            numTexts, result)))
        {
            goto exit;
        }

        /* prepare next round */
        texts[0] = result;
        textLens[0] = SHA1_RESULT_SIZE;
        texts[1] = labelSeed;
        textLens[1] = labelSeedLen;
        numTexts = 3; /* for all subsequent rounds */

        /* increment counters and pointers */
        ++suffix[2];
        resultLen -= SHA1_RESULT_SIZE;
        result += SHA1_RESULT_SIZE;
    }

    if ( resultLen > 0)
    {
        ubyte   temp[SHA1_RESULT_SIZE]; /* last result */
        if ( OK > (status = HMAC_SHA1Ex(MOC_HASH(hwAccelCtx) secret, secretLen,
                                            (const ubyte**)texts, textLens,
                                            numTexts, temp)))
        {
            goto exit;
        }

        DIGI_MEMCPY( result, temp, resultLen);
    }

    status = OK;

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_EAP_FAST__ */


/*--------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_FAST__)
static MSTATUS
SSL_SOCK_generateEAPFASTMasterSecret(SSLSocket *pSSLSock)
{
    /*    Master_secret = T-PRF(PAC-Key,
                     "PAC to master secret label hash",
                          server_random + Client_random,
                          48)
    */
    /* use a stack buffer so that the pSSLSock pSecretAndRand is not
    perturbed: we would need to switch client and server randoms twice
    otherwise */
    ubyte   labelSeed[EAPFAST_PAC_MASTERSECRET_HASH + 2 * SSL_RANDOMSIZE];

    DIGI_MEMCPY( labelSeed, (ubyte *)"PAC to master secret label hash",
                EAPFAST_PAC_MASTERSECRET_HASH);
    DIGI_MEMCPY( labelSeed + EAPFAST_PAC_MASTERSECRET_HASH,
                pSSLSock->pServerRandHello,
                SSL_RANDOMSIZE);
    DIGI_MEMCPY( labelSeed + EAPFAST_PAC_MASTERSECRET_HASH + SSL_RANDOMSIZE,
                pSSLSock->pClientRandHello,
                SSL_RANDOMSIZE);

   return T_PRF(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pacKey, PACKEY_SIZE,
                    labelSeed, EAPFAST_PAC_MASTERSECRET_HASH + 2 * SSL_RANDOMSIZE,
                    pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);
}
#endif /* __ENABLE_DIGICERT_EAP_FAST__ */


/*--------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_FAST__)
extern MSTATUS
SSL_SOCK_generateEAPFASTIntermediateCompoundKey(SSLSocket *pSSLSock,
                                    ubyte *s_imk,
                                    ubyte *msk,
                                    ubyte mskLen, ubyte *imk)
{
    ubyte   labelSeed[EAPFAST_IM_COMPOUND_KEY_SIZE + EAPFAST_IM_MSK_SIZE + 1];
    sbyte4  labelSeedLen = EAPFAST_IM_COMPOUND_KEY_SIZE+EAPFAST_IM_MSK_SIZE+1;
    MSTATUS status = OK;
    DIGI_MEMSET(labelSeed, 0, labelSeedLen);
    DIGI_MEMCPY(labelSeed, (const ubyte *)"Inner Methods Compound Keys", EAPFAST_IM_COMPOUND_KEY_SIZE);
    if (msk && mskLen != 0)
    {
        if (mskLen > EAPFAST_IM_MSK_SIZE)
        {
            DIGI_MEMCPY(labelSeed + EAPFAST_IM_COMPOUND_KEY_SIZE + 1,
                       msk, EAPFAST_IM_MSK_SIZE);
        }
        else
        {
            DIGI_MEMCPY(labelSeed + EAPFAST_IM_COMPOUND_KEY_SIZE + 1,
            msk, mskLen);
        }
    }
    if (NULL == s_imk)
    {
        status = T_PRF(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->sessionKeySeed,
                           40, labelSeed, labelSeedLen, imk, 60);
    }
    else
    {
        status = T_PRF(MOC_HASH(pSSLSock->hwAccelCookie) s_imk,
                           40, labelSeed, labelSeedLen, imk, 60);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_EAP_FAST__ */


/*--------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_FAST__)
extern MSTATUS
SSL_SOCK_generateEAPFASTSessionKeys(SSLSocket *pSSLSock, ubyte* S_IMCK, sbyte4 s_imckLen,
                                    ubyte* MSK, sbyte4 mskLen, ubyte* EMSK, sbyte4 emskLen/*64 Len */)

{
    ubyte   labelSeed[] = "Session Key Generating Function";
    ubyte4  labelSeedLen;
    ubyte   emsklabelSeed[] = "Extended Session Key Generating Function";
    ubyte4  emsklabelSeedLen;
    MSTATUS status = OK;

    labelSeedLen = DIGI_STRLEN((const sbyte *)labelSeed) + 1;
    emsklabelSeedLen = DIGI_STRLEN((const sbyte *)emsklabelSeed) + 1;

    T_PRF(MOC_HASH(pSSLSock->hwAccelCookie) S_IMCK, s_imckLen, labelSeed, labelSeedLen, MSK, mskLen/*64 Bytes */);

    T_PRF(MOC_HASH(pSSLSock->hwAccelCookie) S_IMCK, s_imckLen, emsklabelSeed, emsklabelSeedLen, EMSK, emskLen/*64 Bytes */);
#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"FAST S IMCK ");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    PrintBytes(S_IMCK, s_imckLen);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"MSK ");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    PrintBytes(MSK, mskLen);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"EMSK ");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    PrintBytes(EMSK, emskLen);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_EAP_FAST__ */


/*--------------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
extern MSTATUS
SSL_SOCK_generatePEAPIntermediateKeys(SSLSocket *pSSLSock, ubyte* IPMK, sbyte4 ipmkLen,
                                      ubyte* ISK, sbyte4 iskLen, ubyte* result, sbyte4 resultLen/*32 Len */)
{
    ubyte*  temp = NULL;   /* temp buffer allocated locally */
    ubyte   labelSeed[] = "Intermediate PEAP MAC key";
    ubyte4  labelSeedLen;
    MSTATUS status = OK;

    labelSeedLen = DIGI_STRLEN((const sbyte*)labelSeed);

    if (NULL == (temp = (ubyte*) MALLOC(iskLen+labelSeedLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(temp,labelSeed,labelSeedLen);
    DIGI_MEMCPY(temp+labelSeedLen,ISK,iskLen);

    P_hash(pSSLSock, IPMK, ipmkLen, temp, iskLen+labelSeedLen, result, resultLen, &SHA1Suite);

exit:
    if (NULL != temp)
        FREE(temp);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */


/*--------------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
extern MSTATUS
SSL_SOCK_generatePEAPServerCompoundMacKeys(SSLSocket *pSSLSock, ubyte* IPMK,
                                           sbyte4 ipmkLen, ubyte* S_NONCE, sbyte4 s_nonceLen,
                                           ubyte* result, sbyte4 resultLen/*20 bytes*/)
{
    ubyte*  temp = NULL;   /* temp buffer allocated locally */
    ubyte   labelSeed[] = "PEAP Server B1 MAC key";
    ubyte4  labelSeedLen;
    MSTATUS status = OK;

    labelSeedLen = DIGI_STRLEN((const sbyte*)labelSeed);

    if (NULL == (temp = (ubyte*) MALLOC(s_nonceLen+labelSeedLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(temp,labelSeed,labelSeedLen);
    DIGI_MEMCPY(temp+labelSeedLen,S_NONCE,s_nonceLen);

    P_hash(pSSLSock, IPMK, ipmkLen, temp, s_nonceLen+labelSeedLen, result, resultLen, &SHA1Suite);

exit:
    if (NULL != temp)
        FREE(temp);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */


/*--------------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
extern MSTATUS
SSL_SOCK_generatePEAPClientCompoundMacKeys(SSLSocket *pSSLSock, ubyte* IPMK,
                                           sbyte4 ipmkLen, ubyte* S_NONCE, sbyte4 s_nonceLen,
                                           ubyte* C_NONCE, sbyte4 c_nonceLen, ubyte* result,
                                           sbyte4 resultLen/*20 bytes*/)
{
    ubyte*  temp = NULL;   /* temp buffer allocated locally */
    ubyte   labelSeed[] = "PEAP Client B2 MAC key";
    ubyte4  labelSeedLen;
    MSTATUS status = OK;

    labelSeedLen = DIGI_STRLEN((const sbyte*)labelSeed);

    if (NULL == (temp = (ubyte*) MALLOC(s_nonceLen+c_nonceLen+labelSeedLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(temp,labelSeed,labelSeedLen);
    DIGI_MEMCPY(temp+labelSeedLen,S_NONCE,s_nonceLen);
    DIGI_MEMCPY(temp+labelSeedLen+s_nonceLen,C_NONCE,c_nonceLen);

    P_hash(pSSLSock, IPMK, ipmkLen, temp, s_nonceLen+c_nonceLen+labelSeedLen, result, resultLen, &SHA1Suite);

exit:
    if (NULL != temp)
        FREE(temp);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */


/*--------------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
extern MSTATUS
SSL_SOCK_generatePEAPCompoundSessionKey(SSLSocket *pSSLSock, ubyte* IPMK , sbyte4 ipmkLen,
                                        ubyte* S_NONCE, sbyte4 s_nonceLen, ubyte* C_NONCE,
                                        sbyte4 c_nonceLen, ubyte* result, sbyte4 resultLen)
{
    ubyte*  temp = NULL;   /* temp buffer allocated locally */
    ubyte   labelSeed[] = "PEAP compound session key";
    ubyte4  labelSeedLen;
    MSTATUS status = OK;

    labelSeedLen = DIGI_STRLEN((const sbyte*)labelSeed);

    if (NULL == (temp = (ubyte*) MALLOC(s_nonceLen+c_nonceLen+labelSeedLen+4)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(temp,labelSeed,labelSeedLen);
    DIGI_MEMCPY(temp+labelSeedLen,S_NONCE,s_nonceLen);
    DIGI_MEMCPY(temp+labelSeedLen+s_nonceLen,C_NONCE,c_nonceLen);
    DIGI_MEMCPY(temp+labelSeedLen+s_nonceLen+c_nonceLen,(ubyte *)&resultLen,4);

    P_hash(pSSLSock, IPMK, ipmkLen, temp, s_nonceLen+c_nonceLen+labelSeedLen+4, result, resultLen, &SHA1Suite);

exit:
    if (NULL != temp)
        FREE(temp);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */


#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
/*******************************************************************************
* SHAMD5Rounds
* implement the core routine used to generate the master secret and the key
* pMaterials for SSL 3.0
*  ASSUMPTIONS:
    dest receives the results, it should be numRounds * MD5_DIGESTSIZE long
    dest should not share space with data (can add a test for this)
*/
static MSTATUS
SHAMD5Rounds(SSLSocket *pSSLSock, const ubyte* pPresecret, ubyte4 presecretLength,
             const ubyte data[2 * SSL_RANDOMSIZE],
             sbyte4 numRounds,
             ubyte* dest)
{
    ubyte prefix = (ubyte)'A';
    sbyte4 i;
    MD5_CTX*    pMd5Hash  = NULL;
    shaDescr*   pSha1Hash = NULL;
    ubyte*      pSha1Result = NULL;
    MSTATUS     status;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pSha1Hash))))
        goto exit;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Hash))))
        goto exit;

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pSha1Result))))
        goto exit;

    if (OK > (status = DIGI_MEMSET((ubyte*)pSha1Hash, 0x00, sizeof(shaDescr*))))
        goto exit;

    if (OK > (status = DIGI_MEMSET((ubyte*)pMd5Hash, 0x00, sizeof(MD5_CTX*))))
        goto exit;

    for (i = 1; i <= numRounds; ++i, ++prefix)
    {
        sbyte4 j;

        MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Hash);
        SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash);

        /* hash 'A' , 'BB', 'CCC' depending on the round */
        for (j = 0; j < i; ++j)
        {
            SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, &prefix, 1);
        }

        /* hash the rest, this is either presecret,clientrandom, serverrandom for
         the master secret generation or mastersecret,clientrandom, serverrandom for
         the key material generation */
        SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, pPresecret, presecretLength);
        SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, data, 2 * SSL_RANDOMSIZE);
        SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, pSha1Result);

        /*SHA done*/

        /* hash only the first presecretLength(RSA == 48) bytes of data with MD5 */
        MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Hash, (ubyte *)pPresecret, presecretLength);
        /* followed by the just computed SHA1 hash */
        MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Hash, pSha1Result, SHA_HASH_RESULT_SIZE);
        /* store the result in dest */
        MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Hash, dest);

        /* increment dest pointer */
        dest += MD5_DIGESTSIZE;
    }

exit:
    if (pMd5Hash)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_freeCloneHashCtx(pMd5Hash);
#endif
        MEM_POOL_putPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Hash));
    }
    if (pSha1Hash)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_freeCloneHashCtx(pSha1Hash);
#endif
        MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pSha1Hash));
    }

    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pSha1Result));

    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
extern MSTATUS
SSL_SOCK_generateTLSKeyExpansionMaterial(SSLSocket *pSSLSock,
                                         ubyte *pKey, ubyte2 keySize,
                                         ubyte *keyPhrase, ubyte2 keyPhraseLen)
{
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];
    sbyte4              i;
    ubyte4              keyLen = keySize;
    ubyte*              random1;
    ubyte*              random2;
    MSTATUS             status = OK;

#if defined(__ENABLE_DIGICERT_TLS13__)
    /* RFC 8446 - Section 7.5
     *
     * RFC specifies if no context is provided then this will fall into the
     * empty context category.
     */
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        return SSLSOCK_generateHmacKdfExporterKey(
            pSSLSock, pSSLSock->pExporterMasterSecret, keyPhrase, keyPhraseLen,
            NULL, 0, pKey, keySize);
    }
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
         (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))) &&
        (TRUE == pSSLSock->supportExtendedMasterSecret) &&
        (FALSE == pSSLSock->useExtendedMasterSecret))
    {
        /* Version negotiated is TLS 1.2 or lower OR DTLS 1.2
         * Application enabled extended_master_secret at runtime,
         * but stack could not negotiate to use extended_master_secret,
         * do NOT export key material
         */
        return ERR_SSL_EXPORT_KEY_MATERIAL;
    }
#endif

    DIGI_MEMCPY( masterSecret, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

    random1 = START_RANDOM( pSSLSock);
    random2 = random1 + SSL_RANDOMSIZE;
    for (i = 0; i < SSL_RANDOMSIZE; ++i)
    {
        ubyte swap = *random1;
        *random1++ = *random2;
        *random2++ = swap;
    }

    /* copy label "key expansion" in its special place */
    DIGI_MEMCPY( START_RANDOM( pSSLSock) - keyPhraseLen,
            keyPhrase,
            keyPhraseLen);
    /* generate keys with PRF */
    if (128 >= keySize)
        keyLen = keySize;
    else
        keyLen = 128;

    status = PRF(pSSLSock, masterSecret, SSL_MASTERSECRETSIZE,
            START_RANDOM( pSSLSock) - keyPhraseLen,
            keyPhraseLen + 2 * SSL_RANDOMSIZE,
            pKey, keyLen);

    if (OK > status)
        goto exit;


    if (128 <  keySize)
    {
        status = PRF(pSSLSock, (const ubyte*)"", 0,
                START_RANDOM( pSSLSock) - keyPhraseLen,
                keyPhraseLen + 2 * SSL_RANDOMSIZE,
                pKey + 128, keySize - 128);
    }

exit:
        /* store master secret in its place after that */
    DIGI_MEMCPY(pSSLSock->pSecretAndRand, masterSecret, SSL_MASTERSECRETSIZE);
    random1 = START_RANDOM( pSSLSock);
    random2 = random1 + SSL_RANDOMSIZE;
    for (i = 0; i < SSL_RANDOMSIZE; ++i)
    {
        ubyte swap = *random1;
        *random1++ = *random2;
        *random2++ = swap;
    }

    return status;
}

extern MSTATUS
SSL_SOCK_generateTLSKeyExpansionMaterialWithContext(SSLSocket *pSSLSock,
                                                    ubyte *pKey, ubyte2 keySize,
                                                    ubyte *keyPhrase, ubyte2 keyPhraseLen,
                                                    ubyte *pContext, ubyte2 contextLen)
{
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];
    ubyte4              keyLen = keySize;
    ubyte*              random1;
    ubyte*              random2;
    ubyte*              completeLabel = NULL;
    MSTATUS             status = OK;

#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        status = SSLSOCK_generateHmacKdfExporterKey(
            pSSLSock, pSSLSock->pExporterMasterSecret, keyPhrase, keyPhraseLen,
            pContext, contextLen, pKey, keySize);
        goto exit;
    }
    else
#endif
    {
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
        if (((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
             (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))) &&
            (TRUE == pSSLSock->supportExtendedMasterSecret) &&
            (FALSE == pSSLSock->useExtendedMasterSecret))
        {
            /* Version negotiated is TLS 1.2 or lower OR DTLS 1.2
             * Application enabled extended_master_secret at runtime,
             * but stack could not negotiate to use extended_master_secret,
             * do NOT export key material
             */
            status = ERR_SSL_EXPORT_KEY_MATERIAL;
            goto exit;
        }
#endif
        DIGI_MEMCPY( masterSecret, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

        status = DIGI_CALLOC((void **) &completeLabel, 1, keyPhraseLen + 2 * SSL_RANDOMSIZE + 2/* length of context */ + contextLen);

        if ((OK > status) || (NULL == completeLabel))
        {
            goto exit;
        }

        DIGI_MEMCPY(completeLabel, keyPhrase, keyPhraseLen);

        random1 = START_RANDOM( pSSLSock);
        random2 = random1 + SSL_RANDOMSIZE;

        DIGI_MEMCPY(completeLabel + keyPhraseLen, random2, SSL_RANDOMSIZE);
        DIGI_MEMCPY(completeLabel + keyPhraseLen + SSL_RANDOMSIZE, random1, SSL_RANDOMSIZE);

        *(completeLabel + keyPhraseLen + 2 * SSL_RANDOMSIZE) = (ubyte) contextLen;
        if (contextLen > 0)
        {
            DIGI_MEMCPY((completeLabel + keyPhraseLen + 2 * SSL_RANDOMSIZE + 1), pContext, contextLen);
        }

        /* generate keys with PRF */
        if (128 >= keySize)
        {
            keyLen = keySize;
        }
        else
        {
            keyLen = 128;
        }

        status = PRF(pSSLSock, masterSecret, SSL_MASTERSECRETSIZE,
                    completeLabel,
                    keyPhraseLen + 2 * SSL_RANDOMSIZE + 1 + contextLen,
                    pKey, keyLen);

        if (OK > status)
            goto exit;


        if (128 < keySize)
        {
            status = PRF(pSSLSock, (const ubyte*)"", 0,
                        completeLabel,
                        keyPhraseLen + 2 * SSL_RANDOMSIZE + 1 + contextLen,
                        pKey + 128, keySize - 128);
        }
    }

exit:
    if (NULL != completeLabel)
    {
        DIGI_FREE((void **) &completeLabel);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_SSL_KEY_EXPANSION__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
extern MSTATUS
SSL_SOCK_generateKeyExpansionMaterial(SSLSocket *pSSLSock,
                                      ubyte *pKey, ubyte2 keySize,
                                      ubyte *keyPhrase, ubyte2 keyPhraseLen)
{
    ubyte               masterSecret[SSL_MASTERSECRETSIZE];
    sbyte4              i;
    ubyte*              random1;
    ubyte*              random2;
    MSTATUS             status = OK;

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (((!pSSLSock->isDTLS && (TLS12_MINORVERSION >= pSSLSock->sslMinorVersion)) ||
         (pSSLSock->isDTLS && (DTLS12_MINORVERSION == pSSLSock->sslMinorVersion))) &&
        (TRUE == pSSLSock->supportExtendedMasterSecret) &&
        (FALSE == pSSLSock->useExtendedMasterSecret))
    {
        /* Version negotiated is TLS 1.2 or lower OR DTLS 1.2
         * Application enabled extended_master_secret at runtime,
         * but stack could not negotiate to use extended_master_secret,
         * do NOT export key material
         */
        return ERR_SSL_EXPORT_KEY_MATERIAL;
    }
#endif
    DIGI_MEMCPY( masterSecret, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

    random1 = START_RANDOM( pSSLSock);
    random2 = random1 + SSL_RANDOMSIZE;
    for (i = 0; i < SSL_RANDOMSIZE; ++i)
    {
        ubyte swap = *random1;
        *random1++ = *random2;
        *random2++ = swap;
    }

    /* copy label "key expansion" in its special place */
    DIGI_MEMCPY( START_RANDOM( pSSLSock) - keyPhraseLen,
            keyPhrase,
            keyPhraseLen);
    /* generate keys with PRF */
    status = PRF(pSSLSock, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE,
            START_RANDOM( pSSLSock) - keyPhraseLen,
            keyPhraseLen + 2 * SSL_RANDOMSIZE,
            pKey, keySize);

        /* store master secret in its place after that */
    DIGI_MEMCPY(pSSLSock->pSecretAndRand, masterSecret, SSL_MASTERSECRETSIZE);

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_KEY_EXPANSION__ */


/*------------------------------------------------------------------*/

/*******************************************************************************
* SSL_SOCK_generateKeyMaterial
* see pages 97-104 of SSL and TLS Essentials
* the algorithm used varies between SSL and TLS
*
* preMasterSecret & preMasterSecretLength is used only when the session is not
* resumed
*/
extern MSTATUS
SSL_SOCK_generateKeyMaterial(SSLSocket *pSSLSock,
                             ubyte* preMasterSecret, ubyte4 preMasterSecretLength)
{
    ubyte*              pMasterSecret = NULL; /* [SSL_MASTERSECRETSIZE] */
    sbyte4              totalMaterialSize=0, i;
    ubyte*              random1;
    ubyte*              random2;
    const CipherSuiteInfo*    pCS = pSSLSock->pHandshakeCipherSuite;
    MSTATUS             status = OK;
    ubyte*              preMasterSecretCopy = NULL;
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    ubyte*              pLabelAndHash = NULL;
    ubyte4              labelAndHashSize = 0;
#endif

    if ((preMasterSecretLength > 0) && (preMasterSecret != NULL))
    {
        if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, preMasterSecretLength, TRUE, (void **)&preMasterSecretCopy)))
            goto exit;
        DIGI_MEMCPY(preMasterSecretCopy, preMasterSecret, preMasterSecretLength);
    }

    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pMasterSecret))))
        goto exit;

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (TRUE == pSSLSock->useExtendedMasterSecret)
    {
        BulkCtx pHashCtxCopy = NULL;
        const BulkHashAlgo *pHashAlgo = NULL;
        pHashAlgo = pCS->pPRFHashAlgo;

#ifndef __DISABLE_DIGICERT_SHA256__
        if (!pHashAlgo)
        {
            pHashAlgo = &SHA256Suite;
        }
#endif
        labelAndHashSize = pHashAlgo->digestSize + TLS_EXTENDED_MASTERSECRET_LABEL_SIZE;

        if (OK > (DIGI_CALLOC((void **)&pLabelAndHash, 1, labelAndHashSize)))
            goto exit;

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->hashPool, (void **)(&pHashCtxCopy))))
            goto exit;

#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_cloneHashCtx(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx,
                                               pHashCtxCopy, pSSLSock->hashPool.poolObjectSize);
        if (OK != status)
            goto exit1;
#else
        DIGI_MEMCPY(pHashCtxCopy, pSSLSock->pHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#else
        CopyCtx_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtxCopy,
                          pSSLSock->pHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif /* ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__ */

        /* copy label "extended master secret" */
        DIGI_MEMCPY(pLabelAndHash, (ubyte *)TLS_EXTENDED_MASTERSECRET_LABEL, TLS_EXTENDED_MASTERSECRET_LABEL_SIZE);

        /* Copy the hash */
        pHashAlgo->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pHashCtxCopy,
                             pLabelAndHash + TLS_EXTENDED_MASTERSECRET_LABEL_SIZE);

exit1:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_freeCloneHashCtx(pHashCtxCopy);
#endif
        MEM_POOL_putPoolObject(&pSSLSock->hashPool, (void **)(&pHashCtxCopy));
    }
#endif
    /* compute the total size of pMaterials needed */
    /* for TLS1.1 and up, don't need clientIV or serverIVs, R is generated per record, so don't generate them */
    totalMaterialSize = 2 * (pCS->keySize +
                             IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS) +
                             pCS->pCipherAlgo->getFieldFunc(Hash_Size));

#if defined(__ENABLE_DIGICERT_EAP_FAST__)
    if ((pSSLSock->roleSpecificInfo.client.ticket != NULL) &&
        (pSSLSock->roleSpecificInfo.client.ticketLength > 0))
    {
        totalMaterialSize += SKS_SIZE;
        totalMaterialSize += FAST_MSCHAP_CHAL_SIZE;
    }
#endif

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        if (E_NoSessionResume == pSSLSock->sessionResume)
        {
            /************************ generate the master secret */
#ifdef __ENABLE_ALL_DEBUGGING__
            status = ERR_NULL_POINTER;
            if(NULL != preMasterSecretCopy)
            {
                DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" premaster secret");
                PrintBytes(preMasterSecretCopy, preMasterSecretLength);
            }

            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" client random");
            PrintBytes(START_RANDOM(pSSLSock), SSL_RANDOMSIZE);

            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" server random");
            PrintBytes(START_RANDOM(pSSLSock) + SSL_RANDOMSIZE, SSL_RANDOMSIZE);
#endif
            /* generate master secret with 3 rounds */
            if (OK > (status = SHAMD5Rounds(pSSLSock, preMasterSecretCopy, preMasterSecretLength, START_RANDOM(pSSLSock), 3, pMasterSecret)))
                goto exit;

            /* place master secret */
            DIGI_MEMCPY(pSSLSock->pSecretAndRand, pMasterSecret, SSL_MASTERSECRETSIZE);
        }

        /* *************************** generate keys */
        /* swap server random and client random in pSecretAndRand */
        random1 = START_RANDOM( pSSLSock);
        random2 = random1 + SSL_RANDOMSIZE;
        for (i = 0; i < SSL_RANDOMSIZE; ++i)
        {
            ubyte swap = *random1;
            *random1++ = *random2;
            *random2++ = swap;
        }

        /* generate key pMaterials with the appropriate number of rounds */
        if (OK > (status = SHAMD5Rounds(pSSLSock, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE,
                                        START_RANDOM(pSSLSock),
                                        (totalMaterialSize + MD5_RESULT_SIZE - 1 )/ MD5_RESULT_SIZE,
                                        pSSLSock->pMaterials)))
        {
            goto exit;
        }
    }
    else
#endif
    /* TLS */
    {
        if (E_NoSessionResume == pSSLSock->sessionResume)
        {
            /************************ generate the master secret */

            /* copy label "master secret" in its special place */
            DIGI_MEMCPY( START_RANDOM( pSSLSock) - TLS_MASTERSECRETSIZE, (ubyte *)"master secret", TLS_MASTERSECRETSIZE);

#ifdef __ENABLE_ALL_DEBUGGING__

            if(NULL != preMasterSecretCopy)
            {
                DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" premaster secret");
                PrintBytes(preMasterSecretCopy, preMasterSecretLength);
            }

            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" client random");
            PrintBytes(START_RANDOM(pSSLSock), SSL_RANDOMSIZE);

            DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" server random");
            PrintBytes(START_RANDOM(pSSLSock) + SSL_RANDOMSIZE, SSL_RANDOMSIZE);
#endif
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
            if (TRUE == pSSLSock->useExtendedMasterSecret)
            {
                status = PRF(pSSLSock, preMasterSecretCopy, preMasterSecretLength,
                            pLabelAndHash, labelAndHashSize,
                            pMasterSecret, SSL_MASTERSECRETSIZE);
            }
            else
#endif
            {
                /* generate master secret with PRF */
                status = PRF(pSSLSock, preMasterSecretCopy, preMasterSecretLength,
                             START_RANDOM( pSSLSock) - TLS_MASTERSECRETSIZE,
                             TLS_MASTERSECRETSIZE + 2 * SSL_RANDOMSIZE,
                             pMasterSecret, SSL_MASTERSECRETSIZE);
            }
            if (OK > status)
                goto exit;
        }
        else /* TLS: copy the master secret to the buffer because we are going to use
                its space for "key expansion" */
        {
            DIGI_MEMCPY(pMasterSecret, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);
        }

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
        if (pSSLSock->isDTLS && pSSLSock->useSrtp)
        {
            ubyte4 srtpMaterialSize;

            if (!pSSLSock->pHandshakeSrtpProfile)
            {
                status = ERR_DTLS_SRTP_NO_PROFILE_MATCH;
                goto exit;
            }

            /* assign the maximum material size, in case keySize and saltSize are 0 */
            srtpMaterialSize = 2 * (SRTP_MAX_KEY_SIZE + SRTP_MAX_SALT_SIZE);

            /* copy label "key expansion" in its special place */
            DIGI_MEMCPY( START_RANDOM( pSSLSock) - DTLS_SRTP_EXTRACTOR_SIZE,
                (ubyte *)DTLS_SRTP_EXTRACTOR,
                DTLS_SRTP_EXTRACTOR_SIZE);

            /* generate extractor for dtls_srtp with PRF */
            status = PRF(pSSLSock, pMasterSecret, SSL_MASTERSECRETSIZE,
                START_RANDOM( pSSLSock) - DTLS_SRTP_EXTRACTOR_SIZE,
                DTLS_SRTP_EXTRACTOR_SIZE + 2 * SSL_RANDOMSIZE,
                pSSLSock->pSrtpMaterials, srtpMaterialSize);

            if (OK > status)
                goto exit;
        }
#endif

        /* *************************** generate keys */
        /* NOTE: the method below is valid only for non export
         algorithm. See a text on SSL for the method to use in this case */
        /* swap server random and client random in pSecretAndRand */
        random1 = START_RANDOM(pSSLSock);
        random2 = random1 + SSL_RANDOMSIZE;

        for (i = 0; i < SSL_RANDOMSIZE; ++i)
        {
            ubyte swap = *random1;
            *random1++ = *random2;
            *random2++ = swap;
        }

        /* copy label "key expansion" in its special place */
        DIGI_MEMCPY( START_RANDOM( pSSLSock) - TLS_KEYEXPANSIONSIZE,
                (ubyte *)"key expansion",
                TLS_KEYEXPANSIONSIZE);

        /* generate keys with PRF */
        status = PRF(pSSLSock, pMasterSecret, SSL_MASTERSECRETSIZE,
                     START_RANDOM( pSSLSock) - TLS_KEYEXPANSIONSIZE,
                     TLS_KEYEXPANSIONSIZE + 2 * SSL_RANDOMSIZE,
                     pSSLSock->pMaterials, totalMaterialSize);

        if (OK > status)
            goto exit;

        /* store master secret in its place after that */
        DIGI_MEMCPY(pSSLSock->pSecretAndRand, pMasterSecret, SSL_MASTERSECRETSIZE);

    }

#if defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    /* finally store the master secret for session resumption */
    if (pSSLSock->server && E_SessionIDResume != pSSLSock->sessionResume
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        && E_SessionTicketResume != pSSLSock->sessionResume
#endif
        )
    {
        sbyte4 cacheIndex;

        if (OK > (status = RTOS_mutexWait(gSslSessionCacheMutex)))
        {
            DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"sslsock.c: RTOS_mutexWait() failed.");
            goto exit;
        }

        cacheIndex = pSSLSock->roleSpecificInfo.server.sessionId % SESSION_CACHE_SIZE;
        gSessionCache[cacheIndex].m_pCipherSuite = pSSLSock->pHandshakeCipherSuite;
        gSessionCache[cacheIndex].m_sessionId = pSSLSock->roleSpecificInfo.server.sessionId;
        DIGI_MEMCPY(gSessionCache[cacheIndex].m_masterSecret,
                pSSLSock->pSecretAndRand,
                SSL_MASTERSECRETSIZE);

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
        gSessionCache[cacheIndex].isExtendedMasterSecret = pSSLSock->useExtendedMasterSecret;
#endif

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
        if (pSSLSock->isDTLS && pSSLSock->useSrtp)
        {
            gSessionCache[cacheIndex].m_pSrtpProfile = pSSLSock->pHandshakeSrtpProfile;
        }
#endif
		if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
            (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
        {
            gSessionCache[cacheIndex].m_signatureAlgo = pSSLSock->signatureAlgo;
        }

		gSessionCache[cacheIndex].m_clientECCurves = pSSLSock->roleSpecificInfo.server.clientECCurves;

        RTOS_deltaMS(NULL, &gSessionCache[cacheIndex].startTime);
        gSessionCache[cacheIndex].m_minorVersion = pSSLSock->sslMinorVersion;

        status = RTOS_mutexRelease(gSslSessionCacheMutex);
    }
#endif

exit:
#ifdef __ENABLE_ALL_DEBUGGING__
    RTOS_sleepMS(200);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");

    if (pSSLSock->server)
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (SERVER) ");
    else
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (CLIENT) ");

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"master secret");
    PrintBytes(pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"key material");
    PrintBytes(pSSLSock->pMaterials, totalMaterialSize);
#endif

#ifdef __ENABLE_DIGICERT_SSL_KEYLOG_FILE__
    if(status == OK)
    {
        sbyte pLogFileString[20];
        sprintf(pLogFileString,"TLS1 minor ver:%d", pSSLSock->sslMinorVersion);
        appendToKeyLogFile(pSSLSock, pLogFileString, DIGI_STRLEN(pLogFileString), FALSE, TRUE);
        appendToKeyLogFile(pSSLSock, "CLIENT_RANDOM ", DIGI_STRLEN("CLIENT_RANDOM "), FALSE, FALSE);
        appendToKeyLogFile(pSSLSock, START_RANDOM(pSSLSock) + SSL_RANDOMSIZE, SSL_RANDOMSIZE, TRUE, FALSE);
        appendToKeyLogFile(pSSLSock, " ", 1, FALSE, FALSE);
        appendToKeyLogFile(pSSLSock, pSSLSock->pSecretAndRand, SSL_MASTERSECRETSIZE, TRUE, TRUE);
    }
#endif

    if (preMasterSecretCopy)
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, &preMasterSecretCopy);

    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pMasterSecret));

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    if (pLabelAndHash != NULL)
        DIGI_FREE((void **)&pLabelAndHash);
#endif

    return status;

} /* SSL_SOCK_generateKeyMaterial */


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_setClientKeyMaterial(SSLSocket *pSSLSock)
{
    const CipherSuiteInfo*    pCS = pSSLSock->pHandshakeCipherSuite;
    ubyte*              keyStart;
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    ubyte*              keyStartFast;
#endif
    sbyte4              offset;
    MSTATUS             status = OK;

    /* dup client key material */
    DIGI_MEMCPY(pSSLSock->pActiveMaterials, pSSLSock->pMaterials, pCS->pCipherAlgo->getFieldFunc(Hash_Size));

    offset = (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
    DIGI_MEMCPY(offset + pSSLSock->pActiveMaterials, offset + pSSLSock->pMaterials, pCS->keySize);

    if (0 < IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS))
    {
        offset = offset + (2 * pCS->keySize);
        DIGI_MEMCPY(offset + pSSLSock->pActiveMaterials, offset + pSSLSock->pMaterials, IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
    }

    /* initialize all the parameters for the cipher */
    resetCipher(pSSLSock, TRUE, FALSE);

#ifdef __ENABLE_HARDWARE_ACCEL_CRYPTO__
    if ( pCS->pCipherAlgo->getFieldFunc(Hash_Size))
    {
        if (NULL == (pSSLSock->clientMACSecret = MALLOC_ALIGN(pCS->pCipherAlgo->getFieldFunc(Hash_Size), hwCryptoMac)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSSLSock->clientMACSecret, pSSLSock->pActiveMaterials, pCS->pCipherAlgo->getFieldFunc(Hash_Size));
    }

    keyStart = pSSLSock->pActiveMaterials + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    keyStartFast = pSSLSock->pMaterials + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#endif
    pSSLSock->clientBulkCtx = pCS->pCipherAlgo->createCtxFunc(MOC_SYM(pSSLSock->hwAccelCookie) keyStart, pCS->keySize, pSSLSock->server ? FALSE : TRUE);

    /* initialize pointers to IV if used */
    if (IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS) > 0)
    {
        if (NULL == (pSSLSock->clientIV = MALLOC_ALIGN(IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS), hwCryptoIV)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSSLSock->clientIV, keyStart + (2 * pCS->keySize),IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize) + (2 * IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
    else
    {
        pSSLSock->clientIV = 0;
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize);
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
#else

    /* initialize pointers to MAC secrets */
    pSSLSock->clientMACSecret = pSSLSock->pActiveMaterials;

    /* initialize bulkCtx */
    keyStart = pSSLSock->clientMACSecret + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    keyStartFast = pSSLSock->pMaterials + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#endif
    pSSLSock->clientBulkCtx = pCS->pCipherAlgo->createCtxFunc(MOC_SYM(pSSLSock->hwAccelCookie) keyStart, pCS->keySize, pSSLSock->server ? FALSE : TRUE);

    if (NULL == pSSLSock->clientBulkCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize pointers to IV if used */
    if (IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS))
    {
        pSSLSock->clientIV = keyStart + (2 * pCS->keySize);
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize) + (2 * IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
    else
    {
        pSSLSock->clientIV = 0;
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize);
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
#endif

#ifdef __ENABLE_ALL_DEBUGGING__
    RTOS_sleepMS(200);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"client MAC secret");
    PrintBytes( pSSLSock->clientMACSecret, pCS->pCipherAlgo->getFieldFunc(Hash_Size));
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTSTR1HEXINT1(DEBUG_SSL_TRANSPORT, (sbyte*)"client cipher suite id 0x", pCS->cipherSuiteId);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"client key");
    PrintBytes( keyStart, pCS->keySize);

    if ( pSSLSock->clientIV)
    {
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"client IV");
        PrintBytes( pSSLSock->clientIV, IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    }
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Session Key Seed");
    PrintBytes( pSSLSock->sessionKeySeed, SKS_SIZE);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"CHAP CHALLENGES");
    PrintBytes( pSSLSock->fastChapChallenge, FAST_MSCHAP_CHAL_SIZE);
#endif
#endif

#ifdef __ENABLE_DIGICERT_INNER_APP__
    /* Initialize innerSecret to Master Secret */
    DIGI_MEMCPY(pSSLSock->innerSecret, pSSLSock->pSecretAndRand, SSL_INNER_SECRET_SIZE);
#endif

    /* on the client, the master secret is always at pSSLSock->pSecretAndRand */

exit:
    return status;

} /* SSL_SOCK_setClientKeyMaterial */


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_setServerKeyMaterial(SSLSocket *pSSLSock)
{
    const CipherSuiteInfo*    pCS = pSSLSock->pHandshakeCipherSuite;
    ubyte*              keyStart;
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    ubyte*              keyStartFast;
#endif
    sbyte4              offset;
    MSTATUS             status = OK;

    /* dup server key material */
    DIGI_MEMCPY(pCS->pCipherAlgo->getFieldFunc(Hash_Size) + pSSLSock->pActiveMaterials, pCS->pCipherAlgo->getFieldFunc(Hash_Size) + pSSLSock->pMaterials, pCS->pCipherAlgo->getFieldFunc(Hash_Size));

    offset = (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
    DIGI_MEMCPY(pCS->keySize + offset + pSSLSock->pActiveMaterials, pCS->keySize + offset + pSSLSock->pMaterials, pCS->keySize);

    if (0 < IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS))
    {
        offset = offset + (2 * pCS->keySize) + IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS);
        DIGI_MEMCPY(offset + pSSLSock->pActiveMaterials, offset + pSSLSock->pMaterials, IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
    }

    /* initialize all the parameters for the cipher */
    resetCipher(pSSLSock, FALSE, TRUE);

#ifdef __ENABLE_HARDWARE_ACCEL_CRYPTO__
    if (pCS->pCipherAlgo->getFieldFunc(Hash_Size))
    {
        if (NULL == (pSSLSock->serverMACSecret = MALLOC_ALIGN(pCS->pCipherAlgo->getFieldFunc(Hash_Size), hwCryptoMac)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSSLSock->serverMACSecret, pSSLSock->pActiveMaterials + pCS->pCipherAlgo->getFieldFunc(Hash_Size), pCS->pCipherAlgo->getFieldFunc(Hash_Size));
    }

    keyStart = pSSLSock->pActiveMaterials + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    keyStartFast = pSSLSock->pMaterials + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#endif

    pSSLSock->serverBulkCtx = pCS->pCipherAlgo->createCtxFunc(MOC_SYM(pSSLSock->hwAccelCookie) keyStart + pCS->keySize, pCS->keySize, pSSLSock->server ? TRUE : FALSE);

    /* initialize pointers to IV if used */
    if (IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS) > 0)
    {
        if (NULL == (pSSLSock->serverIV= MALLOC_ALIGN(IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS), hwCryptoIV)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSSLSock->serverIV, keyStart + (2 * pCS->keySize) + IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS),
                   IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize) + (2 * IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
    else
    {
        pSSLSock->serverIV = 0;
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize);
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
#else

    /* initialize pointers to MAC secrets */
    pSSLSock->serverMACSecret = pSSLSock->pActiveMaterials + pCS->pCipherAlgo->getFieldFunc(Hash_Size);

    /* initialize bulkCtx */
    keyStart = pSSLSock->serverMACSecret + pCS->pCipherAlgo->getFieldFunc(Hash_Size);
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    keyStartFast = pSSLSock->pMaterials + (2 * pCS->pCipherAlgo->getFieldFunc(Hash_Size));
#endif

    pSSLSock->serverBulkCtx = pCS->pCipherAlgo->createCtxFunc(MOC_SYM(pSSLSock->hwAccelCookie) keyStart + pCS->keySize, pCS->keySize, pSSLSock->server ? TRUE : FALSE);

    if (NULL == pSSLSock->serverBulkCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize pointers to IV if used */
    if (0 < IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS))
    {
        pSSLSock->serverIV = keyStart + (2 * pCS->keySize) + IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS);
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize) + (2 * IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
    else
    {
        pSSLSock->serverIV = 0;
#ifdef __ENABLE_DIGICERT_EAP_FAST__
        pSSLSock->sessionKeySeed = keyStartFast + (2 * pCS->keySize);
        pSSLSock->fastChapChallenge = pSSLSock->sessionKeySeed + SKS_SIZE;
#endif
    }
#endif

#ifdef __ENABLE_ALL_DEBUGGING__
    RTOS_sleepMS(200);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"server MAC secret");
    PrintBytes( pSSLSock->serverMACSecret, pCS->pCipherAlgo->getFieldFunc(Hash_Size));
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTSTR1HEXINT1(DEBUG_SSL_TRANSPORT, (sbyte*)"server cipher suite id 0x", pCS->cipherSuiteId);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"server key");
    PrintBytes( keyStart + pCS->keySize, pCS->keySize);

    if ( pSSLSock->serverIV)
    {
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"server IV");
        PrintBytes( pSSLSock->serverIV, IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS));
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    }
#ifdef __ENABLE_DIGICERT_EAP_FAST__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"Session Key Seed");
    PrintBytes( pSSLSock->sessionKeySeed, 40);
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"CHAP CHALLENGES");
    PrintBytes( pSSLSock->fastChapChallenge, FAST_MSCHAP_CHAL_SIZE);
#endif
#endif

#ifdef __ENABLE_DIGICERT_INNER_APP__
    /* Initialize innerSecret to Master Secret */
    DIGI_MEMCPY(pSSLSock->innerSecret, pSSLSock->pSecretAndRand, SSL_INNER_SECRET_SIZE);
#endif

exit:
    return status;

} /* SSL_SOCK_setServerKeyMaterial */


/*------------------------------------------------------------------*/
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION

extern MSTATUS
SSL_SOCK_computeSSLMAC(SSLSocket *pSSLSock, ubyte* secret, sbyte4 macSize,
                       ubyte *pSequence, ubyte2 mesgLen,
                       ubyte result[SSL_MAXDIGESTSIZE])
{
    /* Complete Message Format: <sequence counter : 8 bytes><SSL frame : 5 bytes><pMessage -> message to encrypt : (mesgLen bytes)><hmac to insert><Pad><PadLen byte> */
    MD5_CTX*    pMd5Ctx  = NULL;
    shaDescr*   pSha1Ctx = NULL;
    MSTATUS     status;

    if (MD5_DIGESTSIZE == macSize) /* MD5 */
    {
        if (OK <= (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Ctx))))
        {
            if (OK > (status = DIGI_MEMSET((ubyte*)pMd5Ctx, 0x00, sizeof(MD5_CTX))))
                goto exit;

            if (OK > (status = MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx)))
                goto exit;

            if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, secret, macSize)))
                goto exit;

            if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, gHashPad36, SSL_MD5_PADDINGSIZE)))
                goto exit;

            if (OK > (status = MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, pSequence, mesgLen)))
                goto exit;

            if (OK > (status = MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, result)))
                goto exit;

            MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx);

            MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, secret, macSize);

            MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, gHashPad5C, SSL_MD5_PADDINGSIZE);

            MD5Update_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, result, macSize);

            status = MD5Final_m(MOC_HASH(pSSLSock->hwAccelCookie) pMd5Ctx, result);
        }
    }
    else /* SHA1 */
    {
        if (OK <= (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pSha1Ctx))))
        {
            if (OK > (status = DIGI_MEMSET((ubyte*)pSha1Ctx, 0x00, sizeof(shaDescr))))
                goto exit;

            if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx)))
                goto exit;

            if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, secret, macSize)))
                goto exit;

            if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, gHashPad36, SSL_SHA1_PADDINGSIZE)))
                goto exit;

            if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, pSequence, mesgLen)))
                goto exit;

            if (OK > (status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, result)))
                goto exit;

            if (OK > (status = SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx)))
                goto exit;

            if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, secret, macSize)))
                goto exit;

            if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, gHashPad5C, SSL_SHA1_PADDINGSIZE)))
                goto exit;

            if (OK > (status = SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, result, macSize)))
                goto exit;

            status = SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Ctx, result);
        }
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"secret=");
    PrintBytes(secret, macSize);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"complete message=");
    PrintBytes(pSequence, mesgLen);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL Mac=");
    PrintBytes( result, macSize);
#endif

exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pMd5Ctx)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pMd5Ctx);
    }
    if (pSha1Ctx)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSha1Ctx);
    }
#endif
    MEM_POOL_putPoolObject(&pSSLSock->md5Pool, (void **)(&pMd5Ctx));
    MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void **)(&pSha1Ctx));

    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_computeTLSMAC(MOC_HASH(SSLSocket *pSSLSock) ubyte* secret,
                       ubyte *pMesg, ubyte2 mesgLen,
                       ubyte *pMesgOpt, ubyte2 mesgOptLen,
                       ubyte result[SSL_MAXDIGESTSIZE], const BulkHashAlgo *pBHAlgo)
{
    MSTATUS status;

    /* Complete Message Format: <sequence counter : 8 bytes><SSL frame : 5 bytes><message to encrypt><hmac to insert><Pad><PadLen byte> */

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_HmacQuickEx(MOC_HASH(pSSLSock->hwAccelCookie) secret, pBHAlgo->digestSize, pMesg, mesgLen, pMesgOpt, mesgOptLen, result, pBHAlgo);
#else
    status = HmacQuickEx(MOC_HASH(pSSLSock->hwAccelCookie) secret, pBHAlgo->digestSize, pMesg, mesgLen, pMesgOpt, mesgOptLen, result, pBHAlgo);
#endif

#ifdef __ENABLE_ALL_DEBUGGING__
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"secret=");
    PrintBytes(secret, pBHAlgo->digestSize);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"complete message=");
    PrintBytes(pMesg, mesgLen);
    PrintBytes(pMesgOpt, mesgOptLen);

    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)"TLS Mac=");
    PrintBytes( result, pBHAlgo->digestSize);
#endif

    return status;
}


#ifdef __ENABLE_DIGICERT_SSL_SRP__
/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_SRPConcatPadSha( SSLSocket* pSSLSock,
                         const ubyte* first, sbyte4 firstSize,
                         const ubyte* second, sbyte4 secondSize,
                         sbyte4 padSize, ubyte* shaResult)
{
    MSTATUS status;
    SHA1_CTX* pSha1Hash = 0;
    sbyte4 i;
    intBoolean is12 = (pSSLSock->isDTLS && (pSSLSock->sslMinorVersion == DTLS12_MINORVERSION)) ||
    (!pSSLSock->isDTLS && (pSSLSock->sslMinorVersion == TLS12_MINORVERSION));

    if (is12)
    {
        /* no shaPool was allocated so CRYPTO_ALLOC it */
        if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, sizeof(SHA1_CTX), TRUE, &pSha1Hash)))
            goto exit;
    }
    else
    {
        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)(&pSha1Hash))))
            goto exit;
    }

    DIGI_MEMSET((ubyte*)pSha1Hash, 0x00, sizeof(SHA1_CTX));

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    CRYPTO_INTERFACE_SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash);
    for (i = firstSize; i < padSize; ++i)
    {
        CRYPTO_INTERFACE_SHA1_updateDigest( MOC_HASH( pSSLSock->hwAccelCookie) pSha1Hash,
                                   (ubyte*)"", 1);
    }
    CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, first, firstSize);

    for (i = secondSize; i < padSize; ++i)
    {
        CRYPTO_INTERFACE_SHA1_updateDigest( MOC_HASH( pSSLSock->hwAccelCookie) pSha1Hash,
                                   (ubyte*)"", 1);
    }
    CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, second, secondSize);
    CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, shaResult);
#else
    SHA1_initDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash);
    for (i = firstSize; i < padSize; ++i)
    {
        SHA1_updateDigestHandShake( MOC_HASH( pSSLSock->hwAccelCookie) pSha1Hash,
                                   (ubyte*)"", 1);
    }
    SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, first, firstSize);

    for (i = secondSize; i < padSize; ++i)
    {
        SHA1_updateDigestHandShake( MOC_HASH( pSSLSock->hwAccelCookie) pSha1Hash,
                                   (ubyte*)"", 1);
    }
    SHA1_updateDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, second, secondSize);
    SHA1_finalDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSha1Hash, shaResult);
#endif

exit:

    if (is12)
    {
        CRYPTO_FREE( pSSLSock->hwAccelCookie, TRUE, &pSha1Hash);
    }
    else
    {
        if (pSha1Hash)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_freeCloneHashCtx(pSha1Hash);
#endif
            MEM_POOL_putPoolObject(&pSSLSock->shaPool, (void**)(&pSha1Hash));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_SerializeVLong(const vlong* src, ubyte** dest, sbyte4* destLen)
{
    MSTATUS status;
    ubyte* alloc = 0;

    if (OK > (status = VLONG_byteStringFromVlong(src, NULL, destLen)))
    {
        goto exit;
    }

    alloc = (ubyte*) MALLOC( *destLen);
    if (!alloc)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > ( status = VLONG_byteStringFromVlong(src, alloc, destLen)))
    {
        goto exit;
    }

    *dest = alloc; alloc = 0;

exit:

    FREE(alloc);
    return status;

}

#endif

/*------------------------------------------------------------------*/

static void
resetCipher(SSLSocket* pSSLSock, intBoolean clientSide, intBoolean serverSide)
{
    const struct CipherSuiteInfo* pClientCryptoSuite;
    const struct CipherSuiteInfo* pServerCryptoSuite;
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    intBoolean   isSetKey = (clientSide && serverSide) ? FALSE : TRUE;
#endif

    if (0 == pSSLSock->server)
    {
        pClientCryptoSuite = pSSLSock->pActiveOwnCipherSuite;
        pServerCryptoSuite = pSSLSock->pActivePeerCipherSuite;
    }
    else
    {
        pClientCryptoSuite = pSSLSock->pActivePeerCipherSuite;
        pServerCryptoSuite = pSSLSock->pActiveOwnCipherSuite;
    }

    if (NULL == pClientCryptoSuite)
        clientSide = FALSE;

    if (NULL == pServerCryptoSuite)
        serverSide = FALSE;

    if ((clientSide) && (pSSLSock->clientBulkCtx))
    {
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
        if (isSetKey && pSSLSock->isDTLS && !pSSLSock->server && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
        {
            /* make sure we delete the ctx when closing connection */
            pSSLSock->retransCipherInfo.deleteOldBulkCtx = TRUE;
        } else
#endif
        {
            pClientCryptoSuite->pCipherAlgo->deleteCtxFunc(MOC_SYM(pSSLSock->hwAccelCookie) &pSSLSock->clientBulkCtx);
        }

        pSSLSock->clientBulkCtx = 0;
    }

    if ((serverSide) && (pSSLSock->serverBulkCtx))
    {
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
        if (isSetKey && pSSLSock->isDTLS && pSSLSock->server && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
        {
            /* make sure we delete the ctx when closing connection */
            pSSLSock->retransCipherInfo.deleteOldBulkCtx = TRUE;
        } else
#endif
        {
            pServerCryptoSuite->pCipherAlgo->deleteCtxFunc(MOC_SYM(pSSLSock->hwAccelCookie) &pSSLSock->serverBulkCtx);
        }

        pSSLSock->serverBulkCtx = 0;
    }

#ifdef __ENABLE_HARDWARE_ACCEL_CRYPTO__
    if ((clientSide) && (pSSLSock->clientMACSecret))
    {
        FREE_ALIGN(pSSLSock->clientMACSecret, hwCryptoMac);
        pSSLSock->clientMACSecret = 0;
    }

    if ((serverSide) && (pSSLSock->serverMACSecret))
    {
        FREE_ALIGN(pSSLSock->serverMACSecret, hwCryptoMac);
        pSSLSock->serverMACSecret = 0;
    }

    if ((clientSide) && (pSSLSock->clientIV))
    {
        FREE_ALIGN(pSSLSock->clientIV, hwCryptoIV);
        pSSLSock->clientIV = 0;
    }

    if ((serverSide) && (pSSLSock->serverIV))
    {
        FREE_ALIGN(pSSLSock->serverIV, hwCryptoIV);
        pSSLSock->serverIV = 0;
    }
#endif
}

/*------------------------------------------------------------------*/

static MSTATUS
SSL_SOCK_receiveV23Record(SSLSocket* pSSLSock, ubyte* pSRH,
                          ubyte **ppPacketPayload, ubyte4 *pPacketLength)
{
    MSTATUS status;
    ubyte4 sizeofRecordHeader;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    ubyte pSeqNum[8];
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        sizeofRecordHeader = sizeof(DTLSRecordHeader);
    } else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    if (SSL_ASYNC_RECEIVE_RECORD_2 == SSL_RX_RECORD_STATE(pSSLSock))
        goto nextState;

    status = recvAll(pSSLSock, (sbyte *)pSRH, sizeofRecordHeader,
                     SSL_ASYNC_RECEIVE_RECORD_1, SSL_ASYNC_RECEIVE_RECORD_2,
                     ppPacketPayload, pPacketLength);

    /* check for errors and no state change */
    if ((OK > status) || (SSL_ASYNC_RECEIVE_RECORD_1 == SSL_RX_RECORD_STATE(pSSLSock)))
        goto exit;

    status = ERR_SSL_PROTOCOL_RECEIVE_RECORD;

    if (SSLV2_HELLO_CLIENT == (((SSLClientHelloV2 *)pSRH)->record.recordType))
    {
        /* handle SSLv2 clientHello record */
        pSSLSock->recordSize = ((SSLClientHelloV2 *)pSRH)->record.recordLen;

        if (3 > pSSLSock->recordSize)
            goto exit;

        pSSLSock->recordSize = pSSLSock->recordSize - 3;
    }
    else
    {
        /* get the size */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            pSSLSock->recordSize = getShortValue(((DTLSRecordHeader*)pSRH)->recordLength);
        } else
#endif
        {
            pSSLSock->recordSize = getShortValue(((SSLRecordHeader*)pSRH)->recordLength);
        }

        if ((SSL_MAX_RECORDSIZE < pSSLSock->recordSize) || (0 > pSSLSock->recordSize))
        {
#ifdef SSL_MESG_TOO_LONG_COUNTER
            if (SSL_MAX_RECORDSIZE < pSSLSock->recordSize)
               {
                   SSL_MESG_TOO_LONG_COUNTER(1);        /* increment counter by 1 */
               }
#endif

            /* buffer overrun (attack?) */
            goto exit;
        }
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            /* in DTLS, the record carries peerSeqnum explicitly */
            DIGI_MEMCPY(pSeqNum, (ubyte*)((DTLSRecordHeader*)pSRH)->epoch, 8);
            if ((ubyte2)(DTLS_PEEREPOCH(pSSLSock) + 1) == (((DTLSRecordHeader*)pSRH)->epoch[0] << 8 | ((DTLSRecordHeader*)pSRH)->epoch[1]))
            {
                pSSLSock->shouldChangeCipherSpec = TRUE;
            }
            pSSLSock->peerSeqnumHigh = (ubyte4) ((((ubyte4)(pSeqNum[0])) << 24) | (((ubyte4)(pSeqNum[1])) << 16) | (((ubyte4)(pSeqNum[2])) << 8) | ((ubyte4)(pSeqNum[3])));
            pSSLSock->peerSeqnum = (ubyte4)((((ubyte4)(pSeqNum[4])) << 24) | (((ubyte4)(pSeqNum[5])) << 16) | (((ubyte4)(pSeqNum[6])) << 8) | ((ubyte4)(pSeqNum[7])));
        }
#endif
    }
    /* grow buffer support here */
    if (OK > (status = checkBuffer(pSSLSock, pSSLSock->recordSize, 0)))
        goto exit;

nextState:
    status = recvAll(pSSLSock, pSSLSock->pReceiveBuffer, pSSLSock->recordSize,
                     SSL_ASYNC_RECEIVE_RECORD_2, SSL_ASYNC_RECEIVE_RECORD_COMPLETED,
                     ppPacketPayload, pPacketLength);

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_receiveV23Record() returns status = ", status);
#endif

    return status;

} /* SSL_SOCK_receiveV23Record */

static MSTATUS
handleFragmentedRecord(SSLSocket* pSSLSock, ubyte **ppPacketPayload , ubyte4 *pPacketLength)
{
    ubyte   headerTemp[20]; /* enough for either SSL or DTLS record header */
    ubyte4  sizeofRecordHeader;
    sbyte4  totalSize = 0;
    ubyte4  recordSize = 0;
    sbyte  *pRecvBuffer = NULL;
    sbyte  *pTempBuffer = NULL;
    MSTATUS status = ERR_SSL_PROTOCOL;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        if (pSSLSock->sslMinorVersion == DTLS13_MINORVERSION)
            sizeofRecordHeader = DTLS13_MOC_RECORD_HEADER_LEN;
        else
            sizeofRecordHeader = sizeof(DTLSRecordHeader);
    }
    else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    if (ppPacketPayload == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (sizeofRecordHeader >= *pPacketLength)
    {
        status = ERR_SSL_PROTOCOL;
        goto exit;
    }

    /* copy out SSL record header, if we realloc */
    DIGI_MEMCPY(headerTemp, *ppPacketPayload, sizeofRecordHeader);

    /*  rfc5246 A.1.  Record Layer */
    if ((((SSLRecordHeader*)headerTemp)->protocol) != SSL_HANDSHAKE )
    {
        /* status is already initialized to ERR_SSL_PROTOCOL */
        status = ERR_SSL_PROTOCOL;
        goto exit;
    }

    recordSize = getShortValue(((SSLRecordHeader*)headerTemp)->recordLength);

    totalSize = (sbyte4)(SSL_MALLOC_BLOCK_SIZE + (pSSLSock->recordSize + recordSize )+ sizeofRecordHeader + SSL_MAXMACSECRETSIZE);

    /* Nothing to copy - current buffer can be used */
    if (totalSize <= pSSLSock->receiveBufferSize)
            goto payload_update;

    /* Alloc new buffer based on new size + previous size */
    status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, totalSize , TRUE, (void **)&pTempBuffer);

    if ((OK > status) || (NULL == pTempBuffer))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    /* Copy Existing Buffer */
    pRecvBuffer = pTempBuffer + SSL_MALLOC_BLOCK_SIZE;
    DIGI_MEMCPY(pRecvBuffer - sizeofRecordHeader, pSSLSock->pReceiveBuffer - sizeofRecordHeader, pSSLSock->recordSize + sizeofRecordHeader);

    /* Free the existing Buffer */
    CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pSSLSock->pReceiveBufferBase);

    pSSLSock->receiveBufferSize = totalSize;
    pSSLSock->pReceiveBufferBase = pTempBuffer;
    pSSLSock->pReceiveBuffer = pSSLSock->pReceiveBufferBase + SSL_MALLOC_BLOCK_SIZE;
    pSSLSock->pSharedInBuffer = (ubyte *)(pSSLSock->pReceiveBuffer - sizeofRecordHeader);

    /* set the record buffer values */
    SSL_RX_RECORD_BUFFER(pSSLSock) = (ubyte *)pSSLSock->pReceiveBuffer;

payload_update:
    /* digest bytes from packet */
    *ppPacketPayload += sizeofRecordHeader;
    *pPacketLength   -= sizeofRecordHeader;

    /* increase the record size */
    pSSLSock->recordSize = pSSLSock->recordSize + recordSize;

    /* require bytes will increase based on new record size*/
    SSL_RX_RECORD_BYTES_REQUIRED(pSSLSock) = pSSLSock->recordSize;

    status = OK;

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"handleFragmentedRecord() returns status = ", status);
#endif

    return status;

} /* handleFragmentedRecord */

/*------------------------------------------------------------------*/
/*
    Generic SSL encryption+hash algorithm implementation
*/

static BulkCtx
SSLComboCipher_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, ubyte4 keySize, sbyte4 encrypt, const ComboAlgo *pComboAlgo)
{
    return pComboAlgo->pBEAlgo->createFunc(MOC_SYM(hwAccelCtx) key, keySize, encrypt);
}

static MSTATUS
SSLComboCipher_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx, const ComboAlgo *pComboAlgo)
{
    return pComboAlgo->pBEAlgo->deleteFunc(MOC_SYM(hwAccelCtx) ctx);
}

static MSTATUS
SSLComboCipher_decryptVerifyRecord(SSLSocket* pSSLSock, ubyte protocol, const ComboAlgo *pComboAlgo)
{
    ubyte*              header;
    ubyte4              headerLength;
    ubyte*              pData;
    ubyte4              dataLength;
    ubyte*              macSecret = pSSLSock->server ? pSSLSock->clientMACSecret : pSSLSock->serverMACSecret;
    BulkCtx             ctx = pSSLSock->server ? pSSLSock->clientBulkCtx : pSSLSock->serverBulkCtx;
    ubyte*              pIV = pSSLSock->server ?     pSSLSock->clientIV : pSSLSock->serverIV ;
    ubyte*              pMacOut = NULL;
    ubyte4              paddingLength;
    ubyte               padChar;
    ubyte4              padLoop;
    ubyte*              pSeqNum=0;
    ubyte4              seqNumHigh;
    ubyte4              seqNum;
    MSTATUS             status = OK;
    byteBoolean         isTLS11Compatible;
    ubyte4              explicitIVLen;
    ubyte               nilIV[64];
    ubyte4              sizeofRecordHeader;
    ubyte*              tmpData = NULL;
#if defined(__SSL_SINGLE_PASS_SUPPORT__)
    sbyte4              result = -1;
    CipherSuiteInfo*    pCipherSuite = pSSLSock->pActivePeerCipherSuite;
#endif
#if !(MIN_SSL_MINORVERSION <= SSL3_MINORVERSION)
    MOC_UNUSED(protocol);
#endif

    pData = (ubyte *)(pSSLSock->pReceiveBuffer);
    dataLength = pSSLSock->recordSize;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        isTLS11Compatible = TRUE;
        sizeofRecordHeader = sizeof(DTLSRecordHeader);
    } else
#endif
    {
        isTLS11Compatible = (pSSLSock->sslMinorVersion >= TLS11_MINORVERSION);
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    explicitIVLen = (isTLS11Compatible? pComboAlgo->pBEAlgo->blockSize : 0);

    pMacOut = (ubyte *)(pData + dataLength);  /* buffer has padding for a second hash */

    if (isTLS11Compatible)
    {
        DIGI_MEMSET(nilIV, 0x00, 64);
        pIV = nilIV;
    }
    if ((dataLength < (pComboAlgo->pBHAlgo->digestSize + 1)) ||
        ((pComboAlgo->pBEAlgo->blockSize) && (0 != (dataLength % pComboAlgo->pBEAlgo->blockSize))) )
    {
        /* someone mucked with the clear text record size field, */
        /* not revealing anything by breaking out early */
        status = ERR_SSL_CRYPT_BLOCK_SIZE;
        goto exit;
    }

    if (!pSSLSock->isDTLS)
    {
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        /* buffer has leading pad */
        if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            pSeqNum    = (ubyte *)(pData - (3 /* (proto: byte) + (length: 2 byte) */ + SSL_HASH_SEQUENCE_SIZE));
            pSeqNum[SSL_HASH_SEQUENCE_SIZE] = protocol;
            header = pSeqNum;
            headerLength = 3 /* (proto: byte) + (length: 2 byte) */ + SSL_HASH_SEQUENCE_SIZE;
        }
        else
#endif
        {
            pSeqNum    = (ubyte *)(pData - (sizeofRecordHeader + SSL_HASH_SEQUENCE_SIZE));
            header = pSeqNum;
            headerLength = sizeofRecordHeader + SSL_HASH_SEQUENCE_SIZE;
        }

        seqNumHigh = pSSLSock->peerSeqnumHigh;
        seqNum     = pSSLSock->peerSeqnum;

        pSeqNum[0]  = (ubyte)(seqNumHigh >> 24);
        pSeqNum[1]  = (ubyte)(seqNumHigh >> 16);
        pSeqNum[2]  = (ubyte)(seqNumHigh >> 8);
        pSeqNum[3]  = (ubyte)(seqNumHigh);
        pSeqNum[4]  = (ubyte)(seqNum >> 24);
        pSeqNum[5]  = (ubyte)(seqNum >> 16);
        pSeqNum[6]  = (ubyte)(seqNum >> 8);
        pSeqNum[7]  = (ubyte)(seqNum);

        if (0 == (++pSSLSock->peerSeqnum))
            pSSLSock->peerSeqnumHigh++;
    } else
    {
        header = pData - sizeofRecordHeader;
        headerLength = sizeofRecordHeader;
    }

/* TODO: can't do single pass with tls1.1 unless chip supports tls1.1: due to data structure change */
#if defined(__SSL_SINGLE_PASS_SUPPORT__)
    if (NO_SINGLE_PASS != pCipherSuite->sslSinglePassInCookie)
    {
        ubyte4 verified = 0;

#if defined(__SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__)
        /* some chips have a bug in which they do not process the SSL record size correctly for hmac calculations */
        /* we could have hidden this code in hw abstraction layer, but that would have been problematic for SSL-CC. JAB */
        if (pComboAlgo->pBEAlgo->blockSize)
        {
            ubyte*  pDecryptBlock = pSSLSock->pReceiveBuffer + pSSLSock->recordSize - pComboAlgo->pBEAlgo->blockSize;
            ubyte2  adjustSum;

            /* this is only a problem for block ciphers */
            if (OK > (status = (MSTATUS)HWOFFLOAD_doQuickBlockDecrypt(MOC_SYM(pSSLSock->hwAccelCookie) pCipherSuite->sslSinglePassInCookie,
                                                                      pSSLSock->server ? pSSLSock->clientBulkCtx : pSSLSock->serverBulkCtx,  /* key */
                                                                      pDecryptBlock - pComboAlgo->pBEAlgo->blockSize,                      /* incoming iv */
                                                                      pComboAlgo->pBEAlgo->blockSize,                                      /* iv length */
                                                                      pDecryptBlock,                                                         /* decrypt last block */
                                                                      pMacOut)))                                                             /* outgoing iv / original last block of data */
            {
                goto exit;
            }

            /* we can now access the pad length */
            paddingLength = pDecryptBlock[pComboAlgo->pBEAlgo->blockSize - 1];
            adjustSum     = (paddingLength + pComboAlgo->pBHAlgo->digestSize + 1);

            if (adjustSum <= pSSLSock->recordSize)
            {
                /* paddingLength looks acceptable --- we want to adjust the record length in the buffer */
                setShortValue((((SSLRecordHeader *)pSSLSock->pReceiveBuffer) - 1)->recordLength, (ubyte2)(pSSLSock->recordSize - adjustSum));
            }

            /* put the encrypted block back over the last block */
            DIGI_MEMCPY(pDecryptBlock, pMacOut, pComboAlgo->pBEAlgo->blockSize);
        }
#endif /* __SSL_SINGLE_PASS_DECRYPT_ADJUST_SSL_RECORD_SIZE_SUPPORT__ */

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        /* do single pass decryption */
        if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            status = HWOFFLOAD_doSinglePassDecryption(MOC_SYM(pSSLSock->hwAccelCookie) MOCANA_SSL,
                                                      pCipherSuite->sslSinglePassInCookie, SSL3_MINORVERSION,
                                                      pSSLSock->server ? pSSLSock->clientBulkCtx : pSSLSock->serverBulkCtx,
                                                      pSSLSock->server ? pSSLSock->clientMACSecret : pSSLSock->serverMACSecret,
                                                      pComboAlgo->pBHAlgo->digestSize,
                                                      pSeqNum, pSSLSock->recordSize + (3 + SSL_HASH_SEQUENCE_SIZE),
                                                      pSSLSock->pReceiveBuffer, pSSLSock->recordSize,
                                                      NULL,
                                                      pSSLSock->server ? pSSLSock->clientIV : pSSLSock->serverIV,
                                                      pComboAlgo->pBEAlgo->blockSize,
                                                      pMacOut, pComboAlgo->pBHAlgo->digestSize,
                                                      &verified);
        }
        else
#endif
        {
            status = HWOFFLOAD_doSinglePassDecryption(MOC_SYM(pSSLSock->hwAccelCookie) MOCANA_SSL,
                                                      pCipherSuite->sslSinglePassInCookie, pSSLSock->sslMinorVersion,
                                                      pSSLSock->server ? pSSLSock->clientBulkCtx : pSSLSock->serverBulkCtx,
                                                      pSSLSock->server ? pSSLSock->clientMACSecret : pSSLSock->serverMACSecret,
                                                      pComboAlgo->pBHAlgo->digestSize,
                                                      pSeqNum, SSL_HASH_SEQUENCE_SIZE + sizeof(SSLRecordHeader) + pSSLSock->recordSize,
                                                      pSSLSock->pReceiveBuffer, pSSLSock->recordSize,
                                                      NULL,
                                                      pSSLSock->server ? pSSLSock->clientIV : pSSLSock->serverIV,
                                                      pComboAlgo->pBEAlgo->blockSize,
                                                      pMacOut, pComboAlgo->pBHAlgo->digestSize,
                                                      &verified);
        }

        if (0 < pComboAlgo->pBEAlgo->blockSize)
        {
            /* to prevent timing attacks go through all verifications
                even if there is an error in some of them */
            paddingLength = ((ubyte4)(pSSLSock->pReceiveBuffer[pSSLSock->recordSize - 1])) & 0xff;

            if (!(HW_OFFLOAD_PAD_VERIFIED & verified))
            {
                /* padding is (padding[paddingLength] + paddingLength) */
                if (((paddingLength + 1) > (pSSLSock->recordSize - pComboAlgo->pBHAlgo->digestSize)) ||
                    ((SSL3_MINORVERSION == pSSLSock->sslMinorVersion) && (paddingLength >= (sbyte)(pComboAlgo->pBEAlgo->blockSize))) )
                {
                    /* only SSLv3 pad length must be shorter than the block/iv size */
                    if (OK <= status)
                        status = ERR_SSL_INVALID_PADDING;

                    paddingLength = 0;
                }

                padChar = (ubyte)paddingLength;

                if ((TLS10_MINORVERSION <= pSSLSock->sslMinorVersion) && (0 < paddingLength))
                {
                    /* verify padding is filled w/ padChar */
                    for (padLoop = 1; padLoop < (paddingLength + 1); padLoop++)
                        if (padChar != (ubyte)pSSLSock->pReceiveBuffer[pSSLSock->recordSize - 1 - padLoop])
                            if (OK <= status)
                                status = ERR_SSL_INVALID_PADDING;
                }
            }

            if (OK <= status)
                pSSLSock->recordSize -= (1 + paddingLength);
        }

        /* remove MAC size from size of message */
        if (pSSLSock->recordSize >= pComboAlgo->pBHAlgo->digestSize)
        {
            pSSLSock->recordSize -= pComboAlgo->pBHAlgo->digestSize;
        }
        else
        {
            /* runt message */
            status = ERR_SSL_INVALID_MAC;
        }

        if (!(HW_OFFLOAD_MAC_VERIFIED & verified))
        {
            if ((OK > DIGI_CTIME_MATCH(pMacOut, (ubyte *)(pSSLSock->pReceiveBuffer + pSSLSock->recordSize),
                                 pComboAlgo->pBHAlgo->digestSize, &result)) ||
                (0 != result))
            {
                if (OK <= status)
                    status = ERR_SSL_INVALID_MAC;
            }
        }

        goto exit;
    }
#endif /* __SSL_SINGLE_PASS_SUPPORT__ */

    /* decrypt the received record in place */
    status = pComboAlgo->pBEAlgo->cipherFunc(MOC_SYM(pSSLSock->hwAccelCookie)
                    ctx,
                    (ubyte *)pData,
                    dataLength,
                    0, /* decrypt */
                    pIV);

    if (OK > status)
    {
        /* RFC 5246 Section 7.2.2
         * If TLSCiphertext is decrypted in an invalid way, the receiver MUST
	 * terminate the connection with a "bad_record_mac" alert.
         */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, TRUE,
            SSL_ALERT_BAD_RECORD_MAC,
            SSLALERTLEVEL_FATAL);
#endif
        goto exit;
    }

    if (0 < pComboAlgo->pBEAlgo->blockSize)
    {
        /* to prevent timing attacks go through all verifications
            even if there is an error in some of them */
        paddingLength = ((ubyte4)(pData[dataLength - 1])) & 0xff;

        /* padding is (padding[paddingLength] + paddingLength) */
        if (((paddingLength + 1) > (dataLength - pComboAlgo->pBHAlgo->digestSize)) ||
            ((SSL3_MINORVERSION == pSSLSock->sslMinorVersion) && (paddingLength >= (pComboAlgo->pBEAlgo->blockSize))) )
        {
            /* only SSLv3 pad length must be shorter than the block/iv size */
            if (OK <= status)
                status = ERR_SSL_INVALID_PADDING;

            paddingLength = 0;
        }

        padChar = (ubyte)paddingLength;

        if ((TLS10_MINORVERSION <= pSSLSock->sslMinorVersion) && (0 < paddingLength))
        {
            /* verify padding is filled w/ padChar */
            for (padLoop = 1; padLoop < (paddingLength + 1); padLoop++)
                if (padChar != (ubyte)pData[dataLength - 1 - padLoop])
                    if (OK <= status)
                        status = ERR_SSL_INVALID_PADDING;
        }

	    /* Lucky13 protection -- loop over the rest of potential padding */
        {
            MSTATUS tempStatus = DIGI_CALLOC((void **)&tmpData, 1, 256);
            ubyte4 tmpDataLength = dataLength;

            if (OK != tempStatus)
            {
                goto exit;
            }

            dataLength = 255;
            for (padLoop = paddingLength; padLoop < 256; padLoop++)
                if (padChar != tmpData[dataLength - padLoop])
                    if (OK <= tempStatus)
                        tempStatus = ERR_SSL_INVALID_PADDING;

            dataLength = tmpDataLength;
            DIGI_FREE((void **)&tmpData);

            /* Make sure we perform the computation regardless */
            if (OK <= status)
                dataLength -= (1 + paddingLength);
            else
                tmpDataLength -= (1 + paddingLength);
        }
    }

    /* remove MAC size and explicitIVLen from size of message */
    if (dataLength >= (pComboAlgo->pBHAlgo->digestSize + explicitIVLen))
    {
        dataLength -= (pComboAlgo->pBHAlgo->digestSize + explicitIVLen);
    }
    else
    {
        /* runt message */
        status = ERR_SSL_INVALID_MAC;
    }

    /* overwrite with adjusted value, prior to mac calculation */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        setShortValue((((DTLSRecordHeader *)pData) - 1)->recordLength, (ubyte2)dataLength);
    } else
#endif
    {
        setShortValue((((SSLRecordHeader *)pData) - 1)->recordLength, (ubyte2)dataLength);
    }

    /* verify MAC of message (p. 94) */
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        SSL_SOCK_computeSSLMAC(pSSLSock,
                               macSecret,
                               pComboAlgo->pBHAlgo->digestSize,
                               header,
                               (ubyte2)(dataLength + headerLength),
                               pMacOut);
    }
    else
#endif
    {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            DTLSRecordHeader tmpRecordHeader;

            /*
             * since seq_num comes first when generating TLS MAC, we need to reorder
             * DTLS record header so that epoch + sequence number comes before protocol type
             */
            reorderDTLSRecordHeader((ubyte*)header,
                                    (ubyte*)&tmpRecordHeader);

            SSL_SOCK_computeTLSMAC(MOC_HASH(pSSLSock)
                                   macSecret,
                                   (ubyte*)&tmpRecordHeader,
                                   (ubyte2)headerLength,
                                   (ubyte*)pData + explicitIVLen,
                                   (ubyte2)dataLength,
                                   pMacOut,
                                   pComboAlgo->pBHAlgo);
        } else
#endif
        {
            SSL_SOCK_computeTLSMAC(MOC_HASH(pSSLSock)
                                   macSecret,
                                   header,
                                   (ubyte2) headerLength,
                                   (ubyte*)pData + explicitIVLen,
                                   (ubyte2)dataLength,
                                   pMacOut, pComboAlgo->pBHAlgo);
        }
    }
    {
        /* Lucky13 protection --
	 * make sure that we run HMAC data on all our data */
	sbyte4 L1 = 13 + pSSLSock->recordSize - pComboAlgo->pBHAlgo->digestSize;
	sbyte4 L2 = dataLength + headerLength;   /* L1 - paddingLength - 1 */
	sbyte4 bs = pComboAlgo->pBHAlgo->blockSize;
	sbyte4 compressions = ((L1-(bs-9))+(bs-1))/bs - ((L2-(bs-9))+(bs-1))/bs;
	sbyte4 luckyLen = compressions * bs;
	BulkCtx hashCtxt = NULL;

	if (luckyLen < 0)
	    luckyLen = 0;

	if (OK <= pComboAlgo->pBHAlgo->allocFunc(MOC_HASH(pSSLSock->hwAccelCookie) &hashCtxt) &&
	    OK <= pComboAlgo->pBHAlgo->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) hashCtxt))
	{
	    if (luckyLen > 0)
	        pComboAlgo->pBHAlgo->updateFunc(MOC_HASH(pSSLSock->hwAccelCookie) hashCtxt, pData, luckyLen);
	    pComboAlgo->pBHAlgo->freeFunc(MOC_HASH(pSSLSock->hwAccelCookie) &hashCtxt);
    }
    }

    /* For Lucky13, make this a constant-time compare */
    {
        ubyte* p1 = pMacOut;
        ubyte* p2 = (ubyte *)(pData + dataLength + explicitIVLen);
        for (padLoop = 0; padLoop < pComboAlgo->pBHAlgo->digestSize; padLoop++)
            if (*(p1++) != *(p2++))
                if (OK <= status)
                    status = ERR_SSL_INVALID_MAC;
    }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS && OK >= status)
    {
        /* MAC verification succeeded, clear anti-replay window */
        DIGI_MEMSET(pSSLSock->replayWindow, 0x0, sizeof(pSSLSock->replayWindow));

        /* update starting sequence number */
        pSSLSock->windowStartSeqnum     = pSSLSock->peerSeqnum;
        pSSLSock->windowStartSeqnumHigh = pSSLSock->peerSeqnumHigh;

        if (0 == (++pSSLSock->windowStartSeqnum))
            pSSLSock->windowStartSeqnumHigh = (pSSLSock->windowStartSeqnumHigh & 0xffff0000) | ((pSSLSock->windowStartSeqnumHigh + 1) & 0xffff);
    }
#endif

    if (isTLS11Compatible)
    {
        /* for TLS1.1 and up, get rid of the explicit IV after the SRH */
        ubyte* pTransfer;
		pTransfer = (ubyte*)pData;
        /* use memmove to improve performance more */
		DIGI_MEMMOVE(pTransfer, (pData+explicitIVLen), dataLength);
    }
    pSSLSock->recordSize = dataLength;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if ((!pSSLSock->isDTLS) && (SSL3_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        /* for SSL 3.0 only */
        /* version information is checked in processClientHello3,
           so we should restore record header; otherwise, rehandshake fails */
        ubyte* pRH = pData - sizeofRecordHeader;

        pRH[0] = protocol;
        pRH[1] = SSL3_MAJORVERSION;
        pRH[2] = SSL3_MINORVERSION;
    }
#endif

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLComboCipher_decryptVerifyRecord() returns status = ", status);
#endif
    if (ERR_SSL_INVALID_MAC == status || ERR_SSL_INVALID_PADDING == status)
    {
        /* RFC 5246 Section 6.2.3.2 and Section 7.2.2
         * If there is a padding error or invalid mac, the receiver MUST
         * terminate the connection with a "bad_record_mac" alert.
         */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, TRUE,
            SSL_ALERT_BAD_RECORD_MAC,
            SSLALERTLEVEL_FATAL);
#endif
    }

    return status;

} /* decryptVerifyRecord */


/*------------------------------------------------------------------*/

static MSTATUS
SSLComboCipher_formEncryptedRecord(SSLSocket* pSSLSock, ubyte* pData, ubyte2 dataLength, sbyte padLength, const ComboAlgo *pComboAlgo)
{
    /* Complete Message Format: <HMAC sequence : 8 bytes><SSL frame : 5 bytes><message to encrypt><hash><Pad><PadLen byte> */
    /* pData points to message to be encrypted.  An empty 16 byte block is before message for sequence number and SSL frame data */
    BulkCtx             ctx = pSSLSock->server ? pSSLSock->serverBulkCtx : pSSLSock->clientBulkCtx;
    ubyte*              pIV = pSSLSock->server ? pSSLSock->serverIV      : pSSLSock->clientIV;
    ubyte*              macSecret = pSSLSock->server ? pSSLSock->serverMACSecret : pSSLSock->clientMACSecret;
    sbyte4              len;
    MSTATUS             status;
    byteBoolean         isTLS11Compatible;
    ubyte4              explicitIVLen;
    ubyte               nilIV[64];
    ubyte4              sizeofRecordHeader;
    ubyte               *header;
    ubyte4              headerLength;

#if defined(__SSL_SINGLE_PASS_SUPPORT__)
    CipherSuiteInfo*    pCS = pSSLSock->pActiveOwnCipherSuite;
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        isTLS11Compatible = TRUE;
        sizeofRecordHeader = sizeof(DTLSRecordHeader);
    } else
#endif
    {
        isTLS11Compatible = (pSSLSock->sslMinorVersion >= TLS11_MINORVERSION);
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (isTLS11Compatible)
    {
        DIGI_MEMSET(nilIV, 0x00, 64);
        pIV = nilIV;
        explicitIVLen = pComboAlgo->pBEAlgo->blockSize;

        /* for TLS1.1 and up, write the explicit IV at the beginning of pData in the buffer */
        pSSLSock->rngFun(pSSLSock->rngFunArg, explicitIVLen, pData - explicitIVLen);
    } else
    {
        explicitIVLen = 0;
    }

    /* compute mac before encryption */
    /* write mac directly to buffer to avoid an unnecessary copy */
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        header = pData - (SSL_HASH_SEQUENCE_SIZE + 3);
        headerLength = (SSL_HASH_SEQUENCE_SIZE + 3) + dataLength;
    }
    else
#endif
    {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            header = pData - sizeofRecordHeader - explicitIVLen;
            headerLength = sizeofRecordHeader;
        } else
#endif
        {
            header = pData - (SSL_HASH_SEQUENCE_SIZE + sizeofRecordHeader + explicitIVLen);
            headerLength = (SSL_HASH_SEQUENCE_SIZE + sizeofRecordHeader);
        }
    }

    /* pad if block algo */
    len = dataLength + pComboAlgo->pBHAlgo->digestSize;

    if (pComboAlgo->pBEAlgo->blockSize)
    {
        sbyte padChar = (sbyte)(padLength-1);
        sbyte padLoop;

        for (padLoop = 0; padLoop < padLength; padLoop++)
            pData[len++] = padChar;

    }
    len += explicitIVLen;

    /* TODO: can't do single pass with tls1.1 unless chip supports tls1.1: due to data structure change */
#if defined(__SSL_SINGLE_PASS_SUPPORT__)
    if (NO_SINGLE_PASS != pCS->sslSinglePassOutCookie)
    {
        ubyte4 sslFrameSize = sizeof(SSLRecordHeader);

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
            sslFrameSize = 3;
#endif

        /* do single pass encryption */
        status = HWOFFLOAD_doSinglePassEncryption(MOC_SYM(pSSLSock->hwAccelCookie) MOCANA_SSL,
                                                  pCS->sslSinglePassOutCookie, pSSLSock->sslMinorVersion,
                                                  ctx,
                                                  pSSLSock->server ? pSSLSock->serverMACSecret : pSSLSock->clientMACSecret,
                                                  pCS->pCipherAlgo->getFieldFunc(Hash_Size),
                                                  pData - (SSL_HASH_SEQUENCE_SIZE + sslFrameSize),
                                                  (SSL_HASH_SEQUENCE_SIZE + sslFrameSize) + dataLength,
                                                  pData, dataLength + pCS->pCipherAlgo->getFieldFunc(Hash_Size) + padLength,
                                                  NULL,
                                                  pIV, pCS->pCipherAlgo->getFieldFunc(Block_Size),
                                                  pCS->pCipherAlgo->getFieldFunc(Hash_Size), padLength);

        goto exit;
    }
#endif

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    /* compute mac before encryption */
    /* write mac directly to buffer to avoid an unnecessary copy */
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        status = SSL_SOCK_computeSSLMAC(pSSLSock,
                                        macSecret,
                                        pComboAlgo->pBHAlgo->digestSize,
                                        header,
                                        (ubyte2) headerLength,
                                        pData + dataLength);
    }
    else
#endif
    {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            DTLSRecordHeader tmpRecordHeader;

            /*
             * since seq_num comes first when generating TLS MAC, we need to reorder
             * DTLS record header so that epoch + sequence number comes before protocol type
             */
            reorderDTLSRecordHeader((ubyte*)header,
                                    (ubyte*)&tmpRecordHeader);

            status = SSL_SOCK_computeTLSMAC(MOC_HASH(pSSLSock)
                                            macSecret,
                                            (ubyte*)&tmpRecordHeader,
                                            headerLength,
                                            pData,
                                            dataLength,
                                            pData + dataLength, /* mac */
                                            pComboAlgo->pBHAlgo);
        } else
#endif
        {
            status = SSL_SOCK_computeTLSMAC(MOC_HASH(pSSLSock)
                                            macSecret,
                                            header,
                                            (ubyte2) headerLength,
                                            pData,
                                            dataLength,
                                            pData + dataLength, /* mac */
                                            pComboAlgo->pBHAlgo);
        }
    }

    if (OK > status)
        goto exit;

    status = pComboAlgo->pBEAlgo->cipherFunc(MOC_SYM(pSSLSock->hwAccelCookie) ctx, pData - explicitIVLen, len, TRUE, pIV);
exit:
    return status;

} /* formEncryptedRecord */

/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_AEAD_CIPHER__)
/* Generic AEAD cipher implementations */

static BulkCtx

SSLAeadCipher_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, ubyte4 keySize, sbyte4 encrypt, const AeadAlgo *pAeadAlgo)
{
    return pAeadAlgo->createFunc(MOC_SYM(hwAccelCtx) key, keySize, encrypt);
}

static MSTATUS
SSLAeadCipher_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx, const AeadAlgo *pAeadAlgo)
{
    return pAeadAlgo->deleteFunc(MOC_SYM(hwAccelCtx) ctx);
}

static MSTATUS
SSLAeadCipher_decryptVerifyRecord(SSLSocket* pSSLSock, ubyte protocol,
                                  ubyte nonceStyle, const AeadAlgo *pAeadAlgo)
{
    ubyte*              header;
    ubyte*              pData;
    ubyte4              dataLength;
    BulkCtx             ctx = pSSLSock->server ? pSSLSock->clientBulkCtx : pSSLSock->serverBulkCtx;
    ubyte*              pImplicitNonce = pSSLSock->server ? pSSLSock->clientIV : pSSLSock->serverIV ;
    ubyte*              pSeqNum=0;
    ubyte4              seqNumHigh;
    ubyte4              seqNum;
    MSTATUS             status = OK;
    ubyte*              explicitNonce;
    ubyte4              explicitNonceLen;
    ubyte4              sizeofRecordHeader;
    ubyte               nonce[MAX_AEAD_NONCE_LEN] = {0};
    ubyte*              aData = NULL;
    ubyte4              aDataLen = 0;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    ubyte               aDataBuf[16]; /* only going to use 13 bytes */
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte pSeqTls13[8];
#endif /* __ENABLE_DIGICERT_TLS13__ */
    MOC_UNUSED(protocol);

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    DTLSRecordHeader    *pHeader;
    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
             sizeofRecordHeader = pSSLSock->sharedInBufferLen;
        else
#endif
             sizeofRecordHeader = sizeof(DTLSRecordHeader);
    } else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    pData = (ubyte *)(pSSLSock->pReceiveBuffer);
    dataLength = pSSLSock->recordSize;

    /* The data should have a nonce and tag, so the dataLength should be atleast the sum of tagSize and explicitNonceSize */
    if (dataLength < (pAeadAlgo->explicitNonceSize + pAeadAlgo->tagSize))
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

    explicitNonceLen = pAeadAlgo->explicitNonceSize;
    /* This is the sequence number */
    explicitNonce = pData;

    /* now pData starts from the real data content */
    pData = pData + explicitNonceLen;
    dataLength -= (explicitNonceLen + pAeadAlgo->tagSize);

    if (!pSSLSock->isDTLS)
    {
#if defined(__ENABLE_DIGICERT_TLS13__)
        if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            aData = pData - sizeofRecordHeader;
            aDataLen = sizeofRecordHeader;
            pSeqNum = pSeqTls13;
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            ubyte2 tmpRecordSize = getShortValue(((SSLRecordHeader *)(pData - sizeofRecordHeader - explicitNonceLen))->recordLength);
            /* buffer has leading pad */
            pSeqNum    = (ubyte *)(pData - (sizeofRecordHeader + SSL_HASH_SEQUENCE_SIZE + explicitNonceLen));
            /* adjust the record size before decryption: recordSize -= tagSize + explicitIVLen */
            setShortValue(((SSLRecordHeader *)(pData - sizeofRecordHeader - explicitNonceLen))->recordLength, (ubyte2)(tmpRecordSize - explicitNonceLen - pAeadAlgo->tagSize));

            header = pSeqNum;

            aData = header;
            aDataLen = SSL_HASH_SEQUENCE_SIZE + 5;

        }

        seqNumHigh = pSSLSock->peerSeqnumHigh;
        seqNum     = pSSLSock->peerSeqnum;

        pSeqNum[0]  = (ubyte)(seqNumHigh >> 24);
        pSeqNum[1]  = (ubyte)(seqNumHigh >> 16);
        pSeqNum[2]  = (ubyte)(seqNumHigh >> 8);
        pSeqNum[3]  = (ubyte)(seqNumHigh);
        pSeqNum[4]  = (ubyte)(seqNum >> 24);
        pSeqNum[5]  = (ubyte)(seqNum >> 16);
        pSeqNum[6]  = (ubyte)(seqNum >> 8);
        pSeqNum[7]  = (ubyte)(seqNum);

        if (0 == (++pSSLSock->peerSeqnum))
            pSSLSock->peerSeqnumHigh++;
    }
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    else
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            pSeqNum = pSeqTls13;
            seqNumHigh = pSSLSock->peerSeqnumHigh;
            seqNum     = pSSLSock->peerSeqnum;

            /* first two bytes of of seqNumHigh are the epoch, don't copy */
            pSeqNum[0]  = 0x0;
            pSeqNum[1]  = 0x0;
            pSeqNum[2]  = (ubyte)(seqNumHigh >> 8);
            pSeqNum[3]  = (ubyte)(seqNumHigh);
            pSeqNum[4]  = (ubyte)(seqNum >> 24);
            pSeqNum[5]  = (ubyte)(seqNum >> 16);
            pSeqNum[6]  = (ubyte)(seqNum >> 8);
            pSeqNum[7]  = (ubyte)(seqNum);

            aData = pSSLSock->pSharedInBuffer;
            aDataLen = pSSLSock->sharedInBufferLen;
        }
        else
#endif
        {
            ubyte2 tmpRecordSize;
            header = pData - sizeofRecordHeader - explicitNonceLen;

            pHeader = (DTLSRecordHeader*)header;
            pSeqNum = pHeader->epoch;
            /* copy out the a data from the record header */
            DIGI_MEMCPY(aDataBuf, pHeader->epoch, sizeof(pHeader->epoch));
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch), pHeader->seqNo, sizeof(pHeader->seqNo));
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo), &pHeader->protocol, 1);
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo)+1, &pHeader->majorVersion, 1);
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo)+1 +1, &pHeader->minorVersion, 1);
            /* adjust the record size before decryption: recordSize -= tagSize + explicitIVLen */
            tmpRecordSize = getShortValue(pHeader->recordLength);

            setShortValue(pHeader->recordLength, (ubyte2)(tmpRecordSize - explicitNonceLen - pAeadAlgo->tagSize));

            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo)+1 +1+ 1, pHeader->recordLength, 2);

            aData = aDataBuf;
            aDataLen = sizeof(pHeader->epoch)+sizeof(pHeader->seqNo) +1 +1 +1 +2;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
     || DTLS13_MINORVERSION == pSSLSock->sslMinorVersion
#endif
       )
    {
        nonceStyle = pSSLSock->sslMinorVersion;
    }
#endif
    switch (nonceStyle)
    {
        case TLS12_MINORVERSION:
            /* initializ nonce= implicitNonce + explicitNonce */
            DIGI_MEMCPY(nonce, pImplicitNonce, pAeadAlgo->implicitNonceSize);
            /* the explicitNonce is using the sequence number */
            DIGI_MEMCPY(nonce+pAeadAlgo->implicitNonceSize,
                       explicitNonce, explicitNonceLen);
            break;

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        case DTLS13_MINORVERSION:
#endif
        case TLS13_MINORVERSION:
            DIGI_MEMCPY(nonce, pImplicitNonce, pAeadAlgo->implicitNonceSize);
            /* XOR with Big End 64 bit sequence number padded to 0 */
            DIGI_XORCPY(nonce + pAeadAlgo->implicitNonceSize - 8, pSeqNum, 8);
            break;

        default:
            status = ERR_SSL_CONFIG;
            goto exit;
            break;
    }

    /* decrypt the received record in place */
    status = pAeadAlgo->cipherFunc(MOC_SYM(pSSLSock->hwAccelCookie) ctx, nonce,
                                   pAeadAlgo->implicitNonceSize + explicitNonceLen,
                                   aData, aDataLen, pData, dataLength,
                                   pAeadAlgo->tagSize, FALSE);

    if (OK > status)
    {
        /* RFC 5246 Section 6.2.3.3 and RFC 8446 Section 5.2
         *      If the decryption fails, the receiver MUST terminate the connection
         *      with a "bad_record_mac" alert.
         */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, TRUE,
                SSL_ALERT_BAD_RECORD_MAC,
                SSLALERTLEVEL_FATAL);
#endif
        goto exit;
    }

    {
        /* for TLS1.1 and up, get rid of the explicit IV after the SRH */
        ubyte* pTransfer;
        ubyte4 i;

        for (pTransfer = (ubyte*)pData-explicitNonceLen, i = 0; i < dataLength; i++, pTransfer++)
        {
            *pTransfer = pData[i];
        }

        /* RFC 8446 Section 5.2
         *
         * According to RFC 8446 section 5.2 the protected payload will contain
         * the data, along with a single byte indicating the ContentType, and
         * an optional padding of all zeroes.
         */
        if ( (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
              (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            /* There must be at least a single byte for the ContentType.
             */
            if (0 == dataLength)
            {
                status = ERR_BAD_LENGTH;
                goto exit;
            }

            while ( (dataLength != 0) && (0 == pData[--dataLength]) );

            /* The last byte will dicate the content type.
             */
            pSSLSock->protocol = pData[dataLength];
        }
    }
    pSSLSock->recordSize = dataLength;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS && status == OK)
    {
        /* MAC verification succeeded, clear anti-replay window */
        DIGI_MEMSET(pSSLSock->replayWindow, 0x0, sizeof(pSSLSock->replayWindow));

        /* update starting sequence number */
        pSSLSock->windowStartSeqnum     = pSSLSock->peerSeqnum;
        pSSLSock->windowStartSeqnumHigh = pSSLSock->peerSeqnumHigh;

        if (0 == (++pSSLSock->windowStartSeqnum))
            pSSLSock->windowStartSeqnumHigh = (pSSLSock->windowStartSeqnumHigh & 0xffff0000) | ((pSSLSock->windowStartSeqnumHigh + 1) & 0xffff);
    }
#endif

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLAeadCipher_decryptVerifyRecord() returns status = ", status);
#endif

    return status;

} /* decryptVerifyRecord */


/*------------------------------------------------------------------*/

static MSTATUS
SSLAeadCipher_formEncryptedRecord(SSLSocket* pSSLSock,
                                  ubyte* pData, ubyte2 dataLength,
                                  sbyte padLength, ubyte nonceStyle,
                                  const AeadAlgo *pAeadAlgo)
{
    /* Complete Message Format: <HMAC sequence : 8 bytes><SSL frame : 5 bytes><message to encrypt>*/
    /* pData points to message to be encrypted.  An empty 16 byte block is before message for sequence number and SSL frame data */
    BulkCtx             ctx = pSSLSock->server ? pSSLSock->serverBulkCtx : pSSLSock->clientBulkCtx;
    ubyte*              pImplicitNonce = pSSLSock->server ? pSSLSock->serverIV : pSSLSock->clientIV;
    MSTATUS             status;
    ubyte4              sizeofRecordHeader;
    ubyte*              header;
    ubyte*              explicitNonce;
    ubyte4              explicitNonceLen;
    ubyte               nonce[MAX_AEAD_NONCE_LEN] = {0};
    ubyte*              aData = NULL;
    ubyte4              aDataLen = 0;
    ubyte*              pSeqNum=0;

    MOC_UNUSED(padLength);

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#if defined(__ENABLE_DIGICERT_TLS13__)
    ubyte               pSeqBuffer[8];
#endif
    ubyte               aDataBuf[16]; /* only going to use 11 bytes */
    DTLSRecordHeader    *pHeader;

    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            sizeofRecordHeader = DTLS13_MOC_RECORD_HEADER_LEN; /* 5 */
        else
#endif
            sizeofRecordHeader = sizeof(DTLSRecordHeader);
    } else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
    }

    explicitNonceLen = pAeadAlgo->explicitNonceSize;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    explicitNonce = pData - explicitNonceLen;

    /* adata = seq_num + message_type + version + length */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            aDataLen = DTLS13_MOC_RECORD_HEADER_LEN;
            DIGI_MEMCPY(aDataBuf, pData - DTLS13_MOC_RECORD_HEADER_LEN, aDataLen);
            aData = aDataBuf;

            ubyte4 seqNumHigh = pSSLSock->ownSeqnumHigh;
            ubyte4 seqNum     = pSSLSock->ownSeqnum - 1;

            /* first two bytes of of seqNumHigh are the epoch, don't copy */
            pSeqBuffer[0]  = 0x00;
            pSeqBuffer[1]  = 0x00;
            pSeqBuffer[2]  = (ubyte)(seqNumHigh >> 8);
            pSeqBuffer[3]  = (ubyte)(seqNumHigh);
            pSeqBuffer[4]  = (ubyte)(seqNum >> 24);
            pSeqBuffer[5]  = (ubyte)(seqNum >> 16);
            pSeqBuffer[6]  = (ubyte)(seqNum >> 8);
            pSeqBuffer[7]  = (ubyte)(seqNum);
            pSeqNum = (ubyte *) pSeqBuffer;
        }
        else
#endif
        {
            header = pData - sizeofRecordHeader - explicitNonceLen;
            pHeader = (DTLSRecordHeader*)header;
            header = pHeader->epoch;
            pSeqNum = pHeader->epoch;
            /* copy out the a data from the record header */
            DIGI_MEMCPY(aDataBuf, pHeader->epoch, sizeof(pHeader->epoch));
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch), pHeader->seqNo, sizeof(pHeader->seqNo));
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo), &pHeader->protocol, 1);
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo)+1, &pHeader->majorVersion, 1);
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo)+1 +1, &pHeader->minorVersion, 1);
            DIGI_MEMCPY(aDataBuf+sizeof(pHeader->epoch)+sizeof(pHeader->seqNo)+1 + 1+ 1, &pHeader->recordLength, 2);

            aData = aDataBuf;
            aDataLen = sizeof(pHeader->epoch) + sizeof(pHeader->seqNo)+1 + 1+ 1 + 2;

            /* the explicitNonce is using the sequence number */
            DIGI_MEMCPY(explicitNonce, ((DTLSRecordHeader*) header)->epoch, explicitNonceLen);
        }
    }
    else
#endif
    {
        pSeqNum = (ubyte *)(pData - (SSL_HASH_SEQUENCE_SIZE + sizeofRecordHeader + explicitNonceLen));
        header = pSeqNum;
#ifdef __ENABLE_DIGICERT_TLS13__
        if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            aData = header + SSL_HASH_SEQUENCE_SIZE;
            aDataLen = 5;
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            aData = header;
            aDataLen = SSL_HASH_SEQUENCE_SIZE+5;
        }

        /* the explicitNonce is using the sequence number */
        DIGI_MEMCPY(explicitNonce, header, explicitNonceLen);
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
     || DTLS13_MINORVERSION == pSSLSock->sslMinorVersion
#endif
       )
    {
        nonceStyle = pSSLSock->sslMinorVersion;
    }
#endif
    switch (nonceStyle)
    {
        case TLS12_MINORVERSION:
            /* initializ nonce= implicitNonce + explicitNonce */
            DIGI_MEMCPY(nonce, pImplicitNonce, pAeadAlgo->implicitNonceSize);
            /* the explicitNonce is using the sequence number */
            DIGI_MEMCPY(nonce+pAeadAlgo->implicitNonceSize,
                       explicitNonce, explicitNonceLen);
            break;

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        case DTLS13_MINORVERSION:
#endif
        case TLS13_MINORVERSION:
            DIGI_MEMCPY(nonce, pImplicitNonce, pAeadAlgo->implicitNonceSize);
            DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"Form Encrypted Record: nonce");
            DEBUG_HEXDUMP(DEBUG_SSL_TRANSPORT, nonce, MAX_AEAD_NONCE_LEN);
            /* According to RFC 8446 section 5.3 the nonce must be XOR'd with
             * the sequence number.
             */
            DIGI_XORCPY(nonce + pAeadAlgo->implicitNonceSize - 8, pSeqNum, 8);
            break;

        default:
            status = ERR_SSL_CONFIG;
            goto exit;
            break;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"Form Encrypted Record: nonce");
    DEBUG_HEXDUMP(DEBUG_SSL_TRANSPORT, nonce, pAeadAlgo->implicitNonceSize + explicitNonceLen);
    DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"Form Encrypted Record: implicit nonce");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
#if (!defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && !defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (!pSSLSock->isDTLS)
    {
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte *)"Form Encrypted Record: seqNum");
        DEBUG_HEXDUMP(DEBUG_SSL_TRANSPORT, pSeqNum, explicitNonceLen);
        DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)"");
    }
#endif
#endif

    status = pAeadAlgo->cipherFunc(MOC_SYM(pSSLSock->hwAccelCookie) ctx, nonce,
                                   pAeadAlgo->implicitNonceSize + explicitNonceLen,
                                   aData, aDataLen, pData, dataLength,
                                   pAeadAlgo->tagSize, TRUE);

exit:
    return status;

} /* formEncryptedRecord */

#endif /* #if defined(__ENABLE_DIGICERT_AEAD_CIPHER__) */

/*------------------------------------------------------------------*/

static MSTATUS
sendDataSSL(SSLSocket* pSSLSock, ubyte protocol, const sbyte* data, sbyte4 dataSize, intBoolean skipEmptyMesg)
{
    ubyte*           pFreeBuffer = NULL;
    ubyte*           pSendBuffer;
    sbyte4           emptyRecordLen;
    sbyte4           chunkLen;
    sbyte4           padLenEmpty = 0;
    sbyte4           padLenMessage;
    ubyte4           sendBufferLen;
    SSLRecordHeader* pRecordHeaderEmpty;
    SSLRecordHeader* pRecordHeaderMessage;
    const CipherSuiteInfo* pCS = pSSLSock->pActiveOwnCipherSuite;
    ubyte4           numBytesSent = 0;
    ubyte4           numBytesSocketSent = 0;
    ubyte4           seqNumHigh;
    ubyte4           seqNum;
    ubyte*           pSeqNumEmpty = NULL;
    ubyte*           pSeqNumMessage;
    MSTATUS          status = OK;
    byteBoolean      isTLS11Compatible;
    ubyte4           explicitIVLen;
    ubyte4           hashOrTagLen;
    /* RFC 8446 Section 5.2
     *
     * This is the extra byte required for TLS 1.3 which the peer will use to
     * determine the content type of the data.
     */
    ubyte            contentTypeLen = 0;

#ifdef __ENABLE_DIGICERT_TLS13__
    if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        contentTypeLen = 1;
#endif
    isTLS11Compatible = (pSSLSock->sslMinorVersion >= TLS11_MINORVERSION);
    explicitIVLen = EXPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS);
    hashOrTagLen = pCS->pCipherAlgo->getFieldFunc(TagLen) == 0? pCS->pCipherAlgo->getFieldFunc(Hash_Size) : pCS->pCipherAlgo->getFieldFunc(TagLen);

    /* compute the maximum data that can be sent in one record */
    chunkLen = SSL_RECORDSIZE; /* The maximum data sent in one record can be 16K (this is excluding the mac appended to the record) */
    if (chunkLen > dataSize)
    {
        /* no reason to allocate more than required */
        chunkLen = dataSize;
    }

    /* CBCATTACK counter measures is only on if
     * 1. using block cipher;
     * and 2. not TLS1.1 or up
     * and 3. not single record msgs such as changeCipherSuite or Finished
     * and 4. flag is turned on
     */
    if ((!isTLS11Compatible) && pCS->pCipherAlgo->getFieldFunc(Block_Size) && (TRUE != skipEmptyMesg) && (0 != (pSSLSock->runtimeFlags & SSL_FLAG_ENABLE_SEND_EMPTY_FRAME)))
    {
        padLenEmpty    = computePadLength(pCS->pCipherAlgo->getFieldFunc(Hash_Size), pCS->pCipherAlgo->getFieldFunc(Block_Size));
        emptyRecordLen = SSL_MALLOC_BLOCK_SIZE + pCS->pCipherAlgo->getFieldFunc(Hash_Size) + padLenEmpty;       /* this result will be a multiple of the IV */
        sendBufferLen  = pCS->pCipherAlgo->getFieldFunc(Hash_Size) + padLenEmpty + sizeof(SSLRecordHeader);
    }
    else
    {
        emptyRecordLen = 0;
        sendBufferLen  = 0;
    }

    /* enough space for everything */
    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie,
                                    emptyRecordLen + SSL_MALLOC_BLOCK_SIZE + explicitIVLen + chunkLen +
                                    SSL_MAXDIGESTSIZE + SSL_MAXIVSIZE + SSL_MALLOC_BLOCK_SIZE,
                                    TRUE, (void **)&pFreeBuffer)))
    {
        goto exit;
    }

    /* these fields never change */
    pRecordHeaderEmpty   = (SSLRecordHeader *)((pFreeBuffer + SSL_MALLOC_BLOCK_SIZE) - sizeof(SSLRecordHeader));
    pRecordHeaderMessage = (SSLRecordHeader *)((pFreeBuffer + emptyRecordLen + SSL_MALLOC_BLOCK_SIZE) - sizeof(SSLRecordHeader));

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        pSeqNumMessage = pFreeBuffer + emptyRecordLen + SSL_MALLOC_BLOCK_SIZE - (SSL_HASH_SEQUENCE_SIZE + 3);
    }
    else
#endif
    {
        pSeqNumMessage = ((ubyte *)(pRecordHeaderMessage)) - SSL_HASH_SEQUENCE_SIZE;

        pRecordHeaderMessage->majorVersion = SSL3_MAJORVERSION;
#ifdef __ENABLE_DIGICERT_TLS13__
        if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            pRecordHeaderMessage->protocol     = SSL_APPLICATION_DATA;
            pRecordHeaderMessage->minorVersion = pSSLSock->legacySSLMinorVersion;
        }
        else
#endif
        {
            pRecordHeaderMessage->protocol     = protocol;
            pRecordHeaderMessage->minorVersion = pSSLSock->sslMinorVersion;
        }
    }

    pSendBuffer = (ubyte *)pRecordHeaderMessage;

    if (emptyRecordLen)
    {
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            pSeqNumEmpty = pFreeBuffer + SSL_MALLOC_BLOCK_SIZE - (SSL_HASH_SEQUENCE_SIZE + 3);
        }
        else
#endif
        {
            pSeqNumEmpty = ((ubyte *)(pRecordHeaderEmpty)) - SSL_HASH_SEQUENCE_SIZE;

            pRecordHeaderEmpty->protocol     = protocol;
            pRecordHeaderEmpty->majorVersion = SSL3_MAJORVERSION;


#if defined(__ENABLE_DIGICERT_TLS13__)
            if (pSSLSock->sslMinorVersion == TLS13_MINORVERSION)
            {
                pRecordHeaderMessage->minorVersion = pSSLSock->legacySSLMinorVersion;
            }
            else
#endif
            {
                pRecordHeaderMessage->minorVersion = pSSLSock->sslMinorVersion;
            }
        }

        pSendBuffer = ((ubyte *)pRecordHeaderMessage) - (hashOrTagLen + padLenEmpty + sizeof(SSLRecordHeader));
    }

    /* compute pad length for encrypted message */
    padLenMessage = computePadLength(chunkLen + pCS->pCipherAlgo->getFieldFunc(Hash_Size), pCS->pCipherAlgo->getFieldFunc(Block_Size));

    /* set the length of the first n chunk records */
    sendBufferLen += (ubyte4)(sizeof(SSLRecordHeader) + explicitIVLen + chunkLen + hashOrTagLen + padLenMessage + contentTypeLen);

    /* this loop is a bit misleading -- used only when writing to socket */
    while ((status >= OK) && (dataSize > 0))
    {
        if (dataSize < chunkLen)
        {
            if (emptyRecordLen)
                sendBufferLen = hashOrTagLen + padLenEmpty + sizeof(SSLRecordHeader);
            else
                sendBufferLen = 0;

            /* compute pad length for encrypted message */
            padLenMessage = computePadLength(dataSize + pCS->pCipherAlgo->getFieldFunc(Hash_Size), pCS->pCipherAlgo->getFieldFunc(Block_Size));

            sendBufferLen += (ubyte4)(sizeof(SSLRecordHeader) + explicitIVLen + dataSize + hashOrTagLen + padLenMessage + contentTypeLen);
            chunkLen = dataSize;
        }

        if (emptyRecordLen)
        {
            seqNumHigh = pSSLSock->ownSeqnumHigh;
            seqNum     = pSSLSock->ownSeqnum;

            pSeqNumEmpty[0]  = (ubyte)(seqNumHigh >> 24);
            pSeqNumEmpty[1]  = (ubyte)(seqNumHigh >> 16);
            pSeqNumEmpty[2]  = (ubyte)(seqNumHigh >> 8);
            pSeqNumEmpty[3]  = (ubyte)(seqNumHigh);
            pSeqNumEmpty[4]  = (ubyte)(seqNum >> 24);
            pSeqNumEmpty[5]  = (ubyte)(seqNum >> 16);
            pSeqNumEmpty[6]  = (ubyte)(seqNum >> 8);
            pSeqNumEmpty[7]  = (ubyte)(seqNum);

            pSeqNumEmpty[8]  = (ubyte)(protocol);

            if (0 == (++pSSLSock->ownSeqnum))
                pSSLSock->ownSeqnumHigh++;

            setShortValue(pRecordHeaderEmpty->recordLength, (ubyte2)0);

            /* create an empty record */
            if (OK > (status = pCS->pCipherAlgo->encryptRecordFunc(pSSLSock, ((ubyte *)(pRecordHeaderEmpty + 1)), 0, (sbyte)padLenEmpty)))
                goto exit;

            setShortValue(pRecordHeaderEmpty->recordLength, (ubyte2)(hashOrTagLen + padLenEmpty));
        }

        seqNumHigh = pSSLSock->ownSeqnumHigh;
        seqNum     = pSSLSock->ownSeqnum;

        pSeqNumMessage[0]  = (ubyte)(seqNumHigh >> 24);
        pSeqNumMessage[1]  = (ubyte)(seqNumHigh >> 16);
        pSeqNumMessage[2]  = (ubyte)(seqNumHigh >> 8);
        pSeqNumMessage[3]  = (ubyte)(seqNumHigh);
        pSeqNumMessage[4]  = (ubyte)(seqNum >> 24);
        pSeqNumMessage[5]  = (ubyte)(seqNum >> 16);
        pSeqNumMessage[6]  = (ubyte)(seqNum >> 8);
        pSeqNumMessage[7]  = (ubyte)(seqNum);

#if defined(__ENABLE_DIGICERT_TLS13__)
        if (TLS13_MINORVERSION > pSSLSock->sslMinorVersion)
#endif
            pSeqNumMessage[8]  = (ubyte)(protocol);

        if (0 == (++pSSLSock->ownSeqnum))
            pSSLSock->ownSeqnumHigh++;

        /* duplicate message data */
        if (OK > (status = DIGI_MEMCPY(((ubyte *)(pRecordHeaderMessage + 1)) + explicitIVLen, data, chunkLen)))
            goto exit;

        /* TLS 1.3 uses the record header as the additional data for the AEAD
         * encrypt operation. The length in this header must be the total
         * amount of data encrypted plus any additional data added by the AEAD
         * encipherment. There is also an extra byte required for the content
         * type.
         *
         * TLS 1.2 and below only requires the length to be set to the total
         * amount of data being encrypted. However, once the data has been
         * encrypted it must be updated to the actual length produced by the
         * encryption.
         */
#ifdef __ENABLE_DIGICERT_TLS13__
        if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            *(((ubyte *) (pRecordHeaderMessage + 1)) + chunkLen) = (ubyte) protocol;
            setShortValue(pRecordHeaderMessage->recordLength, (ubyte2)chunkLen + hashOrTagLen + contentTypeLen);
        }
        else
#endif
        {
            setShortValue(pRecordHeaderMessage->recordLength, (ubyte2)chunkLen);
        }

        /* create real message record */
        if (OK > (status = pCS->pCipherAlgo->encryptRecordFunc(pSSLSock, ((ubyte *)(pRecordHeaderMessage + 1)) + explicitIVLen, (ubyte2)(chunkLen + contentTypeLen), (sbyte)padLenMessage)))
            goto exit;

        /* For TLS 1.2 and below the length was set to the length of the data
         * to encrypt, but when sending the actual record, the record length
         * must also include the length of the data along with any addional data
         * the encryption process created.
         */
#ifdef __ENABLE_DIGICERT_TLS13__
        if ((pSSLSock->isDTLS) || (TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
#endif
        {
            setShortValue(pRecordHeaderMessage->recordLength, (ubyte2)(explicitIVLen + chunkLen + hashOrTagLen + padLenMessage));
        }

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
        if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            pRecordHeaderMessage->protocol     = protocol;
            pRecordHeaderMessage->majorVersion = SSL3_MAJORVERSION;
            pRecordHeaderMessage->minorVersion = SSL3_MINORVERSION;
        }
#endif
        if (emptyRecordLen)
        {
            ubyte* pTransfer = ((ubyte *)pRecordHeaderMessage);
            sbyte4 i;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
            if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                pRecordHeaderEmpty->protocol     = protocol;
                pRecordHeaderEmpty->majorVersion = SSL3_MAJORVERSION;
                pRecordHeaderEmpty->minorVersion = SSL3_MINORVERSION;
            }
#endif
            /* move empty record byte adjacent to real message */
            for (pTransfer--, i = (sizeof(SSLRecordHeader) + hashOrTagLen + padLenEmpty); 0 < i; i--, pTransfer--)
            {
                *pTransfer = ((ubyte *)pRecordHeaderEmpty)[i - 1];
            }
        }

        data += chunkLen;
        dataSize -= chunkLen;
        numBytesSent += chunkLen;

        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            if (NULL == pSSLSock->pOutputBufferBase)
            {
                pSSLSock->pOutputBufferBase = pFreeBuffer;
                pSSLSock->pOutputBuffer     = pSendBuffer;
                pSSLSock->outputBufferSize  = emptyRecordLen + SSL_MALLOC_BLOCK_SIZE + explicitIVLen + chunkLen + SSL_MAXDIGESTSIZE + SSL_MAXIVSIZE;
                pSSLSock->numBytesToSend    = sendBufferLen;
                status = (MSTATUS) pSSLSock->numBytesToSend;
                pFreeBuffer                 = NULL;

                /* Sequence number overflowed. Perform renegotiation */
                if (0 == pSSLSock->ownSeqnum && 0 == pSSLSock->ownSeqnumHigh)
                {
                    DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"sendDataSSL() Sequence number overflow");
#if defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)
                    status = SSLSOCK_initiateRehandshake(pSSLSock);
                    if (OK > status)
                    {
                        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSLSOCK_initiateRehandshake() failed");
                        goto exit;
                    }
#else
                    status = pSSLSock->server ? ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED : ERR_SSL_CLIENT_RENEGOTIATE_NOT_ALLOWED;
                    goto exit;
#endif
                }

                /* EXIT before all data has been sent */
                goto exit;
            }
            else
            {
                if (pSSLSock->outputBufferSize <
                             pSSLSock->numBytesToSend + sendBufferLen)
                {
                    /* Need to Realloc this buffer */
                    ubyte * output = (ubyte*) MALLOC(pSSLSock->numBytesToSend + sendBufferLen);
                    if (NULL == output)
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }
                    DIGI_MEMCPY(output, pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
                    pSSLSock->outputBufferSize  = pSSLSock->numBytesToSend + sendBufferLen;
                    FREE(pSSLSock->pOutputBufferBase);
                    pSSLSock->pOutputBufferBase = output;

                }
                else
                {
                    if (pSSLSock->pOutputBufferBase != pSSLSock->pOutputBuffer)
                        DIGI_MEMMOVE(pSSLSock->pOutputBufferBase, pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
                }

                pSSLSock->pOutputBuffer      = pSSLSock->pOutputBufferBase + pSSLSock->numBytesToSend;
                DIGI_MEMCPY(pSSLSock->pOutputBuffer, pSendBuffer, sendBufferLen);
                pSSLSock->pOutputBuffer      = pSSLSock->pOutputBufferBase;
                pSSLSock->numBytesToSend    += sendBufferLen;
                CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pFreeBuffer);
                pFreeBuffer                 = NULL;

                /* EXIT before all data has been sent */
                goto exit;
            }
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
            if (NULL != pSSLSock->pTransportHandler)
            {
                if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
                {
                    if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId, 
                                                                                         (sbyte *)pSendBuffer, sendBufferLen, &numBytesSocketSent)))
                    {
                        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                        goto exit;
                    }
                }
                else
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
            }
            else
#endif
            {
#ifndef __DIGICERT_IPSTACK__
                if (OK > (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSendBuffer, sendBufferLen, &numBytesSocketSent)))
#else
                if (OK > (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSendBuffer, sendBufferLen, &numBytesSocketSent)))
#endif
                {
                    goto exit;
                }
            }
            /* Sequence number overflowed. Perform renegotiation */
            if (0 == pSSLSock->ownSeqnum && 0 == pSSLSock->ownSeqnumHigh)
            {
                DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"sendDataSSL() Sequence number overflow");
#if defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)
                status = SSLSOCK_initiateRehandshake(pSSLSock);
                if (OK > status)
                {
                    DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSLSOCK_initiateRehandshake() failed");
                    goto exit;
                }
#else
                status = pSSLSock->server ? ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED : ERR_SSL_CLIENT_RENEGOTIATE_NOT_ALLOWED;
                goto exit;
#endif
            }

        }

        if (numBytesSocketSent != sendBufferLen)
        {
            pSSLSock->pOutputBufferBase = pFreeBuffer;
            pSSLSock->pOutputBuffer     = numBytesSocketSent + pSendBuffer;
            pSSLSock->outputBufferSize  = emptyRecordLen + SSL_MALLOC_BLOCK_SIZE + explicitIVLen + chunkLen + SSL_MAXDIGESTSIZE + SSL_MAXIVSIZE;
            pSSLSock->numBytesToSend    = sendBufferLen - numBytesSocketSent;

            pFreeBuffer                 = NULL;

            /* Sequence number overflowed. Perform renegotiation */
            if (0 == pSSLSock->ownSeqnum && 0 == pSSLSock->ownSeqnumHigh)
            {
                DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"sendDataSSL() Sequence number overflow");
#if defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)
                status = SSLSOCK_initiateRehandshake(pSSLSock);
                if (OK > status)
                {
                    DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"SSLSOCK_initiateRehandshake() failed");
                    goto exit;
                }
#else
                status = pSSLSock->server ? ERR_SSL_SERVER_RENEGOTIATE_NOT_ALLOWED : ERR_SSL_CLIENT_RENEGOTIATE_NOT_ALLOWED;
                goto exit;
#endif
            }

            goto exit;
        }
    }

exit:
    CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pFreeBuffer);

    /* if successful, return the total number of input bytes sent */
    if (OK <= status)
        status = (MSTATUS)numBytesSent;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"sendData() returns status = ", status);
#endif

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
sendData(SSLSocket* pSSLSock, ubyte protocol, const sbyte* data, sbyte4 dataSize, intBoolean skipEmptyMesg)
{
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
#if defined(__ENABLE_DIGICERT_TLS13__)
        if(DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            return sendDataDTLS13(pSSLSock, protocol, data, dataSize, skipEmptyMesg);
        }
        else
#endif
        {
            return sendDataDTLS(pSSLSock, protocol, data, dataSize, skipEmptyMesg);
        }
    }
    else
#endif
    {
        return sendDataSSL(pSSLSock, protocol, data, dataSize, skipEmptyMesg);
    }
}

/*------------------------------------------------------------------*/

/*******************************************************************************
*      sendChangeCipherSpec
* see page 72 of SSL and TLS essentials
*/
static MSTATUS
sendChangeCipherSpec(SSLSocket* pSSLSock)
{
    ubyte   ccs[20]; /* this would be adequate for both SSL and DTLS ccs */
    ubyte4  numBytesSent = 0;
    ubyte4  sizeofRecordHeader;
    ubyte4  sizeofCcs;
    MSTATUS status;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        sizeofRecordHeader = sizeof(DTLSRecordHeader);

        /* sendData will set record header if encrypted */
        if (NULL == pSSLSock->pActiveOwnCipherSuite)
        {
            DTLS_SET_RECORD_HEADER_EXT(ccs,pSSLSock,SSL_CHANGE_CIPHER_SPEC,1);
        }
    } else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
        SSL_SET_RECORD_HEADER(ccs,SSL_CHANGE_CIPHER_SPEC,pSSLSock->sslMinorVersion, 1);
    }

    sizeofCcs = sizeofRecordHeader + 1;

    /* */
    ccs[sizeofRecordHeader] = 0x01;

    /* THIS NEEDS TO BE REFACTORED AS A SINGLE FUNCTION */
    if (NULL == pSSLSock->pActiveOwnCipherSuite)
    {
        if (SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags)
        {
            numBytesSent = 0;

            if (NULL == pSSLSock->pOutputBufferBase)
            {
                if (NULL == (pSSLSock->pOutputBufferBase = (ubyte*) MALLOC(sizeofCcs + TLS_EAP_PAD)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                pSSLSock->pOutputBuffer      = pSSLSock->pOutputBufferBase;
                pSSLSock->outputBufferSize   = sizeofCcs + TLS_EAP_PAD;
                pSSLSock->numBytesToSend     = 0;
            }

            if ((sizeofCcs + pSSLSock->numBytesToSend) > pSSLSock->outputBufferSize)
            {
                /* Need to Realloc this buffer */
                ubyte * output = (ubyte*) MALLOC(pSSLSock->numBytesToSend + sizeofCcs);

                if (NULL == output)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(output, pSSLSock->pOutputBufferBase, pSSLSock->numBytesToSend);
                pSSLSock->outputBufferSize  += sizeofCcs;

                FREE(pSSLSock->pOutputBufferBase);
                pSSLSock->pOutputBufferBase = output;

            }
            else
            {
                if (pSSLSock->pOutputBufferBase != pSSLSock->pOutputBuffer)
                    DIGI_MEMMOVE(pSSLSock->pOutputBufferBase, pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend);
            }

            pSSLSock->pOutputBuffer   = pSSLSock->pOutputBufferBase + pSSLSock->numBytesToSend;
            DIGI_MEMCPY(pSSLSock->pOutputBuffer, ccs, sizeofCcs);

            pSSLSock->numBytesToSend += sizeofCcs;
            pSSLSock->pOutputBuffer   = pSSLSock->pOutputBufferBase;
            status = (MSTATUS)pSSLSock->numBytesToSend;

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
            if (pSSLSock->isDTLS)
            {
                if (OK > (status = addDataToRetransmissionBuffer(pSSLSock, SSL_CHANGE_CIPHER_SPEC,(const sbyte*) ccs, sizeofCcs)))
                    goto exit;
            }
#endif

            goto exit;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
            if (NULL != pSSLSock->pTransportHandler)
            {
                if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
                {
                    if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId, 
                                                                                         (sbyte *)ccs, sizeofCcs, &numBytesSent)))
                    {
                        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                        goto exit;
                    }
                }
                else
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
            }
            else
#endif
            {
#ifndef __DIGICERT_IPSTACK__
                if (OK > (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)ccs, sizeofCcs, &numBytesSent)))
#else
                if (OK > (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)ccs, sizeofCcs, &numBytesSent)))
#endif
                    goto exit;
            }
            if (sizeofCcs != numBytesSent)
            {
                if (NULL == (pSSLSock->pOutputBufferBase = (ubyte*) MALLOC(sizeofCcs)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(pSSLSock->pOutputBufferBase, ccs, sizeofCcs);

                pSSLSock->pOutputBuffer     = numBytesSent + pSSLSock->pOutputBufferBase;
                pSSLSock->outputBufferSize  = sizeofCcs;
                pSSLSock->numBytesToSend    = sizeofCcs - numBytesSent;
            }
        }
    }
    else
    {
        sbyte one[] = { 0x01 };
        sbyte4 sizeOne = sizeof(one);

        status = sendData(pSSLSock, SSL_CHANGE_CIPHER_SPEC, one, sizeOne, TRUE);
        goto exit;
    }

    /* END REFACTOR */

exit:
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        /* save for retransmission */
        pSSLSock->oldSeqnum     = pSSLSock->ownSeqnum;
        pSSLSock->oldSeqnumHigh = pSSLSock->ownSeqnumHigh;

        /* epoch++, seqNo = 0 */
        pSSLSock->ownSeqnum     = 0;
        pSSLSock->ownSeqnumHigh = (pSSLSock->ownSeqnumHigh & 0xffff0000) + 0x00010000;
    } else
#endif
    {
        pSSLSock->ownSeqnum = 0;
        pSSLSock->ownSeqnumHigh = 0;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
sendFinished(SSLSocket* pSSLSock)
{
    ubyte*              pFinished = NULL;
    ubyte*              pSHSH;
    ubyte4              sizeofHandshakeHeader;
    MSTATUS             status = OK;
#if defined(__ENABLE_DIGICERT_TLS13__)
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    /* common initialization for SSL or TLS */
    if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pFinished))))
        goto exit;

    pSHSH = pFinished;

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if (SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_FINISHED;
        setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE);
        calculateSSLTLSHashes(pSSLSock, pSSLSock->server ? 0 : 1, (ubyte *)(pSHSH+sizeofHandshakeHeader), hashTypeSSLv3Finished);
        addToHandshakeHash(pSSLSock, pFinished, sizeofHandshakeHeader + MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE);

        status = sendData(pSSLSock, SSL_HANDSHAKE, (sbyte *)pFinished, sizeofHandshakeHeader + MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE, TRUE);
    }
    else
#endif
    /* TLS */
    {

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            ((DTLSHandshakeHeader*)pSHSH)->handshakeType = SSL_FINISHED;
            setMediumValue(((DTLSHandshakeHeader*)pSHSH)->handshakeSize, TLS_VERIFYDATASIZE);

            DTLS_SET_HANDSHAKE_HEADER_EXTRA(((DTLSHandshakeHeader*)pSHSH), pSSLSock->nextSendSeq++, TLS_VERIFYDATASIZE);
        } else
#endif
        {
            ((SSLHandshakeHeader*)pSHSH)->handshakeType = SSL_FINISHED;
            setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, TLS_VERIFYDATASIZE);
        }

#ifdef __ENABLE_DIGICERT_TLS13__
        if ((pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
            (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            /* RFC 8446 Section 4.4.4
             */
            if (pSSLSock->server)
            {
                status = SSLSOCK_calcFinishedVerifyData(
                    pSSLSock, pSSLSock->pServerHandshakeTrafficSecret,
                    &pData, &dataLen);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(
                    pSSLSock->server_verify_data, pData, dataLen);
                if (OK != status)
                {
                    goto exit;
                }

                pSSLSock->server_verify_data_len = dataLen;
            }
            else
            {
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
                if (pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST))
                {
                    status = SSLSOCK_calcFinishedVerifyData(
                        pSSLSock, pSSLSock->pClientApplicationTrafficSecret,
                        &pData, &dataLen);
                }
                else
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
                {
                    status = SSLSOCK_calcFinishedVerifyData(
                        pSSLSock, pSSLSock->pClientHandshakeTrafficSecret,
                        &pData, &dataLen);
                }
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(
                    pSSLSock->client_verify_data, pData, dataLen);
                if (OK != status)
                {
                    goto exit;
                }

                pSSLSock->client_verify_data_len = dataLen;
            }

            status = DIGI_MEMCPY(
                pSHSH + sizeofHandshakeHeader, pData, dataLen);
            if (OK != status)
                goto exit;

            setMediumValue(((SSLHandshakeHeader*)pSHSH)->handshakeSize, dataLen);

            addToHandshakeHash(
                pSSLSock, pFinished, sizeofHandshakeHeader + dataLen);

            status = sendData(
                pSSLSock, SSL_HANDSHAKE, (sbyte *) pSHSH,
                sizeofHandshakeHeader + dataLen, TRUE);
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            if (OK > (status = calculateTLSFinishedVerify( pSSLSock,  pSSLSock->server ? 0 : 1, (ubyte *)(pSHSH+sizeofHandshakeHeader))))
                goto exit;

            /* set the rehandshake to false */
            pSSLSock->rehandshake = 0;
            addToHandshakeHash(pSSLSock, pFinished, sizeofHandshakeHeader + TLS_VERIFYDATASIZE);
            status = sendData(pSSLSock, SSL_HANDSHAKE, (sbyte *)pFinished, sizeofHandshakeHeader + TLS_VERIFYDATASIZE, TRUE);
        }
    }

    pSSLSock->sentFinished = TRUE;

exit:
    MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pFinished));

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }
#endif

    return status;

} /* sendFinished */


/*------------------------------------------------------------------*/

static MSTATUS
SSLSOCK_doOpenUpcalls(SSLSocket* pSSLSock)
{
    MSTATUS             status = OK;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    if (pSSLSock->isDTLS)
    {
        if (pSSLSock->useSrtp)
        {
            status = ERR_DTLS_SRTP_CALLBACK_MISSING;
            if(NULL != SSL_sslSettings()->funcPtrSrtpInitCallback)
            {
                if (OK > (status = SSL_sslSettings()->funcPtrSrtpInitCallback(
                                                SSL_findConnectionInstance(pSSLSock),
                                                &pSSLSock->peerDescr, pSSLSock->pHandshakeSrtpProfile,
                                                pSSLSock->pSrtpMaterials, pSSLSock->srtpMki)))
                {
                    goto exit;
                }
            }
        }
    }
#endif

    pSSLSock->handshakeCount++;

    if (0 == pSSLSock->handshakeCount)
    {
        status = ERR_SSL_TOO_MANY_REHANDSHAKES;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
    if ((IS_SSL_ASYNC(pSSLSock)) && (0 == pSSLSock->server) && (NULL != SSL_sslSettings()->funcPtrClientOpenStateUpcall))
        status = (MSTATUS) SSL_sslSettings()->funcPtrClientOpenStateUpcall(SSL_findConnectionInstance(pSSLSock), (sbyte4)((1 < pSSLSock->handshakeCount) ? TRUE : FALSE));
#endif

#ifdef __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
    if ((IS_SSL_ASYNC(pSSLSock)) && (pSSLSock->server) && (NULL != SSL_sslSettings()->funcPtrOpenStateUpcall))
        status = (MSTATUS) SSL_sslSettings()->funcPtrOpenStateUpcall(SSL_findConnectionInstance(pSSLSock), (sbyte4)((1 < pSSLSock->handshakeCount) ? TRUE : FALSE));
#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*******************************************************************************
*      processFinished
*    see page 91 of SSL and TLS esssentials
*/
static MSTATUS
processFinished(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 recLen)
{
    sbyte4  result = -1;
    ubyte4  sizeofHandshakeHeader;
    MSTATUS status;
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
    if ( SSL3_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        ubyte* pFinishedHashes = NULL;      /* [ MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE] */

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pFinishedHashes))))
            goto exit;

        calculateSSLTLSHashes(pSSLSock, pSSLSock->server ? 1 : 0, pFinishedHashes, hashTypeSSLv3Finished);

        if ((recLen != MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE) ||
            (OK > DIGI_CTIME_MATCH(pFinishedHashes, (ubyte *)(pSHSH+sizeofHandshakeHeader), MD5_DIGESTSIZE + SHA_HASH_RESULT_SIZE, &result)) ||
            (0 != result))
        {
            status = ERR_SSL_PROTOCOL_PROCESS_FINISHED;
            /* RFC #8446, section 4.4.4 Finished:
               Recipients of Finished messages MUST verify that the contents are
               correct and if incorrect MUST terminate the connection with a
               "decrypt_error" alert.
             */
#ifdef __ENABLE_DIGICERT_TLS13__
            if((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
               (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                /* TODO send alert in DTLS? */
                SSLSOCK_sendAlert(pSSLSock, TRUE,
                        SSL_ALERT_DECRYPT_ERROR,
                        SSLALERTLEVEL_FATAL);
#endif
            }
#endif
        }

        MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pFinishedHashes));
    }
    else
#endif
#ifdef __ENABLE_DIGICERT_TLS13__
    if((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        /* RFC 8446 Section 4.4.4
         */
        if (pSSLSock->server)
        {
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
            if (pSSLSock->postHandshakeMessages & (1 << CERTIFICATE_REQUEST))
            {
                status = SSLSOCK_calcFinishedVerifyData(
                    pSSLSock, pSSLSock->pClientApplicationTrafficSecret,
                    &pData, &dataLen);
            }
            else
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__ */
            {
                status = SSLSOCK_calcFinishedVerifyData(
                    pSSLSock, pSSLSock->pClientHandshakeTrafficSecret,
                    &pData, &dataLen);
            }
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(
                pSSLSock->client_verify_data, pData, dataLen);
            if (OK != status)
            {
                goto exit;
            }

            pSSLSock->client_verify_data_len = dataLen;
        }
        else
        {
            status = SSLSOCK_calcFinishedVerifyData(
                pSSLSock, pSSLSock->pServerHandshakeTrafficSecret,
                &pData, &dataLen);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(
                pSSLSock->server_verify_data, pData, dataLen);
            if (OK != status)
            {
                goto exit;
            }

            pSSLSock->server_verify_data_len = dataLen;
        }

        if (recLen != dataLen)
        {
            status = ERR_SSL_PROTOCOL_PROCESS_FINISHED;
            goto exit;
        }

        status = DIGI_CTIME_MATCH(
            pData, (ubyte *) (pSHSH + sizeofHandshakeHeader), dataLen, &result);
        if ( (OK != status) || (0 != result) )
        {
            status = ERR_SSL_PROTOCOL_PROCESS_FINISHED;
        }

        if (OK != status)
            goto exit;


        SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_FINISHED;
    }
    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
    {
        ubyte* pVerifyData = NULL;      /* [TLS_VERIFYDATASIZE] */

        if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->smallPool, (void **)(&pVerifyData))))
            goto exit;

        if (OK <= (status = calculateTLSFinishedVerify(pSSLSock, pSSLSock->server ? 1 : 0, pVerifyData)))
        {
            if ((recLen != TLS_VERIFYDATASIZE) ||
                (OK > DIGI_CTIME_MATCH(pVerifyData, (ubyte *)(pSHSH+sizeofHandshakeHeader), TLS_VERIFYDATASIZE, &result)) ||
                (0 != result))
            {
                status = ERR_SSL_PROTOCOL_PROCESS_FINISHED;
                /* RFC 5246 7.2.2.  Error Alerts
                 *
                 *   decrypt_error
                 *      A handshake cryptographic operation failed, including being unable
                 *      to correctly verify a signature or validate a Finished message.
                 *      This message is always fatal.
                 */
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, pSSLSock->server ? FALSE : TRUE,
                        SSL_ALERT_DECRYPT_ERROR,
                        SSLALERTLEVEL_FATAL);
#endif
            }
        }

        MEM_POOL_putPoolObject(&pSSLSock->smallPool, (void **)(&pVerifyData));
    }

exit:

#ifdef __ENABLE_DIGICERT_TLS13__
    if (NULL != pData)
    {
        DIGI_FREE((void **) &pData);
    }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (OK <= status)
        pSSLSock->receivedFinished = TRUE;
#endif

    return status;
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__))
#if defined(__ENABLE_DIGICERT_TLS13__)

static MSTATUS
processCertificateChainExtensions(
    SSLSocket *pSSLSock, ValidationConfig *pConfig)
{
    MSTATUS status;
    ubyte4 certCount = 0, i;

    status = CERTCHAIN_numberOfCertificates(pSSLSock->pCertChain, &certCount);
    if (OK > status)
    {
        goto exit;
    }

    for (i = 0; i < certCount; i++)
    {

        status = SSLSOCK_processCertificateExtensions(pSSLSock, i, pConfig);
        if (OK > status)
        {
            goto exit;
        }
    }

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13__ */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_ENFORCE_CERT_SIG_ALGO__)

static MSTATUS
SSL_SOCK_certificateValidateSigAlgo(SSLSocket *pSSLSock)
{
    MSTATUS status;
    const ubyte *pCert = NULL;
    ubyte2 *pSigAlgs;
    ubyte4 i, j, certCount, certLen, sigAlgLen;
    ubyte2 certSigAlgo;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRoot = NULL;

    /* TLS 1.3 allows a signature certificate algorithm list to be specified
     * explicitly. If the list is not provided then the signature algorithm list
     * must be used to validate signatures in a certificate. */
#if defined(__ENABLE_DIGICERT_TLS13__)
    if ( (TLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
         (NULL != pSSLSock->pConfiguredSignatureCertAlgoList) )
    {
        pSigAlgs = pSSLSock->pConfiguredSignatureCertAlgoList;
        sigAlgLen = pSSLSock->configuredSignatureCertAlgoListLength;
    }
    else
#endif
    {
        pSigAlgs = pSSLSock->pSupportedSignatureAlgoList;
        sigAlgLen = pSSLSock->supportedSignatureAlgoListLength;
    }

    if (OK > (status = CERTCHAIN_numberOfCertificates(pSSLSock->pCertChain, &certCount)))
        goto exit;

    if (OK > (status = CERTCHAIN_getCertificate(pSSLSock->pCertChain, certCount - 1, (const ubyte **)&pCert, &certLen)))
        goto exit;

    /* Check if the last certificate is self-signed. If it is then do not
     * enforce the signature algorithm restriction */
    MF_attach(&mf, certLen, (ubyte *) pCert);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    if (OK == X509_isRootCertificate(ASN1_FIRST_CHILD(pRoot), cs))
    {
        certCount--;
    }

    for (i = 0; i < certCount; i++)
    {
        if (OK > (status = CERTCHAIN_getCertificate(pSSLSock->pCertChain, i, (const ubyte **)&pCert, &certLen)))
            goto exit;

        if (OK > (status = getCertSigAlgo((ubyte *) pCert, certLen, &certSigAlgo)))
            goto exit;

        for (j = 0; j < sigAlgLen; j++)
            if (pSigAlgs[j] == certSigAlgo)
                break;

        if (j == sigAlgLen)
        {
            DEBUG_PRINT(DEBUG_SSL_MESSAGES, (sbyte*)"SSL_SOCK_certificateValidateSigAlgo() invalid signature algorithm = ");
            DEBUG_HEXINT(DEBUG_SSL_MESSAGES, certSigAlgo);
            DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte*)"");
            status = ERR_SSL_NO_SIGNATURE_ALGORITHM_MATCH;
            goto exit;
        }
    }

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_ENFORCE_CERT_SIG_ALGO__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
static MSTATUS checkCertPublicKeyAlgo(SSLSocket *pSSLSock)
{
    const struct KeyExAuthSuiteInfo *pKeyExAuthAlgo = NULL;
    ubyte4 expectedKeyType = 0;
    MSTATUS status = OK;

    if (NULL == pSSLSock)
    {
        status = ERR_SSL_BAD_ID;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        ubyte2 *pSigAlgs = NULL;
        ubyte4 sigAlgLen = 0;
        ubyte4 i = 0;
        ubyte keyTypeVerified = 0;

        pSigAlgs = pSSLSock->pSupportedSignatureAlgoList;
        sigAlgLen = pSSLSock->supportedSignatureAlgoListLength;

        for (i = 0; i < sigAlgLen; i++)
        {
            switch (pSigAlgs[i])
            {
#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__))
#if !defined(__DISABLE_DIGICERT_SHA512__)
            case (TLS_SHA512 << 8 | TLS_ECDSA):
#endif
#if !defined(__DISABLE_DIGICERT_SHA384__)
            case (TLS_SHA384 << 8 | TLS_ECDSA):
#endif
#if !defined(__DISABLE_DIGICERT_SHA256__)
            case (TLS_SHA256 << 8 | TLS_ECDSA):
#endif
                if (akt_ecc == (pSSLSock->handshakeKey.type & 0xFF))
                {
                    keyTypeVerified = 1;
                    status = OK;
                }
                break;
#endif
#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
#if !defined(__DISABLE_DIGICERT_SHA512__)
            case (TLS_SHA512 << 8 | TLS_RSA):
#endif
#if !defined(__DISABLE_DIGICERT_SHA384__)
            case (TLS_SHA384 << 8 | TLS_RSA):
#endif
#if !defined(__DISABLE_DIGICERT_SHA256__)
            case (TLS_SHA256 << 8 | TLS_RSA):
#endif
#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)
            case (TLS_SHA1 << 8 | TLS_RSA):
#endif
                if (akt_rsa == (pSSLSock->handshakeKey.type & 0xFF))
                {
                    keyTypeVerified = 1;
                    status = OK;
                }
                break;

#ifdef __ENABLE_DIGICERT_PKCS1__
#if !defined(__DISABLE_DIGICERT_SHA256__)
            case (TLS_INTRINSIC << 8 | TLS_13_RSA_PSS_RSAE_SHA256):
#endif
#if !defined(__DISABLE_DIGICERT_SHA384__)
            case (TLS_INTRINSIC << 8 | TLS_13_RSA_PSS_RSAE_SHA384):
#endif
#if !defined(__DISABLE_DIGICERT_SHA512__)
            case (TLS_INTRINSIC << 8 | TLS_13_RSA_PSS_RSAE_SHA512):
#endif
#if !defined(__DISABLE_DIGICERT_SHA256__)
            case (TLS_INTRINSIC << 8 | TLS_13_RSA_PSS_PSS_SHA256):
#endif
#if !defined(__DISABLE_DIGICERT_SHA384__)
            case (TLS_INTRINSIC << 8 | TLS_13_RSA_PSS_PSS_SHA384):
#endif
#if !defined(__DISABLE_DIGICERT_SHA512__)
            case (TLS_INTRINSIC << 8 | TLS_13_RSA_PSS_PSS_SHA512):
#endif
                if (akt_rsa == (pSSLSock->handshakeKey.type & 0xFF))
                {
                    keyTypeVerified = 1;
                    status = OK;
                }
                break;
#endif /* __ENABLE_DIGICERT_PKCS1__ */
#endif /* !__DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            case (TLS_INTRINSIC << 8 | TLS_EDDSA25519):
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
            case (TLS_INTRINSIC << 8 | TLS_EDDSA448):
#endif
                if (akt_ecc_ed == (pSSLSock->handshakeKey.type & 0xFF))
                {
                    keyTypeVerified = 1;
                    status = OK;
                }
                break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
            case (TLS_QS << 8 | TLS_MLDSA_44_ECDSA_P256_SHA256):
            case (TLS_QS << 8 | TLS_MLDSA_65_ECDSA_P384_SHA384):
            case (TLS_QS << 8 | TLS_MLDSA_87_ECDSA_P384_SHA384):
            case (TLS_QS << 8 | TLS_MLDSA_44_EDDSA_25519):
            case (TLS_QS << 8 | TLS_MLDSA_65_EDDSA_25519):
            case (TLS_QS << 8 | TLS_MLDSA_44_RSA_2048_SHA256):
            case (TLS_QS << 8 | TLS_MLDSA_65_RSA_3072_SHA256):
            case (TLS_QS << 8 | TLS_MLDSA_65_RSA_4096_SHA384):
            case (TLS_QS << 8 | TLS_MLDSA_44_RSA_2048_PSS_SHA256):
            case (TLS_QS << 8 | TLS_MLDSA_65_RSA_3072_PSS_SHA256):
            case (TLS_QS << 8 | TLS_MLDSA_65_RSA_4096_PSS_SHA384):
            case (TLS_QS << 8 | TLS_MLDSA_87_EDDSA_448):
                if (akt_hybrid == (pSSLSock->handshakeKey.type & 0xFF))
                {
                    keyTypeVerified = 1;
                    status = OK;
                }
                break;
#endif
            case (TLS_QS << 8 | TLS_MLDSA_44):
            case (TLS_QS << 8 | TLS_MLDSA_65):
            case (TLS_QS << 8 | TLS_MLDSA_87):
                if (akt_qs == (pSSLSock->handshakeKey.type & 0xFF))
                {
                    keyTypeVerified = 1;
                    status = OK;
                }
                break;
#endif
            default:
                break;
            }

            if (1 == keyTypeVerified)
            {
                goto exit;
            }
        }

        if (0 == keyTypeVerified)
        {
            status = ERR_BAD_KEY_TYPE;
        }
    }
    else
#endif
    {
        pKeyExAuthAlgo = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo;
        switch(pKeyExAuthAlgo->flags)
        {
#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
            case SSL_RSA:
#ifdef __ENABLE_DIGICERT_SSL_DHE_SUPPORT__
            case SSL_DHE_RSA:
#endif /*  __ENABLE_DIGICERT_SSL_DHE_SUPPORT__ */
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
            case SSL_ECDHE_RSA:
#endif
                expectedKeyType = akt_rsa;
                break;
#endif /* !__DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */

#if defined(__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)
#ifdef __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
            case SSL_ECDH_RSA:
#endif /* ! __DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */
            case SSL_ECDH_ECDSA:
#endif /*  __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__ */
#ifdef __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
            case SSL_ECDHE_ECDSA:
#endif
                expectedKeyType = akt_ecc;
                break;
#endif /*__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__ || __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__*/

#if (defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__))
            case SSL_DHE_DSA:
                expectedKeyType = akt_dsa;
                break;
#endif
            default:
                break;
        }

        if (expectedKeyType != 0)
        {
            if (expectedKeyType == (pSSLSock->handshakeKey.type & 0xFF))
            {
                status = OK;
            }
            else
            {
                status = ERR_BAD_KEY_TYPE;
            }
        }
    }

exit:
    return status;
}
#endif /*  __ENABLE_DIGICERT_SSL_CLIENT__ */

static MSTATUS
processCertificate(SSLSocket* pSSLSock, ubyte* pSHSH, ubyte2 handshakeRecLen,
                   intBoolean isCertRequired)
{
    MSTATUS     status           = OK;
    ubyte4      sizeofHandshakeHeader;
    TimeDate    td;
    ValidationConfig vc = {0};
    ubyte4      minRSAKeyLen = 0;
    ubyte4      certRecNum;
    ubyte4      certChainNum;
    intBoolean  isComplete;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    vlong*      modulus = NULL;
#endif
    intBoolean  emptyCertMsg = FALSE;

#ifdef __ENABLE_DIGICERT_SSL_EXTENDED_KEYUSAGE__
     /* verify Extended Key Usage */
    MSTATUS     extendedKeyStatus   = OK;
    ubyte *extendedOIDsServer[] = {(ubyte*)&id_kp_clientAuth_OID, 0};
    ubyte *extendedOIDsClient[] = {(ubyte*)&id_kp_serverAuth_OID, 0};
#endif
#ifdef __ENABLE_DIGICERT_CV_CERT__
    byteBoolean isCvc = FALSE;
#endif
    /* always validate for date */
    if (OK > (status = RTOS_timeGMT(&td)))
    {
        goto exit;
    }
    vc.td = &td;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    /* move over the handshakeheader and create a cert chain */
    pSHSH += sizeofHandshakeHeader;
    /*clean up memory */
    if (pSSLSock->pCertChain != NULL)
    {
        CERTCHAIN_delete(&pSSLSock->pCertChain);
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        if (!pSSLSock->server)
        {
            /* RFC #8446, section 4.4.2
             * Certificate request context length in case of server
             * authentication is 0.
             */
            if (handshakeRecLen > 0 && *pSHSH != 0)
            {
                status = ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE;
                goto exit;
            }

            /* RFC #8446, section 4.4.2.4
             * If the server supplies an empty Certificate message, the client MUST
             * abort the handshake with a "decode_error" alert.
             */
            if (handshakeRecLen <= 1)
            {
                status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                SSLSOCK_sendAlert(pSSLSock, TRUE /* TLS 1.3 only - encrypt alert */,
                        SSL_ALERT_DECODE_ERROR,
                        SSLALERTLEVEL_FATAL);
#endif
                goto exit;
            }

            pSHSH++;
            handshakeRecLen--;
        }
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
        else
        {
            ubyte len = 0;
            sbyte4 cmpResult = 0;

            status = ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE;

            if (0 == handshakeRecLen)
            {
                goto exit;
            }

            len = *pSHSH;
            pSHSH++;
            handshakeRecLen -= 1;

            if ((handshakeRecLen < len) || (len != pSSLSock->certificateRequestContextLength))
            {
                goto exit;
            }

            if (NULL != pSSLSock->certificateRequestContext)
            {
                if ( OK > (status = DIGI_MEMCMP(pSHSH, pSSLSock->certificateRequestContext,
                                pSSLSock->certificateRequestContextLength, &cmpResult)))
                {
                    goto exit;
                }

                if (cmpResult != 0)
                {
                    goto exit;
                }
            }

            /* Context Length has been procssed */
            pSHSH += pSSLSock->certificateRequestContextLength;
            handshakeRecLen = handshakeRecLen - pSSLSock->certificateRequestContextLength;

        }
#endif
    }
#endif

    if ((3 == handshakeRecLen) && (0 == getMediumValue(pSHSH)))
    {
        if (TRUE == isCertRequired)
        {
            status = ERR_SSL_EMPTY_CERTIFICATE_MESSAGE;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            if (pSSLSock->server)
            {
#if defined(__ENABLE_DIGICERT_TLS13__)
                if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
                    (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
                {
                    /* TODO sendAlert for DTLS? */
                    /* RFC 8446, Section 4.4.2.4 */
                    SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_CERTIFICATE_REQUIRED, SSLALERTLEVEL_FATAL);
                }
                else
#endif /* __ENABLE_DIGICERT_TLS13__ */
                {
                    /* RFC 5246, Section 7.4.6 */
                    SSLSOCK_sendAlert(pSSLSock, FALSE, SSL_ALERT_HANDSHAKE_FAILURE, SSLALERTLEVEL_FATAL);
                }
            }
#endif /* __ENABLE_DIGICERT_SSL_ALERTS__ */
            goto exit;
        }
        else
        {
            /* If the certificate is not required and the certificate message is
             * empty, set status to OK.
             */
            status = OK;
            emptyCertMsg = TRUE;
        }
    }
    else
    {
#ifdef __ENABLE_DIGICERT_CV_CERT__
        /* Check if this is a valid CVC chain instead of X509 */
        status = CERTCHAIN_CVC_createFromSSLRecordEx(
            MOC_ASYM(pSSLSock->hwAccelCookie) &pSSLSock->pCertChain, pSHSH,
            handshakeRecLen, pSSLSock->sslMinorVersion, &isCvc);
#else
#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
        if (pSSLSock->funcPtrGetOriginalCertChainCallback != NULL)
        {
            sbyte4 connectionInstance = SSL_findConnectionInstance(pSSLSock);
            struct certChain *pCertChain = NULL;

            status = CERTCHAIN_createFromSSLRecordOriginal(
                MOC_ASYM(pSSLSock->hwAccelCookie) &pCertChain, pSHSH,
                handshakeRecLen, pSSLSock->sslMinorVersion);
            if (OK != status)
            {
                goto exit;
            }

            pSSLSock->funcPtrGetOriginalCertChainCallback(connectionInstance, pCertChain);
            CERTCHAIN_delete(&pCertChain);
        }
#endif
        status = CERTCHAIN_createFromSSLRecordEx(
            MOC_ASYM(pSSLSock->hwAccelCookie) &pSSLSock->pCertChain, pSHSH,
            handshakeRecLen, pSSLSock->sslMinorVersion);
#endif
    }
    if (pSSLSock->server)
    {
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__

        if (TRUE != isCertRequired && TRUE == emptyCertMsg)
        {
#ifdef __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__
            if (NULL == pSSLSock->funcPtrInvalidCertCallback)
#endif
            {
                goto exit;
            }
        }

        /* Empty certificate or invalid certificate */
#ifdef __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__
        if ((OK > status) &&  (pSSLSock->funcPtrInvalidCertCallback != NULL))
        {
            sbyte4 connectionInstance = SSL_findConnectionInstance(pSSLSock);

            status = pSSLSock->funcPtrInvalidCertCallback(connectionInstance, status);
            if (OK <= status)
            {
                pSSLSock->mutualAuthKey.type = akt_undefined;
                goto exit;
            }
        }
#endif
        if (OK > status)
        {
#if defined(__ENABLE_DIGICERT_SSL_ALERTS__)
            sbyte4 alertId, alertClass;
            if (FALSE == SSLSOCK_lookupAlert(pSSLSock, status, &alertId, &alertClass))
            {
                /* Default alert in case error code cannot be translated */
                alertId = SSL_ALERT_CERTIFICATE_UNKNOWN;
                alertClass = SSLALERTLEVEL_FATAL;
            }

            SSLSOCK_sendAlert(pSSLSock, pSSLSock->sslMinorVersion == TLS13_MINORVERSION ? TRUE : FALSE,
                              alertId, alertClass);
#endif
            goto exit;
        }

        vc.keyUsage = ( 1 << digitalSignature); /* verify key usage */
        vc.pCertStore = pSSLSock->pCertStore;   /* verify Trust Point */

#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (TRUE == isCvc)
        {
            status = CERTCHAIN_CVC_validate(MOC_ASYM(pSSLSock->hwAccelCookie)
                                              pSSLSock->pCertChain, &vc);
        }
        else
        {
#endif
            status = CERTCHAIN_validate(MOC_ASYM(pSSLSock->hwAccelCookie)
                                                pSSLSock->pCertChain, &vc);
#ifdef __ENABLE_DIGICERT_CV_CERT__
        }
#endif
        if (OK != status)
        {
            if (OK == CERTCHAIN_isComplete(pSSLSock->pCertChain, &isComplete) && FALSE == isComplete)
            {
                if (OK == CERTCHAIN_getSSLRecordCertNum(MOC_ASYM(pSSLSock->hwAccelCookie)
                            pSHSH, handshakeRecLen, pSSLSock->sslMinorVersion,
                            &certRecNum))
                {
                    if (OK == CERTCHAIN_numberOfCertificates(pSSLSock->pCertChain, &certChainNum))
                    {
                        if (certChainNum < certRecNum)
                        {
                            status = ERR_CERT_INVALID_PARENT_CERTIFICATE;
                        }
                    }
                }
            }
        }

#ifdef __ENABLE_DIGICERT_SSL_EXTENDED_KEYUSAGE__
        vc.keyUsage = 0;
        vc.extendedKeyUsage = (const ubyte**)extendedOIDsServer;   /* verify Extended Key Usage */

        extendedKeyStatus = CERTCHAIN_validate(MOC_ASYM(pSSLSock->hwAccelCookie)
                                              pSSLSock->pCertChain, &vc);

#ifdef __ENABLE_DIGICERT_SSL_FORCE_EXTENDED_KEYUSAGE__
        status = extendedKeyStatus;
#else
        if ( OK > status)
        {
            if (ERR_CERT_EXTENDED_KEYUSAGE_NOT_FOUND != extendedKeyStatus)
            {
                status = extendedKeyStatus;
            }
        }
#endif
#endif

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
        if (pSSLSock->funcPtrGetCertAndStatusCallback != NULL)
        {
            sbyte4 connectionInstance = SSL_findConnectionInstance(pSSLSock);

            /* Provide the certChain to application, for additional processing */
            status = pSSLSock->funcPtrGetCertAndStatusCallback(connectionInstance,
                                                               pSSLSock->pCertChain,
                                                               status);
        }
#endif
        if (OK > status)
        {
#if defined(__ENABLE_DIGICERT_SSL_ALERTS__)
            sbyte4 alertId, alertClass;
            if (FALSE == SSLSOCK_lookupAlert(pSSLSock, status, &alertId, &alertClass))
            {
                /* Default alert in case error code cannot be translated */
                alertId = SSL_ALERT_CERTIFICATE_UNKNOWN;
                alertClass = SSLALERTLEVEL_FATAL;
            }
            SSLSOCK_sendAlert(pSSLSock,  pSSLSock->sslMinorVersion == TLS13_MINORVERSION ? TRUE : FALSE, alertId, alertClass);
#endif
            goto exit;
        }

        /* RFC #8446, section 4.4.2.4
         *
         * Any endpoint receiving any certificate which it would need to
         * validate using any signature algorithm using an MD5 hash MUST abort
         * the handshake with a "bad_certificate" alert. SHA-1 is deprecated,
         * and it is RECOMMENDED that any endpoint receiving any certificate
         * which it would need to validate using any signature algorithm using a
         * SHA-1 hash abort the handshake with a "bad_certificate" alert. For
         * clarity, this means that endpoints can accept these algorithms for
         * certificates that are self-signed or are trust anchors.
         *
         * Here the check for MD5 is made. For SHA-1 an error will be thrown
         * later on if the peer provided a certificate with SHA-1 and the
         * appropriate SHA-1 signature algorithm was not provided in the
         * signature algorithms extension.
         */
#ifdef __ENABLE_DIGICERT_TLS13__
        if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
            (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            ubyte4 numOfCerts = 0;
            ubyte4 i = 0;
            ubyte2 signAlgo;

            CERTCHAIN_numberOfCertificates(pSSLSock->pCertChain, &numOfCerts);
            for(i = 0; i < numOfCerts; i++)
            {
                ubyte* pCertData;
                ubyte4 certLen;

                if (OK > (status = CERTCHAIN_getCertificate(pSSLSock->pCertChain, i, (const ubyte**)&pCertData, &certLen)))
                {
                    goto exit;
                }

                if (OK > (status = getCertSigAlgo(pCertData, certLen, &signAlgo)))
                {
                    goto exit;
                }

                if (TLS_MD5 >= ((signAlgo >> 8) & 0xff))
                {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
/* TODO sendAlert for DTLS? */
                            SSLSOCK_sendAlert(pSSLSock, TRUE,
                                    SSL_ALERT_BAD_CERTIFICATE,
                                    SSLALERTLEVEL_FATAL);
#endif /* __ENABLE_DIGICERT_SSL_ALERTS__ */
                            status = ERR_SSL_FATAL_ALERT;
                            goto exit;
                }
            }

        }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        if (OK > (status = CERTCHAIN_getKey(MOC_ASYM(pSSLSock->hwAccelCookie)
                                            pSSLSock->pCertChain, 0,
                                            &pSSLSock->mutualAuthKey)))
        {
            goto exit;
        }

        /* if RSA, verify the public key is of sufficient size */
        if (akt_rsa == (pSSLSock->mutualAuthKey.type & 0xFF))
        {
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__            
            minRSAKeyLen = SSL_sslSettings()->minRSAKeySize;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            ubyte4 bitLength;
            status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(pSSLSock->hwAccelCookie)
                pSSLSock->mutualAuthKey.key.pRSA, (sbyte4 *) &bitLength,
                pSSLSock->mutualAuthKey.type);
            if (OK != status)
                goto exit;

            bitLength *= 8;

            if ((minRSAKeyLen - 1) > bitLength)
            {
                status = ERR_SSL_RSA_KEY_SIZE;
                goto exit;
            }
#else
            modulus  = RSA_N(pSSLSock->mutualAuthKey.key.pRSA);
            minRSAKeyLen = SSL_sslSettings()->minRSAKeySize;

            if ((minRSAKeyLen - 1) > VLONG_bitLength(modulus))
            {
                status = ERR_SSL_RSA_KEY_SIZE;
                goto exit;
            }
#endif
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
        }
#endif
    }
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    else
    {
        const struct KeyExAuthSuiteInfo *pKeyExAuthAlgo = NULL;
        pKeyExAuthAlgo = pSSLSock->pHandshakeCipherSuite->pKeyExAuthAlgo;

        if (TRUE != isCertRequired && TRUE == emptyCertMsg)
        {
#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
            if (NULL == pSSLSock->funcPtrGetCertAndStatusCallback)
#endif
            {
                goto exit;
            }
        }

        /* If empty or invalid certificate from server, throw out an error */
        if (OK > status)
        {

#if defined(__ENABLE_DIGICERT_SSL_ALERTS__)
            sbyte4 alertId, alertClass;
            if (FALSE == SSLSOCK_lookupAlert(pSSLSock, status, &alertId, &alertClass))
            {
                /* Default alert in case error code cannot be translated */
                alertId = SSL_ALERT_CERTIFICATE_UNKNOWN;
                alertClass = SSLALERTLEVEL_FATAL;
            }

            SSLSOCK_sendAlert(pSSLSock, pSSLSock->sslMinorVersion == TLS13_MINORVERSION ? TRUE : FALSE,
                              alertId, alertClass);
#endif
            goto exit;
        }

        vc.keyUsage = pKeyExAuthAlgo->keyUsage; /* verify key usage */
        vc.pCertStore = pSSLSock->pCertStore;   /* verify Trust Point */

#if !defined(__DISABLE_DIGICERT_CLIENT_COMMONNAME_VALIDATION__)
        vc.commonName = pSSLSock->roleSpecificInfo.client.pDNSName;
#endif

#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (TRUE == isCvc)
        {
            status = CERTCHAIN_CVC_validate(MOC_ASYM(pSSLSock->hwAccelCookie)
                                              pSSLSock->pCertChain, &vc);
        }
        else
        {
#endif
            status = CERTCHAIN_validate(MOC_ASYM(pSSLSock->hwAccelCookie)
                                                pSSLSock->pCertChain, &vc);
#ifdef __ENABLE_DIGICERT_CV_CERT__                                            
        }
#endif
        if (OK != status)
        {
            if (OK == CERTCHAIN_isComplete(pSSLSock->pCertChain, &isComplete) && FALSE == isComplete)
            {
                if (OK == CERTCHAIN_getSSLRecordCertNum(MOC_ASYM(pSSLSock->hwAccelCookie)
                            pSHSH, handshakeRecLen, pSSLSock->sslMinorVersion,
                            &certRecNum))
                {
                    if (OK == CERTCHAIN_numberOfCertificates(pSSLSock->pCertChain, &certChainNum))
                    {
                        if (certChainNum < certRecNum)
                        {
                            status = ERR_CERT_INVALID_PARENT_CERTIFICATE;
                        }
                    }
                }
            }
        }

#ifdef __ENABLE_DIGICERT_SSL_EXTENDED_KEYUSAGE__
        vc.keyUsage = 0;
        vc.commonName = 0;
        vc.extendedKeyUsage = (const ubyte**)extendedOIDsClient;   /* verify Extended Key Usage */
        extendedKeyStatus = CERTCHAIN_validate(MOC_ASYM(pSSLSock->hwAccelCookie)
                                              pSSLSock->pCertChain, &vc);

#ifdef __ENABLE_DIGICERT_SSL_FORCE_EXTENDED_KEYUSAGE__
        status = extendedKeyStatus;
#else
        if ( OK > status)
        {
            if (ERR_CERT_EXTENDED_KEYUSAGE_NOT_FOUND != extendedKeyStatus)
            {
                status = extendedKeyStatus;
            }
        }
#endif
#endif

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
        if (pSSLSock->funcPtrGetCertAndStatusCallback != NULL)
        {
            sbyte4 connectionInstance = SSL_findConnectionInstance(pSSLSock);

            /* Provide the certChain to application, for additional processing */
            status = pSSLSock->funcPtrGetCertAndStatusCallback(connectionInstance,
                                                               pSSLSock->pCertChain,
                                                               status);
        }
#endif

        if (OK > status)
        {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            sbyte4 alertId, alertClass;
            if (FALSE == SSLSOCK_lookupAlert(pSSLSock, status, &alertId, &alertClass))
            {
                /* Default alert in case error code cannot be translated */
                alertId = SSL_ALERT_CERTIFICATE_UNKNOWN;
                alertClass = SSLALERTLEVEL_FATAL;
            }
            SSLSOCK_sendAlert(pSSLSock, pSSLSock->sslMinorVersion == TLS13_MINORVERSION ? TRUE : FALSE,
                              alertId, alertClass);
#endif
            goto exit;
        }

        if (OK > (status = CERTCHAIN_getKey(MOC_ASYM(pSSLSock->hwAccelCookie)
                                            pSSLSock->pCertChain, 0,
                                            &pSSLSock->handshakeKey)))
        {
            goto exit;
        }
        /* if RSA, verify the public key is of sufficient size (FREAK) */
        if (akt_rsa == (pSSLSock->handshakeKey.type & 0xFF))
        {
#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
            minRSAKeyLen = SSL_sslSettings()->minRSAKeySize;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            ubyte4 bitLength;
            status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(pSSLSock->hwAccelCookie)
                pSSLSock->handshakeKey.key.pRSA, (sbyte4 *) &bitLength,
                pSSLSock->handshakeKey.type);
            if (OK != status)
                goto exit;

            bitLength *= 8;

            if ((minRSAKeyLen - 1) > bitLength)
            {
                status = ERR_SSL_RSA_KEY_SIZE;
                goto exit;
            }
#else
            modulus  = RSA_N(pSSLSock->handshakeKey.key.pRSA);

            if ((minRSAKeyLen - 1) > VLONG_bitLength(modulus))
            {
                status = ERR_SSL_RSA_KEY_SIZE;
                goto exit;
            }
#endif
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
        }

        if (OK > (status = checkCertPublicKeyAlgo(pSSLSock)))
        {
            DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Certificate Public Key does not match supported algorithms. status = ", status);
            goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

#if defined(__ENABLE_DIGICERT_ENFORCE_CERT_SIG_ALGO__)
    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion >= TLS12_MINORVERSION))
    {
        /* Ensure none of the certificates provided by the peer contain a
         * signature algorithm which was not sent */
        if (OK > (status = SSL_SOCK_certificateValidateSigAlgo(pSSLSock)))
            goto exit;
    }
#endif /* __ENABLE_DIGICERT_ENFORCE_CERT_SIG_ALGO__ */

#if defined(__ENABLE_DIGICERT_TLS13__)
    /* Certificate chain has been validated. Now process the certificate
     * extensions.
     */
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
        (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
    {
        status = processCertificateChainExtensions(pSSLSock, &vc);
        if (OK > status)
        {
            goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    /* Need server certificate and its issuer here for certificate status request extension */
    if (!pSSLSock->server && pSSLSock->certStatusReqExt &&
        ((pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) || 
         (!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion)))
    {
        /*Add the SSL server certificate and the issuer certificate to the OCSP context*/
        if (OK > (status = SSL_OCSP_addCertificates(pSSLSock)))
            goto exit;
    }
#endif

exit:

    DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"processCertificate() returns status = ", status);
    return status;

} /* processCertificate */

#ifdef __ENABLE_DIGICERT_TLS13__
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
extern MSTATUS
constructTLSExtCertificateAuthorities(SSLSocket *pSSLSock, ubyte **ppPacket, ubyte4 distNameLen)
{
    MSTATUS status = OK;
    MOC_UNUSED(pSSLSock);

    if (SSL_sslSettings()->pClientCANameList != NULL)
    {
        ubyte4 i = 0;

        setShortValue(*ppPacket, (ubyte2)tlsExt_certificateAuthorities);
        *ppPacket += sizeof(ubyte2);

        setShortValue(*ppPacket, distNameLen + 2);
        *ppPacket += sizeof(ubyte2);

        setShortValue(*ppPacket, distNameLen);
        *ppPacket += sizeof(ubyte2);

        for (i = 0; i < SSL_sslSettings()->numClientCANames; i++)
        {
            ubyte4 length = SSL_sslSettings()->pClientCANameList[i].length;
            setShortValue(*ppPacket, length);
            *ppPacket += sizeof(ubyte2);

            DIGI_MEMCPY(*ppPacket, SSL_sslSettings()->pClientCANameList[i].data, length);
            *ppPacket += length;
        }
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */
#endif /* (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__)) */
#endif /* __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
MSTATUS SSLSOCK_populateMutualAuthCertStore(SSLSocket *pSSLSock,
                                            const SizedBuffer *pCerts, ubyte4 numCerts,
                                            ubyte *pKey, ubyte4 keyLen,
                                            const ubyte *pCACert, ubyte4 caCertLength)
{
    MSTATUS status = OK;

    if (NULL == pSSLSock->pMutualAuthCertStore)
    {
        if (OK > (status = CERT_STORE_createStore(&pSSLSock->pMutualAuthCertStore)))
        {
            goto exit;
        }
    }

    if ((pCerts != NULL) && (numCerts > 0))
    {
        if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(pSSLSock->pMutualAuthCertStore,
                                                                      (SizedBuffer *) pCerts, numCerts,
                                                                      pKey, keyLen)))
        {
            goto exit;
        }

        /* Add CA cert only if there is a valid Cert */
        if ((pCACert != NULL) && (caCertLength > 0))
        {
            if (OK > (status = CERT_STORE_addTrustPoint(pSSLSock->pMutualAuthCertStore,
                                                        pCACert, caCertLength)))
            {
                goto exit;
            }
        }
    }


exit:
    return status;
}
#endif

#if ((defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_TLS13__)) || \
    (defined(__ENABLE_DIGICERT_SSL_CLIENT__)))
static MSTATUS
constructTLSExtSupportedGroup(
    SSLSocket *pSSLSock, ubyte **ppPacket, ubyte2 numGroups, ubyte4 supportedGroups)
{
    ubyte4 i;
    MSTATUS status = OK;

    setShortValue( *ppPacket, (ubyte2) tlsExt_supportedGroups);
    *ppPacket += sizeof(ubyte2);

    /* extension length */
    setShortValue( *ppPacket, numGroups * 2 + 2);
    *ppPacket += sizeof(ubyte2);

    /* size of curves list */
    setShortValue( *ppPacket, numGroups * 2);
    *ppPacket += sizeof(ubyte2);

    /* curves in order of preference filtered with supportedGroups */
    for (i = 0; i < pSSLSock->supportedGroupListLength; ++i)
    {
        ubyte4 curve = pSSLSock->pSupportedGroupList[i];

        if ( GROUP_BIT_MASK(curve) & supportedGroups )
        {
            setShortValue( *ppPacket, (ubyte2) curve);
            *ppPacket += sizeof(ubyte2);
        }
    }

    /* For TLS 1.2 there is an additional extension, EC point format, which is
     * used to tell the peer the format of the curve values. For TLS 1.3 this
     * extension does not exist as there is only a single curve format.
     */
    if ((!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion) || 
         (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) )
    {
        setShortValue( *ppPacket, (ubyte2) tlsExt_ECPointFormat);
        *ppPacket += 2;
        setShortValue( *ppPacket, (ubyte2) 2);
        *ppPacket += 2;
        **ppPacket = 1;
        *ppPacket += 1;
        **ppPacket = tlsExtECPointFormat_uncompressed;
        *ppPacket += 1;
    }

    return status;
}
#endif


#ifdef __ENABLE_DIGICERT_TLS13__

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS getNamedGroupCipherTextLen(ubyte4 namedGroup, ubyte4 *pLength)
{
    ubyte4 length;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4 qsLength      = 0;
    ubyte4 qsAlgo        = 0;
    ubyte4 curveId       = 0;
    ubyte4 eccCurveGroup = 0;
    intBoolean isQS      = FALSE;
#endif
    MSTATUS status = ERR_NULL_POINTER;
    intBoolean isECC = FALSE;
    if (NULL == pLength)
    {
        return status;
    }

    *pLength = 0;
    status = OK;
    switch(namedGroup)
    {
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtNamedCurves_secp256r1:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case tlsExtNamedCurves_secp384r1:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case tlsExtNamedCurves_secp521r1:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case tlsExtNamedCurves_secp224r1:
            isECC = TRUE;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case tlsExtNamedCurves_secp192r1:
            isECC = TRUE;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtNamedCurves_x25519:
            isECC = TRUE;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
        case tlsExtNamedCurves_x448:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
        case tlsExtNamedCurves_ffdhe2048:
            length = 256;
            break;
        case tlsExtNamedCurves_ffdhe3072:
            length = 384;
            break;
        case tlsExtNamedCurves_ffdhe4096:
            length = 512;
            break;
        case tlsExtNamedCurves_ffdhe6144:
            length = 768;
            break;
        case tlsExtNamedCurves_ffdhe8192:
            length = 1024;
            break;
#endif

#if defined(__ENABLE_DIGICERT_PQC__)
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtHybrid_SecP256r1MLKEM768:
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtHybrid_X25519MLKEM768:
#endif
        {
            SSL_SOCK_getCurveIdFromNameQS(namedGroup, &eccCurveGroup, &curveId, &qsAlgo);
            isQS  = TRUE;
            isECC = TRUE;
            namedGroup = eccCurveGroup;
            break;
        }
#endif
        default:
            status = ERR_SSL_UNSUPPORTED_CURVE;
    }
    if (OK != status)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if (TRUE == isECC)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(
            SSL_SOCK_getCurveIdFromName(namedGroup),
                            &length)))
#else
        if (OK > (status = EC_getPointByteStringLen(SSL_SOCK_getCurveFromName(namedGroup),
            (sbyte4 *)&length)))
#endif
        {
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_PQC__
        if (TRUE == isQS)
        {
            if (OK > (status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLenFromAlgo(qsAlgo, &qsLength)))
            {
                goto exit;
            }
            length += qsLength;
        }
#endif
    }
#endif

    if (OK == status)
    {
        *pLength = length;
    }

exit:
    return status;
}
#endif

static MSTATUS getNamedGroupLength(ubyte4 namedGroup, ubyte4 *pLength)
{
    ubyte4 length;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4 qsLength      = 0;
    ubyte4 qsAlgo        = 0;
    ubyte4 curveId       = 0;
    ubyte4 eccCurveGroup = 0;
    intBoolean isQS      = FALSE;
#endif
    MSTATUS status = ERR_NULL_POINTER;
    intBoolean isECC = FALSE;
    if (NULL == pLength)
    {
        return status;
    }

    *pLength = 0;
    status = OK;
    switch(namedGroup)
    {
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtNamedCurves_secp256r1:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case tlsExtNamedCurves_secp384r1:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case tlsExtNamedCurves_secp521r1:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case tlsExtNamedCurves_secp224r1:
            isECC = TRUE;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case tlsExtNamedCurves_secp192r1:
            isECC = TRUE;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtNamedCurves_x25519:
            isECC = TRUE;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
        case tlsExtNamedCurves_x448:
            isECC = TRUE;
            break;
#endif
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
        case tlsExtNamedCurves_ffdhe2048:
            length = 256;
            break;
        case tlsExtNamedCurves_ffdhe3072:
            length = 384;
            break;
        case tlsExtNamedCurves_ffdhe4096:
            length = 512;
            break;
        case tlsExtNamedCurves_ffdhe6144:
            length = 768;
            break;
        case tlsExtNamedCurves_ffdhe8192:
            length = 1024;
            break;
#endif
#if defined(__ENABLE_DIGICERT_PQC__)
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtHybrid_SecP256r1MLKEM768:
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtHybrid_X25519MLKEM768:
#endif
        {
            SSL_SOCK_getCurveIdFromNameQS(namedGroup, &eccCurveGroup, &curveId, &qsAlgo);
            isQS  = TRUE;
            isECC = TRUE;
            namedGroup = eccCurveGroup;
            break;
        }
#endif
        default:
            status = ERR_SSL_UNSUPPORTED_CURVE;
    }
    if (OK != status)
    {
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if (TRUE == isECC)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(
            SSL_SOCK_getCurveIdFromName(namedGroup),
                            &length)))
#else
        if (OK > (status = EC_getPointByteStringLen(SSL_SOCK_getCurveFromName(namedGroup),
            (sbyte4 *)&length)))
#endif
        {
            goto exit;
        }
#if defined(__ENABLE_DIGICERT_PQC__)
        if (TRUE == isQS)
        {
            if (OK > (status = CRYPTO_INTERFACE_QS_getPublicKeyLenFromAlgo(qsAlgo, &qsLength)))
            {
                goto exit;
            }
            length += qsLength;
        }
#endif
    }
#endif

    if (OK == status)
    {
        *pLength = length;
    }

exit:
    return status;
}

static MSTATUS getPublicKeyFromSharedKeyEntry(MOC_DH(hwAccelDescr hwAccelCtx1) MOC_ECC(hwAccelDescr hwAccelCtx2) sharedKey *pSharedKey, ubyte *pPubKey, ubyte4 pubKeyLen, ubyte4 namedGroup)
{
    MSTATUS status = ERR_SSL_INVALID_KEY_TYPE;
    ubyte *pKey = NULL;
    ubyte4 keyLen;
    ECCKey *pECCKey = NULL;
#ifndef __ENABLE_DIGICERT_PQC__
    MOC_UNUSED(namedGroup);
#endif

    if ((NULL == pSharedKey) || (NULL == pPubKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_dh == pSharedKey->type)
    {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_getPublicKeyExt(MOC_DH(hwAccelCtx1) (diffieHellmanContext *)pSharedKey->pKey,
            &pKey, &keyLen, NULL);
#else
        status = DH_getPublicKeyExt(MOC_DH(hwAccelCtx1) (diffieHellmanContext *)pSharedKey->pKey,
            &pKey, &keyLen, NULL);
#endif
        if (OK != status)
        {
            goto exit;
        }

        if (keyLen > pubKeyLen)
        {
            status = ERR_BUFFER_TOO_SMALL;
            goto exit1;
        }

        status = DIGI_MEMCPY(pPubKey, pKey, keyLen);
        if (OK != status)
        {
            goto exit1;
        }

exit1:
        if (NULL != pKey)
        {
            MSTATUS status1 = OK;
            status1 = DIGI_FREE((void **) &pKey);

            if ((status >= OK) && (OK > status1))
            {
                status = status1;
            }
        }
        if (OK != status)
        {
            goto exit;
        }
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if((akt_ecc == pSharedKey->type) || (akt_ecc_ed == pSharedKey->type))
    {
        pECCKey = ((AsymmetricKey *) pSharedKey->pKey)->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(hwAccelCtx2)
                pECCKey, pPubKey, pubKeyLen)))
#else
        if (OK > (status = EC_writePointToBuffer(MOC_ECC(hwAccelCtx2) pECCKey->pCurve, pECCKey->Qx, pECCKey->Qy, pPubKey, pubKeyLen)))
#endif
        {
            goto exit;
        }
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_hybrid == pSharedKey->type)
    {
        QS_CTX *pKemCtx = ((AsymmetricKey *) pSharedKey->pKey)->pQsCtx;
        ubyte4 eccKeyLen = 0;
        ubyte4 eccKeyOffset;
        ubyte4 pqcKeyOffset;

        pECCKey = ((AsymmetricKey *) pSharedKey->pKey)->key.pECC;
                
        status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &eccKeyLen);
        if (OK != status)
            goto exit;
        
        if (HYBRID_IS_PQC_FIRST(namedGroup))
        {
            eccKeyOffset = pubKeyLen - eccKeyLen;
            pqcKeyOffset = 0;
        }
        else
        {
            eccKeyOffset = 0;
            pqcKeyOffset = eccKeyLen;
        }

        /* write the ecc key */
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(pECCKey, pPubKey + eccKeyOffset, eccKeyLen);
        if (OK != status)
            goto exit;
        
        /* now write the qs public key */
        status = CRYPTO_INTERFACE_QS_getPublicKey(pKemCtx, pPubKey + pqcKeyOffset, pubKeyLen - eccKeyLen);
    }
#endif
#endif

exit:
    return status;
}

static MSTATUS getLengthFromSharedKeyEntry(sharedKey *pSharedKey, ubyte4 *pPubKeyLen)
{
    MSTATUS status = ERR_SSL_UNSUPPORTED_CURVE;
    ubyte4 length;
    ECCKey *pECCKey = NULL;

    if ((NULL == pSharedKey) || (NULL == pPubKeyLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pPubKeyLen = 0;

    if (akt_dh == pSharedKey->type)
    {
        status = getNamedGroupLength(pSharedKey->namedGroup, &length);
        if (OK != status)
        {
            goto exit;
        }

        *pPubKeyLen = length;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if((akt_ecc == pSharedKey->type) || (akt_ecc_ed == pSharedKey->type))
    {
        pECCKey = ((AsymmetricKey *) pSharedKey->pKey)->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(
            pECCKey, &length)))
#else
        if (OK > (status = EC_getPointByteStringLen(pECCKey->pCurve, (sbyte4 *)&length)))
#endif
        {
            goto exit;
        }

        *pPubKeyLen = length;
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_hybrid == pSharedKey->type)
    {
        ubyte4 qsPubLen = 0;
        QS_CTX *pQsCtx = NULL;
        
        pECCKey = ((AsymmetricKey *) pSharedKey->pKey)->key.pECC;
        pQsCtx = ((AsymmetricKey *) pSharedKey->pKey)->pQsCtx;

        if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCKey, &length)))
            goto exit;
        
        if (OK > (status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pQsCtx, &qsPubLen)))
            goto exit;
        
        *pPubKeyLen = length + qsPubLen;
    }
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_ECC__
static MSTATUS generateKeyShareEntryECDHE(ubyte4 namedGroup, AsymmetricKey **ppAsymKey,
    SSLSocket *pSSLSock)
{
    MSTATUS status;
    AsymmetricKey *pAsymKey = NULL;
    ECCKey *pECCKey = NULL;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte4 curveId = SSL_SOCK_getCurveIdFromName(namedGroup);
#else
    PEllipticCurvePtr pCurve = SSL_SOCK_getCurveFromName(namedGroup);
#endif

    if (NULL == ppAsymKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppAsymKey = NULL;

    /* Allocate a shell for the current AsymmetricKey.
     */
    status = DIGI_CALLOC((void **) &pAsymKey, 1, sizeof(AsymmetricKey));
    if (OK != status)
        goto exit;

    /* Allocate the underlying ECC key.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_createECCKeyEx(pAsymKey, curveId);
#else
    status = CRYPTO_createECCKey(pAsymKey, pCurve);
#endif
    if (OK != status)
        goto exit;

    pECCKey = pAsymKey->key.pECC;

    /* Generate the key data from the specified curve.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_generateKeyPairAux(MOC_ECC(pSSLSock->hwAccelCookie)
        pECCKey, pSSLSock->rngFun, pSSLSock->rngFunArg)))
#else
    if (OK > (status = EC_generateKeyPair(MOC_ECC(pSSLSock->hwAccelCookie) pCurve, pSSLSock->rngFun, pSSLSock->rngFunArg,
                                        pECCKey->k, pECCKey->Qx, pECCKey->Qy)))
#endif
    {
        goto exit;
    }

    *ppAsymKey = pAsymKey;
    pAsymKey = NULL;

exit:
    if (NULL != pAsymKey)
    {
        CRYPTO_uninitAsymmetricKey(pAsymKey, NULL);
        DIGI_FREE((void **) &pAsymKey);
    }

    return status;
}
#endif

#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
static MSTATUS generateKeyShareEntryFFDH(MOC_DH(hwAccelDescr hwAccelCtx) ubyte4 namedGroup, diffieHellmanContext **ppDHContext)
{
    MSTATUS status;
    diffieHellmanContext* pDHContext = NULL;

    if (0 == namedGroup)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (NULL == ppDHContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppDHContext = NULL;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_allocateServerExt(MOC_DH(hwAccelCtx) g_pRandomContext, &pDHContext, namedGroup, NULL);
#else
    status = DH_allocateServerExt(MOC_DH(hwAccelCtx) g_pRandomContext, &pDHContext, namedGroup, NULL);
#endif
    if (OK != status)
    {
        goto exit;
    }

    *ppDHContext = pDHContext;
    pDHContext = NULL;

exit:

    if ((OK != status) && (NULL != pDHContext))
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContextExt(&pDHContext, NULL, NULL);
#else
        DH_freeDhContextExt(&pDHContext, NULL, NULL);
#endif
    }

    return status;
}
#endif

static MSTATUS deleteSharedKey(sharedKey* pSharedKey)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pSharedKey)
    {
        goto exit;
    }

    if (akt_dh == pSharedKey->type)
    {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_freeDhContextExt((diffieHellmanContext **) &(pSharedKey->pKey),
            NULL, NULL);
#else
        status = DH_freeDhContextExt((diffieHellmanContext **) &(pSharedKey->pKey),
            NULL, NULL);
#endif
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }
    else if((akt_ecc == pSharedKey->type) || (akt_ecc_ed == pSharedKey->type) || (akt_hybrid == pSharedKey->type))
    {
        status = CRYPTO_uninitAsymmetricKey((AsymmetricKey *) pSharedKey->pKey, NULL);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGI_FREE((void **) &(pSharedKey->pKey));
        if (OK != status)
        {
            goto exit;
        }
    }
    
exit:
    return status;
}

static MSTATUS generateSharedKey(SSLSocket* pSSLSock, ubyte4 namedGroup, sharedKey* pSharedKey)
{
    ubyte4 type = akt_undefined;
    MSTATUS status = OK;
    diffieHellmanContext *pDHcontext = NULL;
    AsymmetricKey *pAsymKey = NULL;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4 qsAlgo;
    ubyte4 qsEcCurve;
    ubyte4 qsECCurveId;
#endif

    if (NULL == pSharedKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(namedGroup)
    {
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case tlsExtNamedCurves_secp256r1:
            type = akt_ecc;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case tlsExtNamedCurves_secp384r1:
            type = akt_ecc;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case tlsExtNamedCurves_secp521r1:
            type = akt_ecc;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case tlsExtNamedCurves_secp224r1:
            type = akt_ecc;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case tlsExtNamedCurves_secp192r1:
            type = akt_ecc;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtNamedCurves_x25519:
            type = akt_ecc_ed;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
        case tlsExtNamedCurves_x448:
            type = akt_ecc_ed;
            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case tlsExtHybrid_SecP256r1MLKEM768:
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
        case tlsExtHybrid_X25519MLKEM768:
#endif
            type = akt_hybrid;
            if (OK > (status = SSL_SOCK_getCurveIdFromNameQS(namedGroup, &qsEcCurve, &qsECCurveId, &qsAlgo)))
            {
                goto exit;
            }
            break;
#endif
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
        case tlsExtNamedCurves_ffdhe2048:
        case tlsExtNamedCurves_ffdhe3072:
        case tlsExtNamedCurves_ffdhe4096:
        case tlsExtNamedCurves_ffdhe6144:
        case tlsExtNamedCurves_ffdhe8192:
            type = akt_dh;
            break;
#endif
        default:
            status = ERR_SSL_UNSUPPORTED_CURVE;
    };
    if (OK != status)
    {
        goto exit;
    }

    if (akt_dh == type)
    {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
        pSharedKey->type = type;
        pSharedKey->namedGroup = namedGroup;

        status = generateKeyShareEntryFFDH(MOC_DH(pSSLSock->hwAccelCookie) namedGroup, &pDHcontext);
        if (OK != status)
        {
            goto exit;
        }

        pSharedKey->pKey = (void *) pDHcontext;
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if(akt_ecc == type)
    {
        pSharedKey->type = type;
        pSharedKey->namedGroup = namedGroup;

        status = generateKeyShareEntryECDHE(namedGroup, &pAsymKey, pSSLSock);
        if (OK != status)
        {
            goto exit;
        }

        pSharedKey->pKey = (void *) pAsymKey;
    }
#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
    else if(akt_ecc_ed == type)
    {
        pSharedKey->type = type;
        pSharedKey->namedGroup = namedGroup;

        status = generateKeyShareEntryECDHE(namedGroup, &pAsymKey, pSSLSock);
        if (OK != status)
        {
            goto exit;
        }

        pSharedKey->pKey = (void *) pAsymKey;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if(akt_hybrid == type)
    {
        pSharedKey->type = type;
        pSharedKey->namedGroup = namedGroup;
        
        /* generate the ECC portion */
        status = generateKeyShareEntryECDHE(qsEcCurve, &pAsymKey, pSSLSock);
        if (OK != status)
            goto exit;
        
        status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(pSSLSock->hwAccelCookie) &pAsymKey->pQsCtx, qsAlgo);
        if (OK != status)
            goto exit;
        
        status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(pSSLSock->hwAccelCookie) pAsymKey->pQsCtx, pSSLSock->rngFun, pSSLSock->rngFunArg);
        if (OK != status)
            goto exit;

        pAsymKey->type = type;

        pSharedKey->pKey = (void *) pAsymKey;
    }
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

exit:
    return status;
}


/*
 * Construct "key_share" extension
 * We support Elliptic Curves now (not FFDHE).
 */
MSTATUS
constructTLSExtKeyShare(SSLSocket *pSSLSock, ubyte **ppPacket, ubyte2 *pLength)
{
    MSTATUS status = OK;
    ubyte2 extensionLen = 0;
    ubyte4 i = 0;
    ECCKey *pECCKey = NULL;
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    enum tlsExtNamedCurves chosenCurve = (enum tlsExtNamedCurves) 0;
#endif
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    ubyte4 totalCurveLength=0;
#endif
    ubyte4 curveLength;
    ubyte4 pointLen = 0;
    ubyte2* pSupportedGroupsList = pSSLSock->pSupportedGroupList;
    ubyte4  supportedGroupsListLength = pSSLSock->supportedGroupListLength;
    MOC_UNUSED(pLength);

    setShortValue(*ppPacket, (ubyte2)tlsExt_key_share);
    *ppPacket += sizeof(ubyte2);

    /* Group name(2*NUM_SSL_SUPPORTED_NAMED_GROUP) +
     * Key Length (2*NUM_SSL_SUPPORTED_NAMED_GROUP) +
     * Key(SUM_OF_ALL_SIZES) +
     * Legacy(1*NUM_SSL_SUPPORTED_NAMED_GROUP)
     */

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    if (!pSSLSock->server)
    {
        /* RFC: 4.1.2: Client Hello:
         * If a "key_share" extension was supplied in the HelloRetryRequest,
         * replacing the list of shares with a list containing a single
         * KeyShareEntry from the indicated group.
         */
        if (pSSLSock->helloRetryRequest && pSSLSock->roleSpecificInfo.client.selectedGroup) 
        {
            status = getNamedGroupLength(pSSLSock->roleSpecificInfo.client.selectedGroup, &curveLength);
            if (OK != status)
            {
                goto exit;
            }

            totalCurveLength = curveLength + totalCurveLength;
            extensionLen += (2 + (2 * 1) + (2 * 1) + totalCurveLength);
        }
        else
        {
            /* Calculate the length of the key share based on all the
             * supported groups.
             */
            for (i = 0; i < supportedGroupsListLength; i++)
            {
                status = getNamedGroupLength(pSupportedGroupsList[i], &curveLength);
                if (OK != status)
                {
                    goto exit;
                }

                /* 2 bytes - named group
                 * 2 bytes - group data length
                 * x bytes - group data
                 */
                totalCurveLength += 2 + 2 + curveLength;

                /* Compiling with this flag will cause the client to send a key
                 * share entry for all the groups that are supported. If NanoSSL is
                 * compiled without this flag the client will only a key share entry
                 * for the first supported group sent.
                 */
#if !defined(__ENABLE_DIGICERT_ALL_KEYSHARE__)
                break;
#endif
            }

            /* 2 bytes - key share length
             * x bytes - all key shares
             */
            extensionLen += 2 + totalCurveLength;
        }
    }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    if (pSSLSock->server)
    {
        if(pSSLSock->helloRetryRequest)
        {
            extensionLen += 2;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_PQC__
            if ( HYBRID_SUPPORTED_GROUP_MASK == ( pSSLSock->roleSpecificInfo.server.selectedGroup & SUPPORTED_GROUP_MASK ))
            {
                status = getNamedGroupCipherTextLen(pSSLSock->roleSpecificInfo.server.selectedGroup, &curveLength);
                if (OK != status)
                {
                    goto exit;
                }
            }
            else
#endif
            {
                status = getNamedGroupLength(pSSLSock->roleSpecificInfo.server.selectedGroup, &curveLength);
                if (OK != status)
                {
                    goto exit;
                }
            }
            

            extensionLen +=  2 + 2 + curveLength;
        }
    }
#endif

    /* Extension Length */
    setShortValue(*ppPacket, extensionLen); /* Total length - 2(Ext Type) - 2(Ext Length) */
    *ppPacket += sizeof(ubyte2);

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    if (!pSSLSock->server)
    {
        /* Since Server has only one key share entry, this length is not needed */
        /* Lenght of Keyshare */
        setShortValue(*ppPacket, (extensionLen - 2)); /*Key Share Length; Total length - 2(Ext Type) - 2 (Ext Length) -2(KeyShare length)*/
        *ppPacket += sizeof(ubyte2);

        if (pSSLSock->roleSpecificInfo.client.ppSharedKeys != NULL)
        {
            SSLSOCK_clearKeyShare(pSSLSock);
        }

        if(supportedGroupsListLength > 0)
        {
            status = DIGI_CALLOC(
                (void **) &(pSSLSock->roleSpecificInfo.client.ppSharedKeys),
                1, supportedGroupsListLength * sizeof(sharedKey));
            if (OK > status)
            {
                goto exit;
            }
        }

        pSSLSock->roleSpecificInfo.client.sharedKeyCount = supportedGroupsListLength;

        if (pSSLSock->helloRetryRequest && pSSLSock->roleSpecificInfo.client.selectedGroup)
        {
            ubyte4 curve = pSSLSock->roleSpecificInfo.client.selectedGroup;

            status = generateSharedKey(pSSLSock, curve, pSSLSock->roleSpecificInfo.client.ppSharedKeys);
            if (OK != status)
            {
                goto exit;
            }

            status = getLengthFromSharedKeyEntry(pSSLSock->roleSpecificInfo.client.ppSharedKeys, &pointLen);
            if (OK != status)
            {
                goto exit;
            }

            /* Group Name */
            setShortValue(*ppPacket, (ubyte2) pSSLSock->roleSpecificInfo.client.selectedGroup);
            *ppPacket += sizeof(ubyte2);

            /* Length of rest of the entity(X, Y, legacy_form) */
            setShortValue(*ppPacket, pointLen);
            *ppPacket += sizeof(ubyte2);

            status = getPublicKeyFromSharedKeyEntry(MOC_DH(pSSLSock->hwAccelCookie) MOC_ECC(pSSLSock->hwAccelCookie) pSSLSock->roleSpecificInfo.client.ppSharedKeys, *ppPacket, pointLen, pSSLSock->roleSpecificInfo.client.selectedGroup);
            if (OK != status)
            {
                goto exit;
            }
            *ppPacket += pointLen;

        }
        else
        {
            for (i = 0; i < supportedGroupsListLength; i++)
            {
                ubyte4 curve = pSupportedGroupsList[i];

                status = generateSharedKey(pSSLSock, curve, &(pSSLSock->roleSpecificInfo.client.ppSharedKeys[i]));
                if (OK != status)
                {
                    goto exit;
                }

                status = getLengthFromSharedKeyEntry(&(pSSLSock->roleSpecificInfo.client.ppSharedKeys[i]), &pointLen);
                if (OK != status)
                {
                    goto exit;
                }

                /* Group Name */
                setShortValue(*ppPacket, (ubyte2)pSupportedGroupsList[i]);
                *ppPacket += sizeof(ubyte2);

                /* Length of rest of the entity(X, Y, legacy_form) */
                setShortValue(*ppPacket, pointLen);
                *ppPacket += sizeof(ubyte2);

                status = getPublicKeyFromSharedKeyEntry(MOC_DH(pSSLSock->hwAccelCookie) MOC_ECC(pSSLSock->hwAccelCookie) &(pSSLSock->roleSpecificInfo.client.ppSharedKeys[i]), *ppPacket, pointLen, pSupportedGroupsList[i]);
                if (OK != status)
                {
                    goto exit;
                }
                *ppPacket += pointLen;

                /* Compiling with this flag will cause the client to send a key
                 * share entry for all the groups that are supported. If NanoSSL
                 * is compiled without this flag the client will only a key
                 * share entry for the first supported group sent.
                 */
#if !defined(__ENABLE_DIGICERT_ALL_KEYSHARE__)
                break;
#endif
            }
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    if (pSSLSock->server)
    {
        /* Group Name */
        if(pSSLSock->helloRetryRequest)
        {
            for (i = 0; i <supportedGroupsListLength; ++i)
            {
                if (pSupportedGroupsList[i] ==
                    pSSLSock->roleSpecificInfo.server.selectedGroup)
                {
                    chosenCurve = (enum tlsExtNamedCurves)pSupportedGroupsList[i];
                    break;
                }
            }
            setShortValue(*ppPacket, (ubyte2)chosenCurve);
            *ppPacket += sizeof(ubyte2);
        }
        else
        {
            ubyte4 namedGroup = pSSLSock->roleSpecificInfo.server.selectedGroup;
            if (FFDH_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & namedGroup))
            {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
                /* Finite Field Groups (DHE) */
                diffieHellmanContext* pDHcontext = NULL;
                ubyte *pKey = NULL;
                ubyte4 keyLen = 0;

                if (NULL != pSSLSock->pDHcontext)
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
#else
                    status = DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
#endif
                    if (OK != status)
                    {
                        goto exit;
                    }
                }

                status = generateKeyShareEntryFFDH(MOC_DH(pSSLSock->hwAccelCookie) namedGroup, &(pSSLSock->pDHcontext));
                if (OK != status)
                {
                    goto exit;
                }

                pDHcontext = pSSLSock->pDHcontext;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_DH_getPublicKeyExt(MOC_DH(pSSLSock->hwAccelCookie) pDHcontext, &pKey, &keyLen, NULL);
#else
                status = DH_getPublicKeyExt(MOC_DH(pSSLSock->hwAccelCookie) pDHcontext, &pKey, &keyLen, NULL);
#endif
                if (OK != status)
                {
                    goto exit;
                }

                /* Group Name */
                setShortValue(*ppPacket, (ubyte2)namedGroup);
                *ppPacket += sizeof(ubyte2);

                /* Length of rest of the entity(X, Y, legacy_form) */
                setShortValue(*ppPacket, keyLen);
                *ppPacket += sizeof(ubyte2);

                status = DIGI_MEMCPY(*ppPacket, pKey, keyLen);
                if (OK != status)
                {
                    DIGI_FREE((void **) &pKey);
                    goto exit;
                }
                *ppPacket += keyLen;

                status = DIGI_FREE((void **) &pKey);
                if (OK != status)
                {
                    goto exit;
                }
#else
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
#endif /* __DISABLE_DIGICERT_DIFFIE_HELLMAN__ */
            }
#ifdef __ENABLE_DIGICERT_ECC__
            else if (ECDH_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & namedGroup))
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                ubyte4 curveId = SSL_SOCK_getCurveIdFromName(pSSLSock->roleSpecificInfo.server.selectedGroup);
#else
                PEllipticCurvePtr pCurve = SSL_SOCK_getCurveFromName(pSSLSock->roleSpecificInfo.server.selectedGroup);
#endif

                /*
                 * if (OK > (status = CRYPTO_initAsymmetricKey(&pSSLSock->ecdheKey)))
                 *   goto exit;
                 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK > (status = CRYPTO_createECCKeyEx(&pSSLSock->ecdheKey, curveId)))
#else
                if (OK > (status = CRYPTO_createECCKey(&pSSLSock->ecdheKey, pCurve)))
#endif
                {
                    goto exit;
                }

                pECCKey = pSSLSock->ecdheKey.key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK > (status = CRYPTO_INTERFACE_EC_generateKeyPairAux(MOC_ECC(pSSLSock->hwAccelCookie)
                    pECCKey, pSSLSock->rngFun, pSSLSock->rngFunArg)))
#else
                if (OK > (status = EC_generateKeyPair(MOC_ECC(pSSLSock->hwAccelCookie) pCurve, pSSLSock->rngFun, pSSLSock->rngFunArg,
                                                    pECCKey->k, pECCKey->Qx, pECCKey->Qy)))
#endif
                {
                    goto exit;
                }

                pointLen = 0; /* Set to 0 before using */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(
                    pECCKey, &pointLen)))
#else
                if (OK > (status = EC_getPointByteStringLen(pCurve, (sbyte4 *)&pointLen)))
#endif
                {
                    goto exit;
                }

                /* Group Name */
                setShortValue(*ppPacket, (ubyte2)pSSLSock->roleSpecificInfo.server.selectedGroup);
                *ppPacket += sizeof(ubyte2);

                /* Length of rest of the entity(X, Y, legacy_form) */
                setShortValue(*ppPacket, pointLen);
                *ppPacket += sizeof(ubyte2);

                /* Write the points X and Y to the given buffer */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(pSSLSock->hwAccelCookie)
                    pECCKey, *ppPacket, pointLen)))
#else
                if (OK > (status = EC_writePointToBuffer(MOC_ECC(pSSLSock->hwAccelCookie) pCurve, pECCKey->Qx, pECCKey->Qy, *ppPacket, pointLen)))
#endif
                {
                    goto exit;
                }
                *ppPacket += pointLen;
            }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
            else if (HYBRID_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & namedGroup))
            {
                /* Set EC curve and QS algo based on negotiated QS
                 * algorithm. */
                ubyte4 ecCurve = 0, ecCurveId = 0;
                ubyte4 qsAlgo;
                ubyte4 length, qsLength;
                ubyte *pECCPubStart;
                ubyte *pPQCPubStart;

                if (OK > (status = SSL_SOCK_getCurveIdFromNameQS(pSSLSock->roleSpecificInfo.server.selectedGroup,
                                                                 &ecCurve, &ecCurveId, &qsAlgo)))
                {
                    goto exit;
                }

                status = CRYPTO_createECCKeyEx(&(pSSLSock->ecdheKey), ecCurveId);
                if (OK != status)
                {
                    goto exit;
                }

                status = CRYPTO_INTERFACE_EC_generateKeyPairAux(
                    MOC_ECC(pSSLSock->hwAccelCookie) pSSLSock->ecdheKey.key.pECC,
                    pSSLSock->rngFun, pSSLSock->rngFunArg);
                if (OK != status)
                {
                    goto exit;
                }

                status = CRYPTO_INTERFACE_QS_newCtx(
                    MOC_HASH(pSSLSock->hwAccelCookie)
                    &(pSSLSock->ecdheKey.pQsCtx), qsAlgo);
                if (OK != status)
                {
                    goto exit;
                }

                pSSLSock->ecdheKey.type = akt_hybrid;

                status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(
                    ecCurveId, &length);
                if (OK != status)
                {
                    goto exit;
                }

                status = CRYPTO_INTERFACE_QS_setPublicKey(
                    pSSLSock->ecdheKey.pQsCtx,
                    pSSLSock->roleSpecificInfo.server.receivedPubKey + (HYBRID_IS_PQC_FIRST(namedGroup) ? 0 : length),
                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen - length);
                if (OK != status)
                {
                    goto exit;
                }

                /* Generate QS cipher text and shared secret here */
                status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(
                    pSSLSock->ecdheKey.pQsCtx, &(pSSLSock->qsSharedSecretLen));
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MALLOC(
                    (void **) &(pSSLSock->pQsSharedSecret),
                    pSSLSock->qsSharedSecretLen);
                if (OK != status)
                {
                    goto exit;
                }

                status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(
                    pSSLSock->ecdheKey.pQsCtx, &qsLength);
                if (OK != status)
                {
                    goto exit;
                }

                /* Group name */
                setShortValue(*ppPacket, (ubyte2) namedGroup);
                *ppPacket += sizeof(ubyte2);

                /* Length - EC public point and QS ciphertext */
                setShortValue(*ppPacket, (ubyte2) (length + qsLength));
                *ppPacket += sizeof(ubyte2);

                if (HYBRID_IS_PQC_FIRST(namedGroup))
                {
                    pECCPubStart = *ppPacket + qsLength;
                    pPQCPubStart = *ppPacket;
                }
                else
                {
                    pECCPubStart = *ppPacket;
                    pPQCPubStart = *ppPacket + length;
                }

                status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(
                    MOC_ECC(pSSLSock->hwAccelCookie) pSSLSock->ecdheKey.key.pECC,
                    pECCPubStart, length);
                if (OK != status)
                {
                    goto exit;
                }
             
                /* Generate ciphertext and shared secret (non-QS secret is
                 * generated later) */
                status = CRYPTO_INTERFACE_QS_KEM_encapsulate(
                    pSSLSock->ecdheKey.pQsCtx, pSSLSock->rngFun,
                    pSSLSock->rngFunArg, pPQCPubStart, qsLength,
                    pSSLSock->pQsSharedSecret, pSSLSock->qsSharedSecretLen);
                if (OK != status)
                {
                    goto exit;
                }
                *ppPacket += (qsLength + length);
            }
#endif
        }
    }
#endif
exit:
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    if ((!pSSLSock->server) && (status >= OK))
    {
        pSSLSock->roleSpecificInfo.client.extensions = TLS13_CLIENT_SET_KEY_SHARE_TX(pSSLSock);
    }
#endif
    return status;
}

static MSTATUS
SSLSOCK_calcTranscriptHashForBuffer(MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest, ubyte *in, ubyte4 inLen, ubyte *pOutBuffer)
{
    MSTATUS status = OK;
    switch(pDigest->digestSize)
    {
#ifndef __DISABLE_DIGICERT_SHA256__
        case SHA256_RESULT_SIZE:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(hwAccelCtx) in, inLen, pOutBuffer);
#else
            status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) in, inLen, pOutBuffer);
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case SHA384_RESULT_SIZE:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA384_completeDigest(MOC_HASH(hwAccelCtx) in, inLen, pOutBuffer);
#else
            status = SHA384_completeDigest(MOC_HASH(hwAccelCtx) in, inLen, pOutBuffer);
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case SHA512_RESULT_SIZE:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_SHA512_completeDigest(MOC_HASH(hwAccelCtx) in, inLen, pOutBuffer);
#else
            status = SHA512_completeDigest(MOC_HASH(hwAccelCtx) in, inLen, pOutBuffer);
#endif
            break;
#endif
        default:
            status = ERR_SSL_HASH_ALGO_NULL;
            break;
    }

    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TLS13__)

/*
 * This function constructs the "supported_versions" extension for TLS 1.3 and above.
 */
MSTATUS
SSL_SOCK_constructTLSExtSupportedVersions(SSLSocket* pSSLSock, ubyte** ppVersionBuffer, ubyte versionMask)
{
    MSTATUS status = OK;
    int supportedVersionLen = 0;
    ubyte2 serverSupportedVersion = 0;
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    int i;
    ubyte2 maxSupportedVersion = 0;
    ubyte2 minSupportedVersion = 0;
#endif
    ubyte2 majorVersion = SSL3_MAJORVERSION;
    int numSupportedVersions = NUM_SUPPORTED_VERSIONS;

    if (pSSLSock == NULL)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if (pSSLSock->isDTLS)
    {
        majorVersion = DTLS1_MAJORVERSION;
        numSupportedVersions = NUM_SUPPORTED_VERSIONS_DTLS;
    }
#endif

    /* Server also constructs this extension to indicate the version choosen */
    if (pSSLSock->server)
    {
#ifdef __ENABLE_DIGICERT_DTLS_SERVER__
        if (pSSLSock->isDTLS)
        {
            serverSupportedVersion = DTLS1_MAJORVERSION << 8 | pSSLSock->sslMinorVersion;
            supportedVersionLen = 1;
        }
        else
#endif
        {
            serverSupportedVersion = SSL3_MAJORVERSION << 8 | pSSLSock->sslMinorVersion;
            supportedVersionLen = 1;
        }
    }
    else
    {
        if (pSSLSock->helloRetryRequest)
        {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
                if (pSSLSock->isDTLS)
                {
                    maxSupportedVersion = majorVersion << 8 | DTLS13_MINORVERSION;
                }
                else
#endif
                {
                    maxSupportedVersion = majorVersion << 8 | TLS13_MINORVERSION;
                }
#endif
            supportedVersionLen = 1;
        }
        else
        {
            if (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET)
            {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)

                maxSupportedVersion = majorVersion << 8 | pSSLSock->advertisedMinorVersion;
#endif
                supportedVersionLen = 1; /* Include only the configured version */
            }
            else if (pSSLSock->runtimeFlags & SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET)
            {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
                maxSupportedVersion = majorVersion << 8 | SSL_sslSettings()->sslMaxProtoVersion;
                minSupportedVersion = majorVersion << 8 | pSSLSock->minFallbackMinorVersion;
#endif
                supportedVersionLen = numSupportedVersions - pSSLSock->minFallbackMinorVersion + 1;
            }
            else
            {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
                maxSupportedVersion = majorVersion << 8 | SSL_sslSettings()->sslMaxProtoVersion;
                minSupportedVersion = majorVersion << 8 | SSL_sslSettings()->sslMinProtoVersion;
#endif
                supportedVersionLen = numSupportedVersions;
            }
        }
    }

    /* Write extension type */
    setShortValue(*ppVersionBuffer, (ubyte2)tlsExt_supported_versions);
    *ppVersionBuffer += sizeof(ubyte2);

    if (supportedVersionLen < 1)
    {
        status = ERR_SSL_PROTOCOL_VERSION;
        goto exit;
    }

    if (pSSLSock->server)
    {
        /* Write extension length */
        if(versionMask == VERSION_MASK_2)
        {
            setShortValue(*ppVersionBuffer, (ubyte2) ((supportedVersionLen * 2))); /* Length + size of each version */
            *ppVersionBuffer += sizeof(ubyte2);
        }
        else
        {
            setShortValue(*ppVersionBuffer, (ubyte2) (supportedVersionLen * 2)); /* size of each version;
                                                                                Server has only one entry in supported_version,
                                                                                So length is not needed*/
            *ppVersionBuffer += sizeof(ubyte2);
        }

        setShortValue( *ppVersionBuffer, serverSupportedVersion);
        *ppVersionBuffer += sizeof(ubyte2);
        goto exit;
    }
    else
    {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        /* Write extension length */
        setShortValue(*ppVersionBuffer, (ubyte2) (1 + (supportedVersionLen * 2))); /* Length + size of each version */
        *ppVersionBuffer += sizeof(ubyte2);

        /* Write supportedVersionListLength */
        **ppVersionBuffer = (supportedVersionLen * 2);
        *ppVersionBuffer += 1;

        /* SSL version is configured using SSL_ioctl call.
         * Send only the configured version in support version list
         */
        if ( (pSSLSock->runtimeFlags & SSL_FLAG_VERSION_SET) ||
             (pSSLSock->helloRetryRequest) )
        {
            /* Only one version is supported, i.e range is not set */
            setShortValue( *ppVersionBuffer, maxSupportedVersion);
            *ppVersionBuffer += sizeof(ubyte2);
            pSSLSock->roleSpecificInfo.client.pSharedVersions[0] = maxSupportedVersion;
            pSSLSock->roleSpecificInfo.client.sharedSupportedVersion = 1;
            pSSLSock->clientHelloMinorVersion = maxSupportedVersion & 0xFF;
            goto exit;
        }
        else
        {
            /* If version is not explicitly configured, write each supported version */
            for ( i = 0; i < supportedVersionLen; ++i)
            {
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                if (pSSLSock->isDTLS)
                {
                    /* remember dtls max version (1.3 ie, 252) is the smallest value */
                    if ((gSupportedVersionsDTLS[i] <= minSupportedVersion ) &&
                        (gSupportedVersionsDTLS[i] >= maxSupportedVersion))
                    {
                        if (i == 0)
                        {
                            /* note the most preferred version we sent -- used for RSA later on */
                            pSSLSock->clientHelloMinorVersion = gSupportedVersionsDTLS[i] & 0xFF;
                        }

                        setShortValue( *ppVersionBuffer, gSupportedVersionsDTLS[i]);
                        *ppVersionBuffer += sizeof(ubyte2);
                        pSSLSock->roleSpecificInfo.client.pSharedVersions[i] = gSupportedVersionsDTLS[i];
                    }
                }
                else
#endif
                {
                    if ((gSupportedVersions[i] >= minSupportedVersion ) &&
                        (gSupportedVersions[i] <= maxSupportedVersion))
                    {
                        if (i == 0)
                        {
                            /* note the most preferred version we sent -- used for RSA later on */
                            pSSLSock->clientHelloMinorVersion = gSupportedVersions[i] & 0xFF;
                        }

                        setShortValue( *ppVersionBuffer, gSupportedVersions[i]);
                        *ppVersionBuffer += sizeof(ubyte2);
                        pSSLSock->roleSpecificInfo.client.pSharedVersions[i] = gSupportedVersions[i];
                    }
                }
            }
        }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
    }
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    pSSLSock->roleSpecificInfo.client.sharedSupportedVersion = 1;
#endif

exit:
    return status;
}

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined( __ENABLE_DIGICERT_TLS13_0RTT__))
MSTATUS
SSL_SOCK_constructTLSExtEarlyData(SSLSocket *pSSLSock, ubyte handshakeType, ubyte **ppPacket)
{
    MSTATUS status = OK;

    /* Write the extension type */
    setShortValue(*ppPacket, (ubyte2)tlsExt_early_data);
    *ppPacket += sizeof(ubyte2);

    switch(handshakeType)
    {
        case SSL_NEW_SESSION_TICKET:
        {
            /* Write the extension length */
            setShortValue(*ppPacket, (ubyte2)sizeof(ubyte4));
            *ppPacket += sizeof(ubyte2);

            DIGI_MEMCPY(*ppPacket, &(pSSLSock->maxEarlyDataSize), sizeof(ubyte4));
            *ppPacket += sizeof(ubyte4);
            break;
        }
        case SSL_CLIENT_HELLO:
        case SSL_ENCRYPTED_EXTENSIONS:
        {
            /* RFC #8446 section 4.2.10.  Early Data Indication:
               As per RFC, for client hello and encrypted extension types
               the length of extension is 0.
             */
            /* Write the extension length */
            setShortValue(*ppPacket, (ubyte2)0);
            *ppPacket += sizeof(ubyte2);

            break;
        }
    }
    return status;
}

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
extern MSTATUS SSL_SOCK_sendEarlyData(SSLSocket *pSSLSock)
{
    MSTATUS status = OK;
    ubyte4  sizeofRecordHeader;
    ubyte4  sizeofHandshakeHeader;
    ubyte4  sizeofHandshakeRecord;
    ubyte*  pData = NULL;
    ubyte4  dataLen = 0;
    tls13PSK *pPSK = pSSLSock->roleSpecificInfo.client.pTLS13PSKList->pPSK;
    const BulkHashAlgo *pHashAlgo = NULL;

    pHashAlgo = getHashSuite((ubyte4)pPSK->hashAlgo);
    if (NULL == pHashAlgo)
    {
        status = ERR_SSL_HASH_ALGO_NULL;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
    if (pSSLSock->isDTLS)
    {
#ifdef __ENABLE_DIGICERT_TLS13__
        if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
        {
            sizeofRecordHeader = DTLS13_MOC_RECORD_HEADER_LEN;
            sizeofHandshakeRecord = sizeof(DTLSHandshakeHeader) + DTLS13_MOC_RECORD_HEADER_LEN;
        }
        else
#endif
        {
            sizeofRecordHeader = sizeof(DTLSRecordHeader);
            sizeofHandshakeRecord = sizeof(DTLSHandshakeRecord);
        }
        sizeofHandshakeHeader = sizeof(DTLSHandshakeHeader);
    } 
    else
#endif
    {
        sizeofRecordHeader = sizeof(SSLRecordHeader);
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
        sizeofHandshakeRecord = sizeof(SSLHandshakeRecord);
    }

    /* hash pool already initialized for dtls13 */
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && defined(__ENABLE_DIGICERT_TLS13__)
    if (!pSSLSock->isDTLS || DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)                
#endif
    {
        if (OK > (status = SSL_SOCK_initHashPool(pSSLSock)))
            goto exit;
    }

    /* Set the key material for 0-RTT data.
     */
    /* In case of 0-RTT we are adding ClientHello to handshakeHash here */
    addToHandshakeHash(pSSLSock, pSSLSock->roleSpecificInfo.client.helloBuffer, pSSLSock->roleSpecificInfo.client.helloBufferLen);

    status = SSLSOCK_pskEarlySecretDerive(pSSLSock,
                                          pPSK->pskTLS13,
                                          pPSK->pskTLS13Length,
                                          pHashAlgo);
    if (OK != status)
        goto exit;

    status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock, pSSLSock->pClientEarlyTrafficSecret);
    if (OK != status)
        goto exit;

    /*
       RFC #8446 Section 4.2.10
       When a PSK is used and early data is allowed for that PSK,
       the client can send Application Data in its first flight
       of messages.
     */

#if defined(__ENABLE_DIGICERT_TLS13_APPLICATION_DATA_CALLBACK__)
    if (pSSLSock->funcPtrSSLSendApplicationDataCallback != NULL)
    {
        sbyte4 connectionInstance = SSL_findConnectionInstance(pSSLSock);

        if (OK > (status = pSSLSock->funcPtrSSLSendApplicationDataCallback(connectionInstance,
                        &pData, &dataLen,
                        clientEarlyData)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        /* Use the early data set when connecting */
        pData   = pSSLSock->pEarlyData;
        dataLen = pSSLSock->earlyDataSize;
    }

    if ((pData == NULL) || (dataLen == 0))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (dataLen > pPSK->maxEarlyDataSize)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = sendData(pSSLSock, SSL_APPLICATION_DATA, (sbyte *) pData, dataLen, FALSE);

exit:
    CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, &(pSSLSock->buffers[0].pHeader));
    return status;
}
#endif /*__ENABLE_DIGICERT_SSL_CLIENT__ */
#endif
#endif /* __ENABLE_DIGICERT_TLS13__ */

#ifdef __ENABLE_DIGICERT_TLS13_PSK__
extern MSTATUS
SSLSOCK_freePSK(tls13PSK **ppPsk)
{
    MSTATUS status;

    if ( (NULL == ppPsk) || (NULL == *ppPsk) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppPsk)->pskTLS13Identity)
    {
        DIGI_FREE((void **) &((*ppPsk)->pskTLS13Identity));
    }

    DIGI_FREE((void **) ppPsk);

    status = OK;

exit:

    return status;
}

/* This function constructs the "pre_shared_key" extension.
 * This function can be called when building ClientHello or ServerHello.
 * ClientHello : Contains a list of PSKs offered and binder values for each
 * ServerHello : Index of the selected PSK from the list sent in ClientHello
 */
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
extern MSTATUS
constructTLSExtPreSharedKey(SSLSocket *pSSLSock, ubyte **ppPacket, ubyte hrrReply, ubyte selectedIndex)
{
    MSTATUS status = OK;
    ubyte4  extensionLen = 0;
    ubyte   *pTempBinder = NULL;
    ubyte4  binderLen = 0;
    ubyte   *pPartialClientHello = NULL;
    ubyte4  partialClientHelloLen = 0;

    ubyte2  totalBinderLen = 0;
    ubyte2  numOfTLS13PSK = pSSLSock->roleSpecificInfo.client.numOfTLS13PSK;
    ubyte2   i = 0;
    ubyte4  offset = 0, hashIndex;
    ubyte4  totalIdentitiesLength = 0;
    tls13PSK *pTempPSK = NULL;
    tls13PSKList *pTempPSKList = NULL;
    const BulkHashAlgo *pHashAlgo = NULL;
    ubyte *ppPartialDigests[NUM_SSL_SUPPORTED_HASH_ALGORITHMS] = { 0 };
    MOC_UNUSED(selectedIndex);

    /* Write the extension type */
    setShortValue(*ppPacket, (ubyte2)tlsExt_pre_shared_key);
    *ppPacket += sizeof(ubyte2);

    /* Identities Length(2) + Actual Identities (Identity Length(2) +
     * Identity_Value + Obfuscated Ticket Age(4) +Binder Length(2) + numOfBinder * 1 (33)
     * Note: In case of HRR, numofTLS13PSK is 1 as we are sending the selected Identity
     * by server.
     */

    if(hrrReply)
    {
        ubyte4 j = 0;
        pTempPSK     = pSSLSock->roleSpecificInfo.client.pTLS13PSKList->pPSK;
        pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

        extensionLen += 2 + 2;

        i = pSSLSock->roleSpecificInfo.client.serverSelectedIdentityIndex;
        while ((j <= i) && (pTempPSKList != NULL))
        {
            if (j == i)
            {
                pTempPSK = pTempPSKList->pPSK;
                break;
            }
            j++;
            pTempPSKList = pTempPSKList->pNextPSK;
        }

        if (pTempPSK != NULL)
        {
            pHashAlgo = getHashSuite((ubyte4)pTempPSK->hashAlgo);
            if (NULL == pHashAlgo)
            {
                status = ERR_SSL_HASH_ALGO_NULL;
                goto exit;
            }
            totalIdentitiesLength += pTempPSK->pskTLS13IdentityLength + 6; /* Identity Length(2) +  Obfuscated Ticket Age(4)*/
            totalBinderLen = pHashAlgo->digestSize + 1;
        }
    }
    else
    {
        pTempPSK = pSSLSock->roleSpecificInfo.client.pTLS13PSKList->pPSK;
        pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

        extensionLen += 2 + 2;

        i = 0;
        while((i < numOfTLS13PSK) && (pTempPSKList != NULL))
        {
            pTempPSK = pTempPSKList->pPSK;

            pHashAlgo = getHashSuite((ubyte4)pTempPSK->hashAlgo);
            if (NULL == pHashAlgo)
            {
                status = ERR_SSL_HASH_ALGO_NULL;
                goto exit;
            }

            totalIdentitiesLength += pTempPSK->pskTLS13IdentityLength + 6; /* Identity Length(2) +  Obfuscated Ticket Age(4)*/
            totalBinderLen        += pHashAlgo->digestSize + 1;

            i = i + 1;
            pTempPSKList = pTempPSKList->pNextPSK;
        }
    }

    extensionLen += totalIdentitiesLength;
    extensionLen += totalBinderLen;

    /* Write the extension Length */
    setShortValue(*ppPacket, (ubyte2)extensionLen);
    *ppPacket += sizeof(ubyte2);

    /* Write the Identities Length */
    setShortValue(*ppPacket, (ubyte2)(totalIdentitiesLength));
    *ppPacket += sizeof(ubyte2);

    /* RFC: 4.2.11.  Pre-Shared Key Extension : selected_identity:  The server's
     * chosen identity expressed as a (0-based) index into the identities in
     * the client's list.
     */
    if(hrrReply)
    {
        pTempPSK = pSSLSock->roleSpecificInfo.client.pTLS13PSKList->pPSK;
        pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

        if (pTempPSK != NULL)
        {
            setShortValue(*ppPacket, (ubyte2)pTempPSK->pskTLS13IdentityLength);
            *ppPacket += sizeof(ubyte2);

            /* Write the Identity  */
            DIGI_MEMCPY((void *)*ppPacket, pTempPSK->pskTLS13Identity, pTempPSK->pskTLS13IdentityLength);
            *ppPacket += pTempPSK->pskTLS13IdentityLength;

            /* Write the Obfuscated ticket age */
            **ppPacket = pTempPSK->pskTLS13AgeAdd >> 24;
            *ppPacket += 1;
            **ppPacket = (pTempPSK->pskTLS13AgeAdd >> 16) & 0xFF;
            *ppPacket += 1;
            **ppPacket = (pTempPSK->pskTLS13AgeAdd >>  8) & 0xFF;
            *ppPacket += 1;
            **ppPacket = pTempPSK->pskTLS13AgeAdd & 0xFF;
            *ppPacket += 1;
        }
    }
    else
    {
        pTempPSK = pSSLSock->roleSpecificInfo.client.pTLS13PSKList->pPSK;
        pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

        i = 0;

        while((i < numOfTLS13PSK) && (pTempPSKList != NULL))
        {
            pTempPSK = pTempPSKList->pPSK;

            /* Write the Identity Length */
            setShortValue(*ppPacket, (ubyte2)pTempPSK->pskTLS13IdentityLength);
            *ppPacket += sizeof(ubyte2);

            /* Write the Identity  */
            DIGI_MEMCPY((void *)*ppPacket,pTempPSK->pskTLS13Identity,
                       pTempPSK->pskTLS13IdentityLength);

            *ppPacket += pTempPSK->pskTLS13IdentityLength;

            /* Write the Obfuscated ticket age */
            **ppPacket = pTempPSK->pskTLS13AgeAdd >> 24;
            *ppPacket += 1;
            **ppPacket = (pTempPSK->pskTLS13AgeAdd >> 16) & 0xFF;
            *ppPacket += 1;
            **ppPacket = (pTempPSK->pskTLS13AgeAdd >>  8) & 0xFF;
            *ppPacket += 1;
            **ppPacket = pTempPSK->pskTLS13AgeAdd & 0xFF;
            *ppPacket += 1;

            pSSLSock->roleSpecificInfo.client.selectedIdentityIndex = (pSSLSock->roleSpecificInfo.client.selectedIdentityIndex)|(1 << i);

            i = i + 1;
            pTempPSKList = pTempPSKList->pNextPSK;
        }
    }

    pPartialClientHello  = pSSLSock->buffers[0].data;
    /* 2 is the size of binder length that needs to be extracted while
     * calculating the binder value. 5 is the size of handshake header (13 for dtls)
     */
#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
    if (pSSLSock->isDTLS)
    {
        partialClientHelloLen = pSSLSock->buffers[0].length - totalBinderLen - BINDER_LENGTH_VARIABLE - RECORD_LAYER_LENGTH_DTLS; 
    }
    else
#endif
    {
        partialClientHelloLen = pSSLSock->buffers[0].length - totalBinderLen - BINDER_LENGTH_VARIABLE - RECORD_LAYER_LENGTH;
    }

    i = 0;

    /*
     * Write the Binder List Length
     * BinderLen + 1 byte for each of the binders
     * We have already added this additional byte in totalBinderLen
     */
    setShortValue(*ppPacket, (ubyte2)(totalBinderLen));
    *ppPacket += sizeof(ubyte2);

    pTempPSK = pSSLSock->roleSpecificInfo.client.pTLS13PSKList->pPSK;
    pTempPSKList = pSSLSock->roleSpecificInfo.client.pTLS13PSKList;

    while((i < numOfTLS13PSK) && (pTempPSKList != NULL))
    {
        pTempPSK = pTempPSKList->pPSK;

        pHashAlgo = getHashSuite((ubyte4)pTempPSK->hashAlgo);
        if (NULL == pHashAlgo)
        {
            status = ERR_SSL_HASH_ALGO_NULL;
            goto exit;
        }

        status = SSLSOCK_computePartialDigests(
            pSSLSock, ppPartialDigests, NUM_SSL_SUPPORTED_HASH_ALGORITHMS,
            pPartialClientHello, partialClientHelloLen, pHashAlgo, &hashIndex);
        if (OK > status)
        {
            goto exit;
        }

        status = SSLSOCK_pskBinderEntry(MOC_HASH(pSSLSock->hwAccelCookie)
            pSSLSock,
            ppPartialDigests[hashIndex], pHashAlgo->digestSize,
            pTempPSK->pskTLS13,
            pTempPSK->pskTLS13Length,
            pTempPSK->isExternal,
            pHashAlgo,
            &pTempBinder, &binderLen);
        if (OK != status)
            goto exit;

        offset += binderLen;
        if (offset > totalBinderLen)
        {
            /* Error case; Check if we have to raise an alert */
            (void) DIGI_FREE((void **) &pTempBinder);
            goto exit;
        }

        **ppPacket = binderLen;
        *ppPacket += 1;

        /* Write the Binder */
        (void) DIGI_MEMCPY(*ppPacket, pTempBinder, binderLen);
        *ppPacket+= binderLen;

        (void) DIGI_FREE((void **) &pTempBinder);

        pTempBinder += binderLen;
        binderLen = 0;

        i = i + 1;
        pTempPSKList = pTempPSKList->pNextPSK;
    }

exit:

    for (hashIndex = 0; hashIndex < NUM_SSL_SUPPORTED_HASH_ALGORITHMS; hashIndex++)
    {
        DIGI_FREE((void **) &(ppPartialDigests[hashIndex]));
    }

    return status;
}

/* This API clears all the PSK stored */
extern MSTATUS
SSLSOCK_clearPSKList(tls13PSKList **ppPskList, ubyte2 *pPskListLen)
{
    MSTATUS status = OK;
    tls13PSKList *pPSKList = NULL;
    tls13PSKList *pCurrentPSK;

    if ( (NULL == ppPskList) || (NULL == pPskListLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (*pPskListLen == 0)
    {
        goto exit;
    }

    /* if using openssl connect, we want to free memory openssl wrapper
     * layer allocates.*/
    pPSKList = *ppPskList;

    while (NULL != pPSKList)
    {
        pCurrentPSK = pPSKList;
        pPSKList = pPSKList->pNextPSK;

        /* free tls13PSK field */
        if (NULL != pCurrentPSK->pPSK)
        {
            SSLSOCK_freePSK(&(pCurrentPSK->pPSK));
        }

        /* free PSK data field */
        if (NULL != pCurrentPSK->pPskData)
        {
            DIGI_FREE((void **) &pCurrentPSK->pPskData);
        }

        /* free free structure */
        DIGI_FREE((void **) &pCurrentPSK);
    }

    /* Application owns the memory */
    *ppPskList = NULL;
    *pPskListLen = 0;

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__*/
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */

/* sendKeyUpdateRequest function :
 * - Constructs Key Update message with the value of request_update field passed in.
 * - Send the message, encrypting it using current keys
 * - Computes new sender keys and updates the current sender keys
 */
MOC_EXTERN MSTATUS
SSLSOCK_sendKeyUpdateRequest(SSLSocket *pSSLSock, ubyte isRequest)
{
    MSTATUS status = OK;
    ubyte4 sizeofRecordHeader;
    ubyte4 sizeofHandshakeRecord;
    ubyte4 sizeofHandshakeHeader;
    ubyte* pHSH;
    ubyte* pSRH;
    ubyte *pTemp = NULL;

    sizeofRecordHeader    = sizeof(SSLRecordHeader);
    sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    sizeofHandshakeRecord = sizeof(SSLHandshakeRecord);

    pSSLSock->bufIndex   = 0;
    pSSLSock->numBuffers = 1;

    if (pSSLSock->buffers[0].pHeader != NULL)
    {
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->buffers[0].pHeader));
    }

    pSSLSock->buffers[0].data    = NULL;
    pSSLSock->buffers[0].length  = (ubyte2)(sizeofRecordHeader + sizeofHandshakeHeader + 1/* request_update */);

	if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, pSSLSock->buffers[0].length, TRUE, (void **)&(pSSLSock->buffers[0].pHeader))))
        goto exit;

    pSRH = pSSLSock->buffers[0].pHeader;
    SSL_SET_RECORD_HEADER(pSRH, SSL_HANDSHAKE, pSSLSock->sslMinorVersion, pSSLSock->buffers[0].length - sizeofRecordHeader);

    pSSLSock->buffers[0].data = pSSLSock->buffers[0].pHeader + sizeofRecordHeader;
    pHSH = pSSLSock->buffers[0].data;

    setMediumValue(((SSLHandshakeHeader *)pHSH)->handshakeSize, (ubyte2)(pSSLSock->buffers[0].length  - sizeofHandshakeRecord));
    ((SSLHandshakeHeader *)pHSH)->handshakeType = SSL_KEY_UPDATE;

    pTemp = pHSH;
    pTemp += sizeofHandshakeHeader;
    if (isRequest)
    {
        *pTemp = keyUpdateRequest_requested;
    }
    else
    {
        *pTemp = keyUpdateRequest_not_requested;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    if (pSSLSock->server)
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (SERVER)");
    else
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (CLIENT)");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Key Update");
    PrintBytes(pSSLSock->buffers[0].data, pSSLSock->buffers[0].length - sizeofRecordHeader);
#endif

    if (OK > (status = SSLSOCK_sendEncryptedHandshakeBuffer(pSSLSock)))
    {
        goto exit;
    }

    /* Update the sender keys after Key Update Request message is sent */
    if (pSSLSock->server)
    {
        if (OK > (status = SSLSOCK_pskUpdateServerTrafficSecret(pSSLSock)))
        {
            goto exit;
        }

        if (OK > (status = SSLSOCK_setServerTrafficKeyMaterial(pSSLSock,
                            pSSLSock->pServerApplicationTrafficSecret)))
        {
            goto exit;
        }

        /* Change the state to keelReceiveUntil before sending out keyUpdate */
        SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil;
    }
    else
    {
        if (OK > (status = SSLSOCK_pskUpdateClientTrafficSecret(pSSLSock)))
        {
            goto exit;
        }

        if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock,
                            pSSLSock->pClientApplicationTrafficSecret)))
        {
            goto exit;
        }

        /* Change the state to ksslReceiveHelloState before sending out keyUpdate */
        SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveHelloState;
    }

    if (isRequest)
    {
        /* If the keyUpdate was previously requested, do not update the timer */
        if (pSSLSock->keyUpdateRequested != keyUpdateRequest_requested)
        {
            RTOS_deltaMS(NULL, &pSSLSock->keyUpdateTimerCount);
            pSSLSock->keyUpdateRequested = keyUpdateRequest_requested;
        }
    }
    else
    {
        /* KeyUpdate request has been sent and keys have been changed */
        pSSLSock->keyUpdateRequested = keyUpdate_none;
    }

exit:
    /* free the buffers */
    if (pSSLSock->buffers[0].pHeader)
    {
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->buffers[0].pHeader));
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_TLS13__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
extern MSTATUS
SSLSOCK_clearServerSessionCache(SSLSocket* pSSLSock)
{
    MSTATUS status = OK;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* on alert, we want to scramble session cache's master secret */
    if (pSSLSock->server)
    {
        sbyte4 cacheIndex;

        /* cacheIndex is session modulo SESSION_CACHE_SIZE */
        cacheIndex = (pSSLSock->roleSpecificInfo.server.sessionId) % SESSION_CACHE_SIZE;

        if (OK > (status = RTOS_mutexWait(gSslSessionCacheMutex)))
        {
            DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSLSOCK_clearServerSessionCache: RTOS_mutexWait() failed.");
            goto exit;
        }

        /* scramble previous session secret */
        if (pSSLSock->roleSpecificInfo.server.sessionId == gSessionCache[cacheIndex].m_sessionId)
        {
            sbyte4 index;

            /* make sure it will not be reused -- 0 is never a valid session id*/
            gSessionCache[cacheIndex].m_sessionId = 0;

            if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                gSessionCache[cacheIndex].m_masterSecret, SSL_MASTERSECRETSIZE)))
            {
                DIGI_MEMSET((void *)gSessionCache[cacheIndex].m_masterSecret, 1, SSL_MASTERSECRETSIZE);
            }

            for (index = 0; index < SSL_MASTERSECRETSIZE; index++)
            {
                gSessionCache[cacheIndex].m_masterSecret[index] ^= 0x5c;
                gSessionCache[cacheIndex].m_masterSecret[index] += 0x36;
            }
        }

        if (OK > (status = RTOS_mutexRelease(gSslSessionCacheMutex)))
            goto exit;
    }

exit:
    return status;
}

MOC_EXTERN MSTATUS
SSLSOCK_clearAllServerSessionCache()
{
    MSTATUS status = OK;
    sbyte4 cacheIndex;

    if (OK > (status = RTOS_mutexWait(gSslSessionCacheMutex)))
    {
        DIGICERT_log((sbyte4)MOCANA_SSL, (sbyte4)LS_INFO, (sbyte *)"SSLSOCK_clearAllServerSessionCache: RTOS_mutexWait() failed.");
        goto exit;
    }

    /* scramble session cache's master secret for all sessions */
    for (cacheIndex = 0; cacheIndex < SESSION_CACHE_SIZE; cacheIndex++)
    {
        /* scramble previous session secret */
        sbyte4 index;

        /* make sure it will not be reused -- 0 is never a valid session id*/
        gSessionCache[cacheIndex].m_sessionId = 0;

        if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
            gSessionCache[cacheIndex].m_masterSecret, SSL_MASTERSECRETSIZE)))
        {
            DIGI_MEMSET((void *)gSessionCache[cacheIndex].m_masterSecret, 1, SSL_MASTERSECRETSIZE);
        }

        for (index = 0; index < SSL_MASTERSECRETSIZE; index++)
        {
            gSessionCache[cacheIndex].m_masterSecret[index] ^= 0x5c;
            gSessionCache[cacheIndex].m_masterSecret[index] += 0x36;
        }
    }

    if (OK > (status = RTOS_mutexRelease(gSslSessionCacheMutex)))
        goto exit;

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

static MSTATUS
handleAlertMessage(SSLSocket* pSSLSock)
{
    sbyte*  pMsg        = pSSLSock->pReceiveBuffer;
    sbyte4  alertClass;
    sbyte4  alertId;
    ubyte2  recordLen;
    MSTATUS status      = OK;
    MSTATUS status1     = OK;

    recordLen = (ubyte2)(pSSLSock->recordSize);

    if (2 != recordLen)
    {
        status = ERR_SSL_PROTOCOL_BAD_LENGTH;
        goto exit;
    }

    alertId    = pMsg[1];
    alertClass = pMsg[0];

    if (SSLALERTLEVEL_WARNING != alertClass)
    {
        /* default to fatal */
        alertClass = SSLALERTLEVEL_FATAL;
        status     = ERR_SSL_FATAL_ALERT;
        pSSLSock->alertCloseConnection = TRUE;
    }

#if defined(__ENABLE_DIGICERT_SSL_ALERTS__)
    if (NULL != (SSL_sslSettings()->funcPtrAlertCallback))
    {
        status1 = SSL_sslSettings()->funcPtrAlertCallback(SSL_findConnectionInstance(pSSLSock), alertId, alertClass);
        /* Allow callback to override status for warning alerts only
         */
        if (SSLALERTLEVEL_WARNING == alertClass)
            status = status1;
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
    /* on fatal alert, we want to scramble session cache's master secret */
    if (SSLALERTLEVEL_FATAL == alertClass || OK > status1)
    {
        SSLSOCK_clearServerSessionCache(pSSLSock);
    }
#endif

    if ((SSLALERTLEVEL_WARNING == alertClass) && (SSL_ALERT_CLOSE_NOTIFY == alertId))
    {
        pSSLSock->alertCloseConnection = TRUE;
        pSSLSock->sendCloseNotifyAlert = TRUE;
    }
exit:
    return status;

}

/*------------------------------------------------------------------*/

static MSTATUS
handleInnerAppMessage(SSLSocket* pSSLSock)
{
    ubyte2  recordLen;
    MSTATUS status      = OK;

    recordLen = (ubyte2)(pSSLSock->recordSize);

    if (6 > recordLen)
    {
        status = ERR_SSL_PROTOCOL_BAD_LENGTH;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_INNER_APP__
    if (NULL != (SSL_sslSettings()->funcPtrInnerAppCallback))
    {
        /* TODO: And We Negotiated Inner App */
        status = (MSTATUS)SSL_sslSettings()->funcPtrInnerAppCallback(SSL_findConnectionInstance(pSSLSock), (ubyte*)pSSLSock->pReceiveBuffer, recordLen);
    }
#endif

exit:
    return status;

} /* handleInnerAppMessage */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_EAP_FAST__) )
static MSTATUS
resetTicket(SSLSocket* pSSLSock)
{
    pSSLSock->roleSpecificInfo.client.ticketLength = 0;

    if (pSSLSock->roleSpecificInfo.client.ticket)
    {
        FREE(pSSLSock->roleSpecificInfo.client.ticket);
        pSSLSock->roleSpecificInfo.client.ticket = 0;
    }

    return OK;
}
#endif /* (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_EAP_FAST__)) */

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
static MSTATUS
enableFIPSAlgorithms(SSLSocket *pSSLSock)
{
    MSTATUS status = OK;
    sbyte4 index = 0;
    /* If the cipher table has been initialized by invoking SSL_enableCiphers */
    intBoolean cipherInitialized = pSSLSock->isCipherTableInit;

    for (index = 0; index < (sbyte4) NUM_CIPHER_SUITES; index++)
    {
        sbyte4 i;

        /* By default enable all ciphers;
         * Disable the ciphers in the FIPS exclusion list.
         * This index is used when isCipherTableInit is set to TRUE;
         * If all the ciphers in gCipherSuites are FIPS compliant,
         * we do not set isCipherTableInit.
         *
         * If the cipherTable has been already initialized,
         * do NOT over-ride here.
         */
        if (FALSE == cipherInitialized)
        {
            pSSLSock->isCipherEnabled[index] = TRUE;
        }

        for (i = 0; i < (sbyte4) NUM_CIPHERID_FIPS_EXCLUSION; i++)
        {
            if (gCipherSuites[index].cipherSuiteId == gCipherIdFIPSExclusion[i])
            {
                pSSLSock->isCipherTableInit = TRUE;
                pSSLSock->isCipherEnabled[index] = FALSE;
            }
        }
    }

    return status;
}

#endif

/*----------------------------------------------------------------------------*/
/* the socket has been memset to 0, no need to set members to 0               */
extern MSTATUS
SSL_SOCK_init(SSLSocket* pSSLSock, intBoolean isDTLS, TCP_SOCKET tcpSock,
              peerDescr *pPeerDescr, RNGFun rngFun, void* rngFunArg)
{
    MSTATUS status;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    ubyte4  i;
#else
    MOC_UNUSED(pPeerDescr);
#endif

    pSSLSock->isDTLS = isDTLS;
    pSSLSock->sessionResume = E_NoSessionResume;

    /* simplify processing later on */
    if (OK > (status = DIGI_MALLOC((void **) &(pSSLSock->pSupportedGroupList), COUNTOF(gSupportedNamedGroup) * sizeof(ubyte2))))
        goto exit;

    DIGI_MEMCPY(pSSLSock->pSupportedGroupList, gSupportedNamedGroup, COUNTOF(gSupportedNamedGroup) * sizeof(ubyte2));
    pSSLSock->supportedGroupListLength = COUNTOF(gSupportedNamedGroup);

    if (OK > (status = DIGI_MALLOC((void **) &(pSSLSock->pSupportedSignatureAlgoList), COUNTOF(gSupportedSignatureAlgorithms) * sizeof(ubyte2))))
        goto exit;

    DIGI_MEMCPY(pSSLSock->pSupportedSignatureAlgoList, gSupportedSignatureAlgorithms, COUNTOF(gSupportedSignatureAlgorithms) * sizeof(ubyte2));
    pSSLSock->supportedSignatureAlgoListLength = COUNTOF(gSupportedSignatureAlgorithms);

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if (OK > (status = CRYPTO_initAsymmetricKey( &pSSLSock->mutualAuthKey)))
        goto exit;
#endif

#if defined( __ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
    if (OK > (status = CRYPTO_initAsymmetricKey( &pSSLSock->ecdheKey)))
        goto exit;
#endif

    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, SSL_MASTERSECRETSIZE + (4 * SSL_RANDOMSIZE) + (2 * (SSL_MAXROUNDS * MD5_DIGESTSIZE)), TRUE, (void **)&(pSSLSock->pSecretAndRand))))
        goto exit;

    pSSLSock->pClientRandHello = SSL_MASTERSECRETSIZE + 2 * SSL_RANDOMSIZE + pSSLSock->pSecretAndRand;
    pSSLSock->pServerRandHello = SSL_RANDOMSIZE + pSSLSock->pClientRandHello;
    pSSLSock->pMaterials       = SSL_RANDOMSIZE + pSSLSock->pServerRandHello;
    pSSLSock->pActiveMaterials = (SSL_MAXROUNDS * MD5_DIGESTSIZE) + pSSLSock->pMaterials;

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, (2 * (SRTP_MAX_KEY_SIZE + SRTP_MAX_SALT_SIZE)), TRUE, (void **)&(pSSLSock->pSrtpMaterials))))
        goto exit;
#endif
    /* allocate receive buffer */
    if (OK > (status = checkBuffer(pSSLSock, SSL_DEFAULT_SMALL_BUFFER, 0)))
        goto exit;

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    if (pSSLSock->isDTLS)
    {
        MOC_IP_ADDRESS srcAddrRef = REF_MOC_IPADDR(pPeerDescr->srcAddr);
        MOC_IP_ADDRESS peerAddrRef = REF_MOC_IPADDR(pPeerDescr->peerAddr);
        pSSLSock->peerDescr.pUdpDescr = pPeerDescr->pUdpDescr;
        pSSLSock->peerDescr.srcPort = pPeerDescr->srcPort;
        COPY_MOC_IPADDR(pSSLSock->peerDescr.srcAddr, srcAddrRef);
        pSSLSock->peerDescr.peerPort = pPeerDescr->peerPort;
        COPY_MOC_IPADDR(pSSLSock->peerDescr.peerAddr, peerAddrRef);
        /* create handshake timer */
        if (OK > (status = TIMER_createTimer((void*)handshakeTimerCallbackFunc, (ubyte**)&pSSLSock->dtlsHandshakeTimer)))
            goto exit;
        pSSLSock->dtlsHandshakeTimeout = 1000; /*default 1 second */
        pSSLSock->dtlsPMTU = 1500; /* default PMTU 1500 bytes */

        /* initialize handshake message defragment buffer */
        for (i = 0; i < MAX_HANDSHAKE_MESG_IN_FLIGHT; i++)
        {
            DIGI_MEMSET((ubyte*)&pSSLSock->msgBufferDescrs[i], 0x00, sizeof(msgBufferDescr));
        }

        DIGI_MEMSET((ubyte *)pSSLSock->retransBuffers, 0x00, sizeof(retransBufferDescr) * MAX_HANDSHAKE_MESG_IN_FLIGHT);
        pSSLSock->isRetransmit = FALSE;
#if defined(__ENABLE_DIGICERT_TLS13__)
        DIGI_MEMSET((ubyte *)&pSSLSock->postHandshakeState, 0x00, sizeof(pSSLSock->postHandshakeState));
        pSSLSock->postHandshakeState[kKeyUpdate].state = kDtlsWaiting;
        pSSLSock->postHandshakeState[kKeyUpdate].type = kKeyUpdate;

        status = TIMER_createTimer((void*)handshakeTimerKeyUpdateCallbackFunc, (ubyte**)&pSSLSock->postHandshakeState[kKeyUpdate].msgTimer);
        if (OK != status)
            goto exit;

        pSSLSock->postHandshakeState[kKeyUpdate].msgTimeout = 1000;
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
        pSSLSock->postHandshakeState[kNewSessionTicket].state = kDtlsWaiting;
        pSSLSock->postHandshakeState[kNewSessionTicket].type = kNewSessionTicket;

        if (pSSLSock->server)
        {
            status = TIMER_createTimer((void*)handshakeTimerNewSessionCallbackFunc, (ubyte**)&pSSLSock->postHandshakeState[kNewSessionTicket].msgTimer);
            if (OK != status)
                goto exit;

            pSSLSock->postHandshakeState[kNewSessionTicket].msgTimeout = 1000;
        }
#endif
        pSSLSock->postHandshakeState[kCertificateRequest].state = kDtlsWaiting;
        pSSLSock->postHandshakeState[kCertificateRequest].type = kCertificateRequest;

        status = TIMER_createTimer((void*)handshakeTimerCertificateCallbackFunc, (ubyte**)&pSSLSock->postHandshakeState[kCertificateRequest].msgTimer);
        if (OK != status)
            goto exit;

        pSSLSock->postHandshakeState[kCertificateRequest].msgTimeout = 1000;
#endif
    }
    else
#endif
    {
        pSSLSock->tcpSock = tcpSock;
    }

    pSSLSock->rngFun = rngFun;
    pSSLSock->rngFunArg = rngFunArg;
#ifdef __ENABLE_DIGICERT_TLS13__
    pSSLSock->keyUpdateRequested = keyUpdate_none;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (!pSSLSock->server)
    {
        pSSLSock->roleSpecificInfo.client.numOfTLS13PSK = 0;
        pSSLSock->roleSpecificInfo.client.pTLS13PSKList = NULL;
    }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
#if (defined(__ENABLE_DIGICERT_TLS13_PSK__))
    pSSLSock->isPSKSelected = 0;
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    if (pSSLSock->server)
    {
        pSSLSock->roleSpecificInfo.server.sessionTicketNonceLen = SSL_SESSION_TICKET_NONCE_SIZE;
        pSSLSock->roleSpecificInfo.server.receivedExtensions = 0x00;
        if (pSSLSock->roleSpecificInfo.server.numOfSessionTickets == 0)
        {
            /* If PSK is enabled, set the default number of session tickets to 1 */
            pSSLSock->roleSpecificInfo.server.numOfSessionTickets = 1;
        }
    }
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
    if (1 == SSL_sslSettings()->isFIPSEnabled)
    {
        if (OK > (status = enableFIPSAlgorithms(pSSLSock)))
        {
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
    if (OK > (status = rngFun(rngFunArg, sizeof(pSSLSock->heartbeatPayload), pSSLSock->heartbeatPayload)))
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    pSSLSock->sendCloseNotifyAlert = FALSE;
    pSSLSock->alertCloseConnection = FALSE;
#endif
    pSSLSock->receivedServerKeyEx = FALSE;
    pSSLSock->sentFinished = FALSE;

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_init() returns status = ", status);
#endif

    return status;
}

extern MSTATUS
SSL_SOCK_initHashPool(SSLSocket *pSSLSock )
{
    void*       pTempMemBuffer = NULL;
    intBoolean  isRehandshake = FALSE;
    MSTATUS     status;

#if defined(__ENABLE_DIGICERT_TLS13__)
    if ((pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion) || 
        (!pSSLSock->isDTLS && TLS13_MINORVERSION > pSSLSock->sslMinorVersion))
#endif
    {
        isRehandshake = (pSSLSock->pActiveOwnCipherSuite) ? TRUE : FALSE;
    }

    if ((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion > DTLS12_MINORVERSION)) ||
        (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS12_MINORVERSION))
    {
        if (!isRehandshake)
        {
            if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, SSL_SMALL_TEMP_BUF_SIZE * 5, TRUE, &pTempMemBuffer)))
                goto exit;

            DEBUG_RELABEL_MEMORY(pTempMemBuffer);

            if (OK > (status = MEM_POOL_initPool(&pSSLSock->smallPool, pTempMemBuffer, SSL_SMALL_TEMP_BUF_SIZE * 5, SSL_SMALL_TEMP_BUF_SIZE)))
                goto exit;
        }
        else
        {
            if (OK > (status = MEM_POOL_recyclePoolMemory(&pSSLSock->smallPool, SSL_SMALL_TEMP_BUF_SIZE)))
                goto exit;
        }

        if (!pSSLSock->pMd5Ctx && !pSSLSock->pShaCtx)
        {
            if (!isRehandshake)
            {
                if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, sizeof(shaDescrHS) * 5, TRUE, &pTempMemBuffer)))
                    goto exit;

                DEBUG_RELABEL_MEMORY(pTempMemBuffer);

                if (OK > (status = MEM_POOL_initPool(&pSSLSock->shaPool, pTempMemBuffer, sizeof(shaDescrHS) * 5, sizeof(shaDescrHS))))
                    goto exit;

                if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, sizeof(MD5_CTXHS) * 5, TRUE, &pTempMemBuffer)))
                    goto exit;

                DEBUG_RELABEL_MEMORY(pTempMemBuffer);

                if (OK > (status = MEM_POOL_initPool(&pSSLSock->md5Pool, pTempMemBuffer, sizeof(MD5_CTXHS) * 5, sizeof(MD5_CTXHS))))
                    goto exit;
            }
            else
            {
                if (OK > (status = MEM_POOL_recyclePoolMemory(&pSSLSock->shaPool, sizeof(shaDescrHS))))
                    goto exit;

                if (OK > (status = MEM_POOL_recyclePoolMemory(&pSSLSock->md5Pool, sizeof(MD5_CTXHS))))
                    goto exit;
            }

            if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->shaPool, (void **)&(pSSLSock->pShaCtx))))
                goto exit;

            if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->md5Pool, (void **)&(pSSLSock->pMd5Ctx))))
                goto exit;

            DIGI_MEMSET((ubyte *)pSSLSock->pMd5Ctx, 0, sizeof(MD5_CTXHS));
            DIGI_MEMSET((ubyte *)pSSLSock->pShaCtx, 0, sizeof(shaDescrHS));

        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        CRYPTO_INTERFACE_MD5Init_m(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pMd5Ctx);
        CRYPTO_INTERFACE_SHA1_initDigest(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pShaCtx);
#else
        MD5init_HandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pMd5Ctx);
        SHA1_initDigestHandShake(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pShaCtx);
#endif
    }
    else
    {
        const CipherSuiteInfo *pCipher = pSSLSock->pHandshakeCipherSuite;
        const BulkHashAlgo *pHashAlgo = NULL;
        ubyte4 hashDescrSize = 0;

        if (pCipher != NULL)
            pHashAlgo = pCipher->pPRFHashAlgo;

#ifndef __DISABLE_DIGICERT_SHA256__
        if (!pHashAlgo)
            pHashAlgo = &SHA256Suite; /* default is SHA256 */
#endif
        if (!isRehandshake)
        {
            if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, SSL_BIGGER_TEMP_BUF_SIZE * 5, TRUE, &pTempMemBuffer)))
                goto exit;

            DEBUG_RELABEL_MEMORY(pTempMemBuffer);

            if (OK > (status = MEM_POOL_initPool(&pSSLSock->smallPool, pTempMemBuffer, SSL_BIGGER_TEMP_BUF_SIZE * 5, SSL_BIGGER_TEMP_BUF_SIZE)))
                goto exit;
        }
        else
        {
            if (OK > (status = MEM_POOL_recyclePoolMemory(&pSSLSock->smallPool, SSL_BIGGER_TEMP_BUF_SIZE)))
                goto exit;
        }

        if (&MD5Suite == pHashAlgo)
        {
            hashDescrSize = sizeof(MD5_CTXHS);
        } else if (&SHA1Suite == pHashAlgo)
        {
            hashDescrSize = sizeof(shaDescrHS);
#ifndef __DISABLE_DIGICERT_SHA224__
        } else if (&SHA224Suite == pHashAlgo)
        {
            hashDescrSize = sizeof(SHA224_CTX);
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
        } else if (&SHA256Suite == pHashAlgo)
        {
            hashDescrSize = sizeof(SHA256_CTX);
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
        } else if (&SHA384Suite == pHashAlgo)
        {
            hashDescrSize = sizeof(SHA384_CTX);
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
        } else if (&SHA512Suite == pHashAlgo)
        {
            hashDescrSize = sizeof(SHA512_CTX);
#endif
        }
        else
        {
            status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            goto exit;
        }

        if (!pSSLSock->pHashCtx)
        {
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
            if ((TRUE == pSSLSock->sendEarlyData) || (!isRehandshake))
#else
            if (!isRehandshake)
#endif
            {
                if (OK > (status = CRYPTO_ALLOC(pSSLSock->hwAccelCookie, hashDescrSize * 5, TRUE, &pTempMemBuffer)))
                    goto exit;

                DEBUG_RELABEL_MEMORY(pTempMemBuffer);

                if (OK > (status = MEM_POOL_initPool(&pSSLSock->hashPool, pTempMemBuffer, hashDescrSize * 5, hashDescrSize)))
                    goto exit;
            }
            else
            {
                if (OK > (status = MEM_POOL_recyclePoolMemory(&pSSLSock->hashPool, hashDescrSize)))
                    goto exit;
            }

            if (OK > (status = MEM_POOL_getPoolObject(&pSSLSock->hashPool, (void **)&(pSSLSock->pHashCtx))))
                goto exit;
        }

        if (OK > (status = DIGI_MEMSET(pSSLSock->pHashCtx, 0, hashDescrSize)))
            goto exit;

        if (OK > (status = pHashAlgo->initFunc(MOC_HASH(pSSLSock->hwAccelCookie) pSSLSock->pHashCtx)))
            goto exit;
    }
exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_initHashPool() returns status = ", status);
#endif

    return status;
}

#if defined(__ENABLE_DIGICERT_TLS13__)

static void
SSLSOCK_clearTLS13Secrets(SSLSocket *pSSLSock)
{
    if (pSSLSock->pPskSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pPskSecret);
    }

    if (pSSLSock->pClientEarlyTrafficSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pClientEarlyTrafficSecret);
    }

    if (pSSLSock->pClientHandshakeTrafficSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pClientHandshakeTrafficSecret);
    }

    if (pSSLSock->pServerHandshakeTrafficSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pServerHandshakeTrafficSecret);
    }

    if (pSSLSock->pClientApplicationTrafficSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pClientApplicationTrafficSecret);
    }

    if (pSSLSock->pServerApplicationTrafficSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pServerApplicationTrafficSecret);
    }

    if (pSSLSock->pEarlySecret)
    {
        DIGI_FREE((void **)&pSSLSock->pEarlySecret);
    }

    if (pSSLSock->pBinderKey)
    {
        DIGI_FREE((void **)&pSSLSock->pBinderKey);
    }

    if (pSSLSock->pEarlyExporterMasterSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pEarlyExporterMasterSecret);
    }

    if (pSSLSock->pHandshakeSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pHandshakeSecret);
    }

    if (pSSLSock->pMasterSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pMasterSecret);
    }

    if (pSSLSock->pExporterMasterSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pExporterMasterSecret);
    }

    if (pSSLSock->pResumptionMasterSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pResumptionMasterSecret);
    }
}

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
static void SSLSOCK_clearKeyShare(SSLSocket *pSSLSock)
{
    ubyte4  i                         = 0;
    if (pSSLSock->roleSpecificInfo.client.sharedKeyCount > 0 && !pSSLSock->server)
    {
        for (i = 0; i < pSSLSock->roleSpecificInfo.client.sharedKeyCount; i++)
        {
            deleteSharedKey(&(pSSLSock->roleSpecificInfo.client.ppSharedKeys[i]));
        }

        pSSLSock->roleSpecificInfo.client.sharedKeyCount = 0;
        DIGI_FREE((void **)&pSSLSock->roleSpecificInfo.client.ppSharedKeys);
    }
}
#endif

static void
SSLSOCK_clearSharedData(SSLSocket *pSSLSock)
{
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (!pSSLSock->server)
    {
        if (NULL != pSSLSock->roleSpecificInfo.client.pSharedVersions)
        {
            DIGI_FREE((void **)&pSSLSock->roleSpecificInfo.client.pSharedVersions);
        }
    }
#endif
}
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
static MSTATUS findKeyAndToken(ubyte *pHashIn, TAP_KeyHandle *pKeyHandle, TAP_TokenHandle *pTokenHandle)
{
    MSTATUS status = OK;
    struct tapKeyHandle *pCurrKey = NULL;
    sbyte4 result = -1;

    pCurrKey   = g_pTapKeyList;

    while (pCurrKey != NULL)
    {
        if (OK > (status = DIGI_MEMCMP(pCurrKey->certSubjectHashValue, pHashIn, 32, &result)))
        {
            goto exit;
        }

        if (0 == result)
        {
            /* Key and handle have already been added */
            status   = OK;
            *pKeyHandle = pCurrKey->keyHandle;
            *pTokenHandle = pCurrKey->tokenHandle;
            goto exit;
        }
        pCurrKey = pCurrKey->pNextHandle;
    }

exit:
    return status;
}

extern MSTATUS SSLSOCK_clearTAPKeyAndToken()
{
    MSTATUS status = OK;
    struct tapKeyHandle   *pTempKey = NULL, *pCurrKey = NULL;
    TAP_Context           *pTapCtx = NULL;

    if (g_pTapKeyList != NULL)
    {
        pCurrKey   = g_pTapKeyList;

        while (pCurrKey != NULL)
        {
            /* API gets the TapContext if pTapCtx is NULL */
            if (OK > (status = CRYPTO_INTERFACE_unloadTapKey(pTapCtx, pCurrKey->tokenHandle, &pCurrKey->keyHandle)))
            {
                goto exit;
            }

            pCurrKey = pCurrKey->pNextHandle;
        }

        pCurrKey   = g_pTapKeyList;

        while (pCurrKey != NULL)
        {
            /* API gets the TapContext if pTapCtx is NULL */
            if (OK > (status = CRYPTO_INTERFACE_unloadTapToken(pTapCtx, pCurrKey->tokenHandle)))
            {
                goto exit;
            }

            /* Free the Current Key */
            pTempKey = pCurrKey;
            pCurrKey = pCurrKey->pNextHandle;
            DIGI_FREE((void **)&pTempKey);
        }
        g_pTapKeyList = NULL;
    }
exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"clearTAPKeyAndToken() returns status = ", status);
#endif
    return status;
}

static MSTATUS addTAPKeyAndToken(MOC_HASH(hwAccelDescr hwAccelCtx) TAP_TokenHandle token, TAP_KeyHandle key, ubyte *pHash)
{
    MSTATUS             status = OK;
    struct tapKeyHandle *pTempKey = NULL;

    if (OK > (status = DIGI_MALLOC((void **)&pTempKey, sizeof(struct tapKeyHandle))))
    {
        goto exit;
    }

    pTempKey->keyHandle   = key;
    pTempKey->tokenHandle = token;
    DIGI_MEMCPY(pTempKey->certSubjectHashValue, pHash, 32);

    /* Update the list */
    pTempKey->pNextHandle = g_pTapKeyList;
    g_pTapKeyList         = pTempKey;

exit:
    if (OK > status)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"addTAPKeyAndToken() returns status = ", status);
#endif
    }
    return status;
}

extern MSTATUS SSLSOCK_setKeyAndTokenHandle(SSLSocket *pSSLSock, intBoolean isServer)
{
    AsymmetricKey *pAsymKey = NULL;
    SizedBuffer *pCert      = NULL;
    ubyte *pHash            = NULL;
    MSTATUS status          = OK;

    if (isServer)
    {
        pAsymKey = &(pSSLSock->handshakeKey);
        pCert = pSSLSock->roleSpecificInfo.server.certificates;
    }
    else
    {
        pAsymKey = &(pSSLSock->mutualAuthKey);
        pCert = pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts;
    }

    if ((akt_tap_rsa == pAsymKey->type) || (akt_tap_ecc == pAsymKey->type))
    {
        if (OK > (status = CRYPTO_INTERFACE_TAP_AsymDeferUnload(pAsymKey, TRUE)))
        {
            goto exit;
        }

        if (g_pTapKeyList != NULL)
        {
            TAP_KeyHandle keyHandle     = 0;
            TAP_TokenHandle tokenHandle = 0;
            MocAsymKey pKey             = NULL;
            MRsaTapKeyData *pInfo       = NULL;
            TAP_Key *pTapKey            = NULL;

            if (OK > ( status = SSL_SOCK_getCertificateSerialNumberHash(MOC_HASH(pSSLSock->hwAccelCookie)
                                                                        (const SizedBuffer *)pCert, &pHash)))
            {
                goto exit;
            }

            status = findKeyAndToken(pHash, &keyHandle, &tokenHandle);

            /*  */
            if ((status >= OK) && (keyHandle != 0) && (tokenHandle != 0))
            {
                if (akt_tap_rsa == pAsymKey->type)
                {
                    pKey = (MocAsymKey)pAsymKey->key.pRSA->pPrivateKey;
                }
                else if (akt_tap_ecc == pAsymKey->type)
                {
                    pKey = (MocAsymKey)pAsymKey->key.pECC->pPrivateKey;
                }

                if (pKey != NULL)
                {
                    pInfo = (MRsaTapKeyData *)pKey->pKeyData;
                    pTapKey = (TAP_Key *)pInfo->pKey;

                    pTapKey->tokenHandle = tokenHandle;
                    pTapKey->keyHandle   = keyHandle;
                }
            }
        }
    }

exit:
    if (pHash != NULL)
    {
        DIGI_FREE((void **)&pHash);
    }
}
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
extern MSTATUS SSLSOCK_tapUnloadKey(AsymmetricKey *pAsymKey)
{
    MSTATUS status;

    if (NULL == pAsymKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
    if (akt_tap_rsa == pAsymKey->type)
    {
        status = CRYPTO_INTERFACE_TAP_RsaUnloadKey(pAsymKey->key.pRSA);
    }
    else
#endif
#if defined(__ENABLE_DIGICERT_ECC__)
    if (akt_tap_ecc == pAsymKey->type)
    {
        status = CRYPTO_INTERFACE_TAP_EccUnloadKey(pAsymKey->key.pECC);
    }
    else
#endif
    {
        status = ERR_BAD_KEY_TYPE;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*------------------------------------------------------------------------*/
/* Note: this should be called always and only before FREE'ing the socket
  so free memory, no need to set member to 0 */
extern void
SSL_SOCK_uninit(SSLSocket* pSSLSock)
{
    void *pTemp = NULL;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    ubyte4 i;
#if  defined(__ENABLE_DIGICERT_TLS13__)
    if (pSSLSock->isDTLS)
    {
        freeReceivedRecords(pSSLSock);

        if (pSSLSock->server)
        {
            TIMER_destroyTimerEx(pSSLSock->postHandshakeState[kNewSessionTicket].msgTimer,NULL);
        }
        TIMER_destroyTimerEx(pSSLSock->postHandshakeState[kKeyUpdate].msgTimer,NULL);
        TIMER_destroyTimerEx(pSSLSock->postHandshakeState[kCertificateRequest].msgTimer,NULL);
        (void) freeStateRecvRecords(&pSSLSock->postHandshakeState[kNewSessionTicket]);
        (void) freeStateRecvRecords(&pSSLSock->postHandshakeState[kKeyUpdate]);
        (void) freeStateRecvRecords(&pSSLSock->postHandshakeState[kCertificateRequest]);

#if defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__) && \
    defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        if (TRUE == pSSLSock->earlyDataEpochKeys.isSet)
        {
            pSSLSock->pHandshakeCipherSuite->pCipherAlgo->deleteCtxFunc(
                MOC_SYM(pSSLSock->hwAccelCookie) &(pSSLSock->earlyDataEpochKeys.pBulkCtx));
            DIGI_MEMSET(pSSLSock->earlyDataEpochKeys.pIv, 0x00, 16);
        }
#endif
    }
#endif
#endif

    resetCipher(pSSLSock, TRUE, TRUE);

    if (NULL != pSSLSock->signatureAlgoList)
    {
        DIGI_FREE((void **) &(pSSLSock->signatureAlgoList));
        pSSLSock->signatureAlgoListLength = 0;
    }

    if (NULL != pSSLSock->pSupportedGroupList)
    {
        DIGI_FREE((void **) &(pSSLSock->pSupportedGroupList));
        pSSLSock->supportedGroupListLength = 0;
    }

    if (pSSLSock->pSupportedSignatureAlgoList)
    {
        DIGI_FREE((void **)&(pSSLSock->pSupportedSignatureAlgoList));
        pSSLSock->supportedSignatureAlgoListLength = 0;
    }

#if (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__))
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeDhContextExt(&(pSSLSock->pDHcontext), NULL, NULL);
#else
    DH_freeDhContext(&pSSLSock->pDHcontext, NULL);
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* (defined(__ENABLE_DIGICERT_SSL_DHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__)) */

    CERTCHAIN_delete(&pSSLSock->pCertChain);

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if ((akt_tap_rsa == pSSLSock->mutualAuthKey.type) ||
        (akt_tap_ecc == pSSLSock->mutualAuthKey.type))
    {
        TAP_TokenHandle token = 0;
        TAP_KeyHandle   key   = 0;
        ubyte           *pHashOut = NULL;
        MSTATUS status            = OK;

        SSL_SOCK_getCertificateSerialNumberHash(MOC_HASH(pSSLSock->hwAccelCookie)
                                                         pSSLSock->roleSpecificInfo.client.sslMutualAuthCerts,
                                                         &pHashOut);

        findKeyAndToken(pHashOut, &token, &key);

        /* Only Add if key and token were not found in the list */
        if (0 == key)
        {
            if (OK > (status = CRYPTO_INTERFACE_TAP_AsymGetKeyInfo(&(pSSLSock->mutualAuthKey), MOC_ASYM_KEY_TYPE_PRIVATE,
                                                &token, &key)))
            {
                goto exit1;
            }

            if ((token != 0) && (key != 0))
            {
                addTAPKeyAndToken(token, key, pHashOut);
            }
        }

exit1:
        if (pHashOut != NULL)
        {
            DIGI_FREE((void **)&pHashOut);
        }
    }
#endif
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    CRYPTO_INTERFACE_asymmetricKeyRemoveCreds(&pSSLSock->mutualAuthKey);
#endif
    CRYPTO_uninitAsymmetricKey(&pSSLSock->mutualAuthKey, NULL);
#endif

#if defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || \
    defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)
    CRYPTO_uninitAsymmetricKey( &pSSLSock->ecdheKey, NULL);
#endif

    DIGI_FREE((void **)&(pSSLSock->pOutputBufferBase));

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    releaseRetransmissionBuffer(pSSLSock);
    clearRetransmissionSessionInfo(pSSLSock);
#endif

    DIGI_FREE((void **)&(pSSLSock->buffers[0].pHeader));

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
    if ((akt_tap_rsa == pSSLSock->handshakeKey.type) ||
        (akt_tap_ecc == pSSLSock->handshakeKey.type))
    {
        TAP_TokenHandle token = 0;
        TAP_KeyHandle   key   = 0;
        ubyte           *pHashOut = NULL;
        MSTATUS status            = OK;

        SSL_SOCK_getCertificateSerialNumberHash(MOC_HASH(pSSLSock->hwAccelCookie)
                                                         pSSLSock->roleSpecificInfo.server.certificates,
                                                         &pHashOut);

        findKeyAndToken(pHashOut, &token, &key);

        /* Only Add if key and token were not found in the list */
        if (0 == key)
        {
            if (OK > (status = CRYPTO_INTERFACE_TAP_AsymGetKeyInfo(&(pSSLSock->handshakeKey), MOC_ASYM_KEY_TYPE_PRIVATE,
                                                &token, &key)))
            {
                goto exit2;
            }

            if ((token != 0) && (key != 0))
            {
                addTAPKeyAndToken(token, key, pHashOut);
            }
        }

exit2:
        if (pHashOut != NULL)
        {
            DIGI_FREE((void **)&pHashOut);
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    CRYPTO_INTERFACE_asymmetricKeyRemoveCreds(&pSSLSock->handshakeKey);
#endif
    CRYPTO_uninitAsymmetricKey(&pSSLSock->handshakeKey, NULL);

#if defined(__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__) && \
    defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if ((!pSSLSock->server) && (NULL != pSSLSock->roleSpecificInfo.client.pCNMatchInfos))
    {
        const CNMatchInfo *pCNMatchInfo = pSSLSock->roleSpecificInfo.client.pCNMatchInfos;

        while (NULL != pCNMatchInfo->name)
        {
            DIGI_FREE((void **) &(pCNMatchInfo->name));
            pCNMatchInfo++;
        }
        DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pCNMatchInfos));
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
    if (!(pSSLSock->server))
    {
        if (pSSLSock->roleSpecificInfo.client.helloBuffer)
        {
            DIGI_FREE((void **)&(pSSLSock->roleSpecificInfo.client.helloBuffer));
        }

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
        if (NULL != pSSLSock->roleSpecificInfo.client.pTicketTls)
        {
            DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pTicketTls->pTicket));
            DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pTicketTls));
        }
#endif
    }
#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    if (pSSLSock->certStatusReqExtData)
    {
        DIGI_FREE((void **)&(pSSLSock->certStatusReqExtData));
    }

    if (pSSLSock->pOcspContext)
    {
        OCSP_CONTEXT_releaseContextLocal((ocspContext **) &pSSLSock->pOcspContext);
    }
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

#ifdef __ENABLE_DIGICERT_SSL_SERVER__
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__

    if (pSSLSock->pResponderUrl != NULL)
    {
        DIGI_FREE((void **)&(pSSLSock->pResponderUrl));
    }

#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */
#ifdef __ENABLE_DIGICERT_TLS13__
    if (NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
    {
        DIGI_FREE((void **)&(pSSLSock->roleSpecificInfo.server.receivedPubKey));
    }
#endif
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

    DIGI_FREE((void **)&(pSSLSock->serverNameIndication));
#if defined( __ENABLE_DIGICERT_SSL_SRP__)

    DIGI_FREE((void **)&(pSSLSock->srpIdentity));

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (! (pSSLSock->server))
    {
        DIGI_FREE((void **)&(pSSLSock->roleSpecificInfo.client.srpSB));
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    if ( pSSLSock->server)
    {
        DIGI_FREE((void **)&(pSSLSock->roleSpecificInfo.server.srpB));
        VLONG_freeVlong(&pSSLSock->roleSpecificInfo.server.srpb, 0);
        VLONG_freeVlong(&pSSLSock->roleSpecificInfo.server.srpVerifier, 0);
    }
#endif

#endif /* __ENABLE_DIGICERT_SSL_SRP__ */


    if (pSSLSock->alpnProtocols != NULL)
    {
        DIGI_FREE((void **)&(pSSLSock->alpnProtocols));
    }
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
    if (!pSSLSock->server)
    {
        CERT_STORE_releaseStore(&(pSSLSock->pMutualAuthCertStore));
        if (pSSLSock->roleSpecificInfo.client.pCertAuthAlias != NULL)
        {
            DIGI_FREE((void **) &(pSSLSock->roleSpecificInfo.client.pCertAuthAlias));
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_TLS13__
    if (pSSLSock->pPartialHandshakeRecordBuffer != NULL)
    {
        DIGI_FREE((void **)&(pSSLSock->pPartialHandshakeRecordBuffer));
    }
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if (pSSLSock->certificateRequestContext != NULL)
    {
        DIGI_FREE((void **)&pSSLSock->certificateRequestContext);
    }
#endif

        CA_MGMT_freeCertDistinguishedName(&pSSLSock->pSupportedCADn);
        SSLSOCK_clearTLS13Secrets(pSSLSock);
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
        SSLSOCK_clearKeyShare(pSSLSock);
#endif
        SSLSOCK_clearSharedData(pSSLSock);
#ifdef __ENABLE_DIGICERT_TLS13_PSK__
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
        SSLSOCK_clearPSKList(
            &(pSSLSock->roleSpecificInfo.client.pTLS13PSKList),
            &(pSSLSock->roleSpecificInfo.client.numOfTLS13PSK));
#endif
#endif
#endif

    DIGI_MEMSET(pSSLSock->client_verify_data, 0x00, SSL_VERIFY_DATA_MAX);
    DIGI_MEMSET(pSSLSock->server_verify_data, 0x00, SSL_VERIFY_DATA_MAX);

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_EAP_FAST__))
    if (0 == pSSLSock->server)
        resetTicket(pSSLSock);
#endif /* (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_EAP_FAST__) ) */

    CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pSSLSock->pReceiveBufferBase);
    CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pSSLSock->pSecretAndRand);

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) && defined(__ENABLE_DIGICERT_DTLS_SRTP__)
    CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->pSrtpMaterials));
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pSSLSock->pHashCtx)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pHashCtx);
    }
    if (pSSLSock->pMd5Ctx)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pMd5Ctx);
    }
    if (pSSLSock->pShaCtx)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pShaCtx);
    }
#if defined(__ENABLE_DIGICERT_TLS13__)
    if (pSSLSock->pHandshakeHashCtx)
    {
        CRYPTO_INTERFACE_freeCloneHashCtx(pSSLSock->pHandshakeHashCtx);
    }
#endif
#endif
    if (OK <= MEM_POOL_uninitPool(&pSSLSock->smallPool, &pTemp))
        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pTemp);

    if (OK <= MEM_POOL_uninitPool(&pSSLSock->shaPool, &pTemp))
    {
        if (pTemp)
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pTemp);
    }

    if (OK <= MEM_POOL_uninitPool(&pSSLSock->md5Pool, &pTemp))
    {
        if (pTemp)
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pTemp);
    }

    /* release ctx pool */
    if (OK <= MEM_POOL_uninitPool(&pSSLSock->hashPool, &pTemp))
    {
        if (pTemp)
            CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&pTemp);
    }
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13__))
    /* release the buffer */
    SSLSOCK_freeHashCtxList(pSSLSock);
#endif


#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    /* destroy dtls handshake timer */
    if (pSSLSock->isDTLS)
    {
        TIMER_unTimer(pSSLSock, pSSLSock->dtlsHandshakeTimer);
        TIMER_destroyTimer(pSSLSock->dtlsHandshakeTimer);

        /* release handshake message defragment buffer */
        for (i = 0; i < MAX_HANDSHAKE_MESG_IN_FLIGHT; i++)
        {
            DIGI_FREE((void **)&(pSSLSock->msgBufferDescrs[i].ptr));
#ifdef __ENABLE_DIGICERT_TLS13__
            freeMsgBufferDescrRecords(&pSSLSock->msgBufferDescrs[i]);
#endif
        }
        pSSLSock->isDTLS = FALSE;
#if defined(__ENABLE_DIGICERT_DTLS_SRTP__)
        DIGI_FREE((void **)&(pSSLSock->srtpMki));
#endif
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
    if (NULL != pSSLSock->pTransportHandler)
    {
        (void) DIGI_FREE((void **)&pSSLSock->pTransportHandler);
    }
#endif

}

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_send(SSLSocket* pSSLSock, const sbyte* data, sbyte4 dataSize)
{
    /* block sends between ChangeCipherSpec and Finished */
    if ((( pSSLSock->server) && ((kSslReceiveHelloState1 == SSL_HANDSHAKE_STATE(pSSLSock)) || (kSslReceiveUntil1       == SSL_HANDSHAKE_STATE(pSSLSock)))) ||
        ((!pSSLSock->server) && ((kSslReceiveHelloState1 == SSL_HANDSHAKE_STATE(pSSLSock)) || (kSslReceiveUntilResume1 == SSL_HANDSHAKE_STATE(pSSLSock)))))
    {
        return (MSTATUS)0;
    }

    return sendData(pSSLSock, SSL_APPLICATION_DATA, data, dataSize, FALSE);
}

/*------------------------------------------------------------------*/

static MSTATUS
processChangeCipherSpec(SSLSocket* pSSLSock)
{
    MSTATUS status;

    if (pSSLSock->server)
    {
        status = ERR_SSL_PROTOCOL_SERVER;

        /* is server */
        if (((SSL_CLIENT_KEY_EXCHANGE       == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) && (!pSSLSock->isMutualAuthNegotiated)) ||
            ((SSL_CLIENT_CERTIFICATE_VERIFY == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)) &&  (pSSLSock->isMutualAuthNegotiated)) )
        {
            if (kSslSecureSessionEstablished != SSL_OPEN_STATE(pSSLSock))
                SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionJustEstablished;

            if (OK > (status = SSL_SOCK_setClientKeyMaterial(pSSLSock)))
                goto exit;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if (pSSLSock->isDTLS)
            {
                pSSLSock->shouldChangeCipherSpec = FALSE;
                pSSLSock->currentPeerEpoch++;
            }
#endif

            SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_EXPECTING_FINISHED;
        }
    }
    else
    {
        status = ERR_SSL_PROTOCOL;

        /* is client */
        if (SSL_SERVER_HELLO_DONE == SSL_REMOTE_HANDSHAKE_STATE(pSSLSock))
        {
            if (OK > (status = SSL_SOCK_setServerKeyMaterial(pSSLSock)))
                goto exit;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if (pSSLSock->isDTLS)
            {
                pSSLSock->shouldChangeCipherSpec = FALSE;
                pSSLSock->currentPeerEpoch++;
            }
#endif

            SSL_REMOTE_HANDSHAKE_STATE(pSSLSock) = SSL_EXPECTING_FINISHED;
        }
    }
    /* NOTE: this is needed because in DTLS, due to packet misorder, we need to
     * aggressively try this, but the state may not be ready */
    if (status < OK)
        goto exit;

    pSSLSock->pActivePeerCipherSuite = pSSLSock->pHandshakeCipherSuite;
    pSSLSock->peerSeqnum = 0;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if (pSSLSock->isDTLS)
    {
        pSSLSock->peerSeqnumHigh = pSSLSock->peerSeqnumHigh & 0xffff0000;
        pSSLSock->receivedFinished = FALSE;
    } else
#endif
    {
        pSSLSock->peerSeqnumHigh = 0;
    }

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_TLS13__
static MSTATUS
processKeyUpdateRequest(SSLSocket *pSSLSock, ubyte *pMsg, ubyte2 msgLen)
{
    ubyte4 sizeofHandshakeHeader;
    MSTATUS status = OK;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    if (pSSLSock->isDTLS)
    {
        /* DTLS is NOT supported */
        status = ERR_SSL_NOT_SUPPORTED;
        goto exit;
    }
    else
#endif
    {
        sizeofHandshakeHeader = sizeof(SSLHandshakeHeader);
    }

    pMsg   += sizeofHandshakeHeader;

    if (msgLen != 1)
    {
        status = ERR_SSL_INVALID_MSG_SIZE;
        goto exit;
    }

#ifdef __ENABLE_ALL_DEBUGGING__
    if (pSSLSock->server)
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (SERVER)");
    else
        DEBUG_PRINT(DEBUG_SSL_TRANSPORT, (sbyte*)" (CLIENT)");
    DEBUG_PRINTNL(DEBUG_SSL_TRANSPORT, (sbyte*)" Key Update");
    PrintBytes(pMsg, msgLen);
#endif

    /* Update the keys for sender of this message
     * If Client sent this, update the client receive keys on Server
     * If Server sent this, update the server receive keys on Client
     */
    if (pSSLSock->server)
    {
        if (OK > (status = SSLSOCK_pskUpdateClientTrafficSecret(pSSLSock)))
        {
            goto exit;
        }

        if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock,
                            pSSLSock->pClientApplicationTrafficSecret)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK > (status = SSLSOCK_pskUpdateServerTrafficSecret(pSSLSock)))
        {
            goto exit;
        }

        if (OK > (status = SSLSOCK_setServerTrafficKeyMaterial(pSSLSock,
                            pSSLSock->pServerApplicationTrafficSecret)))
        {
            goto exit;
        }
    }

    if (*pMsg == keyUpdateRequest_requested)
    {
        pSSLSock->keyUpdateRequested = keyUpdateRequest_requested;
        if (pSSLSock->server)
        {
            /* Change the state to keelReceiveUntil3 before sending out keyUpdate */
            SSL_HANDSHAKE_STATE(pSSLSock) = kSslReceiveUntil3;
        }
        else
        {
            /* Change the state to keelReceiveUntil before sending out keyUpdate */
            SSL_HANDSHAKE_STATE(pSSLSock) =  kSslReceiveUntil;
        }

        /* Send a keyUpdate Message with keyUpdateReuqest_not_requested */
        if (OK > (status = SSLSOCK_sendKeyUpdateRequest(pSSLSock, 0/* No update message requested */)))
        {
            goto exit;
        }
    }
    else if (*pMsg == keyUpdateRequest_not_requested)
    {
        /* Response to the KeyUpdate Request; Update the receiving keys */
        /* Requester keys have been updated */
        pSSLSock->keyUpdateRequested = keyUpdate_none;
        DIGI_MEMSET((ubyte*)&pSSLSock->keyUpdateTimerCount, 0x00, sizeof(moctime_t));
    }
    else
    {
        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
        SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
        goto exit;
    }
exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_receive(SSLSocket* pSSLSock, sbyte* buffer, sbyte4 bufferSize,
                 ubyte **ppPacketPayload, ubyte4 *pPacketLength, sbyte4 *pRetNumBytesReceived)
{
    sbyte4  available;
    MSTATUS status = OK;
#if (!defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) && (defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)))
    MOC_UNUSED(buffer);
    MOC_UNUSED(bufferSize);
#endif
#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    byteBoolean isDTLSCipherText = FALSE;
#endif

    *pRetNumBytesReceived = 0;

    /* if empty buffer, retrieve one record */
    /* receive a full record */
#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__)
    if (((pSSLSock->internalFlags & SSL_INT_FLAG_SYNC_MODE) && (kRecordStateReceiveFrameWait == SSL_SYNC_RECORD_STATE(pSSLSock))) ||
        (pSSLSock->internalFlags & SSL_INT_FLAG_ASYNC_MODE) )
#elif (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
    if (kRecordStateReceiveFrameWait == SSL_SYNC_RECORD_STATE(pSSLSock))
#endif /* !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) */
    {
        ubyte               majorVersion, minorVersion;
        ubyte*              pSrh;

        if ((NULL == ppPacketPayload) || (NULL == *ppPacketPayload) ||
            (NULL == pPacketLength) || (0 == *pPacketLength))
        {
            goto exit;
        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
            ubyte protocol = **ppPacketPayload;
#ifdef __ENABLE_DIGICERT_TLS13__
            /* Section 4.1 RFC 9147, first byte 20-26 treat as plaintext protocol, 32-63 ciphertext */
            if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            {
                if (DTLS13_PROTOCOL_MIN <= protocol && protocol <= DTLS13_PROTOCOL_MAX) /* check guarantees first 3 bits are 001 */
                {
                    isDTLSCipherText = TRUE;
                }
                else if (SSL_HANDSHAKE == protocol && DTLS_OWNEPOCH(pSSLSock) >= 0x02)
                {
                    /* this is not cipher text, probably duplicate hello, if so get its length
                       and move to the end of it. We'll silently discard the duplicate hello
                       but records after it may be processable.
                     */
                    DTLSRecordHeader *pSrhTemp = (DTLSRecordHeader *) *ppPacketPayload;

                    if (DTLS1_MAJORVERSION == pSrhTemp->majorVersion && DTLS12_MINORVERSION == pSrhTemp->minorVersion)
                    {
                        ubyte4 lenTemp = (ubyte4) getShortValue(pSrhTemp->recordLength) + sizeof(DTLSRecordHeader);
                        if (*pPacketLength >= lenTemp)
                        {
                            *ppPacketPayload += lenTemp;
                            *pPacketLength -= lenTemp;
                        }
                        else
                        {
                            *ppPacketPayload += *pPacketLength;
                            *pPacketLength = 0;
                        }
                    }
                    else /* not a dtls hello, just drop everything */
                    {
                        *ppPacketPayload += *pPacketLength;
                        *pPacketLength = 0;
                    }
                    if (pSSLSock->pReceiveBuffer && pSSLSock->recordSize)
                    {
                        pSSLSock->recordSize = pSSLSock->offset = 0;
                    }
                    SSL_RX_RECORD_STATE(pSSLSock) = SSL_ASYNC_RECEIVE_RECORD_COMPLETED;
                    status = OK;
                    goto exit;
                }
                /* else same as the 1.2 version except allow 25 and 26 (SSL_ACK) */
                else if (protocol < SSL_CHANGE_CIPHER_SPEC || protocol > SSL_ACK)
                {
                    SSL_RX_RECORD_STATE(pSSLSock) = SSL_ASYNC_RECEIVE_RECORD_COMPLETED;
                    *ppPacketPayload += *pPacketLength;
                    *pPacketLength = 0;
                    status = ERR_SSL_PROTOCOL_RECEIVE_RECORD;
                    goto exit;
                }
                else
                {
                    pSSLSock->protocol = protocol;
                }
            }
            else
#endif
            {
                if (protocol < SSL_CHANGE_CIPHER_SPEC || protocol > SSL_INNER_APPLICATION)
                {
                    SSL_RX_RECORD_STATE(pSSLSock) = SSL_ASYNC_RECEIVE_RECORD_COMPLETED;
                    *ppPacketPayload += *pPacketLength;
                    *pPacketLength = 0;
                    status = ERR_SSL_PROTOCOL_RECEIVE_RECORD;
                    goto exit;
                }
            }
        }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) && defined(__ENABLE_DIGICERT_TLS13__)
        if( isDTLSCipherText)
        {
            status = SSL_SOCK_receiveDTLS13Record(pSSLSock, pSSLSock->pSharedInBuffer, &pSSLSock->sharedInBufferLen, ppPacketPayload, pPacketLength);
            if (ERR_SSL_PROTOCOL_BAD_STATE == status)
            {
                /* silently drop data. it might be OK, since packets can be reordered */
                SSL_RX_RECORD_STATE(pSSLSock) = SSL_ASYNC_RECEIVE_RECORD_COMPLETED;
                *ppPacketPayload += *pPacketLength;
                *pPacketLength = 0;
                status = OK;
                goto exit;
            }
            else if (OK != status)
                goto exit;
        }
        else
#endif
        {
            if (OK > (status = SSL_SOCK_receiveV23Record(pSSLSock, pSSLSock->pSharedInBuffer, ppPacketPayload, pPacketLength)))
                goto exit;

            pSrh = pSSLSock->pSharedInBuffer;
        }

        if (SSL_ASYNC_RECEIVE_RECORD_COMPLETED != SSL_RX_RECORD_STATE(pSSLSock))
        {
            status = OK;
            goto exit;
        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if (pSSLSock->isDTLS)
        {
#if defined(__ENABLE_DIGICERT_TLS13__)
            if (!isDTLSCipherText)
#endif
            {
                pSSLSock->protocol = ((DTLSRecordHeader*)pSrh)->protocol;
                minorVersion = ((DTLSRecordHeader*)pSrh)->minorVersion;
                majorVersion = ((DTLSRecordHeader*)pSrh)->majorVersion;
            }

            status = antiReplay(pSSLSock);

            if (ERR_DTLS_DROP_REPLAY_RECORD == status)
            {
                /* silently drop replayed record */
                if (pSSLSock->pReceiveBuffer && pSSLSock->recordSize)
                {
                    pSSLSock->recordSize = pSSLSock->offset = 0;
                }

                status = OK;
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_TLS13__)
            if ( (DTLS13_MINORVERSION >= pSSLSock->sslMinorVersion) &&
                (NULL != pSSLSock->pHandshakeCipherSuite) && !isDTLSCipherText)
            {
#if !defined(__DISABLE_DIGICERT_SSL_TLS13_VERSION_CHECK__)
                /* This is a valid check, but some testing tool clients
                * do not follow the RFC (8446, section 5.1) correctly;
                * To let the tests go through, this flag is added;
                * Use the __DISABLE_DIGICERT_SSL_TLS13_VERSION_CHECK__ flag with caution.
                */
                if (DTLS12_MINORVERSION != minorVersion)
                {
                    status = ERR_SSL_BAD_HEADER_VERSION;
                    goto exit;
                }
#endif

                minorVersion = DTLS13_MINORVERSION;
            } 

            /* If there is application data and the connection instance is
             * TLS 1.3 and the state is at kSslReceiveHelloState then the
             * client is still processing the ServerHello so change the protocol
             * type to SSL_HANDSHAKE.
             */
            if ( (SSL_APPLICATION_DATA == pSSLSock->protocol) &&
                (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
                (SSL_HELLO_REQUEST < SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
                /*&&
                (kSslReceiveHelloState == SSL_HANDSHAKE_STATE(pSSLSock)) )*/
            {
                pSSLSock->pActivePeerCipherSuite = pSSLSock->pHandshakeCipherSuite;
            }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        } else
#endif
        {
            pSSLSock->protocol = ((SSLRecordHeader*)pSrh)->protocol;
            minorVersion = ((SSLRecordHeader*)pSrh)->minorVersion;
            majorVersion = ((SSLRecordHeader*)pSrh)->majorVersion;

            /* For TLS 1.3 the record layer version is still TLS 1.2. If a minor
             * version of TLS 1.2 was retrieved for TLS 1.3 then set it to
             * TLS 1.3 so the validation against pSSLSock->sslMinorVersion will
             * pass.
             *
             * Only change the minorVersion when a handshake cipher suite has
             * been set. If the handshake cipher suite is set then the TLS
             * version has been agreed upon by the client and server and any
             * proceeding messages must contain the appropriate TLS version
             * number.
             */
#if defined(__ENABLE_DIGICERT_TLS13__)
            if ( (TLS13_MINORVERSION <= pSSLSock->sslMinorVersion) &&
                 (NULL != pSSLSock->pHandshakeCipherSuite) )
            {
#if !defined(__DISABLE_DIGICERT_SSL_TLS13_VERSION_CHECK__)
                /* This is a valid check, but some testing tool clients
                 * do not follow the RFC (8446, section 5.1) correctly;
                 * To let the tests go through, this flag is added;
                 * Use the __DISABLE_DIGICERT_SSL_TLS13_VERSION_CHECK__ flag with caution.
                 */
                if (TLS12_MINORVERSION != minorVersion)
                {
                    status = ERR_SSL_BAD_HEADER_VERSION;
                    goto exit;
                }
#endif

                minorVersion = TLS13_MINORVERSION;
            }

            /* If there is application data and the connection instance is
             * TLS 1.3 and the state is at kSslReceiveHelloState then the
             * client is still processing the ServerHello so change the protocol
             * type to SSL_HANDSHAKE.
             */
            if ( (SSL_APPLICATION_DATA == pSSLSock->protocol) &&
                 (TLS13_MINORVERSION == pSSLSock->sslMinorVersion) &&
                 (SSL_HELLO_REQUEST < SSL_REMOTE_HANDSHAKE_STATE(pSSLSock)))
                 /*&&
                 (kSslReceiveHelloState == SSL_HANDSHAKE_STATE(pSSLSock)) )*/
            {
                pSSLSock->pActivePeerCipherSuite = pSSLSock->pHandshakeCipherSuite;
            }
#endif /* __ENABLE_DIGICERT_TLS13__ */
        }
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        /* in DTLS, since packet can be misordered and lost,
         * but ChangeCipherSpec is reflected by an increment in epoch,
         * and we simulate tcp for handshake messages (i.e. the peer will be at the right state),
         * we ignore the ChangeCipherSpec packet and use increment in epoch to
         * indicate the presence of ChangeCipherSpec */
        if (pSSLSock->isDTLS && pSSLSock->shouldChangeCipherSpec)
        {

#if defined(__ENABLE_DIGICERT_TLS13__)
            if (DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
                (void) processChangeCipherSpec(pSSLSock); /* aggressive try: ignore the return status */
        }
#endif

        if (NULL != pSSLSock->pActivePeerCipherSuite
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) && defined(__ENABLE_DIGICERT_TLS13__)
            && (!pSSLSock->isDTLS || isDTLSCipherText || DTLS13_MINORVERSION < pSSLSock->sslMinorVersion)
#endif
        )
        {
            /* We already took care of checking epoch for DTLS13 */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if (pSSLSock->isDTLS && DTLS13_MINORVERSION < pSSLSock->sslMinorVersion && pSSLSock->currentPeerEpoch != DTLS_PEEREPOCH(pSSLSock))
            {
                /* this packet can't be decrypted successfully
                 * ignore this packet. udp can reorder packet */
                if (pSSLSock->pReceiveBuffer && pSSLSock->recordSize)
                {
                    pSSLSock->recordSize = pSSLSock->offset = 0;
                }
                status = OK;
                goto exit;
            }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)
            if((!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) || 
                (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
            {
                /* In TLS v1.3 flow, we receive encrypted packets before changeCipherSpec.
                 * So the pActivePeerCipherSuite is set, but changeCipherSpec is not encrypted.
                 * It should be processed without decrypting
                 */
                if (SSL_CHANGE_CIPHER_SPEC == pSSLSock->protocol)
                {
                    goto protocol_switch;
                }

                if (SSL_OPEN_STATE(pSSLSock) == kSslSecureSessionEstablished)
                {
                    if ((pSSLSock->server && (kSslReceiveUntil3 == SSL_HANDSHAKE_STATE(pSSLSock))) ||
                        (!pSSLSock->server && (kSslReceiveUntil == SSL_HANDSHAKE_STATE(pSSLSock))))
                    {
                        /* In this state, data is transmitted */
                        goto exit;
                    }
                }
            }
#endif

            if (OK > (status = pSSLSock->pActivePeerCipherSuite->pCipherAlgo->decryptVerifyRecordFunc(pSSLSock, (ubyte)pSSLSock->protocol)))
            {
#if defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_TLS13__) && \
    defined(__ENABLE_DIGICERT_TLS13_PSK__)  && defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                if ((TLS13_MINORVERSION == pSSLSock->sslMinorVersion) && (pSSLSock->server) &&
                    (SSL_OPEN_STATE(pSSLSock) != kSslSecureSessionEstablished) &&
                    (1 == TLS13_0RTT_GET_FALLBACK(pSSLSock)) &&
                    (ERR_SSL_INVALID_MAC == status))
                {
                    pSSLSock->recordSize = pSSLSock->offset = 0;
                    status = OK;
                    if (0 == pSSLSock->peerSeqnum)
                    {
                        pSSLSock->peerSeqnumHigh--;
                    }
                    pSSLSock->peerSeqnum--;
                    pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_RESET_FALLBACK(pSSLSock);
                }
#endif
                goto exit;
            }
        }

        pSSLSock->offset = 0;

        if (pSSLSock->protocol != SSL_CHANGE_CIPHER_SPEC &&
            pSSLSock->protocol != SSL_ALERT &&
            pSSLSock->protocol != SSLV2_HELLO_CLIENT &&
            pSSLSock->protocol != SSL_HANDSHAKE &&
            pSSLSock->protocol != SSL_ACK)
        {
            /* we only deliver application data if the connection state is already opened */
            if (SSL_OPEN_STATE(pSSLSock) != kSslSecureSessionEstablished)
            {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                if (pSSLSock->isDTLS)
                {
#if defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_TLS13__) && \
    defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                    if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion &&
                        (pSSLSock->server) && (1 == pSSLSock->earlyDataExtAccepted) &&
                        (1 == TLS13_0RTT_GET_EARLY_DATA_RX(pSSLSock)))
                    {
                        pSSLSock->protocol = SSL_HANDSHAKE;
                        goto protocol_switch;
                    }
                    else
#endif
                    {
                        /* silently drop data. it might be OK, since packets can be reordered */
                        if (pSSLSock->pReceiveBuffer && pSSLSock->recordSize)
                        {
                            pSSLSock->recordSize = pSSLSock->offset = 0;
                        }
                        status = OK;
                    }
                } 
                else
#endif
                {
#if defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_TLS13__) && \
    defined(__ENABLE_DIGICERT_TLS13_PSK__)  && defined(__ENABLE_DIGICERT_TLS13_0RTT__)
                    if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                    {
                        /* End Of Early Data Message is received before Finished message */
                        if ((pSSLSock->server) && (1 == pSSLSock->earlyDataExtAccepted) &&
                            (1 == TLS13_0RTT_GET_EARLY_DATA_RX(pSSLSock)))
                        {
                            pSSLSock->protocol = SSL_HANDSHAKE;
                            goto protocol_switch;
                        }
                        else
                        {
                            status = ERR_SSL_NOT_OPEN;
                        }
                    }
                    else
#endif
                    {
                        status = ERR_SSL_NOT_OPEN;
                    }
                }
                goto exit;
            }
        }

#if defined(__ENABLE_DIGICERT_TLS13__)
protocol_switch:
#endif
        switch (pSSLSock->protocol)
        {
            case SSL_CHANGE_CIPHER_SPEC:
            {
                /* RFC 8446 Section 5
                 *
                 * The change_cipher_spec can be ignored under the following
                 * conditions.
                 *   - The connection is at a state where the ClientHello
                 *     has been sent or recieved
                 *   - The peer's finished message has not been recieved
                 *   - The change_cipher_spec is a single 0x01 byte
                 *   - The change_cipher_spec is NOT protected
                 *
                 * If the change_cipher_spec message is protected or is not
                 * a single byte of 0x01 then the handshake must be aborted with
                 * an "unexpected_message" alert.
                 */
                if ( (!pSSLSock->isDTLS) &&
                     (TLS13_MINORVERSION == pSSLSock->sslMinorVersion) )
                {
                    /* TODO: Add check for ClientHello state and finished
                     * message state. Add check to see whether
                     * change_cipher_spec is protected or not.
                     */
                    if ( (1 == pSSLSock->recordSize) &&
                         (0x01 == *(pSSLSock->pReceiveBuffer)) )
                    {
                        /* Drop the data and exit.
                         */
                        pSSLSock->recordSize = 0;
                        pSSLSock->offset = 0;
                        status = OK;
                    }
                    else
                    {
                        status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(
                            pSSLSock, TRUE, SSL_ALERT_UNEXPECTED_MESSAGE,
                            SSLALERTLEVEL_FATAL);
#endif
                        goto exit;
                    }
                    goto exit;
                }

                /* verify versions */
                /* No version check for DTLS1.3 ciphertext records */
#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                if (!isDTLSCipherText)
#endif
                {
                    if ((pSSLSock->isDTLS && ((majorVersion != DTLS1_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion))) ||
                        ((!pSSLSock->isDTLS && ((majorVersion != SSL3_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion)))))

                    {
                        status = ERR_SSL_BAD_HEADER_VERSION;
                        goto exit;
                    }
                }
                /* dtls will processChangeCipherSpec when Finished is encountered */
                if (!pSSLSock->isDTLS)
                {
                    status = processChangeCipherSpec(pSSLSock);
                }
                break;
            }

            case SSL_ALERT:
            {
                status = ERR_SSL_BAD_HEADER_VERSION;

                /* No version check for DTLS1.3 ciphertext records */
#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                if (!isDTLSCipherText)
#endif
                {
                    if ((NULL != pSSLSock->pHandshakeCipherSuite) && (kSslReceiveHelloInitState != SSL_HANDSHAKE_STATE(pSSLSock)))
                    {
                        /* verify versions */
                        if ((pSSLSock->isDTLS && ((majorVersion != DTLS1_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion))) ||
                            ((!pSSLSock->isDTLS && ((majorVersion != SSL3_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion)))))
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        /* To make us future proof for TLS 1.9+ */
                        /* do not check SSL minor version here */
                        /* see processClientHello3 */
                        if ((pSSLSock->isDTLS && (majorVersion != DTLS1_MAJORVERSION)) ||
                            ((!pSSLSock->isDTLS && (majorVersion < SSL3_MAJORVERSION))))
                        {
                            goto exit;
                        }
                    }
                }
                if (OK > (status = handleAlertMessage(pSSLSock)))
                {
                    goto exit;
                }
                break;
            }

            case SSLV2_HELLO_CLIENT:
            {
                if ((NULL != pSSLSock->pHandshakeCipherSuite) || (kSslReceiveHelloInitState != SSL_HANDSHAKE_STATE(pSSLSock)))
                    break;  /* ignore SSLv2 rehandshake hello */

                if (0 == pSSLSock->server)
                {
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
                    status = SSL_SOCK_clientHandshake(pSSLSock, FALSE);
#endif
                }
                else
                {
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
                    status = SSL_SOCK_serverHandshake(pSSLSock, FALSE);
#endif
                }

                break;
            }

            case SSL_HANDSHAKE:
            {
                /* verify versions */
                /* No version check for DTLS1.3 ciphertext records */
#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                if (!isDTLSCipherText)
#endif
                {
                    if ((NULL != pSSLSock->pHandshakeCipherSuite) && (kSslReceiveHelloInitState != SSL_HANDSHAKE_STATE(pSSLSock)) && (pSSLSock->isDTLS && (kSslReceiveUntil > SSL_HANDSHAKE_STATE(pSSLSock))))
                    {
                        /* if ((pSSLSock->isDTLS && ((majorVersion != DTLS1_MAJORVERSION) )) || */\

                        if ((pSSLSock->isDTLS && ((majorVersion != DTLS1_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion))) ||
                            ((!pSSLSock->isDTLS && ((majorVersion != SSL3_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion)))))
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        /* To make us future proof for TLS 1.9+ */
                        /* do not check SSL minor version here */
                        /* see processClientHello3 */
                        if ((pSSLSock->isDTLS && (majorVersion != DTLS1_MAJORVERSION)) ||
                            ((!pSSLSock->isDTLS && (majorVersion < SSL3_MAJORVERSION))))
                        {
                            goto exit;
                        }
                    }
                }

                if (0 == pSSLSock->server)
                {
#ifdef __ENABLE_DIGICERT_SSL_CLIENT__
                    status = SSL_SOCK_clientHandshake(pSSLSock, FALSE);
#endif
                }
                else
                {
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
                    status = SSL_SOCK_serverHandshake(pSSLSock, FALSE);
#endif
                }

                break;
            }

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
            case SSL_HEARTBEAT:
            {
                /* No version check for DTLS1.3 ciphertext records */
#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                if (!isDTLSCipherText)
#endif
                {
                    /* Process this packet only if the record header versions match */
                    if ((pSSLSock->isDTLS && ((majorVersion != DTLS1_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion))) ||
                        ((!pSSLSock->isDTLS && ((majorVersion != SSL3_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion)))))
                    {
                        status = ERR_SSL_BAD_HEADER_VERSION;
                        goto exit;
                    }
                }

                /* Process only if secure connection has been established &&
                 * if the peer is allowed to send heartbeat messages
                 */
                if (((pSSLSock->isDTLS && (pSSLSock->sslMinorVersion <= DTLS12_MINORVERSION)) ||
                     (!pSSLSock->isDTLS && pSSLSock->sslMinorVersion < TLS13_MINORVERSION)) &&
                    (SSL_OPEN_STATE(pSSLSock) == kSslSecureSessionEstablished) &&
                    (pSSLSock->sendHeartbeatMessage == peerAllowedToSend))
                {
                    if (OK > (status = SSL_SOCK_processHeartbeatMessage(pSSLSock, pSSLSock->pReceiveBuffer,
                                                                        pSSLSock->recordSize)))
                    {
                        goto exit;
                    }
                }
                break;
            }
#else
            case SSL_INNER_APPLICATION:
            {
                /* verify versions */
                /* No version check for DTLS1.3 ciphertext records */
#if defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
                if (!isDTLSCipherText)
#endif
                {
                    if ((pSSLSock->isDTLS && ((majorVersion != DTLS1_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion))) ||
                        ((!pSSLSock->isDTLS && ((majorVersion != SSL3_MAJORVERSION) || (minorVersion != pSSLSock->sslMinorVersion)))))
                    {
                        status = ERR_SSL_BAD_HEADER_VERSION;
                        goto exit;
                    }
                }

                if (OK > (status = handleInnerAppMessage(pSSLSock)))
                    goto exit;
                break;
            }
#endif /* __ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__ */

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            case SSL_APPLICATION_DATA:
            {
                /* TODO: should do this only after encounter of the first application data
                 * it's not efficient to check this every time afterwards
                 */
                /* by this time, handshake would have successfully finished, release retransmission buffer */
                if (pSSLSock->isDTLS && pSSLSock->sslMinorVersion > DTLS13_MINORVERSION)
                {
                    releaseRetransmissionBuffer(pSSLSock);
                }

                break;
            }

#ifdef __ENABLE_DIGICERT_TLS13__
            case SSL_ACK:
            {
                ubyte remaining;
                enum postHandshakeType type;
                status = processACK(pSSLSock, &remaining, &type);
                if (OK != status)
                    goto exit;

                if (kMainHandshake == type)
                {
                    if (remaining > 0)
                    {
                        /* message has been processed, but not all records
                        * have been acknowledged */
                        if (pSSLSock->pReceiveBuffer && pSSLSock->recordSize)
                        {
                            pSSLSock->recordSize = pSSLSock->offset = 0;
                        }
                        status = OK;
                        goto exit;
                    }

#ifdef __ENABLE_DIGICERT_DTLS_CLIENT__
                    if (!pSSLSock->server && kSslSecureSessionEstablished != SSL_OPEN_STATE(pSSLSock))
                    {
                        if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock,
                                                    pSSLSock->pClientApplicationTrafficSecret)))
                            goto exit;

                        pSSLSock->ownSeqnum = 0;
                        pSSLSock->ownSeqnumHigh = 0x30000;
                        releaseRetransmissionBuffer(pSSLSock);
                    }
#endif

                    if (OK > (status = SSL_INTERNAL_setConnectionState(SSL_findConnectionInstance(pSSLSock), CONNECT_OPEN)))
                        goto exit;

                    status = SSLSOCK_doOpenUpcalls(pSSLSock);
                    if ( OK <= status )
                        status = pSSLSock->numBytesToSend;

                    SSL_OPEN_STATE(pSSLSock) = kSslSecureSessionEstablished;
                }
                else if (kKeyUpdate == type)
                {
                    /* update your own keys now that key update message has been acknowledged */
                    pSSLSock->retransCipherInfo.pOldCipherSuite = pSSLSock->pActiveOwnCipherSuite;
                    releaseRetransmissionBufferType(pSSLSock, kKeyUpdate);
                    clearRetransmissionSessionInfo(pSSLSock);
                    pSSLSock->retransCipherInfo.deleteOldBulkCtx = TRUE;
                    if (pSSLSock->server)
                    {
                        pSSLSock->retransCipherInfo.oldBulkCtx = pSSLSock->serverBulkCtx;
                        pSSLSock->serverBulkCtx = NULL;
                        if (OK > (status = SSLSOCK_pskUpdateServerTrafficSecret(pSSLSock)))
                        {
                            goto exit;
                        }

                        if (OK > (status = SSLSOCK_setServerTrafficKeyMaterial(pSSLSock,
                                            pSSLSock->pServerApplicationTrafficSecret)))
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        pSSLSock->retransCipherInfo.oldBulkCtx = pSSLSock->clientBulkCtx;
                        pSSLSock->clientBulkCtx = NULL;
                        if (OK > (status = SSLSOCK_pskUpdateClientTrafficSecret(pSSLSock)))
                        {
                            goto exit;
                        }

                        if (OK > (status = SSLSOCK_setClientTrafficKeyMaterial(pSSLSock,
                                            pSSLSock->pClientApplicationTrafficSecret)))
                        {
                            goto exit;
                        }
                    }

                    pSSLSock->oldSeqnumHigh = pSSLSock->ownSeqnumHigh;
                    pSSLSock->oldSeqnum = 0;

                    pSSLSock->ownSeqnumHigh = 0xffff0000 & (pSSLSock->ownSeqnumHigh + 0x10000);
                    pSSLSock->ownSeqnum = 0;

                    status = pSSLSock->numBytesToSend;
                }
                break;
            }
#endif
#endif

            default:
            {
                break;
            }
        } /* switch */

        if (SSL_APPLICATION_DATA != pSSLSock->protocol)
        {
#if (!defined(__ENABLE_DIGICERT_OPENSSL_SHIM__) && \
     (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))
            if (SSL_FLAG_ENABLE_RECV_BUFFER & pSSLSock->runtimeFlags)
            {
                if ((SSL_INNER_APPLICATION == pSSLSock->protocol) ||
                    (SSL_ALERT             == pSSLSock->protocol))
                {
                    /* let the app harvest this data (ALERT/INNER_APP) out */
                    if (pSSLSock->recordSize > pSSLSock->offset)
                        *pRetNumBytesReceived = (ubyte4)(pSSLSock->recordSize - pSSLSock->offset);  /* yes, x - 0 == x but logical */

                    goto exit;
                }
            }
#endif
            pSSLSock->recordSize = 0;
        }
        else
        {
            /* Peer must send keyUpdate(if requested) before sending any Application data;
             * The timer is to accomodate any messages already in-flight
             */
#if defined(__ENABLE_DIGICERT_TLS13__)
            if (!pSSLSock->isDTLS && pSSLSock->keyUpdateRequested == keyUpdateRequest_requested)
            {
                ubyte4 keyUpdateTime = 0;
                keyUpdateTime = RTOS_deltaMS(&pSSLSock->keyUpdateTimerCount, NULL);
                if (keyUpdateTime > KEY_UPDATE_REQUEST_TIMEOUT)
                {
                    pSSLSock->recordSize = pSSLSock->offset = 0;
                    status = OK;
                    goto exit;
                }
            }
#endif
        }

#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__)
        if ((0 < pSSLSock->recordSize) && (pSSLSock->internalFlags & SSL_INT_FLAG_SYNC_MODE))
            SSL_SYNC_RECORD_STATE(pSSLSock) = kRecordStateReceiveFrameComplete;
#elif (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
        if (0 < pSSLSock->recordSize)
            SSL_SYNC_RECORD_STATE(pSSLSock) = kRecordStateReceiveFrameComplete;
#endif /* !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) */
    }

#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
    if (pSSLSock->isDTLS && SSL_FLAG_ENABLE_RECV_BUFFER & pSSLSock->runtimeFlags)
    {
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__) && \
    defined(__ENABLE_DIGICERT_SSL_SERVER__))
        if (1 == pSSLSock->server && 1 == pSSLSock->earlyDataExtAccepted)
        {
            /*
                * RFC #8446 Section 4.6.1, Page 75
                * The maximum amount of 0-RTT data that the
                * client is allowed to send when using this ticket, in bytes.  Only
                * Application Data payload (i.e., plaintext but not padding or the
                * inner content type byte) is counted.  A server receiving more than
                * maxEarlyDataSize bytes of 0-RTT data SHOULD terminate the
                * connection with an "unexpected_message" alert.
                */
            if (kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock) &&
                kSslSecureSessionEstablished == SSL_OPEN_STATE(pSSLSock))
            {
                pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_SET_EARLY_DATA_RX(pSSLSock);
                /* SendServerHello. Only 0-RTT case */
                status = SSL_SOCK_serverHandshake(pSSLSock, FALSE);
            }
        }
#endif
        if (pSSLSock->recordSize > pSSLSock->offset)
        {
            /* let the app harvest this data out */
            *pRetNumBytesReceived = pSSLSock->recordSize - pSSLSock->offset;  /* yes, x - 0 == x but logical */
        }
        goto exit;
    }
#endif

    /* return as much of the record as possible */
    if (pSSLSock->recordSize > pSSLSock->offset)
    {
        available = pSSLSock->recordSize - pSSLSock->offset;  /* yes, x - 0 == x but logical */

#if ((!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)) || defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__))
#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__))
        if (pSSLSock->internalFlags & SSL_INT_FLAG_SYNC_MODE)
#endif
        {
            ubyte4 toCopy  = 0;
            toCopy = (available < bufferSize) ? available : bufferSize;
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__) && \
     defined(__ENABLE_DIGICERT_SSL_SERVER__))
            if (1 == pSSLSock->server)
            {
                /*
                 * RFC #8446 Section 4.6.1, Page 75
                 * The maximum amount of 0-RTT data that the
                 * client is allowed to send when using this ticket, in bytes.  Only
                 * Application Data payload (i.e., plaintext but not padding or the
                 * inner content type byte) is counted.  A server receiving more than
                 * maxEarlyDataSize bytes of 0-RTT data SHOULD terminate the
                 * connection with an "unexpected_message" alert.
                 */
                if ((kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock) &&
                    (kSslSecureSessionEstablished == SSL_OPEN_STATE(pSSLSock)) &&
                    (1 == pSSLSock->earlyDataExtAccepted)) &&
                    (0 == TLS13_0RTT_GET_EARLY_DATA_RX(pSSLSock)))
                {
                    /* This data is early application data. This case should be only
                       handled once at the time we receive early application data. */
                    if (pSSLSock->maxEarlyDataSize < toCopy)
                    {
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
                        SSLSOCK_sendAlert(pSSLSock, TRUE,
                                SSL_ALERT_UNEXPECTED_MESSAGE,
                                SSLALERTLEVEL_FATAL);
#endif
                        status = ERR_SSL_FATAL_ALERT;
                        goto exit;

                    }

                    pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_SET_EARLY_DATA_RX(pSSLSock);

                    if (0 == bufferSize)
                    {
                        toCopy = available;
                    }

                    if (SSL_sslSettings()->funcPtrSSLReceiveApplicationDataCallback != NULL)
                    {
                        if (OK > (status = SSL_sslSettings()->funcPtrSSLReceiveApplicationDataCallback(SSL_findConnectionInstance(pSSLSock),
                                                                                              (ubyte*)(pSSLSock->pReceiveBuffer + pSSLSock->offset),
                                                                                              toCopy, 0 /* clientEarlyData */)))
                        {
                            goto exit;
                        }
                    }
                    /* SendServerHello. Only 0-RTT case */
                    status = SSL_SOCK_serverHandshake(pSSLSock, FALSE);
                }
            }
#endif

            DIGI_MEMCPY((ubyte *)buffer, (ubyte *)(pSSLSock->pReceiveBuffer + pSSLSock->offset), toCopy);
            pSSLSock->offset += toCopy;

            if (0 >= ((pSSLSock->recordSize) - (pSSLSock->offset)))
            {
                SSL_SYNC_RECORD_STATE(pSSLSock) = kRecordStateReceiveFrameWait;
            }

            *pRetNumBytesReceived = toCopy;

#if (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__))
            goto exit;
#endif
        }
#endif /* ((!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)) || defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__)) */

#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
        if (SSL_FLAG_ENABLE_RECV_BUFFER & pSSLSock->runtimeFlags)
        {
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__) && \
     defined(__ENABLE_DIGICERT_SSL_SERVER__))
            if (1 == pSSLSock->server)
            {
                /*
                 * RFC #8446 Section 4.6.1, Page 75
                 * The maximum amount of 0-RTT data that the
                 * client is allowed to send when using this ticket, in bytes.  Only
                 * Application Data payload (i.e., plaintext but not padding or the
                 * inner content type byte) is counted.  A server receiving more than
                 * maxEarlyDataSize bytes of 0-RTT data SHOULD terminate the
                 * connection with an "unexpected_message" alert.
                 */
                if ((kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock) &&
                     (kSslSecureSessionEstablished == SSL_OPEN_STATE(pSSLSock)) &&
                     (1 == pSSLSock->earlyDataExtAccepted)) &&
                     (0 == TLS13_0RTT_GET_EARLY_DATA_RX(pSSLSock)))
                {
                    pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_SET_EARLY_DATA_RX(pSSLSock);
                    /* SendServerHello. Only 0-RTT case */
                    status = SSL_SOCK_serverHandshake(pSSLSock, FALSE);
                }
            }
#endif
            /* let the app harvest this data out */
            *pRetNumBytesReceived = available;
            goto exit;
        }
#endif
#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))
        if (1 == pSSLSock->server)
        {
            if (NULL != SSL_sslSettings()->funcPtrReceiveUpcall)
            {
                SSL_sslSettings()->funcPtrReceiveUpcall(SSL_findConnectionInstance(pSSLSock), (ubyte*)pSSLSock->pReceiveBuffer, available);
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
                if ((kSslReceiveHelloInitState == SSL_HANDSHAKE_STATE(pSSLSock) &&
                     (kSslSecureSessionEstablished == SSL_OPEN_STATE(pSSLSock)) &&
                     (1 == pSSLSock->earlyDataExtAccepted)) &&
                     (0 == TLS13_0RTT_GET_EARLY_DATA_RX(pSSLSock)))
                {
                    pSSLSock->roleSpecificInfo.server.zeroRTT = TLS13_0RTT_SET_EARLY_DATA_RX(pSSLSock);
                    /* SendServerHello. Only 0-RTT case */
                    status = SSL_SOCK_serverHandshake(pSSLSock, FALSE);
                }
#endif
            }
        }
#endif
#if (defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))
        if (0 == pSSLSock->server)
        {
            if (NULL != SSL_sslSettings()->funcPtrClientReceiveUpcall)
                SSL_sslSettings()->funcPtrClientReceiveUpcall(SSL_findConnectionInstance(pSSLSock), (ubyte*)pSSLSock->pReceiveBuffer, available);
        }
#endif
    }


exit:
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__) \
    && defined(__ENABLE_DIGICERT_TLS13_0RTT__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if (TRUE == pSSLSock->earlyDataEpochKeys.isSet &&
        TRUE == pSSLSock->earlyDataEpochKeys.needToRevert)
    {
        swapEpochKeys(pSSLSock);
        pSSLSock->earlyDataEpochKeys.needToRevert = FALSE;
    }
#endif
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SOCK_receive() returns status = ", status);
#endif

    if (*pRetNumBytesReceived )
    {
        status = (MSTATUS)(*pRetNumBytesReceived);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_SOCK_getCipherId( SSLSocket* pSSLSock, ubyte2* pCipherId)
{
    if (!pSSLSock)
        return ERR_NULL_POINTER;

    *pCipherId = (pSSLSock->pHandshakeCipherSuite) ?
                    pSSLSock->pHandshakeCipherSuite->cipherSuiteId :
                    0;
    return OK;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
extern sbyte4
SSL_SOCK_getCipherList(SSLSocket *pSSLSock, ubyte2 **ppCipherIdList, ubyte4 *pCount)
{
    ubyte4 count = 0;
    ubyte4 i;
    ubyte  *pCipherList = NULL;
    MSTATUS status = OK;

    if ((NULL == ppCipherIdList) || (NULL == pCount))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppCipherIdList = NULL;
    *pCount = 0;

    for (i = 0; i < NUM_CIPHER_SUITES; i++)
    {
        /* Cipher is supported && 
         * if CipherTable is initialized, check if this cipher is enabled
         */
        if ((gCipherSuites[i].supported) &&
            ((TRUE != pSSLSock->isCipherTableInit) || (TRUE == pSSLSock->isCipherEnabled[i])))
        {
            count++;
        }
    }
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
    if ((TLS11_MINORVERSION > pSSLSock->minFallbackMinorVersion) &&
        (0 == pSSLSock->handshakeCount)
#if defined(__ENABLE_DIGICERT_TLS13__)
        && (0 == pSSLSock->helloRetryRequest)
#endif
        )
    {
        /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
        /* send only during initial SSL 3.0 hello */
        count++;
    }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */
#endif /* MIN_SSL_MINORVERSION <= SSL3_MINORVERSION */
	if(pSSLSock->runtimeFlags & SSL_FLAG_SCSV_FALLBACK_VERSION_SET)
	{
        /* TLS_FALLBACK_SCSV */
        /* send only if client is trying to connect with fallback version */
        count++;
	}

    if (count > 0)
    {
        if (OK > (status = DIGI_MALLOC((void **)&pCipherList, count * sizeof(ubyte2))))
        {
            goto exit;
        }

        *ppCipherIdList = (ubyte2 *) pCipherList;
        *pCount = count;

        for (i = 0; i < NUM_CIPHER_SUITES; i++)
        {
            if ((gCipherSuites[i].supported) &&
                ((TRUE != pSSLSock->isCipherTableInit) || (TRUE == pSSLSock->isCipherEnabled[i])))
            {
                *((ubyte2 *) pCipherList) = gCipherSuites[i].cipherSuiteId;
                pCipherList += 2;
            }
        }
#if MIN_SSL_MINORVERSION <= SSL3_MINORVERSION
#if ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__)))
        if ((TLS11_MINORVERSION > pSSLSock->minFallbackMinorVersion) &&
            (0 == pSSLSock->handshakeCount)
#if defined(__ENABLE_DIGICERT_TLS13__)
            && (0 == pSSLSock->helloRetryRequest)
#endif
            )
        {
            /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV {0x00, 0xFF} */
            /* send only during initial SSL 3.0 hello */
            /* DO NOT add SCSV to gCipherSuites;
             * This SCSV is not a true cipher suite (it does not correspond to any
             * valid set of algorithms) and cannot be negotiated.
             */
            *((ubyte2 *) pCipherList) = 0x00FF;
            pCipherList += 2;
        }
#endif /* ((defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)) && (!defined(__DISABLE_DIGICERT_SSL_REHANDSHAKE_FIX__))) */
#endif /*  MIN_SSL_MINORVERSION <= SSL3_MINORVERSION */

        if(pSSLSock->runtimeFlags & SSL_FLAG_SCSV_FALLBACK_VERSION_SET)
        {
            /* TLS_FALLBACK_SCSV {0x56, 0x00} */
            /* send only when application is trying to re-negotiate with fall back version */
            /* DO NOT add SCSV to gCipherSuites;
             * This SCSV is not a true cipher suite (it does not correspond to any
             * valid set of algorithms) and cannot be negotiated.
             */
            *((ubyte2 *) pCipherList) = 0x5600;
            pCipherList += 2;
        }
    }

exit:
    return status;
}

extern sbyte4
SSL_SOCK_numCiphersAvailable(void)
{
    return NUM_CIPHER_SUITES;
}

/*------------------------------------------------------------------*/
/* If the cipher table is not initialized, all other ciphers are enabled */
extern sbyte4
SSL_SOCK_disableCipherHashAlgorithm(SSLSocket *pSSLSock, TLS_HashAlgorithm hashId)
{
    MSTATUS status;
    ubyte4 index;
    TLS_HashAlgorithm cipherHashId;
    /* Note if the cipher table has been initialized */
    intBoolean cipherInitialized = pSSLSock->isCipherTableInit;
    pSSLSock->isCipherTableInit = TRUE;

    if ( (TLS_NONE > hashId) || (TLS_SHA512 < hashId) )
    {
        status = ERR_SSL_UNSUPPORTED_ALGORITHM;
        goto exit;
    }

    for (index = 0; index < NUM_CIPHER_SUITES; index++)
    {
        switch(gCipherSuites[index].hashId)
        {
            case ht_md5:
                cipherHashId = TLS_MD5;
                break;

            case ht_sha1:
                cipherHashId = TLS_SHA1;
                break;

            case ht_sha224:
                cipherHashId = TLS_SHA224;
                break;

            case ht_sha256:
                cipherHashId = TLS_SHA256;
                break;

            case ht_sha384:
                cipherHashId = TLS_SHA384;
                break;

            case ht_sha512:
                cipherHashId = TLS_SHA512;
                break;

            default:
                status = ERR_SSL_UNSUPPORTED_ALGORITHM;
                goto exit;
        }

        /* By default enable all ciphers;
         * Disable the appropriate ciphers based on the hashId passed.
         * This index is used when isCipherTableInit is set to TRUE;
         *
         * If the cipherTable has been already initialized,
         * do NOT over-ride here.
         */
        if (FALSE == cipherInitialized)
        {
            pSSLSock->isCipherEnabled[index] = TRUE;
        }

        if (cipherHashId <= hashId)
        {
            pSSLSock->isCipherEnabled[index] = FALSE;
        }
    }

    status = OK;

exit:

    return status;
}

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
/* If value = TRUE, enable DSA Ciphers
 *    value = FALSE, disable DSA Ciphers
 * If the cipher table is not initialized, all other ciphers are enabled
 */
extern MSTATUS SSLSOCK_setDSACiphers(SSLSocket *pSSLSock, intBoolean value)
{
    MSTATUS status = OK;
    ubyte4 index = 0;

    /* Note if the cipher table has been initialized */
    intBoolean cipherInitialized = pSSLSock->isCipherTableInit;

    for (index = 0; index < NUM_CIPHER_SUITES; index++)
    {
        ubyte4 i;

        /* By default enable all ciphers;
         * Enable/Disable the DSA ciphers.
         * This index is used when isCipherTableInit is set to TRUE;
         *
         * If the cipherTable has been already initialized,
         * do NOT over-ride here.
         */
        if (FALSE == cipherInitialized)
        {
            pSSLSock->isCipherEnabled[index] = TRUE;
        }

        pSSLSock->isCipherTableInit = TRUE;
        if (value == TRUE)
        {
            continue;
        }

        for (i = 0; i < NUM_CIPHERID_DSA; i++)
        {
            if (gCipherSuites[index].cipherSuiteId == gCipherIdDSA[i])
            {
                /* Do not change disabled cipher suites. Assume another caller
                 * has explicitly disabled this cipher suite.
                 */
                pSSLSock->isCipherEnabled[index] = FALSE;
            }
        }
    }
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_DSA_SUPPORT__ */
#endif /*  __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__ */

/*------------------------------------------------------------------*/

#if defined ( __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__) || (defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_SERVER__))

extern sbyte4
SSL_SOCK_getCipherTableIndex(SSLSocket* pSSLSock, ubyte2 cipherId)
{
    sbyte4  retIndex = -1;
    ubyte4  index;
#if (!defined(__ENABLE_DIGICERT_DTLS_CLIENT__) && !defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    MOC_UNUSED(pSSLSock);
#endif

    for (index = 0; index < NUM_CIPHER_SUITES; index++)
    {
        if ((cipherId == gCipherSuites[index].cipherSuiteId) &&
            (0 != gCipherSuites[index].supported))
        {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if (pSSLSock->isDTLS && isCipherIdExcludedForDTLS(cipherId))
            {
                /* DTLS doesnot support stream ciphers */
                break;
            }
            else
#endif
            {
                retIndex = (sbyte4) index;
                break;
            }
        }
    }

    return retIndex;
}
#endif /* ( __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__) || (defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#if (defined(__ENABLE_DIGICERT_DTLS_SRTP__) && defined(__ENABLE_DIGICERT_SRTP_PROFILES_SELECT__))
extern sbyte4
SSL_SOCK_numSrtpProfilesAvailable(void)
{
    return NUM_SRTP_PROFILES;
}


/*------------------------------------------------------------------*/

extern sbyte4
SSL_SOCK_getSrtpProfileIndex(SSLSocket* pSSLSock, ubyte2 profileId)
{
    sbyte4  retIndex = -1;
    ubyte4  index;

    for (index = 0; index < NUM_SRTP_PROFILES; index++)
    {
        if ((profileId == gSrtpProfiles[index].profileId) &&
            (0 != gSrtpProfiles[index].supported))
        {
            retIndex = (sbyte4) index;
            break;
        }
    }

    return retIndex;
}
#endif /* (__ENABLE_DIGICERT_DTLS_SRTP__) && (__ENABLE_DIGICERT_SRTP_PROFILES_SELECT__) */
#endif /* (__ENABLE_DIGICERT_DTLS_CLIENT__) || (__ENABLE_DIGICERT_DTLS_SERVER__) */




/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)) || (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined (__ENABLE_DIGICERT_ECC__))

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
SSL_SOCK_getECCSignatureLength( ECCKey* pECCKey, sbyte4* signatureLen, ubyte4 keyType)
#else
static MSTATUS
SSL_SOCK_getECCSignatureLength( ECCKey* pECCKey, sbyte4* signatureLen)
#endif
{
    /* computing the ECDSA signature length is complex -- it's DER encoded
    since the largest signature is with P521 -- R and S are at most 66 bytes
    long -- so TLV is 1 + 1 + 66 (68) for each -- (no leading zero for this
    curve but other curves might need one) and TLV for sequence is
    1 + 2 + 2 * 68 (2 bytes for length since 68*2 > 127 ) -- code is more generic
    This is actually the maximum length needed because the presence of leading
    zeros cannot be predicted before the signature is computed */
    MSTATUS         status;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    PrimeFieldPtr   pPF;
    PEllipticCurvePtr pCurve;
#endif
    sbyte4          elementLen;

#if defined (__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK > (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(pECCKey, (ubyte4 *)&elementLen, keyType)))
        goto exit;
#else
    pCurve = pECCKey->pCurve;
    pPF = EC_getUnderlyingField(pCurve);

    if (OK > ( status = PRIMEFIELD_getElementByteStringLen( pPF, &elementLen)))
        goto exit;
#endif

    elementLen += 3; /* leading zero + type + length */
    *signatureLen = 2 * elementLen + 3; /* 2 INTEGER + type + length */
exit:

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined (__ENABLE_DIGICERT_ECC__)) */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TLS13__
static MSTATUS validateExtension(
    SSLSocket *pSSLSock, ubyte4 handshakeType, ubyte2 extensionType,
    ubyte2 extensionSize, sbyte4 extensionsLen, ubyte4 extensionMask[2])
{
    MSTATUS status = OK;
    ubyte raiseAlert = 0;
    ubyte4 i = 0;

    /*
     * RFC #8446 Page 36.
     * Implementations MUST NOT send extension responses if the remote
     * endpoint did not send the corresponding extension requests, with the
     * exception of the "cookie" extension in the HelloRetryRequest.  Upon
     * receiving such an extension, an endpoint MUST abort the handshake
     * with an "unsupported_extension" alert.
    */

    if ((handshakeType != SSL_CLIENT_HELLO) &&
    (handshakeType != SSL_CERTIFICATE_REQUEST) &&
    (handshakeType != SSL_NEW_SESSION_TICKET) &&
    (extensionType != tlsExt_cookie) &&
    (extensionType != tlsExt_renegotiated_connection) &&
    (extensionType != tlsExt_signed_certificate_timestamp))
    {
        for (i = 0; i < pSSLSock->numExtensions; i++)
        {
            if (handshakeType == SSL_HELLO_RETRY_REQUEST)
            {
                break;
            }
            if (extensionType == pSSLSock->sentExtensions[i])
            {
                break;
            }
        }
        if (i == pSSLSock->numExtensions)
        { /* No Match found */

            status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
            SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_UNSUPPORTED_EXTENSION, SSLALERTLEVEL_FATAL);
#endif
            goto exit;
        }
    }

     switch(handshakeType)
     {
         case SSL_SERVER_HELLO:
             {
                 switch(extensionType)
                 {
                     case tlsExt_key_share:
                     case tlsExt_pre_shared_key:
                     case tlsExt_supported_versions:
                     case tlsExt_ticket:
                     case tlsExt_cookie:
                         break;
                     default:
                          break;
                 }
                 break;
             }
         case SSL_CLIENT_HELLO:
             {
                 switch(extensionType)
                 {
                     case tlsExt_pre_shared_key:
#ifdef __ENABLE_DIGICERT_SSL_SERVER__
                if (pSSLSock->server)
                {
                    if (!(extensionMask[1] & (1 << (tlsExt_psk_key_exchange_modes - 32))))
                    {
                        /* RFC 8446 section 4.2.9
                        *
                        * Ensure the PSK key exchange mode extension was
                        * recieved.
                        */
                        status = ERR_SSL_EXTENSION_WRONG_ORDER;
                    }
                    else if (extensionSize != extensionsLen)
                    {
                        /* RFC 8446 section 4.2.11
                        *
                        * The "pre_shared_key" extension must be the last
                        * extension provided in the ClientHello. The client
                        * must abort the handshake with an
                        * "illegal_parameter" alert if it is not.
                        */
                        raiseAlert = 1;
                    }
                }
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */
                case tlsExt_server_name:
                case tlsExt_max_fragment_length:
                case tlsExt_status_request:
                case tlsExt_supportedGroups:
                case tlsExt_supportedSignatureAlgorithms:
                case dtlsExt_use_srtp:
                case tlsExt_applicationLayerProtocolNegotiation:
                case tlsExt_signed_certificate_timestamp:
                case tlsExt_certificate_type:
                case tlsExt_server_certificate_type:
                /*case tlsExt_padding:*/
                case tlsExt_key_share:
                case tlsExt_psk_key_exchange_modes:
                case tlsExt_early_data:
                case tlsExt_cookie:
                case tlsExt_supported_versions:
                case tlsExt_certificateAuthorities:
                case tlsExt_postHandshakeAuth:
                case tlsExt_signatureAlgorithmCerts:
                case tlsExt_ticket:
                case tlsExt_ECPointFormat:
                case tlsExt_encrypt_then_mac:
                case tlsExt_extendedMasterSecret:
                case tlsExt_renegotiated_connection:
                    break;
                default:
                    break;
            }
            break;
        }
        case SSL_ENCRYPTED_EXTENSIONS:
        {
            switch(extensionType)
            {
                case tlsExt_server_name:
                case tlsExt_max_fragment_length:
                case tlsExt_supportedGroups:
                case dtlsExt_use_srtp:
                case tlsExt_applicationLayerProtocolNegotiation:
                case tlsExt_certificate_type:
                case tlsExt_server_certificate_type:
                case tlsExt_early_data:
                case tlsExt_ticket:
                    break;
                default:
                    raiseAlert = 1;
                    break;
            }
            break;
        }
        case SSL_CERTIFICATE:
        {
            switch(extensionType)
            {
                case tlsExt_status_request:
                case tlsExt_signed_certificate_timestamp:
                    break;
                default:
                    raiseAlert = 1;
                    break;
            }
            break;
        }
        case SSL_CERTIFICATE_REQUEST:
        {
            switch(extensionType)
            {
                case tlsExt_status_request:
                case tlsExt_supportedSignatureAlgorithms:
                case tlsExt_signed_certificate_timestamp:
                case tlsExt_certificateAuthorities:
                /*case tlsExt_oidFilters:*/
                case tlsExt_signatureAlgorithmCerts:
                    break;
                default:
                    raiseAlert = 1;
                    break;
            }
            break;
        }
        case SSL_NEW_SESSION_TICKET:
        {
            if (tlsExt_early_data != extensionType)
            {
                raiseAlert = 1;
            }
            break;
        }
        case SSL_HELLO_RETRY_REQUEST:
        {
            switch(extensionType)
            {
                case tlsExt_key_share:
                /*case tlsExt_cookie:*/
                case tlsExt_supported_versions:
                    break;
                default:
                    raiseAlert = 1;
                    break;
            }
            break;
        }

        default:
            break;
    }

    if (1 == raiseAlert)
    {
    status = ERR_SSL_FATAL_ALERT;
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    SSLSOCK_sendAlert(pSSLSock, TRUE, SSL_ALERT_ILLEGAL_PARAMETER, SSLALERTLEVEL_FATAL);
#endif
    }
    exit:
    return status;
}
#endif

/*------------------------------------------------------------------*/
static MSTATUS
processHelloExtensions(SSLSocket* pSSLSock, ubyte *pExtensions,
                       sbyte4 extensionsLen, ubyte4 handshakeType)
{
    /* this function parses the extensions doing some checks before
    calling a role specific function for each extension */
    ubyte2  extensionType;
    ubyte2  extensionSize;
    ubyte4  extensionMask[2] = { 0, 0}; /* 64 bits available */
    MSTATUS status = OK;

    while ((OK <= status) && (0 < extensionsLen))
    {
        if (4 > extensionsLen)
        {
            status = ERR_SSL_PROTOCOL_PROCESS_CLIENT_HELLO;
            goto exit;
        }

        extensionType = getShortValue(pExtensions);
        pExtensions += 2;    extensionsLen -= 2;

        extensionSize = getShortValue(pExtensions);
        pExtensions += 2;    extensionsLen -= 2;

        if (32 > extensionType)
        {
            /* prevent duplicate extensions */
            if (extensionMask[0] & (1 << extensionType))
            {
                status = ERR_SSL_EXTENSION_DUPLICATE;
                goto exit;
            }

            extensionMask[0] |= (1 << extensionType);
        }
        else if ( 64 > extensionType)
        {
            /* prevent duplicate extensions */
            if (extensionMask[1] & (1 << (extensionType-32)))
            {
                /* RFC-3546: There MUST NOT be more than one extension of the same type. */
                status = ERR_SSL_EXTENSION_DUPLICATE;
                goto exit;
            }

            extensionMask[1] |= (1 << (extensionType-32));
        }

        /* check the size */
        if ( extensionsLen < (sbyte4) extensionSize )
        {
            /* buffer overrun attack? */
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        if (0 == pSSLSock->clientHelloMinorVersion)
        {
            /* renegotiation is the only extension supported for SSL 3.0 */
            if (tlsExt_renegotiated_connection != extensionType)
            {
                status = ERR_SSL_INVALID_MSG_SIZE;
                goto exit;
            }
        }

#ifdef __ENABLE_DIGICERT_TLS13__
        if ( (!pSSLSock->isDTLS && TLS13_MINORVERSION == pSSLSock->sslMinorVersion) ||
              (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion))
        {
            status = validateExtension(
                pSSLSock, handshakeType, extensionType, extensionSize,
                extensionsLen, extensionMask);
            if (OK != status)
            {
                goto exit;
            }
        }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
        if (1 == pSSLSock->server)
        {
            status = processClientHelloExtension(pSSLSock, extensionType, extensionSize,
                                                 pExtensions);
        }
#endif

#if defined( __ENABLE_DIGICERT_SSL_CLIENT__)
        if (0 == pSSLSock->server)
        {
            status = processServerHelloExtensions(pSSLSock, extensionType, extensionSize,
                                                 pExtensions);
        }
#endif

        /* move to the next extension */
        pExtensions   += extensionSize;
        extensionsLen -= extensionSize;

    } /* while */

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_TLS13__
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
static MSTATUS
SSL_SOCK_processCertExtStatusResponse(SSLSocket *pSSLSock,
                                      ubyte4 index,
                                      ValidationConfig *pConfig)
{
    MSTATUS status;
    ubyte *pOcspExt = NULL;
    const ubyte *pCert = NULL;
    ubyte4 ocspExtLen = 0, certLen = 0;
    ubyte* pOcspMsg   = NULL;
    ubyte4 ocspMsgLen = 0;

    status = CERTCHAIN_getCertificateExtensionsCertStatus(
        pSSLSock->pCertChain, index, &pOcspExt, &ocspExtLen);
    if (OK > status)
    {
        goto exit;
    }

    /* This extension was not sent, but an OCSP response was recieved.
     */
    if ( (NULL != pOcspExt) && (FALSE == pSSLSock->certStatusReqExt) )
    {
        status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_UNSOLICITED;
        goto exit;
    }

    status = CERTCHAIN_getCertificate(
        pSSLSock->pCertChain, index, &pCert, &certLen);
    if (OK > status)
    {
        goto exit;
    }


    /* Validate the OCSP response if one was provided.
     */
    if (NULL != pOcspExt)
    {
        status = SSL_OCSP_addCertificateAndIssuer(pSSLSock, index, pConfig);
        if (OK > status)
        {
            goto exit;
        }

        if (1 > ocspExtLen)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        if (certStatusType_ocsp != *pOcspExt)
        {
            status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
            goto exit;
        }

        pOcspMsg   = pOcspExt + 4;
        ocspMsgLen = getMediumValue(pOcspExt + 1);

        status = SSL_OCSP_validateOcspResponse(pSSLSock, pOcspMsg, ocspMsgLen);

        /* Check for OCSP callback. Allow the callback to override the OCSP
         * return value.
         */
        if (NULL != SSL_sslSettings()->funcPtrSingleCertStatusCallback)
        {
            status = SSL_sslSettings()->funcPtrSingleCertStatusCallback(
                SSL_findConnectionInstance(pSSLSock), pCert, certLen,
                pOcspMsg, ocspMsgLen, status);

            if (OK > status)
            {
                goto exit;
            }
        }
    }
    else
    {
        /* If no response was provided, send the error and 0 length response to application;
         * Let the application decide whether to continue with the connection
         */
        if (NULL != SSL_sslSettings()->funcPtrSingleCertStatusCallback)
        {
            status = SSL_sslSettings()->funcPtrSingleCertStatusCallback(
                SSL_findConnectionInstance(pSSLSock), pCert, certLen,
                NULL, 0, ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE);

            if (OK > status)
            {
                goto exit;
            }
        }
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

extern MSTATUS
SSLSOCK_processCertificateExtensions(SSLSocket *pSSLSock,
                                     ubyte4 index,
                                     ValidationConfig *pConfig)
{
    const ubyte *pCertificate = NULL;
    ubyte *pExtensions = NULL;
    ubyte4 certificateLen = 0, extensionsLen = 0;
    ubyte2  extensionType;
    ubyte2  extensionSize;
    ubyte4  extensionMask[2] = { 0, 0}; /* 64 bits available */
    MSTATUS status = OK;
#if !defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    MOC_UNUSED(pConfig);
#endif

    status = CERTCHAIN_getCertificate(
        pSSLSock->pCertChain, index, &pCertificate, &certificateLen);
    if (OK > status)
    {
        goto exit;
    }

    status = CERTCHAIN_getCertificateExtensions(
        pSSLSock->pCertChain, index, &pExtensions, &extensionsLen);
    if (OK > status)
    {
        goto exit;
    }

    while ((OK <= status) && (0 < extensionsLen))
    {
        if (4 > extensionsLen)
        {
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        extensionType = getShortValue(pExtensions);
        pExtensions += 2;    extensionsLen -= 2;

        extensionSize = getShortValue(pExtensions);
        pExtensions += 2;    extensionsLen -= 2;

        if (32 > extensionType)
        {
            /* prevent duplicate extensions */
            if (extensionMask[0] & (1 << extensionType))
            {
                status = ERR_SSL_EXTENSION_DUPLICATE;
                goto exit;
            }

            extensionMask[0] |= (1 << extensionType);
        }
        else if (64 > extensionType)
        {
            /* prevent duplicate extensions */
            if (extensionMask[1] & (1 << (extensionType-32)))
            {
                /* RFC-3546: There MUST NOT be more than one extension of the same type. */
                status = ERR_SSL_EXTENSION_DUPLICATE;
                goto exit;
            }

            extensionMask[1] |= (1 << (extensionType-32));
        }

        /* check the size */
        if (extensionsLen < (sbyte4) extensionSize)
        {
            /* buffer overrun attack? */
            status = ERR_SSL_EXTENSION_LENGTH;
            goto exit;
        }

        if(tlsExt_status_request != extensionType)
        {
            status = ERR_SSL_EXTENSION_UNRECOGNIZED_NAME;
        }

        /* move to the next extension */
        pExtensions   += extensionSize;
        extensionsLen -= extensionSize;
    } /* while loop */

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    /* If the OCSP response was requested,
     * Process the OCSP response.
     */
    if (pSSLSock->certStatusReqExt)
    {
        status = SSL_SOCK_processCertExtStatusResponse(pSSLSock, index, pConfig);
    }
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

exit:
    return status;
}
/*------------------------------------------------------------------*/
#endif

static MSTATUS
flushPendingBytes(SSLSocket *pSSLSock)
{
    MSTATUS status = OK;
    ubyte4 numBytesSent = 0;

    /* Check if this is synchronous flow, SSL_FLAG_ENABLE_SEND_BUFFER is set
     * for asynchronous connections */
    if (!(SSL_FLAG_ENABLE_SEND_BUFFER & pSSLSock->runtimeFlags))
    {
        /* Keep looping until all the data has been flushed */
        while (NULL != pSSLSock->pOutputBuffer)
        {
            /* don't spin loop, if writes fail, yield the processor briefly */
            RTOS_sleepMS(SSL_WRITE_FAIL_RETRY_TIME);

#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
            if (NULL != pSSLSock->pTransportHandler)
            {
                if (NULL != pSSLSock->pTransportHandler->funcPtrTransportSend)
                {
                    if (OK > (status = pSSLSock->pTransportHandler->funcPtrTransportSend(pSSLSock->pTransportHandler->sslId,
                                                                                         (sbyte *) pSSLSock->pOutputBuffer,
                                                                                         pSSLSock->numBytesToSend, &numBytesSent)))
                    {
                        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"Send Transport Handler failed, status = ", status);
                        goto exit;
                    }
    
                    if (numBytesSent > pSSLSock->numBytesToSend)
                        pSSLSock->numBytesToSend = numBytesSent = 0;        /**!!! should never happen */
    
                    pSSLSock->pOutputBuffer  = numBytesSent + pSSLSock->pOutputBuffer;
                    pSSLSock->numBytesToSend = pSSLSock->numBytesToSend - numBytesSent;
                }
                else
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
            }
            else
#endif
            {
#ifndef __DIGICERT_IPSTACK__
                if (OK <= (status = TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend, &numBytesSent)))
#else
                if (OK <= (status = DIGI_TCP_WRITE(pSSLSock->tcpSock, (sbyte *)pSSLSock->pOutputBuffer, pSSLSock->numBytesToSend, &numBytesSent)))
#endif
                {
                    if (numBytesSent > pSSLSock->numBytesToSend)
                        pSSLSock->numBytesToSend = numBytesSent = 0;        /**!!! should never happen */
    
                    pSSLSock->pOutputBuffer  = numBytesSent + pSSLSock->pOutputBuffer;
                    pSSLSock->numBytesToSend = pSSLSock->numBytesToSend - numBytesSent;
                }
                else
                {
                    goto exit;
                }
            }


            if (0 == pSSLSock->numBytesToSend)
            {
                if (NULL != pSSLSock->pOutputBufferBase)
                    FREE(pSSLSock->pOutputBufferBase);
        
                pSSLSock->pOutputBufferBase = NULL;
                /* Exit condition */
                pSSLSock->pOutputBuffer     = NULL;
        
            }
        }
    }
 
exit:

    return status;
}

extern MSTATUS
SSLSOCK_sendEncryptedHandshakeBuffer(SSLSocket* pSSLSock)
{
    MSTATUS status = OK;

    if ((NULL != pSSLSock) && (NULL != pSSLSock->buffers[0].pHeader))
    {
        while (pSSLSock->bufIndex < pSSLSock->numBuffers)
        {
            sbyte4  numBytesSent = 0;
            sbyte4  dataSize;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if (pSSLSock->isDTLS)
            {
#ifdef __ENABLE_DIGICERT_TLS13__
                if (DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
                {
                    dataSize = pSSLSock->buffers[pSSLSock->bufIndex].length - DTLS13_MOC_RECORD_HEADER_LEN;
                }
                else
#endif
                {

                    dataSize = pSSLSock->buffers[pSSLSock->bufIndex].length - sizeof(DTLSRecordHeader);
                }
            }
            else
#endif
            {
                dataSize = pSSLSock->buffers[pSSLSock->bufIndex].length - sizeof(SSLRecordHeader);
            }

            while ((0 <= status) && (numBytesSent < dataSize))
            {
                if (OK > (status = sendData(pSSLSock, SSL_HANDSHAKE,
                    (sbyte *)pSSLSock->buffers[pSSLSock->bufIndex].data + numBytesSent,
                    (dataSize - numBytesSent), TRUE)))
                {
                    goto exit;
                }
                numBytesSent += status;
            }
            pSSLSock->bufIndex++;

            /* flush any pending bytes in synchronous mode */
            status = flushPendingBytes(pSSLSock);
            if (OK > status)
                goto exit;
        }

        CRYPTO_FREE(pSSLSock->hwAccelCookie, TRUE, (void **)&(pSSLSock->buffers[0].pHeader));
        pSSLSock->bufIndex = 0;
        pSSLSock->numBuffers = 0;

        status = OK;
    }

exit:
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSLSOCK_sendEncryptedHandshakeBuffer() returns status = ", status);
#endif

    return status;

} /* SSLSOCK_sendEncryptedHandshakeBuffer */

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_SSL_KEYLOG_FILE__

static void appendToKeyLogFile(
    SSLSocket *pSSLSock, ubyte *pOut, ubyte4 outLen, intBoolean byteBuffer,
    intBoolean newLine)
{
    const char *pOutFile;
    ubyte *pFileData = NULL, *pNew = NULL;
    ubyte4 fileDataLen = 0, newLen = 0;
#if defined(__ENABLE_DIGICERT_SSL_KEYLOG_ENV_VAR__)
    sbyte *pEnvVar = NULL;

    FMGMT_getEnvironmentVariableValueAlloc("ENABLE_SSL_KEYLOG", &pEnvVar);
    if ((NULL == pEnvVar) || (0 != DIGI_STRCMP(pEnvVar, "1")))
    {
        DIGI_FREE((void **) &pEnvVar);
        return;
    }
    DIGI_FREE((void **) &pEnvVar);
#endif

    if (pSSLSock->server)
    {
        pOutFile = SERVER_KEYFILENAME;
    }
    else
    {
        pOutFile = CLIENT_KEYFILENAME;
    }

    DIGICERT_readFile(pOutFile, &pFileData, &fileDataLen);

    newLen = fileDataLen + outLen + ((TRUE == newLine) ? 1 : 0);
    if (TRUE == byteBuffer)
    {
        newLen += outLen;
    }
    DIGI_MALLOC((void **) &pNew, newLen);

    DIGI_MEMCPY(pNew, pFileData, fileDataLen);
    if (TRUE == byteBuffer)
    {
        ubyte4 i;

        for (i = 0; i < outLen; i++)
        {
            pNew[fileDataLen + (2 * i)] = returnHexDigit((ubyte4) (pOut[i] >> 4));
            pNew[fileDataLen + (2 * i) + 1] = returnHexDigit((ubyte4) (pOut[i]));
        }
    }
    else
    {
        DIGI_MEMCPY(pNew + fileDataLen, pOut, outLen);
    }
    if (TRUE == newLine)
    {
        pNew[newLen - 1] = '\n';
    }

    DIGICERT_freeReadFile(&pFileData);
    DIGICERT_writeFile(pOutFile, pNew, newLen);
    DIGI_FREE((void **) &pNew);
}

#endif /* __ENABLE_DIGICERT_SSL_KEYLOG_FILE__ */

#ifdef __ENABLE_DIGICERT_TLS13__

/* This function will compute the transcript hash from a SSLSocket. The
 * caller must provide a SSLSocket which has a hash context and hash suite.
 * The output buffer will be allocated by this function and the caller will be
 * given control of the buffer (they must free it when they are done using it).
 *
 * @param pSSLSock      SSL Socket
 * @param ppRetDigest   Buffer that will be allocated by this function. This is
 *                      where the digest will be stored. The length of the
 *                      digest is pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize.
 *                      Caller must free the buffer.
 *
 * This function will not modify the SSL socket structure.
 */
static MSTATUS
SSLSOCK_calcTranscriptHash(SSLSocket *pSSLSock, ubyte **ppRetDigest)
{
    MSTATUS status;
    BulkCtx pDigestCopy = NULL;
    const BulkHashAlgo *pDigest;
    ubyte *pOutput = NULL;

    /* Ensure the SSLSocket contains a digest context and digest suite.
     */
    status = ERR_NULL_POINTER;
    if ( (NULL == pSSLSock->pHashCtx) || (NULL == ppRetDigest) ||
         (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (NULL == pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo) )
        goto exit;

    pDigest = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo;

    /* Allocate memory for the digest context. We will need to make a copy of
     * the digest context in the SSLSocket since we don't want to call final on
     * the context in the SSLSocket.
     */
    status = MEM_POOL_getPoolObject(
        &(pSSLSock->hashPool), (void **) &pDigestCopy);
    if (OK != status)
        goto exit;

    /* Copy the context over to the copy.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_cloneHashCtx( MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pHashCtx, pDigestCopy, pSSLSock->hashPool.poolObjectSize);
#else
    status = DIGI_MEMCPY(
        pDigestCopy, pSSLSock->pHashCtx, pSSLSock->hashPool.poolObjectSize);
#endif
    if (OK != status)
        goto exit;

    /* Allocate memory for the output buffer.
     */
    status = DIGI_MALLOC((void **) &pOutput, pDigest->digestSize);
    if (OK != status)
        goto exit1;

    /* Call final to get the transcript hash.
     */
    status = pDigest->finalFunc(MOC_HASH(pSSLSock->hwAccelCookie) pDigestCopy, pOutput);
    if (OK != status)
        goto exit1;

    *ppRetDigest = pOutput;
    pOutput = NULL;

exit1:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_freeCloneHashCtx(pDigestCopy);
#endif

exit:

    if (NULL != pOutput)
        DIGI_FREE((void **) &pOutput);

    if (NULL != pDigestCopy)
        MEM_POOL_putPoolObject(&(pSSLSock->hashPool), (void **) &pDigestCopy);

    return status;
}

/*------------------------------------------------------------------*/

/* Derive the keys as per Section 7.1 of RFC 8446.
 *
 * This function will derive key material using the HMAC-KDF expand routine.
 * The caller must provide the digest suite which is used by the HMAC-KDF. The
 * digest suite for TLS 1.3 will be the digest suite used to compute the
 * transcript hash (The transcript hash is the digest of all the messages that
 * the server and client have sent to each other so far).
 *
 * The caller must provide a non-null digest suite. The digest suite will be
 * accessed directly (no NULL check). The caller must ensure that the digest
 * suite provided is valid.
 *
 * This function expects a secret which will be the key calculated using
 * HMAC-KDF extract for TLS 1.3. This function will assume the secret length
 * will be the same as the digest size in bytes.
 *
 * The caller must specify the label as well. The input labels are defined in
 * RFC 8446 in section 7.1. Each corresponding key will use a corresponding
 * label. TLS 1.3 defines the context into the HMAC-KDF expand as
 *
 *   struct {
 *       uint16 length = Length;
 *       opaque label<7..255> = "tls13 " + Label;
 *       opaque context<0..255> = Context;
 *   } HkdfLabel;
 *
 * IMPORTANT: The angle brackets <> implicitly means the length of the value
 * must be prepended to the actual data, where the amount of bytes used for the
 * length is the minimum number of bytes required to support the maximum value.
 *
 * where the Length (with a capital L) is the length of the transcript hash,
 * which is assumed to be the length stored in the digest suite. The label is
 * provided as an argument into this function and the Context is the transcript
 * hash.
 *
 * The transcript hash can optionally be provided. If the caller does not
 * provide the transcript hash then a digest of nothing will be used.
 *
 * The output buffer will either be allocated by this function and control of
 * the buffer will be returned to the caller, OR if the buffer is already
 * allocated then this function will use the buffer as is. If the buffer is
 * already allocated, then it will assume that the length of the buffer is the
 * same as the digest size (digest size is based off the digest suite passed
 * into this function). This function will assume that if the output buffer is
 * not NULL then it is a valid buffer.
 */

static MSTATUS
SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest, ubyte *pSecret, ubyte *pLabel, ubyte labelLen,
    ubyte *pTranscriptHash, ubyte **ppRetSecret)
{
    MSTATUS status;
    ubyte *pContext = NULL, *pDerivedSecret = NULL;
    ubyte contextLen;
    ubyte4 transcriptHashLength = 0;

    /* If the transcipt hash was not provided then use a transcript hash of
     * nothing.
     */
    if (NULL == pTranscriptHash)
    {
        transcriptHashLength = 0;
    }
    else
    {
        transcriptHashLength = pDigest->digestSize;
    }

    /* Allocate memory for the HMAC-KDF context. Two bytes for the digest
     * length, a single byte for the label length, the label itself, a single
     * byte for the digest length, and finally the digest itself.
     */
    contextLen = 2 + 1 + labelLen + 1 + transcriptHashLength;
    status = DIGI_MALLOC((void **) &pContext, contextLen);
    if (OK != status)
        goto exit;

    /* Set the digest length in the context.
     */
    setShortValue(pContext, (ubyte2) pDigest->digestSize);

    *(pContext + 2) = labelLen;

    /* Copy the label.
     */
    status = DIGI_MEMCPY(pContext + 3, pLabel, labelLen);
    if (OK != status)
        goto exit;

    /* Copy the transcript hash.
     */
    *(pContext + 3 + labelLen) = (ubyte) transcriptHashLength;

    if (transcriptHashLength > 0)
    {
        status = DIGI_MEMCPY(
            pContext + 4 + labelLen, pTranscriptHash, transcriptHashLength);
        if (OK != status)
            goto exit;
    }

    /* Allocate memory for the buffer.
     */
    status = DIGI_MALLOC((void **) &pDerivedSecret, pDigest->digestSize);
    if (OK != status)
        goto exit;

    /* Calculate the key material using the secret provided by the caller and
     * the context that was created. Section 7.1 of RFC 8446 specifies that the
     * output length of the key should be of digest size.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExpand(MOC_HASH(hwAccelCtx)
        pDigest, pSecret, pDigest->digestSize, pContext, contextLen, 
        NULL, 0, pDerivedSecret, pDigest->digestSize);
#else
    status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
        pDigest, pSecret, pDigest->digestSize, pContext, contextLen,
        NULL, 0, pDerivedSecret, pDigest->digestSize);
#endif
    if (OK != status)
        goto exit;

    *ppRetSecret = pDerivedSecret;
    pDerivedSecret = NULL;

exit:

    if (NULL != pContext)
        DIGI_FREE((void **) &pContext);

    if (NULL != pDerivedSecret)
        DIGI_FREE((void **) &pDerivedSecret);

    return status;
} /* SSLSOCK_HmacKdfDeriveSecret */

/*
 * This function provides a calculation of empty hash if the transcript hash is NULL;
 * All the Secret derivation except for Finished Key should have a non-empty transcipt hash.
 * If the caller passes a NULL transcript hash, this function generates
 * a hash with empty data.
 */
static MSTATUS
SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest, ubyte *pSecret, ubyte *pLabel, ubyte labelLen,
    ubyte *pTranscriptHash, ubyte **ppRetSecret)
{
    MSTATUS status;
    ubyte *pEmptyDigest = NULL;
    BulkCtx pDigestCtx = NULL;

    /* If the transcipt hash was not provided then use a transcript hash of
     * nothing.
     */
    if (NULL == pTranscriptHash)
    {
        status = DIGI_MALLOC((void **) &pEmptyDigest, pDigest->digestSize);
        if (OK != status)
            goto exit;

        status = pDigest->allocFunc(MOC_HASH(hwAccelCtx) &pDigestCtx);
        if (OK != status)
            goto exit;

        status = pDigest->initFunc(MOC_HASH(hwAccelCtx) pDigestCtx);
        if (OK != status)
            goto exit;

        status = pDigest->finalFunc(MOC_HASH(hwAccelCtx) pDigestCtx, pEmptyDigest);
        if (OK != status)
            goto exit;

        pTranscriptHash = pEmptyDigest;
    }

    if (OK > (status = SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(hwAccelCtx) pDigest, pSecret, pLabel, labelLen,
                                                   pTranscriptHash, ppRetSecret)))
    {
        goto exit;
    }

    if (NULL != pDigestCtx)
    {
        pDigest->freeFunc(MOC_HASH(hwAccelCtx) &pDigestCtx);
    }

exit:
    if (NULL != pEmptyDigest)
    {
        DIGI_FREE((void **)&pEmptyDigest);
    }
    return status;
}

/*------------------------------------------------------------------*/

/* Calculate the early secret.
 *
 * This step is defined in section 7.1 of RFC 8446. This occurs during the
 * first part (Early Secret) of the TLS 1.3 handshake.
 *
 *            0
 *            |
 *            v
 *  PSK ->  HKDF-Extract = Early Secret
 *
 * Where 0 denotes a buffer of digest length of all zeroes and PSK denotes the
 * pre-shared key. This function is used as a helper to derive the early secret.
 *
 * The caller must provide a PSK and digest suite. The PSK is optional as per
 * section 7.1 of RFC 8446 ("If a given secret is not available, then the
 * 0-value consisting of a string of Hash.length bytes set to zeros is used.
 * Note that this does not mean skipping rounds, so if PSK is not in use, Early
 * Secret will still be HKDF-Extract(0, 0)"). This function will also allocate
 * the output buffer and pass control back to caller.
 *
 * This function can be called directly to retrieve the early secret, but the
 * caller typically needs the binder key as well. If the binder key is required
 * call SSLSOCK_pskCalcBinderKey instead. Only call this if the early secret
 * is the only value that is required.
 *
 * @param pPsk              The PSK to use when calculating the early secret.
 * @param pskLength         The length of the PSK in bytes.
 * @param pDigest           The digest suite. This will typically be the digest
 *                          suite stored in pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo.
 * @param ppRetEarlySecret  Return buffer containing the early secret. This
 *                          buffer will be however big the digest suite output
 *                          will be. The caller must free this buffer.
 */
static MSTATUS
SSLSOCK_pskCalcEarlySecret(MOC_HASH(hwAccelDescr hwAccelCtx)
    ubyte *pPsk, ubyte2 pskLength, const BulkHashAlgo *pDigest,
    ubyte **ppRetEarlySecret)
{
    MSTATUS status;
    ubyte *pSalt = NULL, *pEarlySecret = NULL;

    /* Allocate a buffer for the early secret.
     */
    status = DIGI_MALLOC((void **) &pEarlySecret, pDigest->digestSize);
    if (OK != status)
        goto exit;

    /* Allocate a buffer of all zeroes. Section 7.1 of RFC 8446 specifies that
     * the computation for the early secret uses a buffer of all zeroes of
     * digest length for the salt value during the HMAC-KDF extract routine.
     */
    status = DIGI_CALLOC((void **) &pSalt, 1, pDigest->digestSize);
    if (OK != status)
        goto exit;

    /* If a PSK was not provided then default to a PSK of all zeroes of digest
     * length. Section 7.1 specifies that the PSK can be all zeroes if no PSK
     * is provided.
     */
    if (NULL == pPsk)
    {
        pPsk = pSalt;
        pskLength = pDigest->digestSize;
    }

    /* Calculate the early secret.
     *
     * The zeroes are provided as the salt value and the PSK is provided as the
     * input key material.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExtract(MOC_HASH(hwAccelCtx)
        pDigest, pSalt, pDigest->digestSize, pPsk, pskLength,
        pEarlySecret, pDigest->digestSize);
#else
    status = HmacKdfExtract(MOC_HASH(hwAccelCtx)
        pDigest, pSalt, pDigest->digestSize, pPsk, pskLength,
        pEarlySecret, pDigest->digestSize);
#endif
    if (OK != status)
        goto exit;

    *ppRetEarlySecret = pEarlySecret;
    pEarlySecret = NULL;

exit:

    if (NULL != pEarlySecret)
    {
        DIGI_MEMSET(pEarlySecret, 0x00, pDigest->digestSize);
        DIGI_FREE((void **) &pEarlySecret);
    }

    if (NULL != pSalt)
    {
        DIGI_FREE((void**) &pSalt);
    }

    return status;
} /* SSLSOCK_pskCalcEarlySecret */

/*------------------------------------------------------------------*/

/* This function will derive the early secret and it will derive all the key
 * values from the early secret except for the binder key. Use
 * SSLSOCK_pskCalcBinderKey to calculate the binder key from a PSK value. The
 * following is taken from RFC 8446 section 7.1.
 *
 *            0
 *            |
 *            v
 *  PSK ->  HKDF-Extract = Early Secret
 *            |
 *  ------------ SKIPPED ------------------------------------------------------
 *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
 *            |                     = binder_key
 *  ---------------------------------------------------------------------------
 *            |
 *            +-----> Derive-Secret(., "c e traffic", ClientHello)
 *            |                     = client_early_traffic_secret
 *            |
 *            +-----> Derive-Secret(., "e exp master", ClientHello)
 *            |                     = early_exporter_master_secret
 *            v
 *      Derive-Secret(., "derived", "")
 *
 * This function will calculate the Early Secret, the
 * client_early_traffic_secret, and the early_exporter_master_secret. The
 * binder_key value will not be computed by this function.
 *
 * The caller must provide the SSLSocket, the PSK, and the hash suite. The hash
 * suite must match the one from the SSLSocket. The client early traffic secret
 * and the early exporter master secret will be stored in the SSLSocket. The
 * last step in the diagram above will derive a secret that will stored in the
 * SSLSocket. This secret will be required during the handshake secret portion
 * of the TLS 1.3 handshake.
 *
 * @param pSSLSock      SSL Socket.
 * @param pPsk          The PSK value used to derive the early secret.
 * @param pskLength     The length of the PSK value in bytes.
 * @param pDigest       The digest suite which must match
 *                      pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo.
 *
 * This function will modify the SSL socket.
 *   - The client_early_traffic_secret will be calculated and stored in
 *     pSSLSock->pClientEarlyTrafficSecret
 *   - The secret for the next stage of the handshake will be calculated and
 *     stored in pSSLSock->pPskSecret
 *   - The early_exporter_master_secret will be calculated and stored in
 *     pSSLSock->pEarlyExporterMasterSecret
 */
static MSTATUS
SSLSOCK_pskEarlySecretDerive(
    SSLSocket *pSSLSock, ubyte *pPsk, ubyte2 pskLength,
    const BulkHashAlgo *pDigest)
{
    MSTATUS status;
    ubyte *pEarlySecret = NULL;
    ubyte *pTranscriptHash = NULL;

    /* The BulkHashAlgo for the PSK must be provided. It must match the digest
     * used for the transcript hash.
     */
    status = ERR_NULL_POINTER;
    if ( (NULL == pDigest) || (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo != pDigest) )
        goto exit;

    /* Calculate the transcript hash. This should be the transcript hash of the
     * ClientHello.
     */
    status = SSLSOCK_calcTranscriptHash(pSSLSock, &pTranscriptHash);
    if (OK != status)
        goto exit;

    /* Calculate the early secret.
     */
    status = SSLSOCK_pskCalcEarlySecret(MOC_HASH(pSSLSock->hwAccelCookie)
        pPsk, pskLength, pDigest, &pEarlySecret);
    if (OK != status)
        goto exit;

    if (pSSLSock->pClientEarlyTrafficSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pClientEarlyTrafficSecret);
    }

    /* Calculate the ClientEarlyTrafficSecret.
     */
    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pEarlySecret, (ubyte *) TLS13_CETS_LABEL(pSSLSock),
        TLS13_CETS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pClientEarlyTrafficSecret));
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_TLS13_0RTT__
    if (pSSLSock->pEarlyExporterMasterSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pEarlyExporterMasterSecret);
    }

    /* Calculate the early exporter master secret.
     */
    status = SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pEarlySecret, (ubyte *) TLS13_EEMS_LABEL(pSSLSock),
        TLS13_EEMS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pEarlyExporterMasterSecret));
    if (OK != status)
        goto exit;
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ */

    if (pSSLSock->pPskSecret)
    {
        DIGI_FREE((void **)&pSSLSock->pPskSecret);
    }

    /* Derive the next secret to use during the next stage of the handshake.
     */
    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pEarlySecret, (ubyte *) TLS13_DERIVED_LABEL(pSSLSock),
        TLS13_DERIVED_LABEL_LEN, NULL, &(pSSLSock->pPskSecret));
    if (OK != status)
        goto exit;

exit:

    if (NULL != pTranscriptHash)
    {
        DIGI_FREE((void **)&pTranscriptHash);
    }

    if (NULL != pEarlySecret)
    {
        DIGI_MEMSET(pEarlySecret, 0x00, pDigest->digestSize);
        DIGI_FREE((void **) &pEarlySecret);
    }

    return status;
} /* SSLSOCK_pskEarlySecretDerive */

/*------------------------------------------------------------------*/

/* This function will derive the handshake secret and it will derive all the key
 * values from the handshake secret. The following is taken from RFC 8446
 * section 7.1.
 *
 *       Derive-Secret(., "derived", "")
 *            |
 *            v
 *  (EC)DHE -> HKDF-Extract = Handshake Secret
 *            |
 *            +-----> Derive-Secret(., "c hs traffic",
 *            |                     ClientHello...ServerHello)
 *            |                     = client_handshake_traffic_secret
 *            |
 *            +-----> Derive-Secret(., "s hs traffic",
 *            |                     ClientHello...ServerHello)
 *            |                     = server_handshake_traffic_secret
 *            v
 *      Derive-Secret(., "derived", "")
 *
 * The caller must provide the SSLSocket at the correct state. This function
 * will expect that the SSLSocket already contains the derived secret from the
 * early secret in the SSLSocket. The caller must also provide the hash suite
 * from the PSK and the shared secret computed.
 *
 * @param pSSLSock          SSL Socket.
 * @param pDigest           Digest Suite. Must match the digest suite stored in
 *                          pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo
 * @param pSharedSecret     The shared secret produced from (EC)DHE.
 * @param sharedSecretLen   The length of the shared secret.
 *
 * This function will modify the SSL socket.
 *   - The client_handshake_traffic_secret will be calculated and stored in
 *     pSSLSock->pClientHandshakeTrafficSecret
 *   - The server_handshake_traffic_secret will be calculated and stored in
 *     pSSLSock->pServerHandshakeTrafficSecret
 *   - The secret for the next stage of the handshake will be calculated and
 *     stored in pSSLSock->pPskSecret
 */
static MSTATUS
SSLSOCK_pskHandshakeSecretDerive(
    SSLSocket *pSSLSock, const BulkHashAlgo *pDigest, ubyte *pSharedSecret,
    ubyte4 sharedSecretLen)
{
    MSTATUS status;
    ubyte *pTranscriptHash = NULL;
    ubyte *pPskSecret = NULL;
    ubyte pZeroes[SHA512_RESULT_SIZE] = { 0 };

    /* The BulkHashAlgo for the PSK must be provided. It must match the digest
     * used for the transcript hash.
     */
    status = ERR_NULL_POINTER;
    if ( (NULL == pDigest) || (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo != pDigest) )
        goto exit;

    /* If the shared secret is not provided then set the shared secret to all
     * zeroes of digest length. This is used as the IKM into the HKDF extract.
     * RFC 8446 specifies that it must be the (EC)DHE shared secret but when
     * resuming a connection with a PSK in psk_ke mode, there is no shared
     * secret to generate. The RFC does not seem to mention what the value
     * should be instead of the (EC)DHE shared secret. It is used as all zeroes
     * of digest length to be compatible with OpenSSL.
     */
    if (NULL == pSharedSecret)
    {
        if (sizeof(pZeroes) < pDigest->digestSize)
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        pSharedSecret = pZeroes;
        sharedSecretLen = pDigest->digestSize;
    }

    /* Calculate the transcript hash. This should be the digest of the Client
     * Hello - Server Hello.
     */
    status = SSLSOCK_calcTranscriptHash(pSSLSock, &pTranscriptHash);
    if (OK != status)
        goto exit;

    /* Extract the handshake secret.
     *
     * The salt and output buffer as the same buffer should be fine.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExtract(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, pDigest->digestSize,
        pSharedSecret, sharedSecretLen, pSSLSock->pPskSecret,
        pDigest->digestSize);
#else
    status = HmacKdfExtract(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, pDigest->digestSize,
        pSharedSecret, sharedSecretLen, pSSLSock->pPskSecret,
        pDigest->digestSize);
#endif
    if (OK != status)
        goto exit;

    /* Generate the client handshake traffic secret.
     */
    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_CHTS_LABEL(pSSLSock),
        TLS13_CHTS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pClientHandshakeTrafficSecret));
    if (OK != status)
        goto exit;

    /* Generate the server handshake traffic secret.
     */
    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_SHTS_LABEL(pSSLSock),
        TLS13_SHTS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pServerHandshakeTrafficSecret));
    if (OK != status)
        goto exit;

    /* Derive the next secret to prepare for the final part of the handshake.
     */
    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_DERIVED_LABEL(pSSLSock),
        TLS13_DERIVED_LABEL_LEN, NULL, &pPskSecret);
    if (OK != status)
        goto exit;

    if (NULL != pSSLSock->pPskSecret)
    {
        DIGI_FREE((void**)&pSSLSock->pPskSecret);
    }
    pSSLSock->pPskSecret = pPskSecret;
    pPskSecret = NULL;

#ifdef __ENABLE_DIGICERT_SSL_KEYLOG_FILE__
    appendToKeyLogFile(pSSLSock, "# TLS 1.3 log file", DIGI_STRLEN("# TLS 1.3 log file"), FALSE, TRUE);
    appendToKeyLogFile(pSSLSock, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ", DIGI_STRLEN("CLIENT_HANDSHAKE_TRAFFIC_SECRET "), FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pClientRandHello, SSL_RANDOMSIZE, TRUE, FALSE);
    appendToKeyLogFile(pSSLSock, " ", 1, FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pClientHandshakeTrafficSecret, pDigest->digestSize, TRUE, TRUE);
    appendToKeyLogFile(pSSLSock, "SERVER_HANDSHAKE_TRAFFIC_SECRET ", DIGI_STRLEN("SERVER_HANDSHAKE_TRAFFIC_SECRET "), FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pClientRandHello, SSL_RANDOMSIZE, TRUE, FALSE);
    appendToKeyLogFile(pSSLSock, " ", 1, FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pServerHandshakeTrafficSecret, pDigest->digestSize, TRUE, TRUE);
#endif

exit:

    if (NULL != pPskSecret)
        DIGI_FREE((void **) &pPskSecret);

    if (NULL != pTranscriptHash)
        DIGI_FREE((void **) &pTranscriptHash);

    return status;
}

/*------------------------------------------------------------------*/

/* This function will derive the master secret and it will derive the
 * application traffic secret and the exporter master secret. This function
 * should be called when the transcript contains the client hello up to the
 * server finished message. If the client finished message has already been
 * processed then call SSLSOCK_pskCalcResumptionMasterSecret to calculate the resumption
 * master secret. The following is taken from RFC 8446 section 7.1.
 *
 *  0 -> HKDF-Extract = Master Secret
 *            |
 *            +-----> Derive-Secret(., "c ap traffic",
 *            |                     ClientHello...server Finished)
 *            |                     = client_application_traffic_secret_0
 *            |
 *            +-----> Derive-Secret(., "s ap traffic",
 *            |                     ClientHello...server Finished)
 *            |                     = server_application_traffic_secret_0
 *            |
 *            +-----> Derive-Secret(., "exp master",
 *            |                     ClientHello...server Finished)
 *            |                     = exporter_master_secret
 *
 * The caller must provide the SSLSocket at the correct state (client hello up
 * to server finished has been processed). The caller must also provide the
 * digest suite.
 *
 * @param pSSLSock      SSL Socket.
 * @param pDigest       Digest Suite. Must match the digest suite stored in
 *                      pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo
 *
 * This function will modify the SSL socket.
 *   - The master secret will be calculated and stored in pSSLSock->pPskSecret
 *   - The client_application_traffic_secret_0 will be calculated and stored in
 *     pSSLSock->pClientApplicationTrafficSecret
 *   - The server_application_traffic_secret_0 will be calculated and stored in
 *     pSSLSock->pServerApplicationTrafficSecret
 *   - The exporter_master_secret will be calculated and stored in
 *     pSSLSock->pExporterMasterSecret
 */
static MSTATUS
SSLSOCK_pskCalcApplicationTrafficSecret(SSLSocket *pSSLSock)
{
    MSTATUS status;
    ubyte *pTranscriptHash = NULL, *pZeroes = NULL;
    const BulkHashAlgo *pDigest = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo == NULL) )
        goto exit;

    pDigest = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo;

    status = SSLSOCK_calcTranscriptHash(pSSLSock, &pTranscriptHash);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **) &pZeroes, 1, pDigest->digestSize);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExtract(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, pDigest->digestSize, pZeroes,
        pDigest->digestSize, pSSLSock->pPskSecret, pDigest->digestSize);
#else
    status = HmacKdfExtract(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, pDigest->digestSize, pZeroes,
        pDigest->digestSize, pSSLSock->pPskSecret, pDigest->digestSize);
#endif
    if (OK != status)
        goto exit;

    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_CATS_LABEL(pSSLSock),
        TLS13_CATS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pClientApplicationTrafficSecret));
    if (OK != status)
        goto exit;

    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_SATS_LABEL(pSSLSock),
        TLS13_SATS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pServerApplicationTrafficSecret));
    if (OK != status)
        goto exit;

    /* Calculate the exporter master secret.
     */
    status = SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_EMS_LABEL(pSSLSock),
        TLS13_EMS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pExporterMasterSecret));
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_SSL_KEYLOG_FILE__
    appendToKeyLogFile(pSSLSock, "CLIENT_TRAFFIC_SECRET_0 ", DIGI_STRLEN("CLIENT_TRAFFIC_SECRET_0 "), FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pClientRandHello, SSL_RANDOMSIZE, TRUE, FALSE);
    appendToKeyLogFile(pSSLSock, " ", 1, FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pClientApplicationTrafficSecret, pDigest->digestSize, TRUE, TRUE);
    appendToKeyLogFile(pSSLSock, "SERVER_TRAFFIC_SECRET_0 ", DIGI_STRLEN("SERVER_TRAFFIC_SECRET_0 "), FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pClientRandHello, SSL_RANDOMSIZE, TRUE, FALSE);
    appendToKeyLogFile(pSSLSock, " ", 1, FALSE, FALSE);
    appendToKeyLogFile(pSSLSock, pSSLSock->pServerApplicationTrafficSecret, pDigest->digestSize, TRUE, TRUE);
#endif

exit:

    if (NULL != pZeroes)
        DIGI_FREE((void **) &pZeroes);

    if (NULL != pTranscriptHash)
        DIGI_FREE((void **) &pTranscriptHash);

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TLS13_PSK__

/* Calculate the binder key value as per section 7.1 of RFC 8446
 *
 *            0
 *            |
 *            v
 *  PSK ->  HKDF-Extract = Early Secret
 *            |
 *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
 *            |                     = binder_key
 *
 * This function will compute the binder key value from a PSK and return it to
 * the caller in the caller provided buffer. The buffer must be of digest
 * length.
 *
 * This function expects a PSK value to be provided. The type of PSK must also
 * be provided (external or internal). Pass in 1 to denote a external PSK,
 * otherwise pass in a 0 for the pskType. The hash suite of the PSK must be
 * provided. A buffer must also be provided for the binder key value that is
 * allocated by the caller.
 *
 * @param pPsk              The PSK value used to compute the early secret.
 * @param pskLength         The length of the PSK value in bytes.
 * @param pskType           The type of PSK. Pass 1 for external and 0 for
 *                          internal.
 * @param pDigest           The digest suite.
 * @param ppRetBinderKey    The output buffer for the binder key. Must be freed
 *                          by the caller.
 * @param pRetBinderKeyLen  The amount of bytes put into the output buffer.
 */
static MSTATUS
SSLSOCK_pskCalcBinderKey(MOC_HASH(hwAccelDescr hwAccelCtx) SSLSocket* pSSLSock,
    ubyte *pPsk, ubyte2 pskLength, ubyte pskType, const BulkHashAlgo *pDigest,
    ubyte **ppRetBinderKey, ubyte4 *pRetBinderKeyLen)
{
    MSTATUS status;
    ubyte *pEarlySecret = NULL;

    /* Caller must provide the hash algorithm suite and the output buffer.
     */
    status = ERR_NULL_POINTER;
    if ( (NULL == pDigest) || (NULL == ppRetBinderKey) ||
         (NULL == pRetBinderKeyLen) )
        goto exit;

    /* Set the output length to 0.
     */
    *pRetBinderKeyLen = 0;

    /* Calculate the early secret. This secret will be cleared and freed at the
     * end of this function.
     */
    status = SSLSOCK_pskCalcEarlySecret(MOC_HASH(hwAccelCtx)
        pPsk, pskLength, pDigest, &pEarlySecret);
    if (OK != status)
        goto exit;

    /* Check if the PSK is internal or external and call the relevant function
     * to compute the binder key.
     *
     * Section 7.1 of RFC 8446 specifies that external PSK values will use a
     * different label then internal PSK values.
     */
    if (pskType)
    {
        status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(hwAccelCtx)
            pDigest, pEarlySecret, (ubyte *) TLS13_EXT_BINDER(pSSLSock),
            TLS13_EXT_BINDER_LEN, NULL, ppRetBinderKey);
    }
    else
    {
        status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(hwAccelCtx)
            pDigest, pEarlySecret, (ubyte *) TLS13_RES_BINDER(pSSLSock),
            TLS13_RES_BINDER_LEN, NULL, ppRetBinderKey);
    }
    if (OK != status)
        goto exit;

    /* Set the return length of the buffer.
     */
    *pRetBinderKeyLen = pDigest->digestSize;

exit:

    if (NULL != pEarlySecret)
    {
        DIGI_MEMSET(pEarlySecret, 0x00, pDigest->digestSize);
        DIGI_FREE((void **) &pEarlySecret);
    }

    return status;
} /* SSLSOCK_pskCalcBinderKey */

/*------------------------------------------------------------------*/

/* This function will compute the resumption master secret. This function should
 * be called when the client hello up to the client finished message are
 * processed. If the server finished message is processed then call
 * SSLSOCK_pskCalcApplicationTrafficSecret instead. The following is taken from
 * RFC 8446 section 7.1.
 *
 *            |
 *            +-----> Derive-Secret(., "res master",
 *                                  ClientHello...client Finished)
 *                                  = resumption_master_secret
 *
 * The caller must provide the SSLSocket at the correct state (client hello up
 * to server finished has been processed). The caller must also provide the
 * digest suite.
 *
 * NOTE: SSLSOCK_pskCalcApplicationTrafficSecret must be called beforehand to
 * prepare the master secret.
 *
 * @param pSSLSock      SSL Socket.
 * @param pDigest       Digest Suite. Must match the digest suite stored in
 *                      pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo
 *
 * This function will modify the SSL socket.
 *   - The resumption_master_secret will be calculated and stored in
 *     pSSLSock->pResumptionMasterSecret
 *   - The master secret, stored in pSSLSock->pPskSecret, will be zeroed out and
 *     freed
 */
static MSTATUS
SSLSOCK_pskCalcResumptionMasterSecret(
    SSLSocket *pSSLSock, const BulkHashAlgo *pDigest)
{
    MSTATUS status;
    ubyte *pTranscriptHash = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pDigest) || (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo != pDigest) )
        goto exit;

    status = SSLSOCK_calcTranscriptHash(pSSLSock, &pTranscriptHash);
    if (OK != status)
        goto exit;

    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigest, pSSLSock->pPskSecret, (ubyte *) TLS13_RMS_LABEL(pSSLSock),
        TLS13_RMS_LABEL_LEN, pTranscriptHash,
        &(pSSLSock->pResumptionMasterSecret));
    if (OK != status)
        goto exit;

exit:

    if (NULL != pTranscriptHash)
        DIGI_FREE((void **) &pTranscriptHash);

    return status;
}

/*------------------------------------------------------------------*/

/* This function will calculate the PSK binder entry value as specified in RFC
 * 8446 Section 4.2.11.2.
 *
 * The function expects the digest of ClientHello message up to the
 * PreSharedKeyExtension.identities. The PSK value must be provided along with
 * the digest algorithm for the PSK and the PSK type (internal or external).
 *
 * The PSK binder key value is derived using the PSK value. Look at
 * SSLSOCK_pskCalcBinderKey to see how the binder key is calculated.
 *
 * Once the binder key is derived a HMAC key is derived using the HMAC KDF
 * expand routine.
 *
 *   hmac_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
 *
 * Once the HMAC key is derived the actual PSK binder entry value can be
 * calculated as follows.
 *
 *   psk_binder_entry = HMAC(hmac_key, partial_client_hello_digest)
 */
static MSTATUS
SSLSOCK_pskBinderEntry(MOC_HASH(hwAccelDescr hwAccelCtx) SSLSocket* pSSLSock,
    ubyte *pPartialClientHelloDigest, ubyte4 partialClientHelloDigestLen,
    ubyte *pPsk, ubyte2 pskLength, ubyte pskType,
    const BulkHashAlgo *pDigestAlgo, ubyte **ppRetBinderEntry,
    ubyte4 *pRetBinderEntryLen)
{
    MSTATUS status;
    ubyte *pBinderKey = NULL, *pHmacKey = NULL, *pBinderEntry = NULL;
    ubyte4 binderKeyLen;

    status = ERR_NULL_POINTER;
    if (NULL == pDigestAlgo)
        goto exit;

    /* Calculate the binder key.
     */
    status = SSLSOCK_pskCalcBinderKey(MOC_HASH(hwAccelCtx) pSSLSock,
        pPsk, pskLength, pskType, pDigestAlgo, &pBinderKey, &binderKeyLen);
    if (OK != status)
        goto exit;

    /* Calculate the HMAC key.
     */
    status = SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pBinderKey, (ubyte *) TLS13_FINISHED_LABEL(pSSLSock), TLS13_FINISHED_LABEL_LEN,
        NULL, &pHmacKey);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pBinderEntry, pDigestAlgo->digestSize);
    if (OK != status)
        goto exit;

    /* Calculate the PSK binder entry.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacQuick(MOC_HASH(hwAccelCtx)
        pHmacKey, pDigestAlgo->digestSize, pPartialClientHelloDigest,
        partialClientHelloDigestLen, pBinderEntry, pDigestAlgo);
#else
    status = HmacQuick(MOC_HASH(hwAccelCtx)
        pHmacKey, pDigestAlgo->digestSize, pPartialClientHelloDigest,
        partialClientHelloDigestLen, pBinderEntry, pDigestAlgo);
#endif
    if (OK != status)
        goto exit;

    *ppRetBinderEntry = pBinderEntry;
    *pRetBinderEntryLen = pDigestAlgo->digestSize;
    pBinderEntry = NULL;

exit:

    if (NULL != pBinderEntry)
    {
        DIGI_MEMSET(pBinderEntry, 0x00, pDigestAlgo->digestSize);
        DIGI_FREE((void **) &pBinderEntry);
    }

    if (NULL != pBinderKey)
    {
        DIGI_MEMSET(pBinderKey, 0x00, pDigestAlgo->digestSize);
        DIGI_FREE((void **) &pBinderKey);
    }

    if (NULL != pHmacKey)
    {
        DIGI_MEMSET(pHmacKey, 0x00, pDigestAlgo->digestSize);
        DIGI_FREE((void **) &pHmacKey);
    }

    return status;
}

static MSTATUS
SSLSOCK_generatePSKFromTicket(SSLSocket *pSSLSock,
                              ubyte *pNonce, ubyte nonceLen,
                              const BulkHashAlgo *pDigestAlgo,
                              ubyte* pResumptionMasterSecret,
                              ubyte **ppPSK, ubyte4 *pPSKLen)
{
    MSTATUS status = OK;

    if ((pSSLSock == NULL) || (pNonce == NULL) ||
        (NULL == pDigestAlgo) ||
        (NULL == pResumptionMasterSecret))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = SSLSOCK_hmacKdfExpandLabel(pSSLSock, pResumptionMasterSecret,
                                                  pDigestAlgo->digestSize, (ubyte *) TLS13_PSK_RESUMPTION_LABEL(pSSLSock),
                                                  TLS13_PSK_RESUMPTION_LABEL_SIZE, pNonce, nonceLen,
                                                  pDigestAlgo->digestSize, ppPSK, pPSKLen)))
    {
        goto exit;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */

/*------------------------------------------------------------------*/

/* Call this function to update the client key. This key will be stored in
 * pSSLSock->pClientApplicationTrafficSecret.
 */
static MSTATUS
SSLSOCK_pskUpdateClientTrafficSecret(SSLSocket *pSSLSock)
{
    MSTATUS status;
    ubyte *pClientApplicationTrafficSecret = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pSSLSock) || (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (NULL == pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo) ||
         (NULL == pSSLSock->pClientApplicationTrafficSecret) )
        goto exit;

    status = SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
        pSSLSock->pClientApplicationTrafficSecret,
        (ubyte *) TLS13_TRAFFIC_UPDATE(pSSLSock), TLS13_TRAFFIC_UPDATE_LEN, NULL,
        &pClientApplicationTrafficSecret);
    if (OK != status)
        goto exit;

    status = DIGI_FREE((void **) &pSSLSock->pClientApplicationTrafficSecret);
    if (OK != status)
        goto exit;

    pSSLSock->pClientApplicationTrafficSecret = pClientApplicationTrafficSecret;

exit:

    return status;
}

/*------------------------------------------------------------------*/

/* Call this function to update the server key. This key will be stored in
 * pSSLSock->pServerApplicationTrafficSecret.
 */
static MSTATUS
SSLSOCK_pskUpdateServerTrafficSecret(SSLSocket *pSSLSock)
{
    MSTATUS status;
    ubyte *pServerApplicationTrafficSecret = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pSSLSock) || (NULL == pSSLSock->pHandshakeCipherSuite) ||
         (NULL == pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo) ||
         (NULL == pSSLSock->pServerApplicationTrafficSecret) )
        goto exit;

    status = SSLSOCK_HmacKdfDeriveSecret(MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
        pSSLSock->pServerApplicationTrafficSecret,
        (ubyte *) TLS13_TRAFFIC_UPDATE(pSSLSock), TLS13_TRAFFIC_UPDATE_LEN, NULL,
        &pServerApplicationTrafficSecret);
    if (OK != status)
        goto exit;

    status = DIGI_FREE((void **) &pSSLSock->pServerApplicationTrafficSecret);
    if (OK != status)
        goto exit;

    pSSLSock->pServerApplicationTrafficSecret = pServerApplicationTrafficSecret;

exit:

    return status;
}

/*------------------------------------------------------------------*/

/* [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
 * [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
 */
static MSTATUS
SSLSOCK_deriveKeyAndNonce(MOC_HASH(hwAccelDescr hwAccelCtx)
    SSLSocket *pSSLSock,
    const BulkHashAlgo *pDigestAlgo,
    ubyte *pSecret, ubyte4 secretLen, ubyte *pRetKey, ubyte4 keyLength,
    ubyte *pRetIv, ubyte4 ivLen)
{
    MSTATUS status;
    ubyte pKeyContext[2 + 1 + TLS13_KEY_LABEL_LEN + 1];
    ubyte pIvContext[2 + 1 + TLS13_IV_LABEL_LEN + 1];

    status = ERR_BAD_LENGTH;
    if ( (keyLength & 0xFFFF0000) || (ivLen & 0xFFFF0000) )
        goto exit;

    setShortValue(pKeyContext, (ubyte2) keyLength);
    *(pKeyContext + 2) = (ubyte) TLS13_KEY_LABEL_LEN;
    DIGI_MEMCPY(pKeyContext + 3, TLS13_KEY_LABEL(pSSLSock), TLS13_KEY_LABEL_LEN);
    *(pKeyContext + 2 + 1 + TLS13_KEY_LABEL_LEN) = 0x00;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExpand(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pSecret, secretLen, pKeyContext, sizeof(pKeyContext),
        NULL, 0, pRetKey, keyLength);
#else
    status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pSecret, secretLen, pKeyContext, sizeof(pKeyContext),
        NULL, 0, pRetKey, keyLength);
#endif
    if (OK != status)
        goto exit;

    setShortValue(pIvContext, (ubyte2) ivLen);
    *(pIvContext + 2) = TLS13_IV_LABEL_LEN;
    DIGI_MEMCPY(pIvContext + 3, TLS13_IV_LABEL(pSSLSock), TLS13_IV_LABEL_LEN);
    *(pIvContext + 2 + 1 + TLS13_IV_LABEL_LEN) = 0x00;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExpand(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pSecret, secretLen, pIvContext, sizeof(pIvContext),
        NULL, 0, pRetIv, ivLen);
#else
    status = HmacKdfExpand(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pSecret, secretLen, pIvContext, sizeof(pIvContext),
        NULL, 0, pRetIv, ivLen);
#endif
    if (OK != status)
        goto exit;

exit:

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SSLSOCK_setServerTrafficKeyMaterial(SSLSocket *pSSLSock, ubyte *pSecret)
{
    MSTATUS status;

    status = SSLSOCK_deriveKeyAndNonce(MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock, pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
        pSecret,
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize,
        pSSLSock->pMaterials + pSSLSock->pHandshakeCipherSuite->keySize,
        pSSLSock->pHandshakeCipherSuite->keySize,
        pSSLSock->pMaterials + (pSSLSock->pHandshakeCipherSuite->keySize * 2) +
        IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pSSLSock->pHandshakeCipherSuite),
        IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pSSLSock->pHandshakeCipherSuite));
    if (OK != status)
        goto exit;

    status = SSL_SOCK_setServerKeyMaterial(pSSLSock);
    if (OK != status)
        goto exit;

    if (pSSLSock->server)
    {
        pSSLSock->ownSeqnum = 0;
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            pSSLSock->ownSeqnumHigh = pSSLSock->ownSeqnumHigh & 0xffff0000;
        else
#endif
            pSSLSock->ownSeqnumHigh = 0;
        pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
    }
    else
    {
        pSSLSock->peerSeqnum = 0;
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            pSSLSock->peerSeqnumHigh = pSSLSock->peerSeqnumHigh & 0xffff0000;
        else
#endif
            pSSLSock->peerSeqnumHigh = 0;
        pSSLSock->pActivePeerCipherSuite = pSSLSock->pHandshakeCipherSuite;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SSLSOCK_setClientTrafficKeyMaterial(SSLSocket *pSSLSock, ubyte *pSecret)
{
    MSTATUS status;

    status = SSLSOCK_deriveKeyAndNonce(MOC_HASH(pSSLSock->hwAccelCookie)
        pSSLSock, pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo,
        pSecret,
        pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo->digestSize,
        pSSLSock->pMaterials,
        pSSLSock->pHandshakeCipherSuite->keySize,
        pSSLSock->pMaterials + (pSSLSock->pHandshakeCipherSuite->keySize * 2),
        IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pSSLSock->pHandshakeCipherSuite));
    if (OK != status)
        goto exit;

    status = SSL_SOCK_setClientKeyMaterial(pSSLSock);
    if (OK != status)
        goto exit;

    if (pSSLSock->server)
    {
        pSSLSock->peerSeqnum = 0;
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_SERVER__)
        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            pSSLSock->peerSeqnumHigh = pSSLSock->peerSeqnumHigh & 0xffff0000;
        else
#endif
            pSSLSock->peerSeqnumHigh = 0;
        pSSLSock->pActivePeerCipherSuite = pSSLSock->pHandshakeCipherSuite;
    }
    else
    {
        pSSLSock->ownSeqnum = 0;
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
        if (pSSLSock->isDTLS && DTLS13_MINORVERSION == pSSLSock->sslMinorVersion)
            pSSLSock->ownSeqnumHigh = pSSLSock->ownSeqnumHigh & 0xffff0000;
        else
#endif
            pSSLSock->ownSeqnumHigh = 0;
        pSSLSock->pActiveOwnCipherSuite = pSSLSock->pHandshakeCipherSuite;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
SSLSOCK_computeHandshakeSecret(SSLSocket *pSSLSock)
{
    MSTATUS status = OK;
    ubyte *pSharedSecret = NULL;
    ubyte4 sharedSecretLen = 0;
    ECCKey *pECCKey = NULL;
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pKemCtx = NULL;
    ubyte4 eccPubLen = 0;
    ubyte *pEccSS = NULL;
    ubyte4 eccSSLen = 0;
    ubyte *pCipher = NULL;
    ubyte4 pqcSSLen = 0;
#endif
    
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    if (pSSLSock->server)
    {
#if defined (__ENABLE_DIGICERT_ECC__)
        /* ecdheKey was generated when processing key_share Extension;
         * The curve used to generate this key is stored in selectedCurveLength variable
         */

        if (NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
        {

            pECCKey = pSSLSock->ecdheKey.key.pECC;
            if (ECDH_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pSSLSock->roleSpecificInfo.server.selectedGroup))
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK > (status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(
                    MOC_ECC(pSSLSock->hwAccelCookie)
                    pECCKey, pSSLSock->roleSpecificInfo.server.receivedPubKey,
                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen, ECDH_X_CORD_ONLY, NULL)))
#else
                if (OK > (status = ECDH_generateSharedSecret(MOC_ECC(pSSLSock->hwAccelCookie)
                    pECCKey->pCurve, pSSLSock->roleSpecificInfo.server.receivedPubKey,
                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen, pECCKey->k,
                    &pSharedSecret, &sharedSecretLen)))
#endif
                {
                    goto exit;
                }
            }
            else if (FFDH_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pSSLSock->roleSpecificInfo.server.selectedGroup))
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_DH_MODES__
                status = CRYPTO_INTERFACE_DH_keyAgreementScheme(MOC_DH(pSSLSock->hwAccelCookie) DH_EPHEMERAL, 
                    g_pRandomContext, NULL, pSSLSock->pDHcontext, NULL, 0, 
                    pSSLSock->roleSpecificInfo.server.receivedPubKey,
                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen);
#else
                status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(pSSLSock->hwAccelCookie)
                    pSSLSock->pDHcontext , g_pRandomContext,
                    pSSLSock->roleSpecificInfo.server.receivedPubKey,
                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen, NULL);
#endif
#else
                status = DH_computeKeyExchangeExExt(MOC_DH(pSSLSock->hwAccelCookie)
                    pSSLSock->pDHcontext , g_pRandomContext,
                    pSSLSock->roleSpecificInfo.server.receivedPubKey,
                    pSSLSock->roleSpecificInfo.server.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen, NULL);
#endif
                if (OK != status)
                {
                    goto exit;
                }
            }
#ifdef __ENABLE_DIGICERT_PQC__
            else if (HYBRID_SUPPORTED_GROUP_MASK == (SUPPORTED_GROUP_MASK & pSSLSock->roleSpecificInfo.server.selectedGroup))
            {
                ubyte4 eccPubOffset;
                pKemCtx = pSSLSock->ecdheKey.pQsCtx;
                
                status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(
                    pECCKey, &eccPubLen);
                if (OK != status)
                    goto exit;

                if (HYBRID_IS_PQC_FIRST(pSSLSock->roleSpecificInfo.server.selectedGroup))
                {
                    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pKemCtx, &eccPubOffset);
                    if (OK != status)
                       goto exit;
                }
                else
                {
                    eccPubOffset = 0;
                }

                /* TO DO, is this always the responder flow? */
                status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(
                    pECCKey, pSSLSock->roleSpecificInfo.server.receivedPubKey + eccPubOffset,
                    eccPubLen, &pEccSS, &eccSSLen, ECDH_X_CORD_ONLY, NULL);
                if (OK != status)
                    goto exit;
                
                /* Server has already computed QS shared secret when QS key
                 * share was sent */
                sharedSecretLen = eccSSLen + pSSLSock->qsSharedSecretLen;

                status = DIGI_MALLOC((void **) &pSharedSecret, sharedSecretLen);
                if (OK != status)
                {
                    goto exit;
                }

                if (HYBRID_IS_PQC_FIRST(pSSLSock->roleSpecificInfo.server.selectedGroup))
                {
                    status = DIGI_MEMCPY(pSharedSecret, pSSLSock->pQsSharedSecret, pSSLSock->qsSharedSecretLen);
                    if (OK != status)
                        goto exit;

                    status = DIGI_MEMCPY(pSharedSecret + pSSLSock->qsSharedSecretLen, pEccSS, eccSSLen);
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = DIGI_MEMCPY(pSharedSecret, pEccSS, eccSSLen);
                    if (OK != status)
                        goto exit;

                    status = DIGI_MEMCPY(pSharedSecret + eccSSLen, pSSLSock->pQsSharedSecret,
                                        pSSLSock->qsSharedSecretLen);
                    if (OK != status)
                        goto exit;
                }
                
                DIGI_MEMSET_FREE(&pSSLSock->pQsSharedSecret, pSSLSock->qsSharedSecretLen);
            }
#endif /* __ENABLE_DIGICERT_PQC__ */
        }
#endif /* __ENABLE_DIGICERT_ECC__ */
        if (OK > (status = SSLSOCK_pskHandshakeSecretDerive(
            pSSLSock, pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo, pSharedSecret,
            sharedSecretLen)))
        {
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (!pSSLSock->server)
    {

#if defined (__ENABLE_DIGICERT_ECC__)
        if (NULL != pSSLSock->roleSpecificInfo.client.receivedPubKey)
        {
            sharedKey *pSharedKey = &pSSLSock->roleSpecificInfo.client.ppSharedKeys[pSSLSock->roleSpecificInfo.client.sharedKeyIndex];

            if (akt_dh == pSharedKey->type)
            {
#ifndef __DISABLE_DIGICERT_DIFFIE_HELLMAN__
                diffieHellmanContext *pCtx = (diffieHellmanContext *) (pSSLSock->roleSpecificInfo.client.ppSharedKeys[pSSLSock->roleSpecificInfo.client.sharedKeyIndex].pKey);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_DH_MODES__
                status = CRYPTO_INTERFACE_DH_keyAgreementScheme(MOC_DH(pSSLSock->hwAccelCookie) DH_EPHEMERAL, 
                    g_pRandomContext, NULL, pCtx, NULL, 0, 
                    pSSLSock->roleSpecificInfo.client.receivedPubKey,
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen);
#else
                status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(pSSLSock->hwAccelCookie)
                    pCtx, g_pRandomContext,
                    pSSLSock->roleSpecificInfo.client.receivedPubKey,
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen, NULL);
#endif
#else
                status = DH_computeKeyExchangeExExt(MOC_DH(pSSLSock->hwAccelCookie)
                    pCtx, g_pRandomContext,
                    pSSLSock->roleSpecificInfo.client.receivedPubKey,
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen, NULL);
#endif
                if (OK != status)
                {
                    goto exit;
                }
#else
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
#endif
            }
            else if((akt_ecc == pSharedKey->type) || (akt_ecc_ed == pSharedKey->type))
            {
                pECCKey = ((AsymmetricKey *) pSSLSock->roleSpecificInfo.client.ppSharedKeys[pSSLSock->roleSpecificInfo.client.sharedKeyIndex].pKey)->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(MOC_ECC(pSSLSock->hwAccelCookie)
                    pECCKey, pSSLSock->roleSpecificInfo.client.receivedPubKey,
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen,
                    &pSharedSecret, &sharedSecretLen, ECDH_X_CORD_ONLY, NULL);
#else
                status = ECDH_generateSharedSecret(MOC_ECC(pSSLSock->hwAccelCookie)
                    pECCKey->pCurve, pSSLSock->roleSpecificInfo.client.receivedPubKey,
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen, pECCKey->k,
                    &pSharedSecret, &sharedSecretLen);
#endif
                if (OK != status)
                    goto exit;

            }
#ifdef __ENABLE_DIGICERT_PQC__
            else if (akt_hybrid == pSharedKey->type)
            {
                ubyte4 eccPubOffset;
                ubyte4 pqcPubOffset;
                ubyte4 eccSSOffset;
                ubyte4 pqcSSOffset;

                 /* TO DO, is this always the initiator flow? */
                pECCKey = ((AsymmetricKey *) pSSLSock->roleSpecificInfo.client.ppSharedKeys[pSSLSock->roleSpecificInfo.client.sharedKeyIndex].pKey)->key.pECC;
                pKemCtx = ((AsymmetricKey *) pSSLSock->roleSpecificInfo.client.ppSharedKeys[pSSLSock->roleSpecificInfo.client.sharedKeyIndex].pKey)->pQsCtx;
                
                status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(
                    pECCKey, &eccPubLen);
                if (OK != status)
                    goto exit;

                if (HYBRID_IS_PQC_FIRST(pSSLSock->roleSpecificInfo.client.selectedGroup))
                {
                    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pKemCtx, &eccPubOffset);
                    if (OK != status)
                        goto exit;
                    
                    pqcPubOffset = 0;
                }
                else
                {
                    eccPubOffset = 0;
                    pqcPubOffset = eccPubLen;
                }

                status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux(
                    pECCKey, pSSLSock->roleSpecificInfo.client.receivedPubKey + eccPubOffset,
                    eccPubLen, &pEccSS, &eccSSLen, ECDH_X_CORD_ONLY, NULL);
                if (OK != status)
                    goto exit;

                status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(pKemCtx, &pqcSSLen);
                if (OK != status)
                    goto exit;
                
                sharedSecretLen = eccSSLen + pqcSSLen;
                status = DIGI_MALLOC((void **) &pSharedSecret, sharedSecretLen);
                if (OK != status)
                    goto exit;

                if (HYBRID_IS_PQC_FIRST(pSSLSock->roleSpecificInfo.client.selectedGroup))
                {
                    eccSSOffset = pqcSSLen;
                    pqcSSOffset = 0;

                }
                else
                {
                    eccSSOffset = 0;
                    pqcSSOffset = eccSSLen;
                }

                status = DIGI_MEMCPY(pSharedSecret + eccSSOffset, pEccSS, eccSSLen);
                if (OK != status)
                    goto exit;
                
                status = CRYPTO_INTERFACE_QS_KEM_decapsulate(
                    pKemCtx, pSSLSock->roleSpecificInfo.client.receivedPubKey + pqcPubOffset,
                    pSSLSock->roleSpecificInfo.client.receivedPubKeyLen - eccPubLen,
                    pSharedSecret + pqcSSOffset, pqcSSLen);
                if (OK != status)
                    goto exit;
                
                /* TO DO how to put ciphertext after the server's public key? Just straight add it to pSSLSock->roleSpecificInfo..receivedPubKey, */
            }
#endif /* __ENABLE_DIGICERT_PQC__ */
        }
#endif /* __ENABLE_DIGICERT_ECC__ */
        status = SSLSOCK_pskHandshakeSecretDerive(
            pSSLSock, pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo, pSharedSecret,
            sharedSecretLen);
        if (OK != status)
            goto exit;
    }
#endif
exit:

#if defined (__ENABLE_DIGICERT_ECC__)

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
    if (NULL != pSSLSock->roleSpecificInfo.server.receivedPubKey)
    {
        DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.server.receivedPubKey);
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    if (NULL != pSSLSock->roleSpecificInfo.client.receivedPubKey)
    {
        DIGI_FREE((void **) &pSSLSock->roleSpecificInfo.client.receivedPubKey);
    }
#endif
#endif

    if (pSharedSecret != NULL)
    {
        DIGI_FREE((void **)&pSharedSecret);
    }
    
#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pEccSS)
    {
        DIGI_MEMSET_FREE(&pEccSS, eccSSLen);
    }
    
    if (NULL != pCipher)
    {
        DIGI_MEMSET_FREE(&pCipher, pqcSSLen);
    }
#endif
    
    return status;
}

static MSTATUS
SSLSOCK_hmacKdfExpandLabel(
    SSLSocket *pSSLSock, ubyte *pSecret, ubyte4 secretLen, ubyte *pLabel,
    ubyte labelLen, ubyte *pContext, ubyte contextLen, ubyte2 length,
    ubyte **ppRetKey, ubyte4 *pRetKeyLen)
{
    MSTATUS status;
    ubyte *pHmacKdfContext = NULL;
    ubyte4 hmacKdfContextLen = 0, i = 0;
    const BulkHashAlgo *pDigestAlgo = NULL;
    ubyte *pKey = NULL;

    if ( (NULL == pSecret) || (NULL == pLabel) || (NULL == ppRetKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDigestAlgo = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo;

    hmacKdfContextLen = 2 + 1 + labelLen + 1 + contextLen;

    status = DIGI_MALLOC((void **) &pHmacKdfContext, hmacKdfContextLen);
    if (OK != status)
        goto exit;

    setShortValue(pHmacKdfContext, length);
    i = 2;

    pHmacKdfContext[i++] = labelLen;
    status = DIGI_MEMCPY(pHmacKdfContext + i, pLabel, labelLen);
    if (OK != status)
        goto exit;

    i += labelLen;

    pHmacKdfContext[i++] = contextLen;

    /* The context can be NULL so don't check the status here.
     */
    DIGI_MEMCPY(pHmacKdfContext + i, pContext, contextLen);

    status = DIGI_MALLOC((void **) &pKey, length);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacKdfExpand(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigestAlgo, pSecret, secretLen, pHmacKdfContext, hmacKdfContextLen,
        NULL, 0, pKey, length);
#else
    status = HmacKdfExpand(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigestAlgo, pSecret, secretLen, pHmacKdfContext, hmacKdfContextLen,
        NULL, 0, pKey, length);
#endif
    if (OK != status)
        goto exit;

    *ppRetKey = pKey;
    *pRetKeyLen = length;
    pKey = NULL;

exit:

    if (NULL != pHmacKdfContext)
    {
        DIGI_FREE((void **) &pHmacKdfContext);
    }

    if (NULL != pKey)
    {
        DIGI_MEMSET(pKey, 0x00, length);
        DIGI_FREE((void **) &pKey);
    }

    return status;
}

static MSTATUS
SSLSOCK_calcFinishedVerifyData(
    SSLSocket *pSSLSock, ubyte *pSecret, ubyte **ppVerifyData,
    ubyte4 *pVerifyDataLen)
{
    MSTATUS status = OK;
    ubyte *pHmacKey = NULL, *pDigest = NULL, *pVerifyData = NULL;
    ubyte4 hmacKeyLen = 0;
    const BulkHashAlgo *pDigestAlgo = NULL;

    if ( (NULL == pSSLSock) || (NULL == ppVerifyData) ||
         (NULL == pVerifyDataLen) || (NULL == pSecret) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDigestAlgo = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo;

    status = SSLSOCK_hmacKdfExpandLabel(
        pSSLSock, pSecret, pDigestAlgo->digestSize,
        (ubyte *) TLS13_FINISHED_LABEL(pSSLSock), TLS13_FINISHED_LABEL_LEN, NULL, 0,
        pDigestAlgo->digestSize, &pHmacKey, &hmacKeyLen);
    if (OK != status)
        goto exit;

    status = SSLSOCK_calcTranscriptHash(pSSLSock, &pDigest);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pVerifyData, pDigestAlgo->digestSize);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_HmacQuick(MOC_HASH(pSSLSock->hwAccelCookie)
        pHmacKey, hmacKeyLen, pDigest, pDigestAlgo->digestSize, pVerifyData,
        pDigestAlgo);
#else
    status = HmacQuick(MOC_HASH(pSSLSock->hwAccelCookie)
        pHmacKey, hmacKeyLen, pDigest, pDigestAlgo->digestSize, pVerifyData,
        pDigestAlgo);
#endif
    if (OK != status)
        goto exit;

    *ppVerifyData = pVerifyData;
    *pVerifyDataLen = pDigestAlgo->digestSize;
    pVerifyData = NULL;

exit:

    if (NULL != pVerifyData)
    {
        DIGI_FREE((void **) &pVerifyData);
    }

    if (NULL != pHmacKey)
    {
        DIGI_MEMSET(pHmacKey, 0x00, hmacKeyLen);
        DIGI_FREE((void **) &pHmacKey);
    }

    if (NULL != pDigest)
    {
        DIGI_FREE((void **) &pDigest);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__

/* RFC 8446 - Section 7.5
 *
 * This method generates an exporter key using the method specified in section
 * 7.5 of RFC 8446. The following is an overview of how the method is supposed
 * to calculate the exporter key.
 *
 * temp_secret = HKDF-Expand-Label(
 *     exporter_master_secret, label, Transcript-Hash(""), Hash.length)
 *
 * exported_key = HKDF-Expand-Label(
 *     temp_secret, "exporter", Hash(context), key_length)
 */
extern MSTATUS
SSLSOCK_generateHmacKdfExporterKey(
    SSLSocket *pSSLSock, ubyte *pSecret, ubyte *pLabel, ubyte2 labelLen,
    ubyte *pContext, ubyte2 contextLen, ubyte *pKey, ubyte2 keyLen)
{
    MSTATUS status;
    ubyte *pRetKey = NULL, *pTemp = NULL, *pDigest = NULL, *pTls13Label = NULL;
    ubyte4 retKeyLen = 0;
    const BulkHashAlgo *pDigestAlgo = pSSLSock->pHandshakeCipherSuite->pPRFHashAlgo;

    if ( (NULL == pContext) && (0 != contextLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pDigest, pDigestAlgo->digestSize);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pTls13Label, labelLen + 6);
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)
    if(pSSLSock->isDTLS)
    {
        status = DIGI_MEMCPY(pTls13Label, "dtls13", 6);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
#endif
    {
        status = DIGI_MEMCPY(pTls13Label, "tls13 ", 6);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = DIGI_MEMCPY(pTls13Label + 6, pLabel, labelLen);
    if (OK != status)
    {
        goto exit;
    }

    /* If a NULL context was provided then calculate the empty digest.
     */
    if (NULL == pContext)
    {
        pContext = (ubyte *) "";
    }

    status = SSLSOCK_calcTranscriptHashForBuffer(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigestAlgo, pContext, contextLen, pDigest);
    if (OK != status)
    {
        goto exit;
    }

    /* Use the exporter secret and the caller provided lable to create the
     * temporary secret.
     */
    status = SSLSOCK_HmacKdfDeriveSecretEx(MOC_HASH(pSSLSock->hwAccelCookie)
        pDigestAlgo, pSecret, pTls13Label, labelLen + 6, NULL, &pTemp);
    if (OK != status)
    {
        goto exit;
    }

    /* Use the TLS 1.3 label and the temporary secret to calculate the key
     * material.
     */
    status = SSLSOCK_hmacKdfExpandLabel(
        pSSLSock, pTemp, pDigestAlgo->digestSize,
        (ubyte *) TLS13_EXPORTER_LABEL(pSSLSock), TLS13_EXPORTER_LABEL_LEN, pDigest,
        pDigestAlgo->digestSize, keyLen, &pRetKey, &retKeyLen);
    if (OK != status)
    {
        goto exit;
    }

    if (retKeyLen != keyLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MEMCPY(pKey, pRetKey, keyLen);

exit:

    if (NULL != pTls13Label)
    {
        DIGI_MEMSET(pTls13Label, 0x00, labelLen + 6);
        DIGI_FREE((void **) &pTls13Label);
    }

    if (NULL != pRetKey)
    {
        DIGI_MEMSET(pRetKey, 0x00, retKeyLen);
        DIGI_FREE((void **) &pRetKey);
    }

    if (NULL != pTemp)
    {
        DIGI_MEMSET(pTemp, 0x00, pDigestAlgo->digestSize);
        DIGI_FREE((void **) &pTemp);
    }

    DIGI_FREE((void **) &pDigest);

    return status;
}

#endif /* __ENABLE_DIGICERT_SSL_KEY_EXPANSION__ */

/*------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_TLS13__ */

#if defined(__ENABLE_DIGICERT_SSL_REHANDSHAKE__)

extern MSTATUS
SSLSOCK_initiateRehandshake(SSLSocket *pSSLSock)
{
    MSTATUS status = ERR_SSL_BAD_ID;

    if (((TLS13_MINORVERSION > pSSLSock->sslMinorVersion) && (kSslOpenState != SSL_HANDSHAKE_STATE(pSSLSock))) ||
        ((pSSLSock->server) && (TLS13_MINORVERSION == pSSLSock->sslMinorVersion) && (kSslReceiveUntil != SSL_HANDSHAKE_STATE(pSSLSock))) ||
        ((!pSSLSock->server) && (TLS13_MINORVERSION == pSSLSock->sslMinorVersion) && (kSslReceiveHelloState != SSL_HANDSHAKE_STATE(pSSLSock))))
    {
        /* we are already doing a (re)handshake */
        status = OK;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__)
    if (TLS13_MINORVERSION == pSSLSock->sslMinorVersion)
    {
        /* Client should indicate it supports posthandshake auth and PSK should not be used */
        if ((pSSLSock->server) && (1 == pSSLSock->postHandshakeAuth) && (!pSSLSock->isPSKSelected))
        {
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
            if (OK > (status = SSL_SERVER_sendPostHandshakeAuthCertificateRequest(pSSLSock)))
            {
                goto exit;
            }
#endif
        }

        if (OK > (status = SSLSOCK_sendKeyUpdateRequest(pSSLSock, 1/* request a keyupdate message from the other end */)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        if (pSSLSock->server)
        {
#if (defined(__ENABLE_DIGICERT_SSL_SERVER__))
            status = SSL_SOCK_sendServerHelloRequest(pSSLSock);
#endif
        }
        else
        {
#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__))
            status = SSL_SOCK_clientHandshake(pSSLSock, TRUE);
#endif
        }
    }

exit:
    return (sbyte4)status;

} /* SSLSOCK_initiateRehandshake */

#endif

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
#include "../ssl/nist/ssl_nist.inc"
#endif

#endif /* (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__)) */
