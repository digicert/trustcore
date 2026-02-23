/*
 * openssl_shim.h
 *
 * Defines function pointers that are implemented in NanoSSL so that
 * OpenSSL calls can be mapped to NanoSSL functions
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

#ifndef OPENSSL_SHIM_H
#define OPENSSL_SHIM_H
#include "../crypto/hw_accel.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_chain.h"
#include "../crypto/cert_store.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/sizedbuffer.h"
#include "../common/hash_table.h"

#ifdef __RTOS_VXWORKS__
#include <sys/types.h> /* for u_int8_t */
#endif

#if defined(__RTOS_LINUX__)
#include <sys/types.h>  /* for u_int8_t */
#endif

#ifdef __RTOS_WIN32__
#include <stdint.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/* definition must match equivalent in mocana_glue.h */
int moc_get_rsa_ex_app_data(void);
int moc_get_ecc_ex_app_data(void);
#if defined(__ENABLE_DIGICERT_TAP__)
void DIGI_EVP_maskCred(ubyte *pIn, ubyte4 inLen);
typedef struct MOC_EVP_KEY_DATA_s
{
    ubyte4 contentsLen;
    ubyte *pContents;
    MKeyContextCallbackInfo *cb_data;
	void *pData;
    ubyte *pCred;
    ubyte4 credLen;
} MOC_EVP_KEY_DATA;
#endif
#endif

typedef struct OSSL_SizedBuffer_t {
     ubyte4 length;
     ubyte  *data;
} OSSL_SizedBuffer;

typedef struct OSSL_RSAParams_t {
     u_int8_t * pN;
     int	lenN;
     u_int8_t * pE;
     int	lenE;
     u_int8_t * pP;
     int	lenP;
     u_int8_t * pQ;
     int	lenQ;
} OSSL_RSAParams;

typedef struct OSSL_DSAParams_t {
     u_int8_t * pP;
     int	lenP;
     u_int8_t * pQ;
     int	lenQ;
     u_int8_t * pG;
     int	lenG;
     u_int8_t * pX;
     int	lenX;
     u_int8_t * pY;
     int	lenY;
} OSSL_DSAParams;

#if (defined (__ENABLE_DIGICERT_ECC__))
typedef enum {
     ossl_prime192v1 = 1,
     ossl_secp224r1,
     ossl_prime256v1,
     ossl_secp384r1,
     ossl_secp521r1,
     ossl_eddsa_448,
     ossl_eddsa_25519
} OSSL_ECCURVE_TYPE;

typedef struct OSSL_ECCParams_t {
     OSSL_ECCURVE_TYPE	curve_name;
     u_int8_t 	      * pPub;
     int		lenPub;
     u_int8_t 	      * pPriv;
     int		lenPriv;
} OSSL_ECCParams;

#endif

typedef struct OSSL_KeyBlobInfo_t {
    ubyte *pKeyBlob;
    ubyte4 keyBlobLength;
    ubyte4 type;
} OSSL_KeyBlobInfo;

/* OpenSSL Connector copy of TLS_HashAlgorithm */
typedef enum OSSL_TLS_HashAlgorithm
{
    OSSL_TLS_NONE        = 0,
    OSSL_TLS_MD5         = 1,
    OSSL_TLS_SHA1        = 2,
    OSSL_TLS_SHA224      = 3,
    OSSL_TLS_SHA256      = 4,
    OSSL_TLS_SHA384      = 5,
    OSSL_TLS_SHA512      = 6,
    OSSL_TLS_HASH_MAX    = 255
} OSSL_TLS_HashAlgorithm;

/* Refer to tlsExtNamedCurves enum in src/ssl/ssl.h */
typedef enum OSSL_tlsExtNamedCurves
{
    /* only the ones we support */
    OSSL_tlsExtNamedCurves_secp192r1 = 19,
    OSSL_tlsExtNamedCurves_secp224r1 = 21,
    OSSL_tlsExtNamedCurves_secp256r1 = 23,
    OSSL_tlsExtNamedCurves_secp384r1 = 24,
    OSSL_tlsExtNamedCurves_secp521r1 = 25
} OSSL_tlsExtNamedCurves;

typedef struct OSSL_SrtpProfileInfo
{
    ubyte2                  profileId;                  /* profile identification */
    ubyte                   supported;                  /* support by this implementation */
    sbyte                   keySize;                    /* size of key */
    sbyte                   saltSize;                   /* size of salt */
} OSSL_SrtpProfileInfo;

typedef struct OSSL_peerDescr
{
    void *pUdpDescr;
    ubyte2 srcPort;
    ubyte4 srcAddr;
    ubyte2 peerPort;
    ubyte4 peerAddr;
} OSSL_peerDescr;

#ifndef SSL_MASTERSECRETSIZE
#define SSL_MASTERSECRETSIZE 48
#endif

typedef struct OSSL_sessionTicketStruct
{
    ubyte2   cipherId;
    ubyte    masterSecret[SSL_MASTERSECRETSIZE];
    ubyte4   lifeTimeHintInSec;
    TimeDate startTime;
    ubyte4   ticketLen;
    ubyte    *pTicket; /* Session ticket sent by the server */
} OSSL_sessionTicket;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define SSL_PSK_TLS13_MAX_LENGTH            (64)
#define SSL_SESSION_TICKET_NONCE_SIZE       (64)
#define SSL_ALPN_MAX_SIZE                   (64)

typedef struct OSSL_tls13PSK
{
    ubyte                   isExternal;
    ubyte                   isPSKavailable;
    ubyte4                  pskTLS13LifetimeHint;
    ubyte4                  pskTLS13AgeAdd;
    ubyte                   ticketNonce[SSL_SESSION_TICKET_NONCE_SIZE];
    ubyte                   pskTLS13[SSL_PSK_TLS13_MAX_LENGTH]; /* Max PSK length is (2^16 - 1) */
    ubyte2                  pskTLS13Length;
    ubyte*                  pskTLS13Identity;
    ubyte4                  pskTLS13IdentityLength;
    ubyte4                  obfuscatedTicketAge;
    OSSL_TLS_HashAlgorithm  hashAlgo;
    TimeDate                startTime;
    ubyte4                  maxEarlyDataSize;
    ubyte2                  pSelectedTlsVersion;
    ubyte                   selectedALPN[SSL_ALPN_MAX_SIZE];
    ubyte2                  selectedCipherSuiteId;
} OSSL_tls13PSK;

typedef struct OSSL_tls13PSKList
{
    OSSL_tls13PSK             *pPSK;
    struct OSSL_tls13PSKList  *pNextPSK;
    ubyte                     *pPskData;
    ubyte4                     pskDataLen;
}OSSL_tls13PSKList;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

/* Both of these structs, certChainEntry and certChain, are defined in
 * cert_chain.c. To access the members of these structs, they are defined here
 * as well.
 */
typedef struct certChainEntry
{
    /* raw data */
    ubyte4 certLength;
    const ubyte* cert;
    /* Certificate extensions - points to the first extension type stored in a
     * TLS 1.3 certificate chain CertificateEntry structure. The length is the
     * length of all the extensions. Each extension is composed of the type
     * bytes followed by the extension length bytes followed by the actual
     * extension data itself. */
    const ubyte *pCertExt;
    ubyte4 certExtLen;
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)
    /* OCSP request - points to the OCSP extension stored in a TLS 1.3
     * certificate chain CertificateEntry structure. The extension type and
     * extension length bytes are not included. The length is the length
     * of just the OCSP extension. */
    const ubyte *pOcspExt;
    ubyte4 ocspExtLen;
#endif /* __ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__ */
    /* ASN.1 parsing tree */
    void* pRoot;
} certChainEntry;

typedef struct certChain
{
    ubyte*              buffer;         /* data from all the certificates */
    sbyte4              numCerts;       /* number of certificates in chain */
    ubyte4              isComplete:1;
    certChainEntry      certs[1];       /* static certificate array which can be
                                         * accessed out of bounds. If you're
                                         * wondering why, take a look at
                                         * CERTCHAIN_createFromSSLRecord in
                                         * the cert_chain.c file. */
} certChain;

typedef void* MOCTAP_HANDLE;

typedef sbyte4 (*ALPN_CALLBACK) (sbyte4 connectionInstance,
                                    ubyte** out[],
                                    sbyte4* outlen,
                                    ubyte* in,
                                    sbyte4 inlen);

typedef sbyte4 (*ALERT_CALLBACK) (sbyte4 connectionInstance,
                                  sbyte4 alertId,
                                  sbyte4 alertClass);


typedef MSTATUS (*CERTSTATUS_CALLBACK)(sbyte4 connectionInstance,
                                      struct certChain *pCertChain,
                                      MSTATUS status);

typedef MSTATUS (*VersionCallback)(ubyte4 serverVersion,
                                    ubyte4 clientVersion,
                                    MSTATUS sslStatus);

typedef MSTATUS (*ClientCertCallback)(sbyte4 connectionInstance,
                                      SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                                      ubyte **ppRetCACert, ubyte4 *pRetNumCACerts);

typedef sbyte4 (*CertVerifySignCallback)(sbyte4 connectionInstance,
                                          const ubyte* hash, ubyte4 hashLen,
                                          ubyte* result, ubyte4 resultLength);

typedef sbyte4 (*SrtpInitCallback)(sbyte4 connectionInstance, void *pChannelDescr,
                                    void *pProfile, void* keyMaterials, ubyte* mki);
typedef sbyte4 (*SrtpEncodeCallback)(sbyte4 connectionInstance, void *pChannelDescr,
                                    const sbyte* pData, ubyte4 pDataLength,
                                    ubyte** encodedData, ubyte4* encodedLength);
typedef sbyte4 (*OCSPCallback)(sbyte4 connectionInstance, const ubyte *pCert, ubyte4 certLen,
                               ubyte* pOcspResp, ubyte4 ocspRespLen,
                               sbyte4 ocspStatus);

extern int OSSL_SB_Allocate(OSSL_SizedBuffer *pSB, int size);
extern int OSSL_SB_Free(OSSL_SizedBuffer *pSB);
extern void OSSL_RSAParamsFree(OSSL_RSAParams *p);
extern void OSSL_DSAParamsFree(OSSL_DSAParams *p);
#if (defined (__ENABLE_DIGICERT_ECC__))
extern void OSSL_ECCParamsFree(OSSL_ECCParams *p);
#endif

typedef struct ClientHelloData {
    ubyte isv2;
    ubyte2 legacy_version;
    ubyte *random; /* fixed size of 32 bytes */
    ubyte4 random_len;
    ubyte *session_id;
    ubyte4 session_id_len;
    ubyte *ciphers;
    ubyte4 ciphers_len;
    ubyte *compression_methods;
    ubyte4 compression_methods_len;
    ubyte *extensions;
    ubyte4 extensions_len;
} ClientHelloData;

typedef sbyte4 (*ClientHelloCallback)(struct ClientHelloData *hello_data, void *args);

typedef sbyte4  (*NSSLSetClientHelloCallback)(sbyte4 connectionInstance, ClientHelloCallback callback, void *args);

#if defined(__ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__) && \
    defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
typedef MSTATUS (*NSSLparseDigestInfo)(ubyte *pDigestInfo, ubyte4 digestInfoLen, ubyte **ppOid, ubyte4 *pOidLen,
                    ubyte **ppDigest, ubyte4 *pDigestLen, ubyte4 *pDigestAlg);
#endif
typedef sbyte4  (*NSSLLibraryInit)(int flag);
typedef sbyte4  (*NSSLLibraryUnInit)(void *arg);
typedef sbyte4  (*NSSLLibraryInitStaticMem)(ubyte *mem, ubyte4 size);
typedef sbyte4  (*NSSLLibraryReadFile)(const char* pFilename, ubyte **ppRetBuffer, ubyte4 *pRetBufLength);
typedef sbyte4	(*NSSLsslInit)(sbyte4 numServerConns, sbyte4 numClientConns);
typedef sbyte4  (*NSSLsslShutdown)(void *arg);
typedef sbyte4  (*NSSLsslReleaseTables)(void *arg);
typedef sbyte4  (*NSSLparseSslBuffer)(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived,
				     ubyte **ppRetBytesReceived, ubyte4 *pRetNumRxBytesRemaining);
typedef sbyte4  (*NSSLreadSslRecord)(sbyte4 connectionInstance, ubyte **data, ubyte4 *len, ubyte4 *pRetProtocol);
typedef sbyte4  (*NSSLprepareSslRecord)(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);
typedef sbyte4  (*NSSLgetPreparedSslBuffer)(sbyte4 connectionInstance, ubyte *data, ubyte4 *len);
typedef sbyte4  (*NSSLgetPreparedSslBufferZC)(sbyte4 connectionInstance, ubyte **data, ubyte4 *len);
typedef sbyte4  (*NSSLreleaseZCsendBuffer)(sbyte4 connectionInstance, ubyte4 numUnusedBytes);
typedef sbyte4  (*NSSLaccept)(TCP_SOCKET tempSocket, void* pCertStore);
typedef sbyte4  (*NSSLconnect)(TCP_SOCKET tempSocket, ubyte sessionIdLen, ubyte * sessionId,
			      ubyte * masterSecret, const sbyte* dnsName,
			      void *certStore);
typedef sbyte4  (*NSSLcloseConnection)(sbyte4 connectionInstance);
typedef sbyte4  (*NSSLisSslEstablished)(sbyte4 connectionInstance);
typedef sbyte4  (*NSSLinConnectInit)(sbyte4 connectionInstance);
typedef sbyte4  (*NSSLsetCiphers)(sbyte4 connectionInstance, const ubyte2 *pCipherSuiteList,
				ubyte4 listLength);
typedef sbyte4  (*NSSLsetECCCurves)(sbyte4 connectionInstance, enum OSSL_tlsExtNamedCurves *pEccCurvesList,
				 ubyte4 listLength);
typedef sbyte4  (*NSSLdisableCipherHash)(sbyte4 connectionInstance, OSSL_TLS_HashAlgorithm hashId);
typedef sbyte4  (*NSSLgetCipherInfo)(sbyte4 connectionInstance, ubyte2* pCipherId,
                  ubyte4* pPeerEcCurves);
typedef MSTATUS (*NSSLgetSigAlgo)(sbyte4 connectionInstance, ubyte2 *pSigAlg);
typedef sbyte4  (*NSSLgetSSLTLSVersion)(sbyte4 connectionInstance, ubyte4 *pVersion);
typedef sbyte4  (*NSSLgetSessionStatus)(sbyte4 connectionInstance, ubyte4 *pRetStatusSSL);
typedef sbyte4  (*NSSLsetSessionFlags)(sbyte4 connectionInstance, ubyte4 flagsSSL);
typedef sbyte4  (*NSSLgetSessionFlags)(sbyte4 connectionInstance, ubyte4* pFlagsSSL);
typedef sbyte4  (*NSSLclientTriggerHello)(sbyte4 connectionInstance);
typedef sbyte4  (*NSSLrsaParamsToKeyBlob)(OSSL_RSAParams *pR, void **ppKeyBlob, unsigned int *pBlobLen);
typedef sbyte4  (*NSSLdsaParamsToKeyBlob)(OSSL_DSAParams *pD, void **ppKeyBlob, unsigned int *pBlobLen);
typedef sbyte4  (*NSSLsslIoctl)(sbyte4 connectionInstance, ubyte4 setting, void *value);
typedef sbyte4  (*NSSLsslSettingsIoctl)(ubyte4 setting, void *value);
typedef sbyte4  (*NSSLsslSetMinVersion)(ubyte4 version);
typedef ubyte4  (*NSSLsslGetMinVersion)();
typedef sbyte4  (*NSSLsslSetMaxVersion)(ubyte4 version);
typedef ubyte4  (*NSSLsslGetMaxVersion)();
typedef sbyte4  (*NSSLsslGetVersion)(sbyte4 connectionInstance);
typedef sbyte4  (*NSSLsslInitializeVersion)();
typedef MSTATUS (*NSSLsslClearAllSessionCache)(void *pPtr);
typedef MSTATUS (*NSSLgetSharedSignatureAlgorithm)(sbyte4 connectionInstance, ubyte4 algoListIndex,
                                                   ubyte2 *pSigAlgo, ubyte isPeer);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef struct ssl_session_st SSL_SESSION;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef MSTATUS (*NSSLsendPostHandshakeAuthCertReq)(sbyte4 connectionInstance);
typedef MSTATUS (*NSSLsendKeyUpdate)(sbyte4 connectionInstance, ubyte updatetype);
typedef MSTATUS (*NSSLsetPskFindSessionCb)(sbyte4 (*funcPtrSetPskFindSessionCallback) (sbyte4 connectionInstance,
                                                                                        ubyte *pIdentity, ubyte4 identityLen,
                                                                                        ubyte **ppPsk, ubyte4 *pPskLen,
                                                                                        intBoolean *pFreeMemory));
typedef sbyte4 (*NSSLsetPskUseSessionCb)(sbyte4 connectionInstance,
                                          sbyte4 (*funcPtrSetPskUseSessionCallback)
                                                   (sbyte4 connectionInstance,
                                                    sbyte* ServerInfo,
                                                    ubyte4 serverInfoLen,
                                                    void *userData,
                                                    void **ppPSKs,
                                                    ubyte2 *pNumPSKs,
                                                    ubyte* selectedIndex,
                                                    intBoolean *pFreeMemory));

typedef MSTATUS (*NSSLsavePskSessionCb)(sbyte4 connectionInstance,
                                        sbyte4 (*funcPtrSavePskSessionCallback)
                                                 (sbyte4 connectionInstance,
                                                  sbyte* ServerInfo, ubyte4 serverInfoLen,
                                                  void *userData, ubyte *pPsk, ubyte4 pskLen));

typedef MSTATUS (*NSSLsaveServerPskSessionCb)(sbyte4 (*funcPtrServerSavePSK)
                                                       (sbyte4 connectionInstance, ubyte *pServerName,
                                                        ubyte4 serverNameLen, ubyte *pIdentityPSK,
                                                        ubyte4 identityLengthPSK, ubyte *pPsk, ubyte4 pskLen));

typedef MSTATUS (*NSSLdeserializePsk)(ubyte *pPsk, ubyte4 pskLen, OSSL_tls13PSK **ppRetPsk);
typedef MSTATUS (*NSSLserializePsk)(OSSL_tls13PSK *pPsk, ubyte **ppPsk, ubyte4 *pPskLen);
typedef MSTATUS (*NSSLfreePsk)(OSSL_tls13PSK **ppPsk);

typedef sbyte4 (*NSSLsetEarlyData)(sbyte4 connectionInstance, ubyte *pEarlyData, ubyte4 earlyDataSize);
typedef sbyte4 (*NSSLgetEarlyDataState)(sbyte4 connectionInstance, ubyte4 *pEarlyDataState);
#endif  /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__   */

typedef sbyte4 (*NSSLgetLocalState)(sbyte4 connectionInstance, sbyte4 *pState);
typedef sbyte4 (*NSSLsslGetState)(sbyte4 connectionInstance, sbyte4 *pState);
typedef MSTATUS  (*NSSLsetCipherAlgorithm)(sbyte4 connectionInstance, ubyte2 *pList,
                                           ubyte4 listLength, ubyte4 listType);
#if (defined (__ENABLE_DIGICERT_ECC__))
typedef sbyte4  (*NSSLeccParamsToKeyBlob)(OSSL_ECCParams *pE, void *ppKeyBlob, unsigned int *pBlobLen);
typedef MSTATUS (*NSSLextractEcKeyData)(AsymmetricKey *pAsymKey, MEccKeyTemplate **ppTemplate);
typedef MSTATUS (*NSSLfreeEcKeyData)(AsymmetricKey *pAsymKey, MEccKeyTemplate **ppTemplate);
typedef MSTATUS (*NSSLgetEcCurveId)(AsymmetricKey *pAsymKey, ubyte4 *pCurveId);
#endif
#ifdef __ENABLE_DIGICERT_SERIALIZE__
#if defined(__ENABLE_DIGICERT_TAP__)
typedef MSTATUS (*NSSLserializeAsymKeyAlloc)(AsymmetricKey *pKeyToSerialize, ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef MSTATUS (*NSSLdeserializeAsymKeyWithCreds)( ubyte *pSerializedKey, ubyte4 serializedKeyLen,
    ubyte *pPassword, ubyte4 passwordLen, AsymmetricKey *pDeserializedKey);
typedef MSTATUS (*NSSLtapUnloadKey)(
    AsymmetricKey *pAsymKey);
#endif
typedef MSTATUS (*NSSLdeserializeAsymKey)( ubyte *pSerializedKey, ubyte4 serializedKeyLen,
    AsymmetricKey *pDeserializedKey);
#endif /* __ENABLE_DIGICERT_TAP__ */
typedef sbyte4  (*NSSLdeserializeKey)(ubyte *pSerializedKey,ubyte4 serializedKeyLen,
                                      AsymmetricKey *pDeserializedKey);
#endif /* __ENABLE_DIGICERT_SERIALIZE__ */

typedef MSTATUS  (*NSSLmakeKeyBlobEx)(const AsymmetricKey *pKey, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength);
typedef sbyte4  (*NSSLdecryptPKCS8PemKey)(ubyte *pContent, ubyte4 contentLength, AsymmetricKey** pKey,
                                          void *pPassword, intBoolean base64);
typedef sbyte4  (*NSSLinitAsymmetricKey)(AsymmetricKey *pAsymKey);
typedef sbyte4  (*NSSLuninitAsymmetricKey)(AsymmetricKey* pAsymKey);
typedef sbyte4  (*NSSLKeyAssociateTapContext)(MOCTAP_HANDLE mh, void *pCertStore);
typedef sbyte4 (*NSSLcreateCertStore)(void **ppNewStore);
typedef MSTATUS (*NSSLgetPeerCertificateBytes)(sbyte4 connectionInstance, ubyte **ppCertBytes, ubyte4 *pCertLen);
typedef MSTATUS (*NSSLreleaseCertStore)(void **ppReleaseStore);
typedef sbyte4  (*NSSLaddIdentityCertChain)(void *pCertStore, OSSL_SizedBuffer *certs,
					    unsigned int numCerts, const u_int8_t *pKeyBlob,
					    unsigned int keyBlobLength, ubyte* alias, ubyte4 aliasLen);
typedef sbyte4  (*NSSLaddIdentityCertChainExtData)(void *pCertStore, OSSL_SizedBuffer *certs,
					    unsigned int numCerts, const u_int8_t *pKeyBlob,
					    unsigned int keyBlobLength, ubyte* alias, ubyte4 aliasLen,
                        ExtendedDataCallback extendedDataFn, sbyte4 identifier);
typedef sbyte4 (*NSSLaddTrustPoint)(void *pCertStore, u_int8_t *pDerBuf, int derLen);
typedef MSTATUS (*NSSLvalidateCertKeyChain)(
    unsigned char *pKey, int keyLen, unsigned char *pCert, int certLen,
    unsigned char *pChain, int chainLen, int chainCount);
typedef sbyte4 (*NSSLget_alpn)(sbyte4 connectionInstance, const unsigned char **data, ubyte4 *len);
typedef sbyte4 (*NSSLset_alpn)(sbyte4 connectionInstance, sbyte4 numNextProtocols, const char** nextProtocols);
typedef MSTATUS (*NSSLset_alpn_callback)(sbyte4 connectionInstance,
                    sbyte4 (*funcPtrAlpnCallback) (sbyte4 connectionInstance,
                                                   ubyte** out[],
                                                   sbyte4* outlen,
                                                   ubyte* in,
                                                   sbyte4 inlen));

typedef MSTATUS (*NSSLset_alert_callback)(sbyte4 connectionInstance,
                                          sbyte4 (*funcPtrAlpnCallback)(sbyte4 connectionInstance,
                                                                         sbyte4 alertId,
                                                                         sbyte4 alertClass));
typedef sbyte4  (*NSSLsslParseAlert)(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass, sbyte4 *pRetErrorCode);

typedef sbyte4  (*NSSLsslSendAlert)(sbyte4 connectionInstance, sbyte4 sslAlert, sbyte4 sslAlertLevel);

typedef MSTATUS (*NSSLsetCertAndStatusCallback)(sbyte4 connectionInstance,
                                                MSTATUS (*funcPtrGetCertAndStatusCallback)(sbyte4 connectionInstance,
                                                                                           struct certChain *pCertChain,
                                                                                           MSTATUS status));
typedef MSTATUS (*NSSLsetClientCertAuthorityCallback)(sbyte4 connectionInstance,
                                               MSTATUS (*funcPtrClientCertAuthorityCallback) (sbyte4 connectionInstance,
                                                  SizedBuffer *pCertAuthorities,
                                                  ubyte4 certAuthorityCount));
typedef MSTATUS (*NSSLsetClientCertCallback)(sbyte4 connectionInstance,
                              MSTATUS (*funcPtrClientCertCallback)(sbyte4 connInstance,
                                                                   SizedBuffer **ppCert, ubyte4 *pNumCerts,
                                                                   ubyte **ppKeyBlob, ubyte4*pKeyBlobLen,
                                                                   ubyte **ppCACert, ubyte4 *pCACertLen));

typedef MSTATUS (*NSSLsetCertVerifySignCallback)(sbyte4 (*funcPtrCertVerifySignCallback)(sbyte4 connInstance,
                                                          const ubyte* hash, ubyte4 hashLen,
                                                          ubyte* result, ubyte4 resultLength));

typedef MSTATUS (*NSSLsetVersionCallback)(sbyte4 connectionInstance,
                                          MSTATUS (*funcPtrVersionCallback)(ubyte4 serverVersion,
                                                                            ubyte4 clientVersion,
                                                                            MSTATUS sslStatus));

typedef MSTATUS (*NSSLsetClientCAList)(OSSL_SizedBuffer *pClientCANameList, ubyte4 numClientCANames);
typedef MSTATUS (*NSSLsetOCSPCallback)(sbyte4 (*funcPtrOCSPCallback)(sbyte4 connectionInstance, const ubyte *pCert, ubyte4 certLen,
                                                                      ubyte* pOcspResp, ubyte4 ocspRespLen, sbyte4 ocspStatus));
#if 0
/* The 2 typedefs below go together, however they are both replaced by the
 * NSSLsetCertAndStatusCallback method. So they will be defined out for now.
 */
typedef int    (*osslVrfyCertChainCB)(certChainPtr pCertChain, void *arg);
typedef int   (*NSSLsetAppCertVrfyCB)(sbyte4 connectionInstance, osslVrfyCertChainCB cb, void *arg);
#endif
typedef sbyte4 (*NSSLreceivePending)(sbyte4 connectionInstance, sbyte4 *pRetPendingLen);
typedef sbyte4 (*NSSLgetClientSessionInfo)(sbyte4 connectionInstance,
                                            ubyte* sessionIdLen,
                                            ubyte sessionId[],
                                            ubyte masterSecret[]);
typedef sbyte4 (*NSSLsetDNSNames)( sbyte4 connectionInstance, const CNMatchInfo* cnMatchInfos);
typedef sbyte4 (*NSSLsetServerNameExtension) (sbyte4 connectionInstance, const char *serverName);
#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
typedef sbyte4 (*NSSLrehandshakeInit)(ubyte4 maxByteCount, ubyte4 maxTimerCount, sbyte4(*funcPtrRehandshake)(sbyte4 connectionInstace));
typedef sbyte4 (*NSSLinitiateRehandshake)(sbyte4 connectionInstance);
typedef sbyte4 (*NSSLisRehandshakeAllowed)(sbyte4 connectionInstance, intBoolean *pRehandshake);
typedef sbyte4 (*NSSLgetTlsUnique)(sbyte4 connectionInstance,
                                   ubyte4 *pTlsUniqueLen,
                                   ubyte **pTlsUnique);
#endif
#if defined(__ENABLE_DIGICERT_DTLS_SERVER__)
typedef sbyte4 (*NSSLdtlsVerifyClientHelloCookie)(void *pPeerDescr, ubyte *pReceived, ubyte4 length, ubyte *pToSend, ubyte4 *pToSendLen);
#endif
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined (__ENABLE_DIGICERT_DTLS_SERVER__)
typedef sbyte4  (*NSSLdtlsInit)(sbyte4 numServerConnections, sbyte4 numClientConnections);
typedef sbyte4  (*NSSLclientDtlsTriggerHello)(sbyte4 connectionInstance);
typedef sbyte4 (*NSSLdtlsConnect) (void *pPeerDescr, ubyte sessionIdLen, ubyte * sessionId,
             ubyte * masterSecret, const sbyte* dnsName, void *pCertStore);
typedef sbyte4 (*NSSLdtlsAccept) (void *pPeerDescr, void *pCertStore);
typedef sbyte4 (*NSSLdtlsIoctl) (sbyte4 connectionInstance, ubyte4 setting, void *value);
typedef sbyte4 (*NSSLdtlsGetSendBuffer)(sbyte4 connectionInstance, ubyte *data, ubyte4 *len);
typedef sbyte4 (*NSSLdtlsSendMessage)(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);
typedef sbyte4 (*NSSLdtlsParseSslBuf)(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived,
                       ubyte **ppRetBytesReceived, ubyte4 *pRetNumRxBytesRemaining);
typedef sbyte4 (*NSSLdtlsReadSslRec)(sbyte4 connectionInstance, ubyte **data, ubyte4 *len, ubyte4 *pRetProtocol);
typedef sbyte4 (*NSSLdtlsCloseConnection)(sbyte4 connectionInstance);
typedef sbyte4 (*NSSLdtlsGetTimeout)(sbyte4 connectoinInstance, void *pTime);
typedef sbyte4 (*NSSLdtlsHandleTimeout)(sbyte4 connectionInstance);
typedef sbyte4 (*NSSLdtlsShutdown)(void *arg);
typedef sbyte4 (*NSSLsetSrtpProfiles)(sbyte4 connectionInstance, ubyte2 *pSrtpProfileList, ubyte4 listLength);
typedef sbyte4 (*NSSLsetSrtpInitCallback)(sbyte4 (*funcPtrSrtpInitCallback)(sbyte4 connectionInstance, void *pChannelDescr,
                                                                            void* pProfile, void* keyMaterials, ubyte* mki));
typedef sbyte4 (*NSSLsetSrtpEncodeCallback)(sbyte4 (*funcPtrSrtpEncodeCallback)(sbyte4 connectionInstance, void *pChannelDescr,
                                                                                const sbyte* pData, ubyte4 pDataLength,
                                                                                ubyte** encodedData, ubyte4* encodedLength));
#endif
typedef sbyte4 (*NSSLsetDHParameters)(ubyte *pP, ubyte4 pLen, ubyte *pG, ubyte4 gLen, ubyte4 lengthY);
typedef sbyte4 (*NSSLgetExportKeyMaterial)(sbyte4 connectionInstance, ubyte *pKey, ubyte2 keyLen,
                                           ubyte *pLabel, ubyte2 labelLen,
                                           ubyte *pContext, ubyte2 contextLen, int use_context);
typedef MSTATUS (*NSSLsetSessionResumeTimeout)(ubyte4 timeout);
typedef MSTATUS (*NSSLcryptoInterfaceRsaExtractKeyData)(AsymmetricKey *pKey, MRsaKeyTemplate *pTemplate, ubyte reqType);
typedef MSTATUS (*NSSLcryptoInterfaceFreeRsaTemplate)(AsymmetricKey *pKey, MRsaKeyTemplate *pTemplate);
typedef MSTATUS (*NSSLcryptoInterfaceDsaExtractKeyData)(AsymmetricKey *pKey, MDsaKeyTemplate *pTemplate, ubyte reqType);
typedef MSTATUS (*NSSLcryptoInterfaceFreeDsaTemplate)(AsymmetricKey *pKey, MDsaKeyTemplate *pTemplate);
typedef MSTATUS (*NSSLasn1EncodeSslSession)(
     ubyte *pSessionId, ubyte4 sessionIdLen, ubyte *pMasterSecret,
     ubyte4 masterSecretLen, sbyte *pDNSName, unsigned char *pRetBuffer, int *pRetLen);
typedef MSTATUS (*NSSLasn1DecodeSslSession)(
     ubyte *pBuffer, ubyte4 bufferLen, ubyte **ppRetSessionId,
     ubyte4 *pRetSessionIdLen, ubyte **ppRetMasterSecret,
     ubyte4 *pRetMasterSecretLen, sbyte **ppRetDNSName, ubyte4 *pRetDNSNameLen);
typedef sbyte4 (*NSSLsetMinRSAKeySize)(ubyte4 keySize);
typedef sbyte4 (*NSSLsetSha1SigAlg)(intBoolean setting);
typedef sbyte4 (*NSSLsetFIPSEnabled)(ubyte isFIPSEnabled);
typedef sbyte4 (*NSSLsslCheckFIPS)();
typedef sbyte4 (*NSSLsetDSACiphers)(sbyte4 connectionInstance, ubyte setDSACiphers);
typedef sbyte4 (*NSSLsetCertifcateStatusRequestExtensions)(
     sbyte4 connectionInstance, char **ppTrustedResponderCertPath,
     ubyte4 trustedResponderCertCount, extensions *pExts, ubyte4 extCount);
typedef MSTATUS (*NSSLdiffTime)(const TimeDate *pDT1, const TimeDate *pDT2, sbyte4 *pSecDiff);
typedef MSTATUS (*NSSLgetNewTime)(const TimeDate *pDT1, sbyte4 secDiff, TimeDate *pDT2);
typedef MSTATUS (*NSSLmocMalloc)(void **ppPtr, ubyte4 bufSize);
typedef MSTATUS (*NSSLmocFree)(void **ppPtr);

typedef MSTATUS (*NSSLrtosMutexCreate)(RTOS_MUTEX *pMutex, enum mutexTypes mutexType, int mutexCount);
typedef MSTATUS (*NSSLrtosMutexWait)(RTOS_MUTEX mutex);
typedef MSTATUS (*NSSLrtosMutexRelease)(RTOS_MUTEX mutex);
typedef MSTATUS (*NSSLrtosMutexFree)(RTOS_MUTEX *pMutex);
typedef MSTATUS (*NSSLsetClientSaveTicketCb)(sbyte4 connInstance,
                                             sbyte4 (*cb)(sbyte4 connectionInstance,
                                                          sbyte *serverInfo, ubyte4 serverInfoLen,
                                                          void *userData, ubyte *pTicket, ubyte4 ticketLen));
typedef MSTATUS (*NSSLsetClientRetrieveTicketCb)(sbyte4 connectionInstance,
                                                 sbyte4 (*cb)(sbyte4 connectionInstance,
                                                              sbyte *serverInfo, ubyte4 serverInfoLen,
                                                              void *userData, ubyte **ppTicket, ubyte4 *pTicketLen,
                                                              intBoolean *pFreememory));
typedef MSTATUS (*NSSLdeserializeTicket)(ubyte *pTicket, ubyte4 ticketLen, OSSL_sessionTicket **ppRetTicket);
typedef MSTATUS (*NSSLfreeTicket)(OSSL_sessionTicket **ppTicket);
typedef MSTATUS (*NSSLisSessionResumed)(sbyte4 connectionInstance, intBoolean *pIsResumed);

typedef MSTATUS (*NSSLhashTableAddPtr)(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pAppData);
typedef MSTATUS (*NSSLhashTableCreatePtrsTable)(hashTableOfPtrs **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie,
                                              funcPtrAllocHashPtrElement pFuncPtrAllocHashPtrElement, funcPtrFreeHashPtrElement pFuncPtrFreeHashPtrElement);
typedef MSTATUS (*NSSLhashTableDeletePtr)(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData, funcPtrExtraMatchTest pFuncPtrExtraMatchTest, void **ppRetAppDataToDelete, intBoolean *pRetFoundHashValue);
typedef MSTATUS (*NSSLhashTableFindPtr)(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData, funcPtrExtraMatchTest pFuncPtrExtraMatchTest, void **ppRetAppData, intBoolean *pRetFoundHashValue);
typedef MSTATUS (*NSSLhashTableRemovePtrsTable)(hashTableOfPtrs *pFreeHashTable, void **ppRetHashCookie);

typedef struct nssl_methods {
     NSSLLibraryInit	      libraryInit;	        /* DIGICERT_initDigicert etc. */
     NSSLLibraryUnInit	      libraryUnInit;	    /* DIGICERT_free etc. */
     NSSLLibraryInitStaticMem libraryInitStaticMem; /* DIGICERT_initDigicertStaticMemory */
     NSSLLibraryReadFile      readFile;             /* DIGICERT_readFile */
     NSSLhashTableAddPtr           hashTableAddPtr;              /* HASH_TABLE_addPtr */
     NSSLhashTableCreatePtrsTable  hashTableCreatePtrsTable;     /* HASH_TABLE_createPtrsTable */
     NSSLhashTableDeletePtr        hashTableDeletePtr;           /* HASH_TABLE_deletePtr */
     NSSLhashTableFindPtr          hashTableFindPtr;             /* HASH_TABLE_findPtr */
     NSSLhashTableRemovePtrsTable  hashTableRemovePtrsTable;     /* HASH_TABLE_removePtrsTable */
     NSSLsslInit	          sslInit;		        /* SSL_ASYNC_init */
     NSSLsslShutdown          sslShutdown;          /* SSL_OSSL_shutdown */
     NSSLsslReleaseTables     sslReleaseTables;     /* SSL_OSSL_releaseTables */
     NSSLparseSslBuffer	      parseSslBuf; 	        /* SSL_ASYNC_recvMessage2 */
     NSSLreadSslRecord 	      readSslRec; 	        /* SSL_ASYNC_getRecvBuffer */
     NSSLprepareSslRecord     prepareSslRec;	   /* SSL_ASYNC_sendMessage  */
     NSSLgetPreparedSslBuffer getPreparedSslRec;   /* SSL_ASYNC_getSendBuffer  */
     NSSLgetPreparedSslBufferZC getPreparedSslRecZC; /* Zero-copy version of above */
     NSSLreleaseZCsendBuffer  releaseZCsendBuffer; /* SSL_ASYNC_freeSendBufferZeroCopy */
     NSSLaccept		          accept;		        /* SSL_ASYNC_acceptConnection */
     NSSLconnect	          connect;	           /* SSL_ASYNC_connect */
     NSSLclientTriggerHello   triggerHello;	       /* SSL_ASYNC_start */
     NSSLcloseConnection      closeConnection;	   /* SSL_ASYNC_closeConnection */
     NSSLisSslEstablished     isEstablished;	   /* SSL_isSecureConnectionEstablished */
     NSSLinConnectInit	      inConnectInit;	   /* SSL_in_connect_init */
     NSSLsetSessionFlags      setSessionFlags;     /* SSL_setSessionFlags */
     NSSLgetSessionFlags      getSessionFlags;     /* SSL_getSessionFlags */
     NSSLsetCiphers	          setCiphers;	       /* SSL_enableCiphers */
     NSSLsetECCCurves         setEccCurves;        /* SSL_enableECCCurves */
     NSSLdisableCipherHash    disableCipherHash;    /* SSL_disableCipherHashAlgorithm */
     NSSLgetCipherInfo        getCipherInfo;       /* SSL_getCipherInfo*/
     NSSLgetSigAlgo           sslGetSigAlgo;       /* SSL_getSignatureAlgo */
#if defined(__ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__) && \
    defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
     NSSLparseDigestInfo      parseDigestInfo;     /* ASN1_parseDigestInfo */
#endif
     NSSLgetSSLTLSVersion     sslGetSSLTLSVersion; /* SSL_getSSLTLSVersion */
     NSSLgetSessionStatus     getSessionStatus;    /* SSL_getSessionStatus */
     NSSLcreateCertStore      createCertStore;     /* CERT_STORE_createStore */
     NSSLgetPeerCertificateBytes  getPeerCertificateBytes; /* SSL_SOCK_getPeerCertificateBytes*/
     NSSLreleaseCertStore     releaseCertStore;    /* CERT_STORE_releaseStore */
     NSSLaddIdentityCertChain addIdenCertChain;    /* CERT_STORE_addIdentityWithCertificateChain */
     NSSLaddIdentityCertChainExtData addIdenCertChainExtData; /* CERT_STORE_addIdentityWithCertificateChainExtData */
     NSSLaddTrustPoint	      addTrustPoint;	   /* */
     NSSLvalidateCertKeyChain validateCertKeyChain; /* SSL_OSSL_validateCertKeyChain */
     NSSLsslIoctl             sslIoctl;            /* SSL_ioctl */
     NSSLsslSettingsIoctl     sslSettingsIoctl;    /* SSL_Settings_Ioctl */
     NSSLsslSetMinVersion     sslSetMinVersion;    /* SSL_setMinProtoVersion */
     NSSLsslGetMinVersion     sslGetMinVersion;    /* SSL_getMinProtoVersion */
     NSSLsslSetMaxVersion     sslSetMaxVersion;    /* SSL_setMaxProtoVersion */
     NSSLsslGetMaxVersion     sslGetMaxVersion;    /* SSL_getMaxProtoVersion */
     NSSLsslGetVersion        sslGetVersion;       /* SSL_getProtoVersion */
     NSSLsslInitializeVersion sslInitializeVersion;/* SSL_initializeVersion */
     NSSLsslClearAllSessionCache sslClearAllSessionCache; /* SSL_clearAllSessionCache */
#if 0
     /* This callback has been replaced by NSSLsetCertAndStatusCallback */
     NSSLsetAppCertVrfyCB     setAppCertVrfyCB;	   /* */
#endif
     NSSLrsaParamsToKeyBlob   rsaParamsToKeyBlob;  /* SSL_OSSL_RSAParamsToKeyBlob */
     NSSLdsaParamsToKeyBlob   dsaParamsToKeyBlob;  /* SSL_OSSL_DSAParamsToKeyBlob */
#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
     NSSLrehandshakeInit      rehandshakeInit;     /* SSL_rehandshakeInit */
     NSSLinitiateRehandshake  initiateRehandshake; /* SSL_initiateRehandshake */
     NSSLisRehandshakeAllowed isRehandshakeAllowed;/* SSL_isRehandshakeAllowed */
     NSSLgetTlsUnique         getTlsUnique;         /* SSL_getTlsUnique */
#endif
#if (defined (__ENABLE_DIGICERT_ECC__))
     NSSLeccParamsToKeyBlob   eccParamsToKeyBlob;  /* SSL_OSSL_ECCParamsToKeyBlob */
     NSSLextractEcKeyData     extractEcKeyData;    /* SSL_extractEcKeyData */
     NSSLfreeEcKeyData        freeEcKeyData;       /* SSL_freeEcKeyData */
     NSSLgetEcCurveId         getEcCurveId;        /* SSL_getEcCurveId */
#endif
#ifdef __ENABLE_DIGICERT_SERIALIZE__
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     NSSLdeserializeAsymKeyWithCreds deserializeAsymKeyWithCreds; /* SSL_DeserializeAsymKey */
     NSSLtapUnloadKey tapUnloadKey; /* SSL_tapUnloadKey */
#endif
     NSSLdeserializeAsymKey deserializeAsymKey;       /* SSL_DeserializeAsymKey */
     NSSLserializeAsymKeyAlloc serializeAsymKeyAlloc; /* SSL_SerializeAsymKeyAlloc */
#endif /* __ENABLE_DIGICERT_TAP__ */
     NSSLdeserializeKey       deserializeKey;      /* SSL_DeserializeKey */
#endif /* __ENABLE_DIGICERT_SERIALIZE__ */
     NSSLmakeKeyBlobEx        makeKeyBlobEx;       /* KEYBLOB_makeKeyBlobEx */
     NSSLdecryptPKCS8PemKey   decryptPKCS8PemKey;  /* SSL_decryptPKCS8PemKey */
     NSSLinitAsymmetricKey    initAsymmetricKey;   /* SSL_InitAsymmetricKey */
     NSSLuninitAsymmetricKey  uninitAsymmetricKey; /* SSL_UninitAsymmetricKey */
     NSSLKeyAssociateTapContext  keyAssociateTapContext; /* SSL_KeyAssociateTapContext */
     NSSLget_alpn            get_alpn_selected;   /* SSL_getSelectedApplicationProtocol*/
     NSSLset_alpn            set_alpn_protos;     /* SSL_setApplicationLayerProtocol*/
     NSSLset_alpn_callback   set_alpn_callback;   /* SSL_setAlpnCallback */
     NSSLset_alert_callback  set_alert_callback;  /* SSL_setAlertCallback */
     NSSLsslParseAlert        sslParseAlert;       /* SSL_parseAlert */
     NSSLsslSendAlert         sslSendAlert;        /* SSL_sendAlert */
     NSSLSetClientHelloCallback setClientHelloCallback; /* SSL_OSSL_setClientHelloCallback */
     NSSLreceivePending       recvPending;
     NSSLgetClientSessionInfo getClientSessionInfo; /*SSL_getClientSessionInfo*/
     NSSLsetDNSNames          setDNSNames;          /*SSL_setDNSName*/
     NSSLsetServerNameExtension  setServerNameExtension;    /*SSL_setServerNameExtension*/
     NSSLsetCertAndStatusCallback    setCertAndStatusCallBack;    /* SSL_setCertAndStatusCallback*/
     NSSLsetClientCertAuthorityCallback    setClientCertAuthorityCallback;    /* SSL_setClientCertAuthorityCallback */
     NSSLsetClientCertCallback setClientCertCallback; /* SSL_setClientCertCallback */
     NSSLsetCertVerifySignCallback setCertVerifySignCallback; /* SSL_setCertVerifySignCallback */
     NSSLsetVersionCallback   setVersionCallback;   /* SSL_setVersionCallback */
     NSSLsetClientCAList      setClientCAList;      /* SSL_setClientCAList */
#if defined (__ENABLE_DIGICERT_DTLS_SERVER__)
     NSSLdtlsVerifyClientHelloCookie  dtlsVerifyClientHelloCookie; /* SSL_DTLS_verifyClientHelloCookie */
#endif
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined (__ENABLE_DIGICERT_DTLS_SERVER__)
     NSSLdtlsInit             dtlsInit;             /* SSL_DTLS_init */
     NSSLclientDtlsTriggerHello triggerDtlsHello;   /* SSL_DTLS_start */
     NSSLdtlsConnect          dtlsConnect;          /* SSL_DTLS_connect */
     NSSLdtlsAccept           dtlsAccept;           /* SSL_DTLS_accept */
     NSSLdtlsIoctl            dtlsIoctl;            /* SSL_DTLS_ioctl*/
     NSSLdtlsGetSendBuffer    dtlsGetSendBuffer;    /* SSL_DTLS_getSendBuffer*/
     NSSLdtlsSendMessage      dtlsSendMessage;      /* SSL_DTLS_sendMessage */
     NSSLdtlsParseSslBuf      dtlsParseSslBuf;      /* SSL_DTLS_parseSslBuf */
     NSSLdtlsReadSslRec       dtlsReadSslRec;       /* SSL_DTLS_readSslRec */
     NSSLdtlsCloseConnection  dtlsCloseConnection;  /* SSL_DTLS_closeConnection */
     NSSLdtlsGetTimeout       dtlsGetTimeout;       /* SSL_DTLS_getTimeout */
     NSSLdtlsHandleTimeout    dtlsHandleTimeout;    /* SSL_DTLS_handleTimeout */
     NSSLdtlsShutdown         dtlsShutdown;         /* SSL_DTLS_shutdown */
     NSSLsetSrtpProfiles      setSrtpProfiles;      /* SSL_enableSrtpProfiles */
     NSSLsetSrtpInitCallback  setSrtpInitCallback;  /* SSL_setSrtpInitCallback */
     NSSLsetSrtpEncodeCallback setSrtpEncodeCallback; /* SSL_setSrtpEncodeCallback */
#endif
     NSSLsetDHParameters      setDHParameters;      /* SSL_setDHParameters */
     NSSLgetExportKeyMaterial getExportKeyMaterial; /* SSL_generateTLSExpansionKey */
     NSSLsetSessionResumeTimeout setSessionResumeTimeout; /*  SSL_SOCK_setSessionResumeTimeout */
     NSSLcryptoInterfaceRsaExtractKeyData  extractRsaKeyData; /* SSL_extractRsaKeyData */
     NSSLcryptoInterfaceFreeRsaTemplate    freeRsaKeyTemplate; /* SSL_freeRsaKeyTemplate */
     NSSLcryptoInterfaceDsaExtractKeyData  extractDsaKeyData;  /* SSL_extractDsaKeyData */
     NSSLcryptoInterfaceFreeDsaTemplate    freeDsaKeyTemplate; /* SSL_freeDsaKeyTemplate */
     NSSLasn1EncodeSslSession asn1EncodeSslSession; /* SSL_asn1EncodeSslSession */
     NSSLasn1DecodeSslSession asn1DecodeSslSession; /* SSL_asn1DecodeSslSession */
     NSSLisSessionResumed     isSessionResumed;     /* SSL_isSessionResumed */
     NSSLsetMinRSAKeySize     setMinRSAKeySize;     /* SSL_setMinRSAKeySize */
     NSSLsetSha1SigAlg        setSha1SigAlg;        /* SSL_setSha1SigAlg */
     NSSLsetFIPSEnabled       setFIPSEnabled;       /* SSL_setFIPSEnabled */
     NSSLsslCheckFIPS         sslCheckFIPS;         /* SSL_checkFIPS */
     NSSLsetDSACiphers        setDSACiphers;        /* SSL_setDSACiphers */
     NSSLdiffTime             diffTime;             /* DATETIME_diffTime */
     NSSLgetNewTime           getNewTime;           /* DATETIME_getNewTime */
     NSSLmocMalloc            mocMalloc;            /* DIGI_MALLOC */
     NSSLmocFree              mocFree;              /* DIGI_FREE */
     NSSLgetSharedSignatureAlgorithm      getSharedSignatureAlgorithm;        /*  SSL_getSharedSignatureAlgorithm */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     NSSLsendPostHandshakeAuthCertReq     sendPostHandshakeAuthCertRequest;   /*  SSL_sendPosthandshakeAuthCertificateRequest */
     NSSLsetPskFindSessionCb              setPskFindSessionCb;                /*  SSL_setServerLookupPSKCallback  */
     NSSLsetPskUseSessionCb               setPskUseSessionCb;                 /*  SSL_CLIENT_setRetrievePSKCallback  */
     NSSLsavePskSessionCb                 savePskSessionCb;                   /*  SSL_setClientSavePSKCallback  */
     NSSLsaveServerPskSessionCb           saveServerPskSessionCb;             /*  SSL_setServerSavePSKCallback */
     NSSLdeserializePsk                   deserializePsk;                     /*  SSL_deserializePsk */
     NSSLserializePsk                     serializePsk;                       /*  SSL_serializePsk */
     NSSLfreePsk                          freePsk;                            /*  SSL_freePSK */
     NSSLsendKeyUpdate                    sendKeyUpdate;                      /*  SSL_sendKeyUpdateRequest  */
     NSSLsetEarlyData                     setEarlyData;                       /*  SSL_setEarlyData */
     NSSLgetEarlyDataState                getEarlyDataState;                  /*  SSL_getEarlyDataState */
#endif  /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__  */
     NSSLgetLocalState                    getLocalState;                      /*  SSL_getLocalState */
     NSSLsslGetState                      sslGetState;                        /*  SSL_getState */
     NSSLsetCipherAlgorithm               setCipherAlgorithm;                 /*  SSL_setCipherAlgorithm */
     NSSLrtosMutexCreate                  rtosMutexCreate;                    /*  RTOS_mutexCreate */
     NSSLrtosMutexWait                    rtosMutexWait;                      /*  RTOS_mutexWait */
     NSSLrtosMutexRelease                 rtosMutexRelease;                   /*  RTOS_mutexRelease */
     NSSLrtosMutexFree                    rtosMutexFree;                      /*  RTOS_mutexFree */
     NSSLsetCertifcateStatusRequestExtensions setCertifcateStatusRequestExtensions; /* SSL_setCertifcateStatusRequestExtensions */
     NSSLsetOCSPCallback                  setOCSPCallback;                    /* SSL_setOCSPCallback */
#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
     NSSLsetClientSaveTicketCb            setClientSaveTicketCb;              /* SSL_setClientSaveTicketCallback */
     NSSLsetClientRetrieveTicketCb        setClientRetrieveTicketCb;          /* SSL_setClientRetrieveTicketCallback */
     NSSLdeserializeTicket                deserializeTicket;                  /* SSL_deserializeSessionTicket */
     NSSLfreeTicket                       freeTicket;                         /* SSL_freeSessionTicket */
#endif
} nssl_methods_t;

extern int gNsslMethodsValid;
extern nssl_methods_t gNsslMethods;
MOC_EXTERN sbyte4 SSL_bindShimMethods(nssl_methods_t *pMeth);
#define NSSL_CHK_CALL(fld, arg1, ...)	( (gNsslMethodsValid && (NULL != gNsslMethods.fld)) ? (MSTATUS) (*gNsslMethods.fld)(arg1, ## __VA_ARGS__) : (MSTATUS) -1)

#define OSSL_MALLOC 	malloc
#define OSSL_CALLOC 	calloc
#define OSSL_FREE	    free

extern int OSSL_bindMethods(nssl_methods_t *pMeth);

#endif
