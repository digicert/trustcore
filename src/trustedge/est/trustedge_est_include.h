/**
 * trustedge_est_include.h
 *
 * @file  trustedge_est_include.h
 * @brief Include file for EST.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#ifndef __EST_INCLUDE_H__
#define __EST_INCLUDE_H__

#include "../../cert_enroll/cert_enroll.h"
#include "../../crypto/tools/crypto_keygen.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs7.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TAP key usage enumerations */
#define ESTC_TAP_KEY_USAGE_SIGNING  "SIGNING"
#define ESTC_TAP_KEY_USAGE_DECRYPT  "DECRYPT"
#define ESTC_TAP_KEY_USAGE_GENERAL  "GENERAL"
#define ESTC_TAP_KEY_USAGE_ATTEST   "ATTEST"

/* TAP signing scheme enumerations */
#define ESTC_TAP_SIG_SCHEME_NONE            "NONE"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5         "PKCS1_5"
#define ESTC_TAP_SIG_SCHEME_PSS_SHA1        "PSS_SHA1"
#define ESTC_TAP_SIG_SCHEME_PSS_SHA256      "PSS_SHA256"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5_SHA1    "PKCS1_5_SHA1"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5_SHA256  "PKCS1_5_SHA256"
#define ESTC_TAP_SIG_SCHEME_PKCS1_5_DER     "PKCS1_5_DER"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA1      "ECDSA_SHA1"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA224    "ECDSA_SHA224"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA256    "ECDSA_SHA256"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA384    "ECDSA_SHA384"
#define ESTC_TAP_SIG_SCHEME_ECDSA_SHA512    "ECDSA_SHA512"

/* TAP encryption scheme enumerations */
#define ESTC_TAP_ENC_SCHEME_NONE            "NONE"
#define ESTC_TAP_ENC_SCHEME_PKCS1_5         "PKCS1_5"
#define ESTC_TAP_ENC_SCHEME_OAEP_SHA1       "OAEP_SHA1"
#define ESTC_TAP_ENC_SCHEME_OAEP_SHA256     "OAEP_SHA256"

/* TAP hierarchy enumerations */
#define ESTC_TAP_HIERARCHY_STORAGE      "STORAGE"
#define ESTC_TAP_HIERARCHY_ENDORSEMENT  "ENDORSEMENT"
#define ESTC_TAP_HIERARCHY_PLATFORM     "PLATFORM"

/*------------------------------------------------------------------*/

#define MAX_NUM_HTTP_CLIENT_SESSIONS    		(10)
#define MAX_NUM_HTTP_SERVER_SESSIONS    		(10)
#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
#define MAX_SSL_SERVER_CONNECTIONS_ALLOWED       (0)
#endif
#define MAX_SSL_CLIENT_CONNECTIONS_ALLOWED      (10)
#define KEY_TYPE_RSA         "RSA"
#define KEY_TYPE_ECDSA       "ECDSA"
#define KEY_TYPE_EDDSA       "EDDSA"
#ifdef __ENABLE_DIGICERT_PQC__
#define KEY_TYPE_QS          "QS"
#define KEY_TYPE_HYBRID      "HYBRID"
#endif

#define EST_DEFAULT_SERVER_URL          "/.well-known/est"
/*Special case to handle keygeneration and csr generation of simpleenroll*/
#define SIMPLEENROLL_KEYGEN_AND_CSRGEN "simpleenroll_genkey_gencsr"
#define DEFAULT_DIGEST_NAME             "SHA256"
#define DIGEST_NAME_SHA224              "SHA224"
#define DIGEST_NAME_SHA384              "SHA384"
#define DIGEST_NAME_SHA512              "SHA512"
#define CURVE_P256                      "P256"
#define CURVE_P384                      "P384"
#define CURVE_P521                      "P521"
#define PKCS8_ENC_ALG_P5_V1_SHA1_DES    "p5_v1_sha1_des"
#define PKCS8_ENC_ALG_P5_V1_SHA1_RC2    "p5_v1_sha1_rc2"
#define PKCS8_ENC_ALG_P5_V1_MD2_DES     "p5_v1_md2_des"
#define PKCS8_ENC_ALG_P5_V1_MD2_RC2     "p5_v1_md2_rc2"
#define PKCS8_ENC_ALG_P5_V1_MD5_DES     "p5_v1_md5_des"
#define PKCS8_ENC_ALG_P5_V1_MD5_RC2     "p5_v1_md5_rc2"
#define PKCS8_ENC_ALG_P5_V2_3DES        "p5_v2_3des"
#define PKCS8_ENC_ALG_P5_V2_DES         "p5_v2_des"
#define PKCS8_ENC_ALG_P5_V2_RC2         "p5_v2_rc2"
#define PKCS8_ENC_ALG_P5_V2_AES128      "p5_v2_aes128"
#define PKCS8_ENC_ALG_P5_V2_AES192      "p5_v2_aes192"
#define PKCS8_ENC_ALG_P5_V2_AES256      "p5_v2_aes256"
#define PKCS8_ENC_ALG_DEFAULT           PKCS8_ENC_ALG_P5_V2_AES256
#define PKCS12_ENC_ALG_SHA_2DES         "sha_2des"
#define PKCS12_ENC_ALG_SHA_3DES         "sha_3des"
#define PKCS12_ENC_ALG_SHA_RC2_40       "sha_rc2_40"
#define PKCS12_ENC_ALG_SHA_RC2_128      "sha_rc2_128"
#define PKCS12_ENC_ALG_SHA_RC4_40       "sha_rc4_40"
#define PKCS12_ENC_ALG_SHA_RC4_128      "sha_rc4_128"
#define PKCS12_ENC_ALG_DEFAULT          PKCS12_ENC_ALG_SHA_3DES
#define DEFAULT_CONF_FILE               "csr.conf"
#if !defined(__RTOS_ZEPHYR__)
/* zephyr defines this in fs_interface.h to 255 */
#define MAX_FILE_NAME                   100
#endif
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __RTOS_WIN32__
#define TPM2_CONFIGURATION_FILE        "tpm2.conf"
#define TPM12_CONFIGURATION            "tpm12.conf"
#define PKCS11_CONFIGURATION           "pkcs11_smp.conf"
#define TEE_CONFIGURATION              "tee_smp.conf"
#define NANOROOT_CONFIGURATION         "nanoroot_smp.conf"
#else
#include "../../common/tpm2_path.h"
#define TPM12_CONFIGURATION             "/etc/digicert/tpm12.conf"
#define PKCS11_CONFIGURATION            "/etc/digicert/pkcs11_smp.conf"
#define TEE_CONFIGURATION               "/etc/digicert/tee_smp.conf"
#define NANOROOT_CONFIGURATION          "/etc/digicert/nanoroot_smp.conf"
#endif
#define ESTC_DEF_TAP_MODULEID           1
#define DEFAULT_TAP_REMOTE_SERVER_NAME      "127.0.0.1"
#define DEFAULT_TAP_REMOTE_SERVER_PORT      8277
#endif
#define ESTC_MAX_INT        "2147483647"
#define ESTC_HEX_IDENTIFIER "0x"

#define ESTC_DEF_IP            		"216.168.245.10"
#define ESTC_DEF_PORT          		443
#define KEY_SOURCE_SW               "SW"
#define ESTC_DEF_KEYSOURCE          KEY_SOURCE_SW
#define ESTC_DEF_USER          		"estuser"
#define ESTC_DEF_PASS          		"estpass"
#define ESTC_DEF_SKG_CLIENTKEY_ALIAS "client_rsa"
#define ESTC_DEF_SERVER_NAME   		"clientauth.demo.one.digicert.com"
#define ESTC_ENC_ALGO_ID_AES_192    "2.16.840.1.101.3.4.1.22"
#define ESTC_ENC_ALGO_ID_3DES       "1.2.840.113549.3.7"
#define ESTC_DEF_ENC_ALGO_ID        ESTC_ENC_ALGO_ID_AES_192
#define REQ_PKI_COMPONENT           "req"
#define PSK_PKI_COMPONENT           "psks"
#define ESTC_EXT_DER                ".der"
#define ESTC_EXT_PEM                ".pem"
#define ESTC_EXT_OLD                ".old"
#if defined( __FREERTOS_RTOS__)
#define ESTC_EXT_TAPKEY             ".tpk"
#else
#define ESTC_EXT_TAPKEY             ".tapkey"
#endif
#define ESTC_EXT_PKCS12             ".pfx"
#define ESTC_RETRY_WAIT_SECONDS_MAX  (300)
#define USER_PASSWORD_LENGTH         32
#define EST_PKCS8                 "application/pkcs8"
#define EST_FULL_CMC_PKCS_MIME    "application/pkcs7-mime"
#define DECRYPT_KEY_ID  0
#define ASYM_DECRYPT_KEY_ID  1
#define FULL_CMC_REQ_TYPE_ENROLL  "enroll"
#define FULL_CMC_REQ_TYPE_RENEW   "renew"
#define FULL_CMC_REQ_TYPE_REKEY   "rekey"
#define SIMPLE_ENROLL_CSR_FILE    "simple_enroll_csr.pem"
#define SIMPLE_REENROLL_CSR_FILE  "simple_reenroll_csr.pem"
#define FULLCMC_CSR_FILE          "pkcs7.csr"
#define SERVERKEYGEN_CSR_FILE     "server_keygen_csr.csr"
#define CACERTS_RESP_FILE         "cacerts"
#define CSRATTRS_RESP_FILE        "csrattrs.pem"
#define SERVERKEYGEN_KEY_FILE     "server_key_gen_key"
#define KEY_SOURCE_TPM2           "TPM2"
#define KEY_SOURCE_PKCS11         "PKCS11"
#define KEY_SOURCE_TEE            "TEE"
#define KEY_SOURCE_NANOROOT       "NANOROOT"
#define EST_SIMPLE_ENROLL_CMD     "simpleenroll"
#define EST_SIMPLE_REENROLL_CMD   "simplereenroll"
#define EST_FULL_CMC_CMD          "fullcmc"
#define EST_CSR_ATTRS_CMD         "csrattrs"
#define EST_CACERTS_CMD           "cacerts"
#define EST_KEYGEN_CMD            "serverkeygen"

#ifndef ESTC_MAX_RENEW_WINDOW_SIZE
#define ESTC_MAX_RENEW_WINDOW_SIZE (0)
#endif

/*------------------------------------------------------------------*/

enum EstOperation{
  EST_GETCA_CERTS=1,
  EST_GETCSR_ATTRS,
  EST_FULLCMC,
  EST_SERVERKEYGEN,
  EST_SIMPLE_ENROLL,
  EST_SIMPLE_REENROLL,
  EST_TCUS_SIGNING_CERTS,
  EST_TCUS_TRUST_CERTS
};

typedef struct _EstPskList {
    sbyte *pCmdArg;
    sbyte *pOid;
} EstPskList;

typedef struct _EstCmdFullCmcInfo {
    sbyte *pFullCmcReqType;
    sbyte  *pRekeyKeyType;
    sbyte *pRekeyKeyAlias;
    ubyte2  usRekeyKeySize;

} EstCmdFullCmcInfo;

enum requestMethod
{
    SIMPLE_ENROLL=1,
    SIMPLE_REENROLL,
    FULLCMC,
    SERVER_KEYGEN,
    CA_CERTS,
    CSR_ATTRS,
    CERTS_DOWNLOAD
};

typedef struct _EstServiceCtx
{
    ubyte4 cmdStatus;
    byteBoolean serviceMode;
    ubyte *pCSRAttrBuffer;
    ubyte4 csrAttrBufferLen;
    sbyte4 maxRetryCount;
    byteBoolean reuseKey;
} EstServiceCtx;
typedef struct _TrustEdgeEstCtx {
    sbyte   *pServerIp;
    ubyte2  usServerPort;
    ubyte2  usKeySize;
    sbyte   *pServerName;
    sbyte   *pUserName;
    sbyte   *pUserPasswd;
    intBoolean isEnteredPass;
    intBoolean cacertTag;
    intBoolean disableCACert;
    intBoolean isOcspRequired;
    intBoolean isIdHex;
    sbyte  *pTlsCert;
    ubyte  *pCAPrefix;
    sbyte  *pNewKeyType;
    ubyte2 newKeySize;
    sbyte  *pTrustPath;
    sbyte  *pRootCA;
    sbyte  *pKeyType;
    sbyte  *pKeySource;
    sbyte  *pKeyAlias;
    sbyte  *pKeyAlias2;
    sbyte  *pSkPskAlias;
    sbyte  *pSkClntCert;
    sbyte  *pSkClntKey;
    ubyte8 skKeyType;
    sbyte  *pDigestName;
    sbyte  *pSkAlg;
    sbyte  *pUserAgent;
    EstCmdFullCmcInfo fullCmcReq;
    ubyte4 fullCMCRequestType;
    enum requestMethod requestType;
    sbyte  *pExtAttrConfFile;
    ubyte2 hasAttrib;
    sbyte  *pUrl;
    sbyte  *pPkcs8Pw;
    sbyte  *pPkcs8EncAlg;
    byteBoolean pkcs8InteractivePass;
    enum PKCS8EncryptionType pkcs8EncType;
    sbyte  pkcs12Gen;
    sbyte  *pPkcs12EncAlg;
    sbyte  *pPkcs12IntPw;
    sbyte  *pPkcs12PriPw;
    sbyte  *pPkcs12KeyPw;
    ubyte4 pkcs12EncType;
    sbyte4 renewWindow;
    intBoolean renewWindowSet;
    sbyte   renewinlinecert;
    httpContext* pHttpContext;
#ifdef __ENABLE_DIGICERT_TAP__
    TAP_Buffer tapKeyHandle;
    sbyte  *pTapKeyHandleStr;
    intBoolean tapKeyHandleSet;
    sbyte  *pTapCertificateNvIndexStr;
    intBoolean tapCertificateNvIndexSet;
    ubyte8 tapCertificateNvIndex;
    intBoolean tapKeyPrimary;
    sbyte  *pTapKeyNonceNvIndex;
    intBoolean tapKeyNonceNvIndexSet;
    sbyte  *pTapKeyTokenHierarchy;
    intBoolean tapTokenHierarchySet;
    ubyte8 tapKeyNonceNvIndex;
    TAP_TokenId tapTokenHierarchy;
#ifdef __ENABLE_DIGICERT_TEE__
    sbyte4 useTEE;
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    sbyte4 useNanoRoot;
#endif
#endif
    sbyte *pAuthScheme;
    ubyte  *pAuthStr;
    ubyte4 authStrLen;
    ubyte4 index;
    sbyte4 verboseLevel;
    EstServiceCtx serviceCtx;
    intBoolean requirePQC;
    ExtendedEnrollFlow flow;
    byteBoolean estEndpointProvided;
} TrustEdgeEstCtx ;

MOC_EXTERN MSTATUS TRUSTEDGE_EST_utilStrToInt(sbyte *pStr, ubyte8 *pInt);
MOC_EXTERN MSTATUS TRUSTEDGE_EST_constructCertStoreFromDir(struct certStore* pCertStoreForValidation, sbyte *pCertPath);
MOC_EXTERN void TRUSTEDGE_EST_setVerboseLevel(ubyte4 level);

MOC_EXTERN MSTATUS TRUSTEDGE_EST_verifyFullcmcResponseWithValidateCb(
    ASN1_ITEMPTR pRoot,
    CStream pkcs7Stream,
    void *pArg,
    PKCS7_ValidateRootCertificate validationCb,
    ASN1_ITEMPTR *pSignerIssuer,
    ASN1_ITEMPTR *pSignerSerial);

MOC_EXTERN MSTATUS TRUSTEDGE_EST_verifyFullcmcResponse(ASN1_ITEMPTR pRoot, CStream pkcs7Stream, certStorePtr pStore, ASN1_ITEMPTR *pSignerIssuer, ASN1_ITEMPTR *pSignerSerial);
MOC_EXTERN MSTATUS TRUSTEDGE_EST_removeOtherCertificates(SizedBuffer **ppCerts, ubyte4 *pCertCount);
MOC_EXTERN MSTATUS TRUSTEDGE_EST_parseEndpoint(sbyte *pEndpoint, sbyte **ppServerName, sbyte **ppUrl);

#ifdef __cplusplus
}
#endif

#endif /* __EST_INCLUDE_H__  */
