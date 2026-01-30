/**
 * @file  est_example_client.c
 * @brief EST Example Client Sample Application
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __RTOS_WIN32__
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#include <unistd.h>
#ifndef __RTOS_VXWORKS__
#include <termios.h>
#endif /* !__RTOS_VXWORKS__ */
#endif /* !__RTOS_AZURE__*/
#endif /* !__RTOS_FREERTOS__*/
#else
#include <Windows.h>
#include <conio.h>
#endif /* !__RTOS_WIN32__ */

#ifdef __RTOS_VXWORKS__
#include <stat.h>
#else /* __RTOS_VXWORKS__ */
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#include <sys/stat.h>
#endif /* !__RTOS_AZURE__ */
#endif /* !__RTOS_FREERTOS__ */
#endif /* __RTOS_VXWORKS__ */

#if defined(__RTOS_LINUX__)
#include <fcntl.h>
#endif /* __RTOS_LINUX__ */

#include "../common/moptions.h"
#include "../common/moc_net_system.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../ssl/ssl.h"
#include "../common/mdefs.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/sizedbuffer.h"
#include "../common/mstdlib.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/mjson.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/utils.h"
#include "../crypto/hw_accel.h"
#include "../common/base64.h"
#include "../common/datetime.h"
#include "../common/mfmgmt.h"
#include "../common/int64.h"
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/keyblob.h"
#include "../crypto/pkcs10.h"
#include "../crypto/crypto_utils.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#include "../http/http_auth.h"
#include "../http/client/http_request.h"
#include "../http/client/http_client_process.h"
#include "../est/est_context.h"
#include "../est/est_utils.h"
#include "../asn1/derencoder.h"
#include "../common/uri.h"
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#include "../common/mtcp_async.h"
#endif /*!__RTOS_AZURE__*/
#endif /*!__RTOS_FREERTOS__*/
#include "../crypto/md5.h"
#include "../common/debug_console.h"
#include "../est/est_cert_utils.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/mocasn1.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_hmac_kdf.h"
#endif
#include "../crypto/hmac_kdf.h"
#include "../crypto/moccms.h"
#include "../crypto/moccms_util.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/pkcs_key.h"
#include "../crypto/pkcs12.h"

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#endif

#ifdef  __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
#include "../tap/tap_conf_common.h"
#endif
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_tap.h"
#endif
#include "../est/est_client_api.h"

#ifdef __ENABLE_DIGICERT_TEE__
#include "../smp/smp_tee/smp_tap_tee.h"
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__FREERTOS_SIMULATOR__) && !defined(__RTOS_FREERTOS_ESP32__)
#include "FreeRTOS.h"
#include "semphr.h"
#include "ff.h"
#endif

#define VERBOSE_DEBUG   (1)

#define MAX_NUM_HTTP_CLIENT_SESSIONS    		(10)
#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
#define MAX_SSL_SERVER_CONNECTIONS_ALLOWED       (0)
#endif
#define MAX_SSL_CLIENT_CONNECTIONS_ALLOWED      (10)
#define KEY_TYPE_RSA         "RSA"
#define KEY_TYPE_ECDSA       "ECDSA"
#define KEY_TYPE_EDDSA       "EDDSA"
#ifdef __ENABLE_DIGICERT_PQC__
#define KEY_TYPE_HYBRID      "HYBRID"
#endif

#define DEFAULT_SERVER_IP    "216.168.245.10"
#define ESTC_DEF_PORT         443
#define DEFAULT_SERVER_USER  "estuser"
#define DEFAULT_SERVER_PASS  "estpass"

/*Special case to handle keygeneration and csr generation of simpleenroll*/
#define SIMPLEENROLL_KEYGEN_AND_CSRGEN "simpleenroll_genkey_gencsr"
#define DEFAULT_DIGEST_NAME  "SHA256"
#define CURVE_P256          "P256"
#define CURVE_P384          "P384"
#define CURVE_P521          "P521"
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
#define DEFAULT_CONF_FILE    "csr.conf"
#define MAX_CERT_PATH_NAME (230)
#define MAX_FILE_NAME (100)
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __RTOS_WIN32__
#define TPM2_CONFIGURATION        "tpm2.conf"
#define TPM12_CONFIGURATION       "tpm12.conf"
#define TEE_CONFIGURATION         "tee_smp.conf"
#else
#define TPM2_CONFIGURATION        "/etc/digicert/tpm2.conf"
#define TPM12_CONFIGURATION       "/etc/digicert/tpm12.conf"
#define PKCS11_CONFIGURATION      "/etc/digicert/pkcs11_smp.conf"
#define TEE_CONFIGURATION         "/etc/digicert/tee_smp.conf"
#endif
#define ESTC_DEF_TAP_MODULEID           1
#endif
#define ESTC_MAX_INT        "2147483647"
#define ESTC_HEX_IDENTIFIER "0x"

#define ESTC_DEF_NEW_KEYTYPE       	KEY_TYPE_RSA
#define KEY_SOURCE_SW               "SW"
#define ESTC_DEF_KEYSOURCE          KEY_SOURCE_SW
#define ESTC_DEF_KEYSIZE          	(2048)
#define ESTC_DEF_HASATTRIB          (0)
#if defined( __RTOS_WIN32__)
#define ESTC_DEF_CERTPATH_NAME  	"keystore"
#endif
#define ESTC_DEF_SKG_CLIENTKEY_ALIAS "client_rsa"
#define ESTC_DEF_SERVER_NAME   		"clientauth.demo.one.digicert.com"
#define ESTC_ENC_ALGO_ID_AES_192    "2.16.840.1.101.3.4.1.22"
#define ESTC_ENC_ALGO_ID_3DES       "1.2.840.113549.3.7"
#define ESTC_DEF_ENC_ALGO_ID        ESTC_ENC_ALGO_ID_AES_192
#define REQ_PKI_COMPONENT           "req"
#define PSK_PKI_COMPONENT           "psks"
#define ESTC_EXT_DER                ".der"
#define ESTC_EXT_PEM                ".pem"
#define ESTC_EXT_TAP_PASS           ".pass"
#define ESTC_EXT_OLD                ".old"
#if defined( __FREERTOS_RTOS__)
#define ESTC_EXT_TAPKEY             ".tpk"
#else
#define ESTC_EXT_TAPKEY             ".tapkey"
#endif
#define ESTC_EXT_TAPKEY_PEM         ".pemtap"
#define ESTC_EXT_PKCS12             ".pfx"
#define ESTC_RETRY_WAIT_SECONDS_MAX  (300)

#define ESTC_VERBOSE_LEVEL_DEFAULT  0
#define ESTC_VERBOSE_LEVEL_INFO     1
#define ESTC_VERBOSE_LEVEL_ALL      2

#define USER_PASSWORD_LENGTH    32

#define EST_PKCS8                 "application/pkcs8"
#define EST_FULL_CMC_PKCS_MIME    "application/pkcs7-mime"
#define MAX_RETRY_COUNT 5
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
#define KEY_SOURCE_TPM1_2         "TPM1.2"
#define KEY_SOURCE_TPM2           "TPM2"
#define KEY_SOURCE_PKCS11         "PKCS11"
#define KEY_SOURCE_NXPA71         "NXPA71"
#define KEY_SOURCE_STSAFE         "STSAFE"
#define KEY_SOURCE_TEE            "TEE"
#define EST_SIMPLE_ENROLL_CMD     "simpleenroll"
#define EST_SIMPLE_REENROLL_CMD   "simplereenroll"
#define EST_FULL_CMC_CMD          "fullcmc"
#define EST_CSR_ATTRS_CMD         "csrattrs"
#define EST_CACERTS_CMD           "cacerts"
#define EST_KEYGEN_CMD            "serverkeygen"

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

#ifndef MOCANA_CERT_VALIDITY_YEARS
#define MOCANA_CERT_VALIDITY_YEARS 1
#endif

#ifndef ESTC_MAX_RENEW_WINDOW_SIZE
#define ESTC_MAX_RENEW_WINDOW_SIZE (0)
#endif

/* Enable the '--keystore' runtime argument for overwriting the
 * parameter(s) saved in the trusted config file.
 * ONLY USE FOR DEBUGGING. Opens a hole when used!
 */
/* #define __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__ */

/*------------------------------------------------------------------*/

#ifdef __RTOS_WIN32__
#define SLEEP(X)    Sleep(X);
#elif (defined(__RTOS_FREERTOS__) || defined(__RTOS_AZURE__))
#define SLEEP(X)    RTOS_sleepMS(X*1000);
#else
#define SLEEP(X)    sleep(X);
#endif /* __RTOS_WIN32__ */

/*------------------------------------------------------------------*/
/* Parameters filled in from args (or elsewhere)                    */
/*------------------------------------------------------------------*/
static sbyte * 		   estc_ServerIpAddr   = NULL;
static ubyte2		   estc_ServerPort     = ESTC_DEF_PORT;
static sbyte * 		   estc_ServerURL      = NULL;
static sbyte * 		   estc_User           = NULL;
static sbyte * 		   estc_Pass           = NULL;
static sbyte * 		   estc_certPath       = NULL;
#ifndef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
static sbyte *         estc_truststorePath = NULL;
#endif
static sbyte *         estc_http_proxy    = NULL;
static sbyte * 		   estc_rootCA         = NULL;
static sbyte * 		   estc_tlscert        = NULL;
static sbyte * 		   estc_serverName     = NULL;
static sbyte * 		   estc_keyType		   = NULL;
static byteBoolean estc_endpointProvided = FALSE;
#ifdef __ENABLE_DIGICERT_PQC__
static sbyte *         estc_qskeytype      = NULL;
static sbyte *         estc_curve          = NULL;
#endif
static sbyte * 		   estc_newKeyType	   = NULL;
#ifdef __ENABLE_DIGICERT_TAP__
static ubyte2		   estc_tapModuleId	   = 0;
static sbyte * 		   estc_tap_confFile   = NULL;
static ubyte2 estc_tapProvider = 0;
static byteBoolean estc_tapKeySourceRuntime = FALSE;

#define  TPM12_EK_OBJECT_ID       0x0001
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
#define TPM2_EK_OBJECT_ID                        0x81010001
#else
#define TPM2_EK_OBJECT_ID                        0x81010000
#endif

/*
    Referenced from - tap_smp.h
    TAP KeyUsage
    0 = TAP_KEY_USAGE_UNDEFINED
    1 = TAP_KEY_USAGE_SIGNING
    2 = TAP_KEY_USAGE_DECRYPT
    3 = TAP_KEY_USAGE_GENERAL
    4 = TAP_KEY_USAGE_ATTESTATION
    TODO below need to suported.
    5 = TAP_KEY_USAGE_STORAGE
*/
static ubyte2          estc_tapKeyUsage   = TAP_KEY_USAGE_UNDEFINED;
/**
 *  Referenced from - tap_smp.h
 *  Supported Encryption schemes
 *   0 - TAP_ENC_SCHEME_NONE
 *   1 - TAP_ENC_SCHEME_PKCS1_5
 *   2 - TAP_ENC_SCHEME_OAEP_SHA1
 *   3 - TAP_ENC_SCHEME_OAEP_SHA256
 */
static ubyte2          estc_tapEncScheme  = TAP_ENC_SCHEME_NONE;
/**
 *  Referenced from - tap_smp.h
 *  Supported Signing schemes
 *  0 - TAP_SIG_SCHEME_NONE
 *  1 - TAP_SIG_SCHEME_PKCS1_5
 *  2 - TAP_SIG_SCHEME_PSS_SHA1
 *  3 - TAP_SIG_SCHEME_PSS_SHA256
 *  4 - TAP_SIG_SCHEME_PKCS1_5_SHA1
 *  5 - TAP_SIG_SCHEME_PKCS1_5_SHA256
 *  6 - TAP_SIG_SCHEME_PKCS1_5_DER
 *  7 - TAP_SIG_SCHEME_ECDSA_SHA1
 *  8 - TAP_SIG_SCHEME_ECDSA_SHA224
 *  9 - TAP_SIG_SCHEME_ECDSA_SHA256
 * 10 - TAP_SIG_SCHEME_ECDSA_SHA384
 * 11 - TAP_SIG_SCHEME_ECDSA_SHA512
 */
static ubyte2          estc_tapSignScheme = TAP_SIG_SCHEME_NONE;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
static sbyte *         estc_tap_serverName  = NULL;
static sbyte4          estc_tap_serverPort  = -1;
#endif
static sbyte *         estc_tap_keyPassword = NULL;
static intBoolean      estc_isIdHex = FALSE;
static sbyte          *estc_tapKeyHandleStr = NULL;
static TAP_Buffer      estc_tapKeyHandle = {0};
static intBoolean      estc_tapKeyHandleSet = FALSE;
static sbyte          *estc_tapCertificateNvIndexStr = NULL;
static ubyte8          estc_tapCertificateNvIndex = 0;
static intBoolean      estc_tapCertificateNvIndexSet = FALSE;
/* TAP key primary */
static intBoolean      estc_tapKeyPrimary = FALSE;
static intBoolean      estc_tapKeyPrimarySet = FALSE;
/* TAP key nonce NV index */
static sbyte          *estc_tapKeyNonceNvIndexStr = NULL;
static ubyte8          estc_tapKeyNonceNvIndex = 0;
static intBoolean      estc_tapKeyNonceNvIndexSet = FALSE;
/* TAP token hierarchy */
static sbyte          *estc_tapTokenHierarchyStr = NULL;
static TAP_TokenId     estc_tapTokenHierarchy = 0;
static intBoolean      estc_tapTokenHierarchySet = FALSE;
#endif
static sbyte * 		   estc_keySource	   = NULL;
static sbyte * 		   estc_confFile       = NULL;
static sbyte * 		   estc_extattrs_confFile  = NULL;
static sbyte * 		   estc_pskFile		   = NULL;
static sbyte * 		   estc_skgAlg		   = NULL;
static sbyte * 		   estc_userAgent	   = NULL;
static ubyte2 		   estc_keySize	       = ESTC_DEF_KEYSIZE;
#ifdef __ENABLE_DIGICERT_PQC__
static ubyte4          estc_qsAlg          = 0;
static ubyte4          estc_curveId        = 0;
#endif
static ubyte2 		   estc_newKeySize     = ESTC_DEF_KEYSIZE;
static sbyte4 		   estc_renewWindow    = 0;
static ubyte2 		   estc_hasAttrib	   = ESTC_DEF_HASATTRIB;
static ubyte * 		   estc_keyAlias1      = NULL;
static ubyte * 		   estc_keyAlias2      = NULL;
static sbyte * 		   estc_skg_clientcert = NULL;
static sbyte * 		   estc_skg_clientkey  = NULL;
static ubyte4 		   estc_skg_clientkeytype  = 0;
static sbyte * 		   estc_digestName     = NULL;
static sbyte * 		   est_fullcmcReqType  = NULL;
static sbyte * 		   estc_pkcs8Pw        = NULL;
byteBoolean            estcHasInteractiveTapPw    = FALSE;
byteBoolean            estcHasInteractivePkcs8Pw  = FALSE;
static sbyte * 		   estc_pkcs8EncAlg    = NULL;
static enum PKCS8EncryptionType estc_pkcs8EncType = PCKS8_EncryptionType_undefined;
static intBoolean      estc_pkcs12Gen      = FALSE;
static sbyte * 		   estc_pkcs12EncAlg   = NULL;
static sbyte * 		   estc_pkcs12IntPw    = NULL;
static sbyte * 		   estc_pkcs12PriPw    = NULL;
static sbyte * 		   estc_pkcs12KeyPw    = NULL;
static ubyte4 estc_pkcs12EncType = PKCS8_EncryptionType_pkcs12;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
static intBoolean      estc_fp_nocrypt = 0;
#endif
static intBoolean      estc_disable_cacert = 0;
static intBoolean      estc_renewinlinecert= 0;
static intBoolean      estc_renewinlinecertSet = FALSE;
static intBoolean      estc_ocsp_required  = 0;
static intBoolean      estc_ocspSet = FALSE;
static intBoolean      estc_renewWindowSet = FALSE;
static intBoolean      estc_genselfsignedcert = FALSE;
static sbyte4          estc_verboseLevel = ESTC_VERBOSE_LEVEL_INFO;
static ubyte4          estc_config_type = EST_CONFIG_FILE;
static ubyte4          estc_rootCA_type = EST_CONFIG_FILE;
static sbyte    *p_estc_csr_config = NULL;
static sbyte    *p_estc_extCsr_config = NULL;
static ubyte4   g_genKeySet = 0;
static ExtendedEnrollFlow estc_extEnrollFlow = EXT_ENROLL_FLOW_NONE;
static byteBoolean     estc_backup = FALSE;


static ubyte estc_skip_ssl_init = 0;
static sbyte* pPkiDatabase = NULL;
struct certStore* pCertStore = NULL;
static httpContext *gHttpContext = NULL;
sbyte4 gSslConnectionInstance;
#if defined(__ENABLE_DIGICERT_TAP__)
typedef struct EST_TapContext
{
    TAP_Context *pTapContext;
    TAP_EntityCredentialList *pEntityCredentialList;
    TAP_CredentialList *pKeyCredentialList;
} EST_TapContext;

static EST_TapContext *g_pEstTapContext = NULL;

typedef struct
{
    sbyte *pStr;
    ubyte2 value;
} EstStrMapping;

static sbyte4 useTAP = 0;

#ifdef __ENABLE_DIGICERT_TEE__
static sbyte4 useTEE = 0;
#endif

#endif /* __ENABLE_DIGICERT_TAP__ */

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
enum requestMethod gRequestType;

ubyte4 gFullCMCRequestType = REKEY;

#if defined( __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__ )
extern RTOS_SEM  g_tpla_sem ;
#endif /* if defined( __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__ ) */

static MSTATUS EST_EXAMPLE_CB_validateRootCertificate(const void* arg, CStream cs, struct ASN1_ITEM* pCertificate, sbyte4 chainLength);
static MSTATUS EST_EXAMPLE_constructCertStoreFromDir(struct certStore* pCertStoreForValidation);

static hwAccelDescr gHwAccelCtx = 0;
static AsymmetricKey *gpPrevAsymKey = NULL;

/* SDEC static VERBOSE METHODS */
/*****************************************************************************/
static void
verbosePrintString(int level, char *pPrintString)
{
    if (level <= estc_verboseLevel)
    {
        if (NULL != pPrintString)
        {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT ("%s", (char *)pPrintString);
#else
            printf("%s", (char *)pPrintString);
#endif
        }
    }
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

static void
verbosePrintStringLength(int level, char *pPrintString, int length)
{
    if (level <= estc_verboseLevel)
    {
        if (NULL != pPrintString)
        {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT ("%.*s", length, (char *)pPrintString);
#else
            printf ("%.*s", length, (char *)pPrintString);
#endif
        }
    }
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

static void
verbosePrintPointer(int level, char *pPrintString, ubyte *ptr)
{
    if (level <= estc_verboseLevel)
    {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
        DB_PRINT ("%s%p", pPrintString, ptr);
#else
        printf("%s%p", pPrintString, ptr);
#endif
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
    }
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

static void
verbosePrintNL(int level, char *pPrintString)
{
    if (level <= estc_verboseLevel)
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, pPrintString);
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
    }
}

static void
verbosePrintLengthNL(int level, char *pPrintString, int length)
{
    if (level <= estc_verboseLevel)
    {
        verbosePrintStringLength(ESTC_VERBOSE_LEVEL_INFO, pPrintString, length);
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
    }
}

static void
verbosePrintString1Int1NL(int level, char *pPrintString1, sbyte4 value1)
{
    if (level <= estc_verboseLevel)
    {
        if (NULL != pPrintString1)
        {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT ("%s", (char *)pPrintString1);
#else
            printf("%s", (char *)pPrintString1);
#endif
        }
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
        DB_PRINT ("%d", value1);
#else
        printf("%d", value1);
#endif
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
    }
}

static void
verbosePrintString1Hex(int level, ubyte value1)
{
    if (level <= estc_verboseLevel)
    {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
        DB_PRINT ("%02X", value1);
#else
        printf("%02X", value1);
#endif
    }
}

static void
verbosePrintString1Hex1NL(int level, char *pPrintString1, ubyte8 value1)
{
    if (level <= estc_verboseLevel)
    {
        if (NULL != pPrintString1)
        {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT ("%s", (char *)pPrintString1);
#else
            printf("%s", (char *)pPrintString1);
#endif
        }
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
        DB_PRINT ("%llX", value1);
#else
        printf("%llX", value1);
#endif
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
    }
}

static void
verbosePrintStringNL(int level, char *pPrintString1, sbyte *pPrintString2)
{
    if (level <= estc_verboseLevel)
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, pPrintString1);
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, (char *)pPrintString2);
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
    }
}

static void
verbosePrintError(char *pPrintString, sbyte4 value)
{
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
    DB_PRINT ("--------------------> ");
    DB_PRINT ("%s Status: %d (%s) \n", (pPrintString ? pPrintString : (char *)""), value, MERROR_lookUpErrorCode(value));
#else
    printf("--------------------> ");
    printf("%s Status: %d (%s) \n", (pPrintString ? pPrintString : (char *)""), value, MERROR_lookUpErrorCode(value));
#endif
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

static void
verbosePrintStringError(char *pPrintString, sbyte *value)
{
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
    DB_PRINT ("--------------------> ");
    DB_PRINT ("%s: %s", pPrintString, (sbyte *)value);
    DB_PRINT ("\n");
#else
    printf("--------------------> ");
    printf("%s: %s", pPrintString, (sbyte *)value);
    printf("\n");
#endif
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

static ubyte
verbosePrintChar(ubyte theChar)
{
    if ((32 > theChar) || (126 < theChar))
        return '.';

    return theChar;
}

static void
verboseHexDump(int level, ubyte *pMesg, ubyte4 mesgLen)
{
    if (level <= estc_verboseLevel)
    {
        ubyte4 index = 0;

        while (index < mesgLen)
        {
            ubyte4 min = (16 > (mesgLen - index)) ? mesgLen - index : 16;
            ubyte4 j, k;

#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT ("  %08x: ", index);
#else
            printf("  %08x: ", index);
#endif

            for (j = 0; j < min; j++)
            {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
                DB_PRINT("%02x ", (int) pMesg[index + j]);
#else
                printf("%02x ", (int) pMesg[index + j]);
#endif
            }

            for (k = j; k < 16; k++)
            {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
                DB_PRINT("   ");
#else
                printf("   ");
#endif
            }
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT("    ");
#else
            printf("    ");
#endif

            for (k = 0; k < j; k++)
            {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
                DB_PRINT("%c", (int) verbosePrintChar(pMesg[index + k]));
#else
                printf("%c", (int) verbosePrintChar(pMesg[index + k]));
#endif
            }
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT("\n");
#else
            printf("\n");
#endif

            index += 16;
        }
    }
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

static void
verboseDumpResponse(int level, ubyte *pResp, ubyte4 respLen, int status)
{
    if (level <= estc_verboseLevel)
    {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
        DB_PRINT("HTTP status code= %d", status);
#else
        printf("HTTP status code= %d", status);
#endif
        if (pResp != NULL)
        {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
            DB_PRINT(" ; response message=");
#else
            printf(" ; response message=");
#endif
            ubyte4 i = 0;
            for (i = 0; i < respLen; i++)
            {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
                DB_PRINT("%c", pResp[i]);
#else
                printf("%c", pResp[i]);
#endif
            }
        }
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
        DB_PRINT("\n");
#else
        printf("\n");
#endif
    }
#ifdef __ENABLE_DIGICERT_FFLUSH_LOGS__
    fflush(NULL);
#endif
}

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS qsKeyTypeToAlgId(sbyte *pKeyType, ubyte4 *pAlgId)
{
    /* internal method, NULL checks not necc */

    if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"MLDSA_44"))
    {
        *pAlgId = cid_PQC_MLDSA_44;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"MLDSA_65"))
    {
        *pAlgId = cid_PQC_MLDSA_65;
    }
    else if (0 == DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)"MLDSA_87"))
    {
        *pAlgId = cid_PQC_MLDSA_87;
    }
    else
    {
        return ERR_INVALID_ARG;
    }

    return OK;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*****************************************************************************/

void EST_setVerboseLevel(ubyte4 level)
{
    estc_verboseLevel = level;
    return;
}

/*****************************************************************************/
static void
EST_EXAMPLE_displayHelp(char *prog)
{
    printf(" Usage: %s <options>\n", prog);
    printf("  options:\n");
    printf("    -est_uri <uri>                              Complete EST endpoint URL.\n");
    printf("    -est_servername <name>                      The EST server's distinguished name.\n");
    printf("    -est_ip <ip_addr>                           The EST server's IP address.\n");
    printf("    -est_port <port>                            The EST server's listening port.\n");
    printf("    -est_url <url>                              The EST operation URL path.\n");
    printf("                                                  Should be one of:\n");
    printf("                                                  /.well-known/est/<groupid/policyid>/cacerts\n");
    printf("                                                  /.well-known/est/<groupid/policyid>/simpleenroll\n");
    printf("                                                  /.well-known/est/<groupid/policyid>/simplereenroll\n");
    printf("    -est_user <name>                            The HTTP authentication username.\n");
    printf("    -est_pass <password>                        The HTTP authentication password.\n");
#ifdef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
    printf("    -est_certpath <path>                        Local path for reading and writing keys and certificates.\n");
#endif /* __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__ */
    printf("    -est_disable_cacert                         Flag to disable validating the issued certificate against the certificate store.\n");
    printf("    -est_csr_conf <file_name>                   Config file containing CSR attributes.\n");
    printf("                                                  File must be in /etc folder under the keystore directory.\n");
    printf("    -est_digestname <digest_algo>               Digest algorithm to use.\n");
    printf("                                                 Should be one of : \n");
    printf("                                                 [SHA1|SHA224|SHA256|SHA384|SHA512]\n");
    printf("    -est_keyalias <file_name>                   The alias of the key in the cert store.\n");
    printf("                                                  File must be in /keys folder under the keystore directory.\n");
#ifdef __ENABLE_DIGICERT_PQC__
    printf("    -est_keytype <RSA|ECDSA|EDDSA|HYBRID>       Enrollment key type.\n");
#else
    printf("    -est_keytype <RSA|ECDSA|EDDSA>              Enrollment key type.\n");
#endif
    printf("    -est_keysize <size>                         Enrollment key size.\n");
    printf("    -est_renew_window <days>                    Number of days to check against the certificate when performing a renew, rekey,\n");
    printf("                                                  or simplereenroll operation. If the certificate is expired or if the certificate\n");
    printf("                                                  will expire within the number of days specified then the renew, rekey, or\n");
    printf("                                                  simplereenroll is performed. Maximum window is %d days\n", ESTC_MAX_RENEW_WINDOW_SIZE);
    printf("    -est_keysource <SW|TPM2>                    Enrollment key source.\n");
#ifdef __ENABLE_DIGICERT_TAP__
    printf("    -est_tapkeypassword                         Prompts user for TAP key password.\n");
    printf("                                                Password can be provided on CLI and must be prefixed with pw: i.e., pw:secret_password.\n");
#endif
    printf("    -est_key_file_pkcs8_pw                      Prompts user for PKCS8 password to encrypt private key.\n");
    printf("                                                Password can be provided on CLI and must be prefixed with pw: i.e., pw:secret_password.\n");
    printf("    -est_key_file_pkcs8_enc_alg  <enc_alg>      PKCS8 encryption algorithm. Only used when -est_key_file_pkcs8_pw\n");
    printf("                                                  is provided. If no encryption algorithm is provided then a default\n");
    printf("                                                  of " PKCS8_ENC_ALG_DEFAULT  " is used. Here are the possible values.\n");
#if defined(__ENABLE_DIGICERT_PKCS5__)
#if defined(__ENABLE_DES_CIPHER__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V1_SHA1_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V1_SHA1_RC2 "\n");
#endif
#if defined(__ENABLE_DES_CIPHER__) && defined(__ENABLE_DIGICERT_MD2__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V1_MD2_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V1_MD2_RC2 "\n");
#endif
#if defined(__ENABLE_DES_CIPHER__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V1_MD5_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V1_MD5_RC2 "\n");
#endif
#if !defined(__DISABLE_3DES_CIPHERS__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V2_3DES "\n");
#endif
#if defined(__ENABLE_DES_CIPHER__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V2_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V2_RC2 "\n");
#endif
#if !defined(__DISABLE_AES_CIPHERS__)
#if !defined(__DISABLE_AES128_CIPHER__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V2_AES128 "\n");
#endif
#if !defined(__DISABLE_AES192_CIPHER__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V2_AES192 "\n");
#endif
#if !defined(__DISABLE_AES256_CIPHER__)
    printf("                                                  " PKCS8_ENC_ALG_P5_V2_AES256 "\n");
#endif
#endif /* !defined(__DISABLE_AES_CIPHERS__) */
#endif /*  __ENABLE_DIGICERT_PKCS5__  */
    printf("    -est_key_file_pkcs12 <0|1>                  Output a PKCS12 file with the issued key and certificate.\n");
    printf("                                                  0 - Do not output a PKCS12 file (default).\n");
    printf("                                                  1 - Generate PKCS12 file.\n");
    printf("    -est_key_file_pkcs12_enc_alg <enc_algo>     Encryption algorithm for PKCS12 file. Only used when -est_key_file_pkcs12\n");
    printf("                                                  is provided. If no encryption algorithm is provided then a default\n");
    printf("                                                  of " PKCS12_ENC_ALG_DEFAULT " is used. Here are the possible values.\n");
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    printf("                                                  " PKCS12_ENC_ALG_SHA_2DES "\n");
#endif
    printf("                                                  " PKCS12_ENC_ALG_SHA_3DES "\n");
#ifdef __ENABLE_ARC2_CIPHERS__
    printf("                                                  " PKCS12_ENC_ALG_SHA_RC2_40 "\n");
    printf("                                                  " PKCS12_ENC_ALG_SHA_RC2_128 "\n");
#endif
    printf("                                                  " PKCS12_ENC_ALG_SHA_RC4_40 "\n");
    printf("                                                  " PKCS12_ENC_ALG_SHA_RC4_128 "\n");
    printf("    -est_key_file_pkcs12_integrity_pw <pw>      Optional integrity password for PKCS12 file. Only used when -est_key_file_pkcs12\n");
    printf("                                                  is provided (must be at least 4 characters). This will generate a PKCS12 file\n");
    printf("                                                  with a mac.\n");
    printf("    -est_key_file_pkcs12_privacy_pw <pw>        Optional privacy password for PKCS12 file. Only used when -est_key_file_pkcs12\n");
    printf("                                                  is provided (must be at least 4 characters). This will protect any data\n");
    printf("                                                  output to the pkcs12 file.\n");
    printf("    -est_key_file_pkcs12_key_pw <pw>            Optional private key password for keys stored in the PKCS12 file. Only used when\n");
    printf("                                                  -est_key_file_pkcs12 is provided (must be at least 4 characters). This will\n");
    printf("                                                  protect the private key stored in the PKCS12 file.\n");
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    printf("    -est_fp_nocrypt <0|1>                       Specify whether to encrypt or sign the device certificates and keys\n");
    printf("                                                  using File Protect.\n");
    printf("                                                  0 - Encrypt keys and certificates (default)\n");
    printf("                                                  1 - Sign keys and certificates\n");
    printf("    -est_protect_lib <file_name>                Path to library containing seed callback implementation for File Protect\n");
#endif
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    printf("    -est_ocsp_required <0|1>                    Check for an OCSP response from the server.\n");
    printf("                                                  0 - Do not send an OCSP status request to the server\n");
    printf("                                                  1 - Send an OCSP status request to the server and enforce that it is provided\n");
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    printf("    -est_qskeytype                              The quantum safe authentication algorithm for hybrid key types.\n");
    printf("                                                  Should be one of: \n");
    printf("                                                  MLDSA_44\n");
    printf("                                                  MLDSA_65\n");
    printf("                                                  MLDSA_87\n");
    printf("    -est_curve                                  The ECC curve for hybrid key types.\n");
    printf("                                                  Should be one of [P256|P384|P521].\n");
#endif
#ifdef __ENABLE_DIGICERT_TAP__
    printf("    -est_tapmoduleid <id>                       TAP module ID to be used.\n");
    printf("    -est_tapkeyusage <1..4>                     The TAP key usage provided as integer or string.\n");
    printf("                                                  1 or SIGNING - TAP_KEY_USAGE_SIGNING\n");
    printf("                                                  2 or DECRYPT - TAP_KEY_USAGE_DECRYPT\n");
    printf("                                                  3 or GENERAL - TAP_KEY_USAGE_GENERAL\n");
    printf("                                                  4 or ATTEST - TAP_KEY_USAGE_ATTESTATION\n");
    printf("    -est_tapsignscheme <0..11>                  The TAP signing scheme provided as integer or string.\n");
    printf("                                                  0 or NONE - TAP_SIG_SCHEME_NONE\n");
    printf("                                                  1 or PKCS1_5 - TAP_SIG_SCHEME_PKCS1_5\n");
    printf("                                                  2 or PSS_SHA1 - TAP_SIG_SCHEME_PSS_SHA1\n");
    printf("                                                  3 or PSS_SHA256 - TAP_SIG_SCHEME_PSS_SHA256\n");
    printf("                                                  4 or PKCS1_5_SHA1 - TAP_SIG_SCHEME_PKCS1_5_SHA1\n");
    printf("                                                  5 or PKCS1_5_SHA256 - TAP_SIG_SCHEME_PKCS1_5_SHA256\n");
    printf("                                                  6 or PKCS1_5_DER - TAP_SIG_SCHEME_PKCS1_5_DER\n");
    printf("                                                  7 or ECDSA_SHA1 - TAP_SIG_SCHEME_ECDSA_SHA1\n");
    printf("                                                  8 or ECDSA_SHA224 - TAP_SIG_SCHEME_ECDSA_SHA224\n");
    printf("                                                  9 or ECDSA_SHA256 - TAP_SIG_SCHEME_ECDSA_SHA256\n");
    printf("                                                  10 or ECDSA_SHA384 - TAP_SIG_SCHEME_ECDSA_SHA384\n");
    printf("                                                  11 or ECDSA_SHA512 - TAP_SIG_SCHEME_ECDSA_SHA512\n");
    printf("    -est_tapencscheme <0..3>                    The TAP encryption scheme provided as integer or string.\n");
    printf("                                                  0 or NONE - TAP_ENC_SCHEME_NONE\n");
    printf("                                                  1 or PKCS1_5 - TAP_ENC_SCHEME_PKCS1_5\n");
    printf("                                                  2 or OAEP_SHA1 - TAP_ENC_SCHEME_OAEP_SHA1\n");
    printf("                                                  3 or OAEP_SHA256 - TAP_ENC_SCHEME_OAEP_SHA256\n");
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    printf("    -est_tapservername <name>                   Name of the remote TAP server.\n");
    printf("    -est_tapserverport <port>                   Port of the remote TAP server.\n");
#endif
#endif
    printf("    -est_verbose <1 or 2>                       Verbose level.\n");
    printf("\n");
    return;
}

#if (!defined(__RTOS_WIN32__) && !defined(__RTOS_VXWORKS__) && !defined(__RTOS_FREERTOS__) && !defined(__RTOS_AZURE__))
static ssize_t getPasswordFromUser (sbyte **password, size_t passwdLength, int mask)
{
    FILE *stdinFp = stdin;
    size_t idx = 0;         /* index, number of chars in read   */
    int c = 0;
    struct termios oldKbdMode;    /* orig keyboard settings   */
    struct termios newKbdMode;

    if (!password || !passwdLength || !stdinFp)
    {
        return -1;
    }

    if (tcgetattr (0, &oldKbdMode))
    {   /* save orig settings   */
        verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "error: tcgetattr failed.");
        return -1;
    }   /* copy old to new */
    DIGI_MEMCPY (&newKbdMode, &oldKbdMode, sizeof(struct termios));

    newKbdMode.c_lflag &= ~(ICANON | ECHO);  /* new kbd flags */
    newKbdMode.c_cc[VTIME] = 0;
    newKbdMode.c_cc[VMIN] = 1;
    if (tcsetattr (0, TCSANOW, &newKbdMode))
    {
        verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "error: tcsetattr failed.");
        return -1;
    }

    /* read chars from stdinFp, mask if valid char specified */
    while (((c = fgetc (stdinFp)) != '\n' && c != EOF && idx < passwdLength - 1) ||
            (idx == passwdLength - 1 && c == 127))
    {
        if (c != 127)
        {
            /* Enforce strict buffer bounds validation */
            if (idx >= passwdLength - 1)
            {
                break;
            }
            if (31 < mask && mask < 127)
            {  /* valid ascii char */
                fputc (mask, stdout);
            }
            (*password)[idx++] = c;
        }
        else if (idx > 0)
        {   /* handle backspace (del)   */
            if (31 < mask && mask < 127)
            {
                fputc (0x8, stdout);
                fputc (' ', stdout);
                fputc (0x8, stdout);
            }
            (*password)[--idx] = 0;
        }
    }
    (*password)[idx] = 0;

    /* reset original keyboard  */
    if (tcsetattr (0, TCSANOW, &oldKbdMode))
    {
        verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "error: tcsetattr failed.");
        return -1;
    }

    if (idx == passwdLength - 1 && c != '\n')
    {   /* warn if password truncated */
        verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "warning: password truncated");
    }

    return idx;
}
#endif


static void
setStringParameter(sbyte **ppParam, char *pValue)
{
    sbyte4 valueStrSize = 0;
    if (pValue == NULL)
        return;
    valueStrSize = DIGI_STRLEN((const sbyte *)pValue);
    *ppParam = MALLOC(valueStrSize+1);
    if (*ppParam == NULL)
        return;
    DIGI_MEMSET(*ppParam, 0, valueStrSize+1);
    DIGI_MEMCPY(*ppParam, pValue, valueStrSize);
    (*ppParam)[valueStrSize] = '\0';
}

MSTATUS displayMissingOptions(char *option, char *programName)
{
    MSTATUS status = OK;
    byteBoolean isEnrollUrl = FALSE;

    if ((NULL != estc_ServerURL) &&
                (NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_ENROLL_CMD)
                || NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)
                || NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)
                || NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)))
    {
        isEnrollUrl = TRUE;
    }

    if ((NULL != estc_ServerURL) && (NULL != strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD) ||
            NULL != strstr((const char *)estc_ServerURL, EST_CACERTS_CMD) || !isEnrollUrl))
    {
        if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keytype") == 0 ||
            DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keysize") == 0 ||
            DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keysource") == 0
            || DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_user") == 0 ||
            DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_pass") == 0
            )
        {
            /* ignore missing mandatory options */
            /* but check only option required for csrattrs and cacerts */

            if (estc_keyType == NULL)
            {
                setStringParameter(&estc_keyType, (char*)KEY_TYPE_RSA);
            }
            if(!estc_keySize)
                estc_keySize = ESTC_DEF_KEYSIZE;
            return status;
        }
    }

    if ((NULL != estc_ServerURL) && (NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)))
    {
        if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keytype") == 0)
        {
            if (estc_keyType == NULL)
            {
                setStringParameter(&estc_keyType, KEY_TYPE_RSA);
            }

            return status;
        }
        else if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keysize") == 0)
        {
            estc_keySize = ESTC_DEF_KEYSIZE;
            return status;
        }
    }

    if (!g_genKeySet && !estc_genselfsignedcert)
    {
        status = ERR_NOT_FOUND;
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\nOption not specified - ", (sbyte *)option);
        if ((NULL != estc_ServerURL) &&
            ((NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)) ||
                (NULL != strstr((const char *)estc_ServerURL, EST_CACERTS_CMD)) ||
                (NULL != strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD))))
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_ip, est_servername, est_user, est_certpath, est_url");
        }
        else
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_ip, est_servername, est_user, est_certpath, est_keytype,  est_keysize, est_url");
        }
        verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "");
        EST_EXAMPLE_displayHelp(programName);
    }
    else if (!estc_genselfsignedcert)
    {
        /* ignore missing mandatory options */
        /* but check only option required for key gen */
        if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keytype") == 0)
        {
            status = ERR_NOT_FOUND;
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\nOption not specified - ", (sbyte *)option);
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_certpath, est_keytype,  est_keysize");
        }
        else if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_certpath") == 0)
        {
            status = ERR_NOT_FOUND;
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\nOption not specified - ", (sbyte *)option);
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_certpath, est_keytype,  est_keysize");
        }
        else if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keysize") == 0)
        {
            status = ERR_NOT_FOUND;
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\nOption not specified - ", (sbyte *)option);
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_certpath, est_keytype,  est_keysize");
        }
        else if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keysource") == 0)
        {
            status = ERR_NOT_FOUND;
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\nOption not specified - ", (sbyte *)option);
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_certpath, est_keytype,  est_keysize");
        }
    }
    else /* must be selfsignedcert */
    {
        if (DIGI_STRCMP((const sbyte *)option, (const sbyte *)"est_keytype") == 0)
        {
            status = ERR_NOT_FOUND;
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\nOption not specified - ", (sbyte *)option);
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Mandatory options: est_keytype");
        }
    }
    return status;
}

void initializeDefaultValues()
{
    if (NULL == estc_ServerIpAddr)
        setStringParameter(&estc_ServerIpAddr, DEFAULT_SERVER_IP);
    estc_ServerPort = ESTC_DEF_PORT;
    /*Special case to handle keygeneration and csr generation of simpleenroll*/
    if (NULL == estc_ServerURL)
        setStringParameter(&estc_ServerURL, SIMPLEENROLL_KEYGEN_AND_CSRGEN);
    if (NULL == estc_User)
        setStringParameter(&estc_User, DEFAULT_SERVER_USER);
    if (NULL == estc_Pass)
        setStringParameter(&estc_Pass, DEFAULT_SERVER_PASS);
    if (NULL == estc_serverName)
        setStringParameter(&estc_serverName, ESTC_DEF_SERVER_NAME);
}

static MSTATUS EST_utilStrToInt(sbyte *pStr, ubyte8 *pInt)
{
    MSTATUS status;
    ubyte4 strLen, tmpLen, i;
    ubyte pHex[8] = {0};
    sbyte4 intVal = 0;
    sbyte *pMaxInt = (sbyte *) ESTC_MAX_INT;
    sbyte *pStop = NULL;

    if ( (NULL == pStr) || (NULL == pInt) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    strLen = DIGI_STRLEN(pStr);
    if (0 == strLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    tmpLen = DIGI_STRLEN((sbyte *)ESTC_HEX_IDENTIFIER);
    if ( (strLen >= tmpLen) &&
         (0 == DIGI_STRNICMP(pStr,(sbyte *)ESTC_HEX_IDENTIFIER, tmpLen)) )
    {
        strLen -= tmpLen;
        pStr += tmpLen;
        if (strLen > 16)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        tmpLen = (16 - strLen) >> 1;
        status = DIGI_convertHexString(
            (char *) pStr, pHex + tmpLen, sizeof(pHex) - tmpLen);
        if (OK != status)
        {
            goto exit;
        }

        U8INIT_HI(*pInt, DIGI_NTOHL(pHex));
        U8INIT_LO(*pInt, DIGI_NTOHL(pHex + 4));
    }
    else
    {
        tmpLen = DIGI_STRLEN(pMaxInt);
        if ( (strLen > tmpLen) || (FALSE == DIGI_ISDIGIT(pStr[0])) )
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        /* Check for overflow */
        if (strLen == tmpLen)
        {
            for (i = 0; i < tmpLen; i++)
            {
                if (FALSE == DIGI_ISDIGIT(pStr[i]))
                {
                    status = ERR_INVALID_INPUT;
                    goto exit;
                }

                if (pStr[i] > pMaxInt[i])
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }
                else if (pStr[i] < pMaxInt[i])
                {
                    break;
                }
            }
        }

        intVal = DIGI_ATOL(pStr, (const sbyte **) &pStop);
        if (*pStop != '\0')
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        U8INIT_HI(*pInt, 0);
        U8INIT_LO(*pInt, intVal);
        status = OK;
    }

exit:

    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__
static MSTATUS EST_utilReadId(sbyte *pStr, TAP_Buffer *pOutId)
{
    MSTATUS status = ERR_INVALID_ARG;
    ubyte *pId = NULL;
    ubyte4 idLen = 0;

    idLen = (ubyte4) DIGI_STRLEN(pStr);
    if ( (idLen >= 2) && pStr[0] == '0' && (pStr[1] == 'x' || pStr[1] == 'X') )
        estc_isIdHex = TRUE;

    /* internal method, NULL checks not necc */
    if (estc_isIdHex)
    {
       /* use idLen as a temp for string form lem */
        if (idLen < 4 || idLen & 0x01)
        {
            goto exit;
        }

        /* now get the real id Len */
        idLen = (idLen - 2) / 2;

        status = DIGI_MALLOC((void **) &pId, idLen);
        if (OK != status)
            goto exit;

        status = DIGI_ATOH(pStr + 2, idLen*2, pId);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_MALLOC((void **) &pId, idLen + 1); /* we'll add a zero byte for string form printing */
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pId, (ubyte *) pStr, idLen);
        if (OK != status)
            goto exit;

        pId[idLen] = 0x0;
    }

    pOutId->pBuffer = pId; pId = NULL;
    pOutId->bufferLen = idLen; idLen = 0;

exit:

    if (NULL != pId)
    {
        (void) DIGI_MEMSET_FREE(&pId, idLen);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_TAP__ */

MSTATUS EST_init_defaults(void)
{
    MSTATUS status = OK;
    sbyte *pConfPath = NULL;
#ifndef __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__
    intBoolean upgrading = FALSE;
#endif
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    byteBoolean verifyConfig;
#endif

    estc_ServerIpAddr = NULL;
    estc_ServerPort   = ESTC_DEF_PORT;
    estc_ServerURL    = NULL;
    estc_User         = NULL;
    estc_Pass         = NULL;
    estc_certPath     = NULL;
    estc_rootCA       = NULL;
    estc_serverName   = NULL;
    estc_keyType      = NULL;
    estc_newKeyType   = NULL;
    estc_keySize      = 0;
    estc_newKeySize   = 0;
    estc_disable_cacert = 0;
    estc_keyAlias1    = NULL;
    estc_keyAlias2    = NULL;
    estc_keySource    = NULL;
#ifdef __ENABLE_DIGICERT_TAP__
    useTAP = 0;
    estc_tapModuleId = 0;
    estc_tapProvider = 0;
    estc_tap_confFile = NULL;
    estc_tapKeyUsage = 0;
    estc_tapSignScheme = TAP_SIG_SCHEME_NONE;
    estc_tapEncScheme = TAP_ENC_SCHEME_NONE;
    estc_tap_keyPassword = NULL;
#ifdef __ENABLE_DIGICERT_TEE__
    useTEE = 0;
#endif
#endif
    estc_hasAttrib = ESTC_DEF_HASATTRIB;
    est_fullcmcReqType  = NULL;
    estc_confFile     = NULL;
    estc_extattrs_confFile = NULL;
    estc_tlscert        = NULL;
    estc_config_type = EST_CONFIG_FILE;
    estc_rootCA_type = EST_CONFIG_FILE;
    p_estc_csr_config = NULL;
    p_estc_extCsr_config = NULL;
    estc_pskFile = NULL;
    estc_skg_clientcert = NULL;
    estc_skg_clientkey = NULL;
    estc_skg_clientkeytype = 0;
    estc_ocsp_required = 0;
    estc_digestName = NULL;
    estc_renewWindow = 0;
    estc_renewWindowSet = FALSE;
#if defined(__ENABLE_DIGICERT_TAP__)
    estc_tapKeyHandleStr = NULL;
    estc_tapKeyHandle.pBuffer = NULL;
    estc_tapKeyHandle.bufferLen = 0;
    estc_isIdHex = FALSE;
    estc_tapKeyHandleSet = FALSE;
    estc_tapCertificateNvIndexStr = NULL;
    estc_tapCertificateNvIndex = 0;
    estc_tapCertificateNvIndexSet = FALSE;
    /* TAP key primary */
    estc_tapKeyPrimary = FALSE;
    estc_tapKeyPrimarySet = FALSE;
    /* TAP key nonce NV index */
    estc_tapKeyNonceNvIndexStr = NULL;
    estc_tapKeyNonceNvIndex = 0;
    estc_tapKeyNonceNvIndexSet = FALSE;
    /* TAP token hierarchy */
    estc_tapTokenHierarchyStr = NULL;
    estc_tapTokenHierarchy = 0;
    estc_tapTokenHierarchySet = FALSE;
#endif
    estc_extEnrollFlow = EXT_ENROLL_FLOW_NONE;;
    estc_backup = FALSE;
    setStringParameter(&estc_pkcs8EncAlg, PKCS8_ENC_ALG_P5_V2_AES256);

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (OK > (status = FMGMT_changeCWD(MANDATORY_BASE_PATH)))
        goto exit;
#endif

#ifndef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = DPM_checkStatus(DPM_CONFIG, &verifyConfig);
    if (OK != status)
    {
        verbosePrintError("Unable to get data protect status for config files.", status);
        goto exit;
    }

    if (FALSE == verifyConfig)
    {
        status = CRYPTO_UTILS_readTrustedPathsWithProxyURLNoVerify(
                &pConfPath, &estc_certPath, &estc_truststorePath, NULL, &estc_http_proxy);
    }
    else
#endif
    {
        /* Load in the keystore from the trusted config file.
         */
        status = CRYPTO_UTILS_readTrustedPathsWithProxyURL(
                &pConfPath, &estc_certPath, &estc_truststorePath, NULL, &estc_http_proxy);
    }
    if (OK != status)
    {
        verbosePrintError("Unable to process config file.", status);
        status = -1;
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__
    status = CRYPTO_UTILS_checkForUpgrade(pConfPath, &upgrading);
    if (OK != status)
    {
        verbosePrintError("Unable to check upgrade status.", status);
        goto exit;
    }
    if (TRUE == upgrading)
    {
        verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Upgrade in progress!");
        status = ERR_GENERAL;
        goto exit;
    }
#endif
#endif /* !defined __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__ */

    /* If the build is for TPLA, let TPLA set the proxy */
#if !defined(__ENABLE_DIGICERT_TRUSTPOINT_LOCAL__) && defined(__ENABLE_DIGICERT_HTTP_PROXY__)
    if (NULL != estc_http_proxy)
    {
        status = HTTP_PROXY_setProxyUrlAndPort(estc_http_proxy);
        if (OK != status)
        {
            verbosePrintError("Unable to process proxy URL from config file.", status);
            goto exit;
        }
    }
#endif

exit:
    DIGI_FREE((void **) &pConfPath);
    return status;
}

#ifdef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__

extern MSTATUS EST_setKeyStorePath(const sbyte *pCertPath)
{
    MSTATUS status = OK;
    if (NULL == estc_certPath)
    {
        if (NULL == pCertPath)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        setStringParameter(&estc_certPath, (char *)pCertPath);
    }
exit:
    return status;
}

#endif

#if defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS EST_convertTapKeyUsageString(sbyte *pStr, ubyte4 strLen, ubyte2 *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    EstStrMapping pMapping[] = {
        { ESTC_TAP_KEY_USAGE_SIGNING, TAP_KEY_USAGE_SIGNING },
        { ESTC_TAP_KEY_USAGE_DECRYPT, TAP_KEY_USAGE_DECRYPT },
        { ESTC_TAP_KEY_USAGE_GENERAL, TAP_KEY_USAGE_GENERAL },
        { ESTC_TAP_KEY_USAGE_ATTEST, TAP_KEY_USAGE_ATTESTATION }
    };
    ubyte4 i, length;

    if (NULL == pStr)
    {
        goto exit;
    }

    for (i = 0; i < COUNTOF(pMapping); i++)
    {
        length = DIGI_STRLEN(pMapping[i].pStr);
        if (length == strLen)
        {
            if (0 == DIGI_STRNCMP(pMapping[i].pStr, pStr, length))
            {
                *pValue = pMapping[i].value;
                break;
            }
        }
    }

    if (i < COUNTOF(pMapping))
    {
        status = OK;
    }

exit:

    return status;
}

static MSTATUS EST_convertTapSigSchemeString(sbyte *pStr, ubyte4 strLen, ubyte2 *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    EstStrMapping pMapping[] = {
        { ESTC_TAP_SIG_SCHEME_NONE, TAP_SIG_SCHEME_NONE },
        { ESTC_TAP_SIG_SCHEME_PKCS1_5, TAP_SIG_SCHEME_PKCS1_5 },
        { ESTC_TAP_SIG_SCHEME_PSS_SHA1, TAP_SIG_SCHEME_PSS_SHA1 },
        { ESTC_TAP_SIG_SCHEME_PSS_SHA256, TAP_SIG_SCHEME_PSS_SHA256 },
        { ESTC_TAP_SIG_SCHEME_PKCS1_5_SHA1, TAP_SIG_SCHEME_PKCS1_5_SHA1 },
        { ESTC_TAP_SIG_SCHEME_PKCS1_5_SHA256, TAP_SIG_SCHEME_PKCS1_5_SHA256 },
        { ESTC_TAP_SIG_SCHEME_PKCS1_5_DER, TAP_SIG_SCHEME_PKCS1_5_DER },
        { ESTC_TAP_SIG_SCHEME_ECDSA_SHA1, TAP_SIG_SCHEME_ECDSA_SHA1 },
        { ESTC_TAP_SIG_SCHEME_ECDSA_SHA224, TAP_SIG_SCHEME_ECDSA_SHA224 },
        { ESTC_TAP_SIG_SCHEME_ECDSA_SHA256, TAP_SIG_SCHEME_ECDSA_SHA256 },
        { ESTC_TAP_SIG_SCHEME_ECDSA_SHA384, TAP_SIG_SCHEME_ECDSA_SHA384 },
        { ESTC_TAP_SIG_SCHEME_ECDSA_SHA512, TAP_SIG_SCHEME_ECDSA_SHA512 }
    };
    ubyte4 i, length;

    if (NULL == pStr)
    {
        goto exit;
    }

    for (i = 0; i < COUNTOF(pMapping); i++)
    {
        length = DIGI_STRLEN(pMapping[i].pStr);
        if (length == strLen)
        {
            if (0 == DIGI_STRNCMP(pMapping[i].pStr, pStr, length))
            {
                *pValue = pMapping[i].value;
                break;
            }
        }
    }

    if (i < COUNTOF(pMapping))
    {
        status = OK;
    }

exit:

    return status;
}

static MSTATUS EST_convertTapEncSchemeString(sbyte *pStr, ubyte4 strLen, ubyte2 *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    EstStrMapping pMapping[] = {
        { ESTC_TAP_ENC_SCHEME_NONE, TAP_ENC_SCHEME_NONE },
        { ESTC_TAP_ENC_SCHEME_PKCS1_5, TAP_ENC_SCHEME_PKCS1_5 },
        { ESTC_TAP_ENC_SCHEME_OAEP_SHA1, TAP_ENC_SCHEME_OAEP_SHA1 },
        { ESTC_TAP_ENC_SCHEME_OAEP_SHA256, TAP_ENC_SCHEME_OAEP_SHA256 }
    };
    ubyte4 i, length;

    if (NULL == pStr)
    {
        goto exit;
    }

    for (i = 0; i < COUNTOF(pMapping); i++)
    {
        length = DIGI_STRLEN(pMapping[i].pStr);
        if (length == strLen)
        {
            if (0 == DIGI_STRNCMP(pMapping[i].pStr, pStr, length))
            {
                *pValue = pMapping[i].value;
                break;
            }
        }
    }

    if (i < COUNTOF(pMapping))
    {
        status = OK;
    }

exit:

    return status;
}

static MSTATUS EST_convertTapHierarchyString(sbyte *pStr, TAP_TokenId *pValue)
{
    MSTATUS status = ERR_TAP_INVALID_INPUT;
    EstStrMapping pMapping[] = {
        { ESTC_TAP_HIERARCHY_STORAGE, TAP_HIERARCHY_STORAGE },
        { ESTC_TAP_HIERARCHY_ENDORSEMENT, TAP_HIERARCHY_ENDORSEMENT },
        { ESTC_TAP_HIERARCHY_PLATFORM, TAP_HIERARCHY_PLATFORM }
    };
    ubyte4 i;

    if ( (NULL == pStr) || (NULL == pValue) )
    {
        goto exit;
    }

    for (i = 0; i < COUNTOF(pMapping); i++)
    {
        if (0 == DIGI_STRCMP(pMapping[i].pStr, pStr))
        {
            *pValue = pMapping[i].value;
            break;
        }
    }

    if (i < COUNTOF(pMapping))
    {
        status = OK;
    }
    else
    {
        /* Try converting it to index */
        status = EST_utilStrToInt(pStr, pValue);
    }

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_TAP__ */

#ifndef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__

/*------------------------------------------------------------------*/

sbyte *EST_getTrustStorePathCopy()
{
    MSTATUS status;
    sbyte *pRet = NULL;

    if (NULL == estc_truststorePath)
    {
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pRet, DIGI_STRLEN(estc_truststorePath) + 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pRet, estc_truststorePath, DIGI_STRLEN(estc_truststorePath) + 1);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if ( (NULL != pRet) && (OK != status) )
    {
        DIGI_FREE((void **) &pRet);
        pRet = NULL;
    }

    return pRet;
}

#endif /* __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__ */

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)

#define MAX_PASSWORD_LEN 128
#define TOSTRING(x) #x
#define MAX_RETRIES 3

static MSTATUS EST_EXAMPLE_getPassword(ubyte **ppRetPassword, ubyte4 *pRetPasswordLen, char *pPwName, char *pFileName)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pRetPw = NULL;
    sbyte *pPassword1 = NULL;
    sbyte *tempPassword = NULL;
    ubyte4 passwordLen = 0;
    ubyte4 retries = 0;

    *pRetPasswordLen = 0;

    status = DIGI_MALLOC((void **)&pPassword1, MAX_PASSWORD_LEN + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&tempPassword, MAX_PASSWORD_LEN + 1);
    if (OK != status)
        goto exit;

    printf("Enter %s pass phrase for protecting the %s: ", pPwName, pFileName);

    if (getPasswordFromUser(&tempPassword, MAX_PASSWORD_LEN + 1, '*') < 0)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    printf("\n");

    passwordLen = DIGI_STRLEN(tempPassword);
    if (passwordLen >= MAX_PASSWORD_LEN + 1)
    {
        status = ERR_INVALID_INPUT;
        verbosePrintError("password too long, must be no more than " TOSTRING(MAX_PASSWORD_LEN) " characters.\n", status);
        *pRetPasswordLen = 0;
        DIGI_MEMSET((ubyte *)tempPassword, 0, passwordLen);
        DIGI_FREE((void **)&tempPassword);
        goto exit;
    }

    DIGI_MEMCPY(pPassword1, tempPassword, passwordLen);
    pPassword1[passwordLen] = '\0';

    DIGI_MEMSET((ubyte *)tempPassword, 0, passwordLen);
    DIGI_FREE((void **)&tempPassword);
    tempPassword = NULL;

    /* exits the loop when retries >= MAX_RETRIES */
    while (TRUE)
    {
        status = DIGI_MALLOC((void **)&tempPassword, MAX_PASSWORD_LEN + 1);
        if (OK != status)
            goto exit;

        printf("Re-enter %s pass phrase for protecting the %s: ", pPwName, pFileName);

        if (getPasswordFromUser(&tempPassword, MAX_PASSWORD_LEN + 1, '*') < 0)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        printf("\n");

        if((passwordLen == DIGI_STRLEN(tempPassword)) && (0 == DIGI_STRCMP(pPassword1, tempPassword)))
        {
            DIGI_MEMSET((ubyte *)tempPassword, 0, DIGI_STRLEN(tempPassword));
            DIGI_FREE((void **)&tempPassword);
            tempPassword = NULL;
            break;
        }
        else
        {
            DIGI_MEMSET((ubyte *)tempPassword, 0, DIGI_STRLEN(tempPassword));
            DIGI_FREE((void **)&tempPassword);
            tempPassword = NULL;

            verbosePrintError("Passwords do not match, please try again.\n", status);
            retries++;

            if (retries >= MAX_RETRIES)
            {
                verbosePrintError("Passwords do not match after %d retries.\n", MAX_RETRIES);
                status = ERR_INVALID_INPUT;
                goto exit;
            }
        }
    }

    /* allocate one extra space so we have a non NULL buffer no matter what */
    status = DIGI_MALLOC((void **) &pRetPw, passwordLen + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY( pRetPw, pPassword1, passwordLen);
    if (OK != status)
        goto exit;

    pRetPw[passwordLen] = 0;

    *ppRetPassword = pRetPw; pRetPw = NULL;
    *pRetPasswordLen = passwordLen;

exit:

    if (NULL != pPassword1)
    {
        DIGI_MEMSET_FREE((ubyte **)&pPassword1, passwordLen);
    }

    if (NULL != pRetPw)
    {
        DIGI_MEMSET_FREE(&pRetPw, passwordLen);
    }

    return status;
}
#endif /* __RTOS_LINUX__ */

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS EST_EXAMPLE_addCreds(TAP_CredentialList *pCredList)
{
    MSTATUS status = ERR_NULL_POINTER;
    TAP_Credential *pNewList = NULL;
    TAP_Credential *pCred = NULL;
    ubyte4 numCreds = 1;
    ubyte *pPassword = NULL;
    ubyte4 passwordLen = 0;

    if (NULL == pCredList)
        goto exit;

    /* if there is an old list we'll copy and add one more */
    if (NULL != pCredList->pCredentialList && pCredList->numCredentials > 0)
    {
        numCreds = (pCredList->numCredentials + 1);
    }

    /* allocate the new credential list */
    status = DIGI_CALLOC((void **) &pNewList, numCreds, sizeof(TAP_Credential));
    if (OK != status)
        goto exit;

    /* copy previous creds if there, shallow copy ok */
    if (NULL != pCredList->pCredentialList && pCredList->numCredentials > 0)
    {
        status = DIGI_MEMCPY((ubyte *) pNewList, (ubyte *) pCredList->pCredentialList,
                            (numCreds - 1) * sizeof(TAP_Credential));
        if (OK != status)
            goto exit;
    }

    /* Set the new credential */
    pCred = &pNewList[numCreds - 1];

    status = EST_EXAMPLE_getPassword(&pPassword, &passwordLen, "TAP", "private key");
    if (OK != status)
        goto exit;

    /* allocate extra space just in case password is empty, let the smp deal with it */
    status = DIGI_MALLOC((void **) &pCred->credentialData.pBuffer, passwordLen + 1);
    if (OK != status)
        goto exit;

    pCred->credentialData.bufferLen = passwordLen;

    /* extra space is there on pPassword too */
    status = DIGI_MEMCPY(pCred->credentialData.pBuffer, pPassword, passwordLen + 1);
    if (OK != status)
        goto exit;

    pCred->credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
    pCred->credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
    pCred->credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;

    /* replace and free the old list */
    if (NULL != pCredList->pCredentialList && pCredList->numCredentials > 0)
    {
        status = DIGI_MEMSET_FREE((ubyte **) &pCredList->pCredentialList,
                                 pCredList->numCredentials * sizeof(TAP_Credential));
        if (OK != status)
            goto exit;
    }

    pCredList->pCredentialList = pNewList; pNewList = NULL;
    pCredList->numCredentials = numCreds;

exit:

    if (NULL != pPassword)
    {
        (void) DIGI_MEMSET_FREE(&pPassword, passwordLen);
    }

    if (NULL != pNewList)
    {
        /* pCred still points to the new credential */
        if (NULL != pCred)
        {
            (void) DIGI_MEMSET_FREE(&pCred->credentialData.pBuffer,
                                    pCred->credentialData.bufferLen);
        }
        (void) DIGI_FREE((void**) &pNewList);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

sbyte4
#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
EST_EXAMPLE_getArgs(int argc, char **pArgv)
#else
EST_CLIENT_getArgs(int argc, char **pArgv)
#endif
{
    sbyte4 status = 0;
    int i;
    char *pTemp;
    char *pJsonBuf = NULL;
    char *pEnd = NULL;
    sbyte4 jbufLen = 0;

    int ipSet=0, portSet=0, urlSet=0, userSet=0, pwdSet=0,
        rootcaSet=0, nameSet=0, keyTypeSet=0, newKeyTypeSet = 0, keySizeSet=0, hasAttribSet=0,
        confFileSet=0, conf_extattrs_FileSet=0, fullcmcReqTypeSet=0, newKeySizeSet=0, keySourceSet=0;
    int estcDigestNameSet = 0, estcVerboseSet = 0;
#if defined __ENABLE_DIGICERT_TAP__
    int	tapModuleIdSet=0, tapconfFileSet =0, tapKeyUsageSet = 0, tapEncSchemeSet=0, tapSignSchemeSet=0;
#endif

    if ((1 == argc))
    {
        EST_EXAMPLE_displayHelp(pArgv[0]);
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if ((2 <= argc) && ('?' == pArgv[1][0]))
    {
        EST_EXAMPLE_displayHelp(pArgv[0]);
        status = ERR_INVALID_INPUT;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#if !defined(__DISABLE_DIGICERT_FP_EXTERNAL_SEED__)
    /* If data protection is enabled, we must process this argument before
     * attempting to read the trusted path from tpconf.json */
    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)pArgv[i],
            (const sbyte *)"-est_protect_lib") == 0)
        {
            if (++i < argc)
            {
                status = FP_registerSeedCallbacksFromExternal(pArgv[i]);
                if (OK != status)
                {
#ifdef __ENABLE_DIGICERT_EST_DEBUG_CONSOLE__
                    DB_PRINT("ERROR registering external seed callbacks for File Protect! status: %d\n", status);
#else
                    printf("ERROR registering external seed callbacks for File Protect! status: %d\n", status);
#endif
                    goto exit;
                }
            }
            continue;
        }
    }
#endif
#endif

    status = EST_init_defaults();
    if (OK != status)
    {
        verbosePrintError("Error initializing default values.", status);
        goto exit;
    }

    /*Skipping pArgv[0] which is example program name. */
    for (i = 1; i < argc; i++)
    {
        pEnd = NULL;

        if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_ip") == 0)
        {

            if (++i < argc)
            {
                setStringParameter(&estc_ServerIpAddr, pArgv[i]);
                ipSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_port") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_ServerPort = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,NULL);
                portSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_url") == 0)
        {
            if (++i < argc)
            {
                if (estc_endpointProvided == FALSE)
                {
                    setStringParameter(&estc_ServerURL, pArgv[i]);
                    urlSet = 1;
                }
                else
                {
                    verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Ignoring -est_url since -est_uri was provided.");
                }
            }

            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_user") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_User, pArgv[i]);
                userSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_pass") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_Pass, pArgv[i]);
                pwdSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_certpath") == 0)
        {
            /* Parse the -est_certpath option but don't actually read it if the
             * keystore is retrieved from the trusted config.
             */
            if (++i < argc)
            {
#ifdef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
                if(DIGI_STRLEN(pArgv[i]) >(MAX_CERT_PATH_NAME ))
                {
                   verbosePrintError("The specified path for -est_certpath argument is greater than 230",ERR_CERT_STRING_TOO_LONG);
                   status = ERR_INVALID_INPUT;
                   goto exit;
                }
                setStringParameter(&estc_certPath, pArgv[i]);
#endif /* __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__ */
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_uri") == 0)
        {
            if (++i < argc)
            {
                /* Free any existing values before EST_parseEndpoint allocates new memory */
                if (estc_serverName != NULL)
                {
                    DIGI_FREE((void **)&estc_serverName);
                    estc_serverName = NULL;
                }
                if (estc_ServerURL != NULL)
                {
                    DIGI_FREE((void **)&estc_ServerURL);
                    estc_ServerURL = NULL;
                }
                status = EST_parseEndpoint(pArgv[i], &estc_serverName, &estc_ServerURL);
                if (OK != status)
                {
                    verbosePrintError("Error parsing endpoint.", status);
                    goto exit;
                }
                estc_endpointProvided = TRUE;
                nameSet = 1;
                urlSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_servername") == 0)
        {
            if (++i < argc)
            {
                if (FALSE == estc_endpointProvided)
                {
                    setStringParameter(&estc_serverName, pArgv[i]);
                    nameSet = 1;
                }
                else
                {
                    verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Ignoring -est_servername since -est_uri was provided.");
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keytype") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_keyType, pArgv[i]);
                keyTypeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_rekeytype") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_newKeyType, pArgv[i]);
                newKeyTypeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_disable_cacert") == 0)
        {
            estc_disable_cacert = 1;
            continue;
        }

        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keyalias") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((sbyte**)&estc_keyAlias1, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_rekeyalias") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((sbyte**)&estc_keyAlias2, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keysource") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_keySource, pArgv[i]);
                keySourceSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs8_pw") == 0)
        {
            if (i + 1 < argc)
            {
                if (0 == DIGI_STRNICMP(pArgv[i + 1], (sbyte *)"pw:", DIGI_STRLEN((const sbyte *)"pw:")))
                {
                    if (DIGI_STRLEN(pArgv[i + 1]) > 3)
                    {
                        setStringParameter(&estc_pkcs8Pw, pArgv[i + 1] + 3);
                    }
                    else
                    {
                        status = ERR_INVALID_INPUT;
                        verbosePrintError("Please provide a valid password.", status);
                        goto exit;
                    }
                    ++i;
                }
                else
                {
                    estcHasInteractivePkcs8Pw = TRUE;
                }
            }
            else
            {
                estcHasInteractivePkcs8Pw = TRUE;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs8_enc_alg") == 0)
        {
            if (++i < argc)
            {
                if (NULL != estc_pkcs8EncAlg)
                {
                    (void) DIGI_FREE((void **) &estc_pkcs8EncAlg);
                    estc_pkcs8EncAlg = NULL;
                }

                setStringParameter(&estc_pkcs8EncAlg, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs12") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_pkcs12Gen = (intBoolean) DIGI_ATOL((const sbyte *) pTemp, NULL);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs12_enc_alg") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_pkcs12EncAlg, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs12_integrity_pw") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_pkcs12IntPw, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs12_privacy_pw") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_pkcs12PriPw, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_key_file_pkcs12_key_pw") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_pkcs12KeyPw, pArgv[i]);
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_fp_nocrypt") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_fp_nocrypt = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,(const sbyte **)&pEnd);
                /* If the range is invalid then set it to the default value.
                 */
                if ( (NULL == pEnd) || ('\0' != *pEnd) || (pTemp == pEnd) )
                {
                    estc_fp_nocrypt = 0;
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_protect_lib") == 0)
        {
            if (++i < argc)
            {
                /* Do nothing, this code ensures the index is maintained
                 * and we wont fall to the default error case. */
            }
            continue;
        }
#endif
#ifdef __ENABLE_DIGICERT_TAP__
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapmoduleid") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_tapModuleId = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                tapModuleIdSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapconfig") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_tap_confFile, pArgv[i]);
                tapconfFileSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapkeyusage") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                if (DIGI_STRLEN(pTemp) > 0 && FALSE == DIGI_ISDIGIT(pTemp[0]))
                {
                    status = EST_convertTapKeyUsageString(
                        pTemp, DIGI_STRLEN(pTemp), &estc_tapKeyUsage);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }
                else
                {
                    estc_tapKeyUsage = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                }
                tapKeyUsageSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapsignscheme") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                if (DIGI_STRLEN(pTemp) > 0 && FALSE == DIGI_ISDIGIT(pTemp[0]))
                {
                    status = EST_convertTapSigSchemeString(
                        pTemp, DIGI_STRLEN(pTemp), &estc_tapSignScheme);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }
                else
                {
                    estc_tapSignScheme = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                }
                tapSignSchemeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapencscheme") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                if (DIGI_STRLEN(pTemp) > 0 && FALSE == DIGI_ISDIGIT(pTemp[0]))
                {
                    status = EST_convertTapEncSchemeString(
                        pTemp, DIGI_STRLEN(pTemp), &estc_tapEncScheme);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }
                else
                {
                    estc_tapEncScheme = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, NULL);
                }
                tapEncSchemeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapkeypassword") == 0)
        {
            if (i + 1 < argc)
            {
                if (0 == DIGI_STRNICMP(pArgv[i + 1], (sbyte *)"pw:", DIGI_STRLEN((const sbyte *)"pw:")))
                {
                    if (DIGI_STRLEN(pArgv[i + 1]) > 3)
                    {
                        setStringParameter(&estc_tap_keyPassword, pArgv[i + 1] + 3);
                    }
                    else
                    {
                        status = ERR_INVALID_INPUT;
                        verbosePrintError("Please provide a valid password.", status);
                        goto exit;
                    }
                    ++i;
                }
                else
                {
                    estcHasInteractiveTapPw = TRUE;
                }
            }
            else
            {
                estcHasInteractiveTapPw = TRUE;
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapservername") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_tap_serverName, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_tapserverport") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_tap_serverPort = (ubyte4) DIGI_ATOL((const sbyte *)pTemp, NULL);
            }
            continue;
        }

#endif
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keyhandle") == 0)
        {
            if (++i < argc)
            {
                estc_tapKeyHandleSet = TRUE;
                setStringParameter(&estc_tapKeyHandleStr, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_certificatenvindex") == 0)
        {
            if (++i < argc)
            {
                estc_tapCertificateNvIndexSet = TRUE;
                setStringParameter(&estc_tapCertificateNvIndexStr, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keyprimary") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_tapKeyPrimary = (intBoolean) DIGI_ATOL((const sbyte *) pTemp, NULL);
                estc_tapKeyPrimarySet = TRUE;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keynoncenvindex") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_tapKeyNonceNvIndexStr, pArgv[i]);
                estc_tapKeyNonceNvIndexSet = TRUE;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keytokenhierarchy") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_tapTokenHierarchyStr, pArgv[i]);
                estc_tapTokenHierarchySet = TRUE;
            }
            continue;
        }
#endif
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_selfsigned") == 0)
        {
            estc_genselfsignedcert = 1;
            continue;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_qskeytype") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_qskeytype, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_curve") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_curve, pArgv[i]);
            }
            continue;
        }
#endif
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_keysize") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_keySize = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,NULL);
                keySizeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_rekeysize") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_newKeySize = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,NULL);
                newKeySizeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_renew_window") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_renewWindow = DIGI_ATOL((const sbyte *)pTemp,(const sbyte **)&pEnd);
                estc_renewWindowSet = TRUE;
                /* If the range is invalid then set it to the default value.
                 */
                if ( (NULL == pEnd) || ('\0' != *pEnd) || (pTemp == pEnd) )
                {
                    estc_renewWindow = 0;
                }
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_attributes") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_hasAttrib = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,NULL);
                hasAttribSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_fullcmcreqtype") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&est_fullcmcReqType, pArgv[i]);
                fullcmcReqTypeSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_renewinlinecert") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_renewinlinecert = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,NULL);
                estc_renewinlinecertSet = TRUE;
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_ocsp_required") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                estc_ocsp_required = (intBoolean) DIGI_ATOL((const sbyte *) pTemp, NULL);
            }
            estc_ocspSet = TRUE;
            continue;
        }
#endif
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_csr_conf") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_confFile, pArgv[i]);
                confFileSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_extattrs_conf") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_extattrs_confFile, pArgv[i]);
                conf_extattrs_FileSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_pskalias") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_pskFile, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_skg_alg") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_skgAlg, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_skg_clientcert") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_skg_clientcert, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_skg_clientkey") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_skg_clientkey, pArgv[i]);
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_digestname") == 0)
        {
            if (++i < argc)
            {
                setStringParameter(&estc_digestName, pArgv[i]);
                estcDigestNameSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_genkey") == 0)
        {
            g_genKeySet = 1;
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_verbose") == 0)
        {
            if (++i < argc)
            {
                pTemp = pArgv[i];
                if (1 == DIGI_STRLEN((sbyte *)pTemp) && pTemp[0] >= '0' && pTemp[0] <= '2')
                {
                    estc_verboseLevel = (unsigned short) DIGI_ATOL((const sbyte *)pTemp,NULL);
                }
                else
                {
                    estc_verboseLevel = ESTC_VERBOSE_LEVEL_INFO;
                }
                estcVerboseSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)pArgv[i], (const sbyte *)"-est_backup") == 0)
        {
            estc_backup = TRUE;
        }
        else
        {
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\n\n   Invalid Argument: ", (sbyte *)pArgv[i]);
            EST_EXAMPLE_displayHelp(pArgv[0]);
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    } /*for*/


    estc_config_type = EST_CONFIG_FILE;

    /* for GneKey or selfsignedcert option to succeed assign default values */
    if (g_genKeySet || estc_genselfsignedcert)
    {
        initializeDefaultValues();
        pwdSet = 1; /* avoid password prompt which is not required for this operation */
    }

    /*Set defaults if nothing entered from command line*/
    if (!ipSet)
    {
        setStringParameter(&estc_ServerIpAddr, ESTC_DEF_SERVER_NAME);
    }
    if (!portSet)
    {
        estc_ServerPort = ESTC_DEF_PORT;
    }
    if (!urlSet)
    {
        if (OK > (status = displayMissingOptions("est_url", pArgv[0])))
        {
            goto exit;
        }
    }
    else if (NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD) ||
                NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD))
    {
        status = ERR_NOT_IMPLEMENTED;
        DB_PRINT("Functionality not implemented\n");
        goto exit;
    }
    if (!userSet)
    {
        setStringParameter(&estc_User, "");
    }
    if (!pwdSet)
    {
        if ((NULL != estc_ServerURL) && (NULL == strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD) &&
                NULL == strstr((const char *)estc_ServerURL, EST_CACERTS_CMD)) &&
                (NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_ENROLL_CMD) ||
                NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD) ||
                NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)))
        {
            /* Try to get from User by prompting for password. */
            sbyte *pUserPasswd = NULL;
            int passwdLoopCount = 0;
            int passwdLen = 0;
#ifdef __RTOS_WIN32__
			char c;
			int idx = 0;
#endif
            if (OK > (status = DIGI_MALLOC((void**)&pUserPasswd, USER_PASSWORD_LENGTH)))
            {
                goto exit;
            }

            do {
                DIGI_MEMSET((ubyte *)pUserPasswd, '\0', USER_PASSWORD_LENGTH);
                passwdLoopCount++;
                printf ("\nPlease enter password for the user \"%s\" \n", estc_User);
#if (!defined(__RTOS_WIN32__) && !defined(__RTOS_VXWORKS__) && !defined(__RTOS_FREERTOS__) && !defined(__RTOS_AZURE__))
                passwdLen = getPasswordFromUser(&pUserPasswd, USER_PASSWORD_LENGTH, '*');
#elif defined(__RTOS_VXWORKS__) || defined(__RTOS_FREERTOS__) || defined(__RTOS_AZURE__)
#else
				while ((c = (char)_getch()) != 13 && idx < (USER_PASSWORD_LENGTH - 1))
				{
					pUserPasswd[idx++] = c;
					printf("*");
				}
				pUserPasswd[idx] = 0;
				passwdLen = idx;
#endif
                verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, ""); /* Just to move cursor to next line */
                if (passwdLen > 0)
                {
                    setStringParameter(&estc_Pass, (char *)pUserPasswd);
                    pwdSet = 1;
                    break;
                }
            } while (passwdLoopCount < 3);

            DIGI_FREE((void **)&pUserPasswd);

            if (!pwdSet)
            {
                if (OK > (status = displayMissingOptions("est_pass", pArgv[0])))
                {
                    goto exit;
                }
            }
        }
        else
        {
            if (NULL == strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD))
            {
                if (OK > (status = displayMissingOptions("est_pass", pArgv[0])))
                {
                    goto exit;
                }
            }
        }
    }
    if (!confFileSet)
    {
        setStringParameter(&estc_confFile, DEFAULT_CONF_FILE);
    }
    if (!estc_keyAlias1)
    {
        setStringParameter((sbyte**)&estc_keyAlias1, "GenKey");
    }
    if (!fullcmcReqTypeSet)
    {
        setStringParameter(&est_fullcmcReqType, FULL_CMC_REQ_TYPE_ENROLL);
    }
    if (NULL == estc_certPath)
    {
#if defined(__RTOS_WIN32__) && defined(__ENABLE_DIGICERT_TAP__)
        status = TAP_UTILS_getWinConfigFilePath(&estc_certPath, ESTC_DEF_CERTPATH_NAME);
        if (OK != status)
        {
            DB_PRINT("%d.%s: Error %d fetching default configuration path\n",
                    __FUNCTION__, __LINE__, status);
            if (OK > (status = displayMissingOptions("est_certpath", pArgv[0])))
            {
                goto exit;
            }
        }
#else
        if (OK > (status = displayMissingOptions("est_certpath", pArgv[0])))
        {
            goto exit;
        }
#endif
    }
    if (!nameSet)
    {
        if (OK > (status = displayMissingOptions("est_servername", pArgv[0])))
        {
            goto exit;
        }
    }
    if (!keyTypeSet)
    {
        if (OK > (status = displayMissingOptions("est_keytype", pArgv[0])))
        {
            goto exit;
        }
    }
    if (!newKeyTypeSet)
    {
        setStringParameter(&estc_newKeyType, ESTC_DEF_NEW_KEYTYPE);
    }
    if (!keySourceSet)
    {
        setStringParameter(&estc_keySource, ESTC_DEF_KEYSOURCE);
    }
#ifdef __ENABLE_DIGICERT_TAP__
    if (!tapModuleIdSet)
    {
        estc_tapModuleId = ESTC_DEF_TAP_MODULEID;
    }
    if (((DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM2) == 0) ||
                (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_STSAFE) == 0) ||
                (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_NXPA71) == 0) ||
                (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM1_2) == 0) ||
                (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_PKCS11) == 0 )))
    {
        useTAP = 1;
    }
#ifdef __ENABLE_DIGICERT_TEE__
    else if (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TEE) == 0)
    {
        useTEE = 1;
    }

    if (useTEE && !tapconfFileSet)
    {
        setStringParameter(&estc_tap_confFile, TEE_CONFIGURATION);
    }
#endif
    if (useTAP && !tapconfFileSet)
    {
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
        setStringParameter(&estc_tap_confFile, PKCS11_CONFIGURATION);
#else
#if defined(__RTOS_WIN32__)
        if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM1_2) == 0)
        {
            status = TAP_UTILS_getWinConfigFilePath(&estc_tap_confFile, TPM12_CONFIGURATION);
            if (OK != status)
            {
                setStringParameter(&estc_tap_confFile, TPM12_CONFIGURATION);
            }
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM2) == 0)
        {
            status = TAP_UTILS_getWinConfigFilePath(&estc_tap_confFile, TPM2_CONFIGURATION);
            if (OK != status)
            {
                setStringParameter(&estc_tap_confFile, TPM2_CONFIGURATION);
            }
        }
#else
        if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM1_2) == 0)
        {
            setStringParameter(&estc_tap_confFile, TPM12_CONFIGURATION);
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM2) == 0)
        {
            setStringParameter(&estc_tap_confFile, TPM2_CONFIGURATION);
        }
#endif /*__RTOS_WIN32__ */
#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */
    }

    if (!tapKeyUsageSet)
    {
        estc_tapKeyUsage = TAP_KEY_USAGE_GENERAL;
    }
    if (!tapSignSchemeSet)
    {
        sbyte *pKeyType = estc_keyType;
        if ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
                (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) )
        {
            pKeyType = estc_newKeyType;
        }

        if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            estc_tapSignScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
        }
        else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            estc_tapSignScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
        }
        else
        {
            estc_tapSignScheme = TAP_SIG_SCHEME_NONE;
        }
    }
    if (!tapEncSchemeSet)
    {
        estc_tapEncScheme = TAP_ENC_SCHEME_PKCS1_5;
    }
    if (TAP_KEY_USAGE_ATTESTATION == estc_tapKeyUsage)
    {
        sbyte *pKeyType = estc_keyType;
        if ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
                (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) )
        {
            pKeyType = estc_newKeyType;
        }

        if ( (DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0) &&
             (TAP_SIG_SCHEME_PKCS1_5_SHA256 != estc_tapSignScheme) )
        {
            if (VERBOSE_DEBUG)
            {
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Overriding estc_tapSignScheme for attestation");
            }
            estc_tapSignScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
        }
    }
#endif /* __ENABLE_DIGICERT_TAP__ */
    if (!keySizeSet)
    {
        if (OK > (status = displayMissingOptions("est_keysize", pArgv[0])))
        {
            goto exit;
        }
    }
    if (!newKeySizeSet)
    {
        estc_newKeySize = ESTC_DEF_KEYSIZE;
    }
    if (!hasAttribSet)
    {
        estc_hasAttrib = ESTC_DEF_HASATTRIB;
    }
    if (!estcDigestNameSet)
    {
        setStringParameter(&estc_digestName, DEFAULT_DIGEST_NAME);
    }
    if (!estcVerboseSet)
    {
        estc_verboseLevel = ESTC_VERBOSE_LEVEL_INFO;
    }
    if (TRUE == estcHasInteractivePkcs8Pw && 0 == DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_SW))
    {
        ubyte4 passwordLen = 0;
        do
        {
            if (NULL != estc_pkcs8Pw)
            {
                DIGI_MEMSET_FREE((ubyte **)&estc_pkcs8Pw, passwordLen);
            }

            status = EST_EXAMPLE_getPassword((ubyte **)&estc_pkcs8Pw, &passwordLen, "PEM", "private key");
            if (OK != status)
            {
                goto exit;
            }

            if (!passwordLen)
            {
                verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "PKCS8 key password cannot be empty string.\n");
                continue;
            }
        } while (0 == passwordLen);
    }

exit:
    /*End of defaults*/
    if (OK != status)
    {
        (void) DIGI_FREE((void **)&estc_keySource);
        (void) DIGI_FREE((void **)&estc_keyType);
        (void) DIGI_FREE((void **)&estc_newKeyType);
        (void) DIGI_FREE((void **)&estc_keyAlias1);
        (void) DIGI_FREE((void **)&est_fullcmcReqType);
        (void) DIGI_FREE((void **)&estc_digestName);
        (void) DIGI_FREE((void **)&estc_User);
        (void) DIGI_FREE((void **)&estc_Pass);
        (void) DIGI_FREE((void **)&estc_ServerURL);
        (void) DIGI_FREE((void **)&estc_serverName);
        (void) DIGI_FREE((void **)&estc_ServerIpAddr);
        (void) DIGI_FREE((void **)&estc_confFile);
        (void) DIGI_FREE((void **)&estc_serverName);
        (void) DIGI_FREE((void **)&estc_keySource);
        (void) DIGI_FREE((void **)&estc_keyAlias1);
        (void) DIGI_FREE((void **)&estc_certPath);
        (void) DIGI_FREE((void **)&estc_truststorePath);
        (void) DIGI_FREE((void **)&estc_http_proxy);
        (void) DIGI_FREE((void **)&estc_certPath);
        (void) DIGI_FREE((void **)&estc_truststorePath);
        (void) DIGI_FREE((void **)&estc_http_proxy);
        (void) DIGI_FREE((void **)&estc_pkcs8EncAlg);
    }

    return status;

}

MOC_EXTERN sbyte4
EST_EXAMPLE_http_responseBodyCallback(httpContext *pHttpContext,
        ubyte *pDataReceived,
        ubyte4 dataLength,
        sbyte4 isContinueFromBlock)
{

    return EST_responseBodyCallbackHandle(pHttpContext,
            pDataReceived, dataLength,
            isContinueFromBlock);
}



extern sbyte4
EST_EXAMPLE_http_responseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock)
{
    /* do nothing */
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);
    return OK;
}


static sbyte4
EST_EXAMPLE_passwordPrompt(httpContext *pHttpContext, const ubyte* pChallenge, ubyte4 challengeLength,
        ubyte **ppUser, ubyte4* pUserLength, ubyte **ppPassword, ubyte4 *pPasswordLength, sbyte4 isContinueFromBlock)
{
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);
	MOC_UNUSED(pChallenge);
	MOC_UNUSED(challengeLength);
    *ppUser = (ubyte *)estc_User;
    *pUserLength = DIGI_STRLEN(estc_User);
    *ppPassword = (ubyte *)estc_Pass;
    *pPasswordLength = DIGI_STRLEN(estc_Pass);
    return OK;
}

extern sbyte4
EST_EXAMPLE_http_requestBodyCallback (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie)
{

    return EST_requestBodyCallback(pHttpContext, ppDataToSend, pDataLength, pRequestBodyCookie);
}

static sbyte4
EST_EXAMPLE_HttpTcpSend(httpContext *pHttpContext, TCP_SOCKET socket,
        ubyte *pDataToSend, ubyte4 numBytesToSend,
        ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MSTATUS status = OK;
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);

    if (VERBOSE_DEBUG)
    {
        verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "numBytesToSend = ", numBytesToSend);
    }

    status = TCP_WRITE(socket, (sbyte *)pDataToSend,numBytesToSend, pRetNumBytesSent);
    return status;
}

MOC_STATIC sbyte4
EST_EXAMPLE_HttpSslSend(httpContext *pHttpContext, TCP_SOCKET socket,
        ubyte *pDataToSend, ubyte4 numBytesToSend,
        ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
	MOC_UNUSED(pHttpContext);
	MOC_UNUSED(isContinueFromBlock);
    if (VERBOSE_DEBUG) verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "connectionInstance = ", gSslConnectionInstance);
    if (VERBOSE_DEBUG) verbosePrintPointer(ESTC_VERBOSE_LEVEL_ALL, "EST_EXAMPLE_HttpSslSend::pDataToSend: ", pDataToSend);
    if (VERBOSE_DEBUG) verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_ALL, "EST_EXAMPLE_HttpSslSend Called numBytesToSend = ", numBytesToSend);
    if (VERBOSE_DEBUG) verbosePrintLengthNL(ESTC_VERBOSE_LEVEL_ALL, (char *)pDataToSend, numBytesToSend);
    if (VERBOSE_DEBUG) verboseHexDump(ESTC_VERBOSE_LEVEL_ALL, pDataToSend, numBytesToSend);

    sbyte4 sslConnectionInst = SSL_getInstanceFromSocket(socket);
    *pRetNumBytesSent = SSL_send(sslConnectionInst, (sbyte  *)pDataToSend, numBytesToSend);
    return OK;
}

static MSTATUS
EST_EXAMPLE_deserializeAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen,
    ubyte *pPass, ubyte4 passLen, AsymmetricKey *pAsymKey)
{
    MSTATUS status;
    ubyte *pDecodedKey = NULL;
    ubyte4 decodedKeyLen = 0;

    if ( (NULL == pKey) || (NULL == pAsymKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(pAsymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(
        MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, pAsymKey);
    if ( (OK != status) && (NULL != pPass) )
    {
        status = CA_MGMT_decodeCertificate(
            pKey, keyLen, &pDecodedKey, &decodedKeyLen);
        if (OK == status)
        {
            pKey = pDecodedKey;
            keyLen = decodedKeyLen;
        }

        status = PKCS_getPKCS8KeyEx(
            MOC_HW(hwAccelCtx) pKey, keyLen, pPass, passLen, pAsymKey);
    }

exit:

    if (NULL != pDecodedKey)
        DIGI_FREE((void **) &pDecodedKey);

    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__
/*
@brief     Initializes the TAP Module and Token.

@details   This function initiliazes the tap module and its token.

@param pTapConfFile     Pointer to the config file.
@param ppEstTapContext  On return, double pointer to the EstTapContext.

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MSTATUS EST_EXAMPLE_tapInitialize(ubyte *pTapConfFile, EST_TapContext *pEstTapContext)
{
    MSTATUS status = OK;
    MSTATUS exit_status = OK;
    TAP_ConfigInfo config = {0};
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_EntityCredentialList *pEntityCredentialList = NULL;
    TAP_Module module = {0};
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

    if (pEstTapContext == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapConfFile)
    {
        if (NULL != estc_tap_confFile)
        {
            DIGI_FREE((void **) &estc_tap_confFile);
        }

        if (estc_tapKeySourceRuntime)
        {
            if (TAP_PROVIDER_TPM2 == estc_tapProvider)
            {
#if defined(__RTOS_WIN32__)
                status = TAP_UTILS_getWinConfigFilePath(&estc_tap_confFile, TPM2_CONFIGURATION);
#else
                pTapConfFile = TPM2_CONFIGURATION;
#endif
            }
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
            else if (TAP_PROVIDER_PKCS11 == estc_tapProvider)
            {
#if defined(__RTOS_WIN32__)
                status = TAP_UTILS_getWinConfigFilePath(&estc_tap_confFile, PKCS11_CONFIGURATION);
#else
                pTapConfFile = PKCS11_CONFIGURATION;
#endif
            }
#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */
#if defined(__ENABLE_DIGICERT_TEE__)
            else if (TAP_PROVIDER_TEE == estc_tapProvider)
            {
#if defined(__RTOS_WIN32__)
                status = TAP_UTILS_getWinConfigFilePath(&estc_tap_confFile, TEE_CONFIGURATION);
#else
                pTapConfFile = TEE_CONFIGURATION;
#endif
            }
#endif /* __ENABLE_DIGICERT_TEE__ */
        }
        else
        {
#if defined(__RTOS_WIN32__)
            /* we really just don't know, default to tpm2 */
            status = TAP_UTILS_getWinConfigFilePath(&estc_tap_confFile, TPM2_CONFIGURATION);
#else
            pTapConfFile = TPM2_CONFIGURATION;
#endif
        }

#if defined(__RTOS_WIN32__)
        if (OK != status)
            goto exit;

        pTapConfFile = estc_tap_confFile;
#endif
    }

    if (!estc_tapKeySourceRuntime)
    {
        if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"TPM2") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_TPM2;
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"TPM1.2") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_TPM;
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"PKCS11") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_PKCS11;
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"NXPA71") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_NXPA71;
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"STSAFE") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_STSAFE;
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"SGX") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_SGX;
        }
        else if(DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)"TEE") == 0)
        {
            estc_tapProvider = TAP_PROVIDER_TEE;
        }
        else /* default */
        {
            estc_tapProvider = TAP_PROVIDER_TPM2;
        }
    }
    /* Otherwise we already have provider and module set */

    config.provider = estc_tapProvider;
    configInfoList.count = 1;
    configInfoList.pConfig = &config;

#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
#if defined (__ENABLE_DIGICERT_NXPA71__)
    if(TAP_PROVIDER_NXPA71 == estc_tapProvider)
    {
        status = initNXPA71TapConfigInfo(&configInfoList.pConfig[0]);
        pTapConfFile[0] = 0;
    }
    else
#endif
    {
        status = TAP_readConfigFile((char *)pTapConfFile,
                   &configInfoList.pConfig[0].configInfo, FALSE);
    }
    if (OK != status)
    {
        verbosePrintError("Unable to read TAP configuration file.", status);
        goto exit;
    }
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        verbosePrintError("Unable to initialize TAP.", status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    /* Discover modules */
    connInfo.serverName.bufferLen = DIGI_STRLEN(estc_tap_serverName)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)estc_tap_serverName, DIGI_STRLEN(estc_tap_serverName));
    if (OK != status)
    goto exit;

    connInfo.serverPort = estc_tap_serverPort;
    module.hostInfo = connInfo;
#endif

    if (0 == estc_tapModuleId)
    {
        status = ERR_TAP_BAD_MODULE_ID;
        goto exit;
    }
    module.providerType = estc_tapProvider;
    module.moduleId = estc_tapModuleId;

    /* no credentials for tee */
#ifndef __ENABLE_DIGICERT_TAP_REMOTE__
#ifdef __ENABLE_DIGICERT_TEE__
    if (TAP_PROVIDER_TEE != estc_tapProvider)
#endif
    {
        status = TAP_getModuleCredentials(&module,
                (char *)pTapConfFile, TRUE,
                &pEntityCredentialList,
                pErrContext);

        if (OK != status)
        {
            verbosePrintError("Unable to get entity credentials.", status);
            goto exit;
        }
    }
#endif

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(&module, pEntityCredentialList,
                                NULL, &pTapContext, pErrContext);
    if ( (OK != status) || (NULL==pTapContext) )
    {
        verbosePrintError("Unable to initialize TAP context.", status);
        goto exit;
    }
    pEstTapContext->pTapContext = pTapContext;
    pEstTapContext->pEntityCredentialList = pEntityCredentialList;

    if (TRUE == estcHasInteractiveTapPw || NULL != estc_tap_keyPassword)
    {
        ubyte *pPassBuf = NULL;
        TAP_Credential *pCredentialList = NULL;

        if (OK != (status = DIGI_CALLOC((void**)&pEstTapContext->pKeyCredentialList, 1, sizeof(TAP_CredentialList))))
        {
            verbosePrintError("Unable to allocate memory.", status);
            goto exit;
        }

        /* If key password is not null copy the password to TAP_CredentialList*/
        if (NULL != estc_tap_keyPassword)
        {
            status = DIGI_CALLOC((void **) &pCredentialList, 1, sizeof(TAP_Credential));
            if (OK != status)
            {
                verbosePrintError("Unable to allocate memory.", status);
                goto exit;
            }

            pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
            pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
            pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;

            status = DIGI_MALLOC((void**)&pPassBuf, DIGI_STRLEN(estc_tap_keyPassword));
            if (OK != status)
            {
                DIGI_FREE((void**)&pCredentialList);
                verbosePrintError("Unable to allocate memory.", status);
                goto exit;
            }
            status = DIGI_MEMCPY((ubyte*)pPassBuf, estc_tap_keyPassword, DIGI_STRLEN(estc_tap_keyPassword));
            if (OK != status)
            {
                DIGI_FREE((void**)&pPassBuf);
                DIGI_FREE((void**)&pCredentialList);
                verbosePrintError("Unable to copy TAP key password.", status);
                goto exit;
            }
            pCredentialList[0].credentialData.bufferLen = DIGI_STRLEN(estc_tap_keyPassword);
            pCredentialList[0].credentialData.pBuffer = pPassBuf;
            pEstTapContext->pKeyCredentialList->numCredentials = 1;
            pEstTapContext->pKeyCredentialList->pCredentialList = pCredentialList;
        }
    }
    else
    {
        pEstTapContext->pKeyCredentialList = NULL;
    }

exit:

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        (void) TAP_UTILS_freeBuffer(&(configInfoList.pConfig[0].configInfo)); /* ok if empty configInfo */
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        (void) DIGI_FREE((void**)&connInfo.serverName.pBuffer);
    }
#endif
    return status;
}

/*
@brief     Uninitializes the Module and the token.

@details   This function uninitiliazes the tap module and its token.

@param pEstTapContext  Pointer to the EstTapContext.

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MSTATUS EST_EXAMPLE_tapUninitialize(EST_TapContext *pEstTapContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext errContext;

    if (pEstTapContext == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Uninitialize context */
    if ((NULL != pEstTapContext->pTapContext))
    {
        status = TAP_uninitContext(&pEstTapContext->pTapContext, &errContext);
        if (OK != status)
        {
            verbosePrintError("Unable to un-initialize TAP context.", status);
            goto exit;
        }
    }
    status = TAP_uninit(&errContext);
    if (OK != status)
        verbosePrintError("Unable to un-initialize TAP error context.", status);

exit:
    return status;
}

static MSTATUS EST_persistDataAtNVIndex(
    ubyte8 index, ubyte *pData, ubyte4 dataLen,
    TAP_AUTH_CONTEXT_PROPERTY inputAuthProp)
{
    MSTATUS status;
    TAP_ObjectInfoList objectInfoList = {0};
    TAP_StorageInfo storageInfo = {0};
    TAP_CredentialList storageCredentials = {0};
    TAP_AttributeList setAttributes = {0};
    TAP_AUTH_CONTEXT_PROPERTY authContext = inputAuthProp;
    TAP_Attribute keyAttribute = {
        TAP_ATTR_AUTH_CONTEXT, sizeof(TAP_AUTH_CONTEXT_PROPERTY), &authContext
    };
    TAP_Buffer nvIn = { 0 };
    ubyte4 i;

    status = TAP_getPolicyStorageList(
        g_pEstTapContext->pTapContext, g_pEstTapContext->pEntityCredentialList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify index does not exist */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            status = ERR_TAP_NV_INDEX_EXISTS;
            goto exit;
        }
    }

    storageInfo.index = index;
    storageInfo.size = dataLen;
    storageInfo.storageType = TAP_WRITE_OP_DIRECT;
    storageInfo.ownerPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE);
    storageInfo.publicPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE);
    storageInfo.pAttributes = NULL;
    storageInfo.authContext = authContext;

    /* Create index */
    status = TAP_allocatePolicyStorage(
        g_pEstTapContext->pTapContext, g_pEstTapContext->pEntityCredentialList,
        &storageInfo, NULL, &storageCredentials, NULL);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    status = TAP_getPolicyStorageList(
        g_pEstTapContext->pTapContext, g_pEstTapContext->pEntityCredentialList,
        NULL, &objectInfoList, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify index exists */
    for (i = 0; i < objectInfoList.count; i++)
    {
        if (objectInfoList.pInfo[i].objectId == index)
        {
            break;
        }
    }

    if (i == objectInfoList.count)
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    nvIn.pBuffer = pData;
    nvIn.bufferLen = dataLen;

    if (TAP_AUTH_CONTEXT_PLATFORM == authContext)
    {
        setAttributes.listLen++;
        setAttributes.pAttributeList = &keyAttribute;
    }

    status = TAP_setPolicyStorage(
        g_pEstTapContext->pTapContext, g_pEstTapContext->pEntityCredentialList,
        &objectInfoList.pInfo[i], &setAttributes, &nvIn, NULL);

exit:

    if (NULL != objectInfoList.pInfo)
    {
        DIGI_FREE((void**) &objectInfoList.pInfo);
    }

    return status;
}

/*
@brief     Creates a tap Asymmetric key.

@details   This function creates a TAP Asymmetric key.

@param keys          On return, Pointer to the MKeyPairGenResult which contains the MocAsymKey.
@param pKeyType      Type of the key.
@param keySize       Size of the key.
@param ppVlongQueue  Double Pointer to the vlong.

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MSTATUS EST_EXAMPLE_createTapAsymKey(AsymmetricKey *pKey, ubyte *pKeyType, ubyte4 keySize)
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pNewKey = NULL;
    ubyte4 numKeyAttrs = 0, i = 0;
    TAP_AttributeList *pKeyAttributes = NULL;
    TAP_AttributeList keyAttributes = { 0 };
    TAP_CREATE_KEY_TYPE keyType = TAP_CREATE_KEY_TYPE_PRIMARY;
    TAP_Buffer uniqueDataBuf = { 0 };
    ubyte4 keyNonceByteLen = 0;
    ubyte *pKeyNonce = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};
#ifdef __ENABLE_DIGICERT_ECC__
    MEccTapKeyGenArgs eccTapArgs = {0};
    ubyte4 curveId;
#endif

    if (pKey != NULL)
    {
        status = CRYPTO_initAsymmetricKey(pKey);
        if (OK != status)
            goto exit;

        if (TRUE == estc_tapKeyPrimary)
        {
            numKeyAttrs += 3;

            status = DIGI_CALLOC(
                (void **) &(keyAttributes.pAttributeList), numKeyAttrs,
                sizeof(TAP_Attribute));
            if (OK != status)
            {
                goto exit;
            }
            keyAttributes.listLen = numKeyAttrs;

            keyAttributes.pAttributeList[i].type = TAP_ATTR_CREATE_KEY_TYPE;
            keyAttributes.pAttributeList[i].length = sizeof(TAP_CREATE_KEY_TYPE);
            keyAttributes.pAttributeList[i].pStructOfType = &keyType;
            i++;

            /* Get byte length relative to curve/key size */
            if (DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
            {
                /* RSA sizes are checked earlier when validating arguments and
                 * ensured to be a multiple of 8 */
                keyNonceByteLen = keySize / 8;
            }
#ifdef __ENABLE_DIGICERT_ECC__
            else
            {
                switch (keySize)
                {
                    case 192:
                        keyNonceByteLen = 24;
                        break;
                    case 224:
                        keyNonceByteLen = 28;
                        break;
                    case 256:
                        keyNonceByteLen = 32;
                        break;
                    case 384:
                        keyNonceByteLen = 48;
                        break;
                    case 521:
                        keyNonceByteLen = 66;
                        break;
                    default:
                        status = ERR_TAP_INVALID_CURVE_ID;
                        goto exit;
                }
            }
#endif

            status = DIGI_MALLOC((void **) &pKeyNonce, keyNonceByteLen);
            if (OK != status)
            {
                goto exit;
            }

            status = RANDOM_numberGenerator(
                g_pRandomContext, pKeyNonce, keyNonceByteLen);
            if (OK != status)
            {
                goto exit;
            }

            uniqueDataBuf.pBuffer = pKeyNonce;
            uniqueDataBuf.bufferLen = keyNonceByteLen;

            keyAttributes.pAttributeList[i].type = TAP_ATTR_CREATE_KEY_ENTROPY;
            keyAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
            keyAttributes.pAttributeList[i].pStructOfType = &uniqueDataBuf;
            i++;

            keyAttributes.pAttributeList[i].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
            keyAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
            keyAttributes.pAttributeList[i].pStructOfType = &estc_tapKeyHandle;
            i++;

            pKeyAttributes = &keyAttributes;
        }

        if (TRUE == estcHasInteractiveTapPw)
        {
            status = EST_EXAMPLE_addCreds(g_pEstTapContext->pKeyCredentialList);
            if (OK != status)
            {
                verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "ERROR: Unable to create password credential for TAP key.\n");
                goto exit;
            }
        }

        if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            if (estc_tapKeyUsage == TAP_KEY_USAGE_DECRYPT) {
                rsaTapArgs.algKeyInfo.rsaInfo.encScheme = estc_tapEncScheme;
            }
            else if (estc_tapKeyUsage == TAP_KEY_USAGE_GENERAL)
            {
                rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = estc_tapSignScheme;
                rsaTapArgs.algKeyInfo.rsaInfo.encScheme = estc_tapEncScheme;
            }
            else
            {
                rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = estc_tapSignScheme;
            }
            rsaTapArgs.tokenId = estc_tapTokenHierarchy;
            rsaTapArgs.keyUsage = estc_tapKeyUsage;
            rsaTapArgs.pTapCtx = g_pEstTapContext->pTapContext;
            rsaTapArgs.pEntityCredentials = g_pEstTapContext->pEntityCredentialList;
            rsaTapArgs.pKeyCredentials = g_pEstTapContext->pKeyCredentialList;
            rsaTapArgs.pKeyAttributes = pKeyAttributes;
            status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(gHwAccelCtx)
                NULL, &pNewKey, keySize, NULL, akt_tap_rsa,
                &rsaTapArgs);
            if (OK != status)
                goto exit;

            pKey->key.pRSA = pNewKey;
            pKey->type = akt_tap_rsa;
        }
#ifdef __ENABLE_DIGICERT_ECC__
        else
        {
            eccTapArgs.tokenId = estc_tapTokenHierarchy;
            eccTapArgs.keyUsage = estc_tapKeyUsage;
            eccTapArgs.pTapCtx = g_pEstTapContext->pTapContext;
            eccTapArgs.algKeyInfo.eccInfo.sigScheme = estc_tapSignScheme;
            eccTapArgs.pEntityCredentials = g_pEstTapContext->pEntityCredentialList;
            eccTapArgs.pKeyCredentials = g_pEstTapContext->pKeyCredentialList;

            switch (keySize)
            {
                case 192:
                    curveId = cid_EC_P192;
                    break;
                case 224:
                    curveId = cid_EC_P224;
                    break;
                case 256:
                    curveId = cid_EC_P256;
                    break;
                case 384:
                    curveId = cid_EC_P384;
                    break;
                case 521:
                    curveId = cid_EC_P521;
                    break;
                default:
                    status = ERR_TAP_INVALID_CURVE_ID;
                    goto exit;
            }

            eccTapArgs.pKeyAttributes = pKeyAttributes;
            status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(gHwAccelCtx)
                curveId, &pNewKey, NULL, NULL, akt_tap_ecc, &eccTapArgs);
            if (OK != status)
                goto exit;

            pKey->key.pECC = pNewKey;
            pKey->type = akt_tap_ecc;
        }
#endif
        if (TRUE == estc_tapKeyPrimary)
        {
            if (OK == status)
            {
                if (TRUE == estc_tapKeyNonceNvIndexSet)
                {
                    /* Primary key was created successfully, persist the primary
                     * key nonce as well. Do not treat failure to store nonce as
                     * error */
                    if (OK == EST_persistDataAtNVIndex(
                        estc_tapKeyNonceNvIndex, pKeyNonce, keyNonceByteLen, TAP_AUTH_CONTEXT_PLATFORM))
                    {
                        verbosePrintString1Hex1NL(ESTC_VERBOSE_LEVEL_INFO, "Persisted primary key nonce at index: 0x", estc_tapKeyNonceNvIndex);
                    }
                    else
                    {
                        verbosePrintString1Hex1NL(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Unable to persist primary key nonce at index: 0x", estc_tapKeyNonceNvIndex);
                    }
                }

                verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "Persisted primary key at index (or id): ");
            }
            else
            {
                verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Unable to persist/generate primary key at index (or id): ");
            }
            if (estc_isIdHex)
            {
                verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "0x");
                for (i = 0; i < estc_tapKeyHandle.bufferLen; i++)
                {
                    verbosePrintString1Hex(ESTC_VERBOSE_LEVEL_INFO, estc_tapKeyHandle.pBuffer[i]);
                }
            }
            else
            {
                verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, (sbyte *) estc_tapKeyHandle.pBuffer);
            }
            verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");
        }
    }
exit:
    if (NULL != pKeyNonce)
    {
        DIGI_FREE((void **) &pKeyNonce);
    }
    if (NULL != keyAttributes.pAttributeList)
    {
        DIGI_FREE((void **) &(keyAttributes.pAttributeList));
    }
    return status;
}

static MSTATUS EST_EXAMPLE_getTapVariables(
    TAP_Context **ppTapContext,
    TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred,
    byteBoolean getContext)
{
    MSTATUS status = OK;

    if ( (NULL == ppTapContext) || (NULL == ppTapEntityCred) ||
         (NULL == ppTapKeyCred) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (getContext)
    {
        if (NULL == g_pEstTapContext)
        {
            status = ERR_TAP_INVALID_CONTEXT;
            goto exit;
        }

        *ppTapContext = g_pEstTapContext->pTapContext;
        *ppTapEntityCred = g_pEstTapContext->pEntityCredentialList;
        *ppTapKeyCred = g_pEstTapContext->pKeyCredentialList;
    }
    else
    {
        *ppTapContext = NULL;
        *ppTapEntityCred = NULL;
        *ppTapKeyCred = NULL;
    }

exit:

    return status;
}



/*
@brief     Get the TAPContext.

@details   This function gets the TAPContext.

@param ppTapContext  On return, Double pointer to tapContext.
@param pKey          Pointer to the MocAsymKey or MocSymCtx.
@param op            TapOperation to be performed.

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
static sbyte4
EST_EXAMPLE_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;

    if (g_pEstTapContext == NULL || g_pEstTapContext->pTapContext == NULL)
    {
        if (OK != (status = DIGI_MALLOC((void**)&g_pEstTapContext, sizeof(EST_TapContext))))
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMSET((ubyte*)g_pEstTapContext, 0x00, sizeof(EST_TapContext))))
        {
            goto exit;
        }

        /* Initialize */
        if (OK != (status = EST_EXAMPLE_tapInitialize((ubyte*)estc_tap_confFile, g_pEstTapContext)))
        {
            verbosePrintError("\nEST_EXAMPLE_getTapContext::EST_EXAMPLE_tapInitialize ",
	                status);
            goto exit;
        }
    }

    if (NULL == ppTapContext || NULL == ppTapEntityCred || NULL == ppTapKeyCred)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        *ppTapContext = g_pEstTapContext->pTapContext;
        *ppTapEntityCred = g_pEstTapContext->pEntityCredentialList;
        *ppTapKeyCred = g_pEstTapContext->pKeyCredentialList;

    }
    else
    {
        /* tapContext, keyCredentials and EntityCredentials will be freed at the end of the application */
        *ppTapContext = NULL;
        *ppTapEntityCred = NULL;
        *ppTapKeyCred = NULL;
    }

exit:
    return status;
}

/*
@brief     Stores MocAsymKey to Certstore.

@details   This function stores MocAsymKey to the certstore.

@param pKeyBlob    Pointer to the keyblob.
@param keyBlobLen  Length of the keyblob.
@param pKeyAlias   Pointer to the key alias name.
@param keyAliasLen Length of the key alias.
@param pCert       Pointer to the certificate buffer.
@param certLen     Length of the certificate buffer.

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MSTATUS EST_EXAMPLE_storeMocKeyInCertstore(ubyte *pKeyBlob, ubyte4 keyBlobLen/*AsymmetricKey pKey*/, ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte *pCert, ubyte4 certLen)
{
	MSTATUS status = OK;
	ubyte* pAsymBlob = NULL; /* This is the blob of the from AsymmetricKey to be fed into CERT_STORE */
	ubyte4 asymBlobLen;
    AsymmetricKey asymKey = {0};

    if (OK != (status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx) pKeyBlob, keyBlobLen, NULL, &asymKey)))
    {
        verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "Failed to deserialize the key, Please cleanup software keys from keystore if any.");
		verbosePrintError("Unable to deserialize the key. Please cleanup software keys from keystore if any.", status);
        goto exit;
    }

	if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &asymKey, mocanaBlobVersion2, &pAsymBlob, &asymBlobLen)))
	{
		verbosePrintError("Unable to serialize asymmetric key.", status);
		goto exit;
	}
	/* Add the KeyBlob to the CERT STORE */
    if (pCert == NULL)
    {
        if (OK != (status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                                                           pKeyAlias, keyAliasLen,
                                                           pAsymBlob, asymBlobLen)))
        {
            verbosePrintError("Unable to add naked key to certstore.", status);
            goto exit;
        }
    }
    else
    {
        if (OK > (status = CERT_STORE_addIdentityEx(pCertStore,
                                                    pKeyAlias, keyAliasLen,
                                                    pCert, certLen,
                                                    pAsymBlob, asymBlobLen)))
        {
            goto exit;
        }
    }
exit:
    if(pAsymBlob)
        DIGI_FREE((void **)&pAsymBlob);

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
	return status;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)

/* Read in an encrypted or signed file which was protected using file protect.
 */
static MSTATUS EST_readFileFp(
    char *pFullPath, ubyte **ppData, ubyte4 *pDataLen,
    byteBoolean releaseContext, ubyte4 category)
{
    MSTATUS status;
    intBoolean fileExist;
    byteBoolean process;

    status = DIGICERT_checkFile(pFullPath, MOC_FP_SIG_SUFFIX, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    status = DPM_checkStatus(category, &process);
    if (OK != status)
    {
        goto exit;
    }

    if ( (TRUE == fileExist) && (TRUE == process) )
    {
        status = DIGICERT_readSignedFile(
            pFullPath, ppData, pDataLen, releaseContext);
    }
    else
    {
        status = DIGICERT_readFileEx(pFullPath, ppData, pDataLen, releaseContext);
    }

exit:

    return status;
}

/* Writes out the data using the file protect APIs. The file will either be
 * written out encrypted or with an additional signature file depending on the
 * arguments provided to TPEC.
 */
static MSTATUS EST_writeFileFp(
    const char *pFullPath, ubyte *pData, ubyte4 dataLen,
    byteBoolean releaseContext, intBoolean fpSignMode, ubyte4 category)
{
    MSTATUS status;
    byteBoolean protectStatus;

    status = DPM_checkStatus(category, &protectStatus);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == protectStatus)
    {
        if (0 == fpSignMode)
        {
            status = DIGICERT_writeFileEx(pFullPath, pData, dataLen, releaseContext);
        }
        else
        {
            status = DIGICERT_writeFile(pFullPath, pData, dataLen);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGICERT_signFile(pFullPath, releaseContext);
        }
    }
    else
    {
        status = DIGICERT_writeFile(pFullPath, pData, dataLen);
    }

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

/*------------------------------------------------------------------*/

/*
@brief     Creates a key and its associated certificate.

@details   This function checks if a key/certificate is present
           with the name as mentioned in the pKeyAlias.
           If the key/certificate is not present in the keystore this function
           creates one.

@param pKeyAlias         Pointer to the keyalias name.
@param keyAliasLen       Length of the keyalias.
@param pKeyType          Type of the key.
@param keySize           Size of the key.


@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
static MSTATUS
EST_EXAMPLE_loadCertsAndKeysIntoCertStore(ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte *pKeyType, ubyte4 keySize)
{
    MSTATUS status = OK;
    ubyte *pReadKeyBlob = NULL;
    ubyte4 readKeyBlobLen = 0;
    sbyte *pFileName = NULL;
    sbyte *pPemFileName = NULL;
#ifdef __ENABLE_DIGICERT_EST_TAP_PEM_FILE__
    sbyte *pTapPemFileName = NULL;
    ubyte4 tapPemFileNameLen = 0;
#endif
    ubyte4 fileNameLen = 0;
    ubyte4 keyType = akt_rsa;
    sbyte *pKeyPath = NULL;
    sbyte *pFullPathR = NULL;
    sbyte *pFullPathPemR = NULL;
    sbyte *pFullPathW = NULL;
    sbyte *pFullPathPemW = NULL;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    char *pCertPath = NULL;
    ubyte *pCertFileName = NULL;
    ubyte *pFullPath = NULL;
    ubyte *pContents = NULL;
    ubyte4 contentsLen = 0;
    ubyte *pSerializedPemKey = NULL;
    ubyte4 serializedPemKeyLen = 0;
    AsymmetricKey asymKey;
    RSAKey *pRsaKey = NULL;
    ECCKey *pEccKey = NULL;
    edECCKey *pEdEccKey = NULL;
    ubyte4 getKeySize = keySize;
    MRsaKeyTemplate rsaTemplate = { 0 };
    byteBoolean foundOldKey = TRUE;
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    sbyte *pPassFileName = NULL;
    ubyte4 passFileLen = 0;
    sbyte *pFullPathP = NULL;
    byteBoolean protectCreds = FALSE;
#endif

    /* Extra 4 bytes to account for the .der or .pem extension */
    fileNameLen = keyAliasLen + 4;

    if (OK > (status = DIGI_MALLOC((void**)&pFileName, fileNameLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MALLOC((void**)&pPemFileName, fileNameLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pFileName, 0x00, fileNameLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pPemFileName, 0x00, fileNameLen + 1)))
    {
        goto exit;
    }
    DIGI_STRCAT(pFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pPemFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pFileName, (const sbyte *)ESTC_EXT_DER);
    DIGI_STRCAT(pPemFileName, (const sbyte *)ESTC_EXT_PEM);
    (pFileName)[fileNameLen] = '\0';
    (pPemFileName)[fileNameLen] = '\0';

#ifdef __ENABLE_DIGICERT_EST_TAP_PEM_FILE__
    tapPemFileNameLen = keyAliasLen + DIGI_STRLEN((sbyte *) ESTC_EXT_TAPKEY_PEM);

    if (OK > (status = DIGI_CALLOC((void**)&pTapPemFileName, 1, tapPemFileNameLen + 1)))
    {
        goto exit;
    }
    DIGI_STRCAT(pTapPemFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pTapPemFileName, (const sbyte *)ESTC_EXT_TAPKEY_PEM);
    (pTapPemFileName)[tapPemFileNameLen] = '\0';
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    passFileLen = keyAliasLen + 9;

    if (OK > (status = DIGI_MALLOC((void**)&pPassFileName, passFileLen + 1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pPassFileName, 0x00, passFileLen + 1)))
    {
        goto exit;
    }

    DIGI_STRCAT(pPassFileName, (const sbyte *)pKeyAlias);
    DIGI_STRCAT(pPassFileName, (const sbyte *)ESTC_EXT_TAP_PASS);
    (pPassFileName)[passFileLen] = '\0';
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    if (useTAP)
        keyType = akt_tap_rsa;
#endif

    pKeyPath = (sbyte*)EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, KEYS_PKI_COMPONENT);
    if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
    {
        keyType = akt_ecc;
#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_ecc;
#endif
    }
    else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_EDDSA) == 0)
    {
        keyType = akt_ecc_ed;
#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_ecc;
#endif
    }

    /* Below logic -
       Check if .der file exists. if exists get the keyblob.
       else check if .pem file exits. if exits get the keyblob and write to .der file.
       else creates both .der and .pem files and get the keyblob.
     */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (OK > (status = EST_readFileFp(
                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                        (char **)&pFullPathR), &pReadKeyBlob, &readKeyBlobLen, TRUE, DPM_KEYS)))
#else
    if (OK > (status = DIGICERT_readFile(
                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                        (char **)&pFullPathR), &pReadKeyBlob, &readKeyBlobLen)))
#endif
    {/*.der file not exists */
        ubyte4 keyContentLen;
        ubyte *pKeyContent = NULL;

        /* Check for .pem file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = EST_readFileFp(
                        EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                            (char **)&pFullPathPemR), &pKeyContent, &keyContentLen, TRUE, DPM_KEYS)))
#else
        if (OK > (status = DIGICERT_readFile(
                        EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                            (char **)&pFullPathPemR), &pKeyContent, &keyContentLen)))
#endif
        { /* No PEM file also found, new Key to be generated */

           /* .pem or .der files not found. generate a new key and convert it
              to .pem and .der files */
            {
                foundOldKey = FALSE;
#ifdef __ENABLE_DIGICERT_TAP__
                if (useTAP)
                {
                    ubyte *pKeyData = NULL;
                    ubyte4 keyDataLen = 0;
                    sbyte *pTapKeyBinFileName = NULL;
                    sbyte *pFullPathbinW = NULL;
                    AsymmetricKey tapAsymKey = { 0 };
                    TAP_Key *pTapKey = NULL;
                    ubyte *pBlob = NULL;
                    ubyte4 blobLen = 0;

                    ubyte *pSerializedPri = NULL;
                    ubyte4 serializedPriLen = 0;

                    if (OK != (status = EST_EXAMPLE_createTapAsymKey(&tapAsymKey, pKeyType, keySize)))
                    {
                        verbosePrintError("Unable to create TAP asymmetric key.", status);
                        goto exit;
                    }

                    /*Serialize the key */
                    /* Write out the TAP key in PKCS8 format here. TAP keys
                    * ignore the PKCS8 password argument. */
                    if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &tapAsymKey, privateKeyInfoDer, &pKeyBlob, &keyBlobLen)))
                    {

                        verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                        goto exit;
                    }

                    /* Write key to file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                    if ( OK > ( status = EST_writeFileFp(
                                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                        (char **)&pFullPathW), pKeyBlob, keyBlobLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
                    if ( OK > ( status = DIGICERT_writeFile(
                                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                        (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
#endif
                    {
                        verbosePrintStringError("Unable to write DER-formatted TAP key to file", pFullPathW);
                        verbosePrintError("Unable to write DER-formatted TAP key to file.", status);
                        goto exit;
                    }

                    /* Serialize to PEM Format */
#ifdef __ENABLE_DIGICERT_EST_TAP_PEM_FILE__
                    /* Create TAP PEM key with TAP PEM header */
                    status = BASE64_makePemMessageAlloc(
                        MOC_PEM_TYPE_PRI_TAP_KEY, pKeyBlob, keyBlobLen,
                        &pSerializedPri, &serializedPriLen);
                    if (OK > status)
                    {
                        verbosePrintError("Unable to create PEM TAP key with TAP header format.", status);
                        goto exit;
                    }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                    if (OK > ( status = EST_writeFileFp(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapPemFileName, (char **)&pFullPathPemW),
                                    pSerializedPri, serializedPriLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
                    if (OK > ( status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapPemFileName, (char **)&pFullPathPemW),
                                    pSerializedPri, serializedPriLen)))
#endif
                    {
                        verbosePrintError("Unable to write PEM-formatted TAP key to file.", status);
                        goto exit;
                    }
                    DIGI_FREE((void **) &pFullPathPemW);

                    if (pSerializedPri != NULL && (OK != (status = DIGI_MEMSET_FREE ((ubyte **)&pSerializedPri, serializedPriLen))))
                    {
                        verbosePrintError("Unable to free TAP key serialized data.", status);
                        goto exit;
                    }
#endif /* __ENABLE_DIGICERT_EST_TAP_PEM_FILE__ */

                    if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &tapAsymKey, privateKeyPem, &pSerializedPri, &serializedPriLen)))
                    {
                        verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                        goto exit;
                    }

                    /* Write out the TAP key in PKCS8 format here. TAP keys
                     * ignore the PKCS8 password argument. */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                    if (OK > ( status = EST_writeFileFp(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName, (char **)&pFullPathPemW),
                                    pSerializedPri, serializedPriLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
                    if (OK > ( status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName, (char **)&pFullPathPemW),
                                    pSerializedPri, serializedPriLen)))
#endif
                    {
                        verbosePrintError("Unable to write PEM-formatted TAP key to file.", status);
                        goto exit;
                    }

                    if (pSerializedPri != NULL && (OK != (status = DIGI_MEMSET_FREE ((ubyte **)&pSerializedPri, serializedPriLen))))
                    {
                        verbosePrintError("Unable to free TAP key serialized data.", status);
                        goto exit;
                    }

                    /* Write TAP key in BIN format */
                    status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx)
                        &tapAsymKey, mocanaBlobVersion2, &pKeyData,
                        &keyDataLen);
                    if (OK != status)
                    {
                        verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                        goto exit;
                    }

                    /* Write private key to file */
                    if (OK > (status = DIGI_MALLOC((void**)&pTapKeyBinFileName, (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                    {
                        goto exit;
                    }

                    if (OK > (status = DIGI_MEMSET((ubyte*)pTapKeyBinFileName, 0x00,
                                                    (keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY) + 1))))
                    {
                        goto exit;
                    }
                    if (NULL == pTapKeyBinFileName)
                    {
                        status = ERR_NULL_POINTER;
                        verbosePrintError("pTapKeyBinFileName is NULL after allocation.", status);
                        goto exit;
                    }

                    DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)pKeyAlias);
                    DIGI_STRCAT(pTapKeyBinFileName, (const sbyte *)ESTC_EXT_TAPKEY);
                    (pTapKeyBinFileName)[(keyAliasLen + DIGI_STRLEN((sbyte*)ESTC_EXT_TAPKEY))] = '\0';

                    if(akt_tap_ecc == keyType)
                    {
                        pBlob = pKeyData + MOC_ECC_TAP_BLOB_START_LEN;
                        blobLen = keyDataLen - MOC_ECC_TAP_BLOB_START_LEN;
                    }
                    else
                    {
                        pBlob = pKeyData + MOC_RSA_TAP_BLOB_START_LEN;
                        blobLen = keyDataLen - MOC_RSA_TAP_BLOB_START_LEN;
                    }
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                    status = EST_writeFileFp(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapKeyBinFileName,
                                        (char **)&pFullPathbinW), pBlob, blobLen, TRUE, estc_fp_nocrypt, DPM_KEYS);
#else
                    status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pTapKeyBinFileName,
                                        (char **)&pFullPathbinW), pBlob, blobLen);
#endif
                    if (OK != status)
                    {
                        verbosePrintStringError("Unable to write binary format TAP key to file", pFullPathbinW);
                        verbosePrintError("Unable to write binary format TAP key to file.", status);
                        goto exit;
                    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
                    if (NULL != estc_tap_keyPassword)
                    {
                        status = DPM_checkStatus(DPM_CREDS, &protectCreds);
                        if (OK != status)
                        {
                            verbosePrintError("Failed to get data-protect credential status.", status);
                            goto exit;
                        }

                        if (TRUE == protectCreds)
                        {
                            status = DPM_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPassFileName, (char **)&pFullPathP),
                                    estc_tap_keyPassword, DIGI_STRLEN(estc_tap_keyPassword), TRUE, DPM_CREDS);
                            if (OK != status)
                            {
                                verbosePrintError("Unable to write encrypted TAP password.", status);
                                goto exit;
                            }
                        }
                    }
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

                    status = CRYPTO_INTERFACE_getTapKey(&tapAsymKey, &pTapKey);
                    if (OK != status)
                        goto exit;

                    status = TAP_unloadKey(pTapKey, NULL);
                    if (OK != status)
                        goto exit;

                    CRYPTO_uninitAsymmetricKey(&tapAsymKey, NULL);

                    if (pTapKeyBinFileName)
                        DIGI_FREE((void **)&pTapKeyBinFileName);

                    if (pFullPathbinW)
                        DIGI_FREE((void **)&pFullPathbinW);

                    if (NULL != pKeyData)
                        DIGI_FREE((void **)&pKeyData);
                }
                else
#endif
                {
#ifdef __ENABLE_DIGICERT_TEE__
                /* For secure storage, before generating a key, make sure we have a keyHandle */
                if (useTEE && (NULL == estc_tapKeyHandle.pBuffer || 0 == estc_tapKeyHandle.bufferLen))
                {
                    status = ERR_INVALID_INPUT;
                    verbosePrintError("ERROR: Must provide -est_keyhandle for generating a new key with source TEE.", status);
                    goto exit;
                }
#endif

                if (OK > (status = CA_MGMT_generateNakedKey(keyType, keySize, &pKeyBlob, &keyBlobLen)))
                {
                    verbosePrintError("Unable to generate new key.", status);
                    goto exit;
                }

                /* Only write out Mocana key blob if the caller does not want
                 * a password protected key file (and we are not TEE)*/
#ifdef __ENABLE_DIGICERT_TEE__
                if (NULL == estc_pkcs8Pw && !useTEE)
#else
                if (NULL == estc_pkcs8Pw)
#endif
                {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                    if ( OK > ( status = EST_writeFileFp(
                                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                        (char **)&pFullPathW), pKeyBlob, keyBlobLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
                    if ( OK > ( status = DIGICERT_writeFile(
                                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                        (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
#endif
                    {
                        verbosePrintStringError("Unable to write key data to file", pFullPathW);
                        verbosePrintError("Unable to write key data to file.", status);
                        goto exit;
                    }
                }
                /* Convert pem key to keyblob and write to the keystore. */

                if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
                {
                    goto exit;
                }

                if (OK > (status = KEYBLOB_extractKeyBlobEx(pKeyBlob, keyBlobLen,&asymKey)))
                {
                    goto exit;
                }

                /* Serialize into PEM Format */
                if (NULL != estc_pkcs8Pw)
                {
#ifdef __ENABLE_DIGICERT_TEE__
                    if (useTEE)
                    {
                        status = ERR_NOT_IMPLEMENTED;
                        goto exit;
                    }
#endif
                    status = PKCS8_encodePrivateKeyPEM(
                        g_pRandomContext, pKeyBlob, keyBlobLen,
                        estc_pkcs8EncType, PKCS8_PrfType_undefined /* uses default */,
                        (ubyte *) estc_pkcs8Pw, DIGI_STRLEN(estc_pkcs8Pw),
                        &pSerializedPemKey, &serializedPemKeyLen);
                }
                else
                {
#ifdef __ENABLE_DIGICERT_TEE__
                    if (useTEE)
                    {
                        status = CRYPTO_serializeAsymKeyToStorage(MOC_ASYM(gHwAccelCtx) &asymKey,
                            privateKeyPem, estc_tapKeyHandle.pBuffer, estc_tapKeyHandle.bufferLen, TEE_SECURE_STORAGE,
                            &pSerializedPemKey, &serializedPemKeyLen);
                    }
                    else
#endif
                    {
                        status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx)
                            &asymKey, privateKeyPem, &pSerializedPemKey,
                            &serializedPemKeyLen);
                    }
                }
                if (OK != status)
                {
                    goto exit;
                }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                if (OK > ( status = EST_writeFileFp(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                                    (char **)&pFullPathPemW),
                                pSerializedPemKey,
                                serializedPemKeyLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
                if (OK > ( status = DIGICERT_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPemFileName,
                                    (char **)&pFullPathPemW),
                                pSerializedPemKey,
                                serializedPemKeyLen)))
#endif
                {
                    goto exit;
                }
                if (OK != (status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL)))
                {
                    goto exit;
                }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                if (NULL != estc_pkcs8Pw)
                {
                    status = DPM_checkStatus(DPM_CREDS, &protectCreds);
                    if (OK != status)
                    {
                        verbosePrintError("Failed to get data-protect credential status.", status);
                        goto exit;
                    }

                    if (TRUE == protectCreds)
                    {
                        status = DPM_writeFile(EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pPassFileName, (char **)&pFullPathP),
                                (ubyte *) estc_pkcs8Pw, DIGI_STRLEN(estc_pkcs8Pw), TRUE, DPM_CREDS);
                        if (OK != status)
                        {
                            verbosePrintError("Unable to write encrypted PKCS#8 password.", status);
                            goto exit;
                        }
                    }
                }
#endif
               }
              }

        } /* .pem or .der files does not exists */
        else
        { /*.pem file exists */

            /* .pem file exists. Get the keyblob and write to .der file */
#ifdef __ENABLE_DIGICERT_TAP__
            if (useTAP)
            {
                ubyte *pSerializedPri = NULL;
                ubyte4 serializedPriLen = 0;
                AsymmetricKey asymKey = {0};
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx) pKeyContent, keyContentLen, NULL, &asymKey);
                if (status < OK)
                    goto exit;
                /*Serialize the key */
                /* Write out the TAP key in PKCS8 format here. TAP keys
                 * ignore the PKCS8 password argument. */
                if (OK != (status = CRYPTO_serializeAsymKey(MOC_ASYM(gHwAccelCtx) &asymKey, privateKeyInfoDer, &pSerializedPri, &serializedPriLen)))
                {

                    verbosePrintError("Unable to serialize TAP asymmetric key.", status);
                    goto exit;
                }

                /* Write key to file */
                pKeyBlob = pSerializedPri;
                keyBlobLen = serializedPriLen;
                if ( OK > ( status = DIGICERT_writeFile(
                                EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                    (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
                {
                    verbosePrintStringError("Unable to write TAP key data to file", pFullPathW);
                    verbosePrintError("Unable to write TAP key data to file.", status);
                    goto exit;
                }

                CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
                if (pKeyContent != NULL)
                    DIGI_FREE((void**)&pKeyContent);
            }
            else
            {
#endif
                /* TPM1.2 and SW Key */
                if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
                {
                    goto exit;
                }
                /* Pem file exists - deserialize to keyblob write the Keyblob file */
                status = EST_EXAMPLE_deserializeAsymKey(
                    MOC_ASYM(gHwAccelCtx) pKeyContent, keyContentLen,
                    (ubyte *) estc_pkcs8Pw, estc_pkcs8Pw ? DIGI_STRLEN(estc_pkcs8Pw) : 0,
                    &asymKey);
                if (OK != status)
                {
                    goto exit;
                }
                if (OK > (status = KEYBLOB_makeKeyBlobEx(&asymKey, &pKeyBlob, &keyBlobLen)))
                {
                    goto exit;
                }

                /* Only write out key blob if file is not password protected (and not TEE) */
#ifdef __ENABLE_DIGICERT_TEE__
                if (NULL == estc_pkcs8Pw && !useTEE)
#else
                if (NULL == estc_pkcs8Pw)
#endif
                {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
                    if ( OK > ( status = EST_writeFileFp(
                                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                        (char **)&pFullPathW), pKeyBlob, keyBlobLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
                    if ( OK > ( status = DIGICERT_writeFile(
                                    EST_CERT_UTIL_getFullPath((const char *)pKeyPath, (const char *)pFileName,
                                        (char **)&pFullPathW), pKeyBlob, keyBlobLen)))
#endif
                    {
                        verbosePrintStringError("Unable to write key data to file", pFullPathW);
                        verbosePrintError("Unable to write key data to file.", status);
                        goto exit;
                    }
                }
                if (OK != (status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL)))
                {
                    goto exit;
                }
                if (pKeyContent != NULL)
                    DIGI_FREE((void**)&pKeyContent);


#ifdef __ENABLE_DIGICERT_TAP__
            }
#endif
        }/*Pem file exists */

    }/*.der file does not exits */
    else
    { /* .der file exists. Read KeyBlob file */
        pKeyBlob = pReadKeyBlob;
        keyBlobLen = readKeyBlobLen;
    }

    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        goto exit;
    }
    /* Pem file exists - deserialize to keyblob write the Keyblob file */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
        pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
    {
        goto exit;
    }

    if (keyType != asymKey.type)
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        status = ERR_KEY_TYPE_MISMATCH;
        verbosePrintError("Existing key type and keyType argument not matching.", status);
        goto exit;
    }
    else if (TRUE == foundOldKey)
    {
        if (keyType == akt_rsa)
        {
            pRsaKey = asymKey.key.pRSA;
            if (OK != RSA_getKeyParametersAlloc(pRsaKey, &rsaTemplate, MOC_GET_PUBLIC_KEY_DATA))
            {
                verbosePrintError("Failed to get RSA public key length.", status);
                goto exit;
            }

            getKeySize = rsaTemplate.nLen * 8;
        }
        else if (keyType == akt_ecc)
        {
            pEccKey = asymKey.key.pECC;
            if (NULL == pEccKey->pCurve || NULL == pEccKey->pCurve->pPF)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            getKeySize = asymKey.key.pECC->pCurve->pPF->numBits;
        }
        else if (keyType == akt_ecc_ed)
        {
            pEdEccKey = (edECCKey *)asymKey.key.pECC->pEdECCKey;
            if (NULL == pEdEccKey)
            {
                goto exit;
            }

            if (curveEd25519 == pEdEccKey->curve)
            {
                getKeySize = 255;
            }
            else if (curveEd448 == pEdEccKey->curve)
            {
                getKeySize = 448;
            }
            else
            {
                verbosePrintError("Unsupported Ed curve key.", status);
                goto exit;
            }
        }

        if (getKeySize != keySize)
        {
            CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
            status = ERR_KEY_TYPE_MISMATCH;
            verbosePrintError("Existing key size and keySize argument not matching.", status);
            goto exit;
        }
    }

    if (OK != (status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL)))
    {
        goto exit;
    }

    /*
       - Incase pKeyAlias matches estc_keyAlias2(rekey), then store only the key.
       - Check if the scenario is RENEW or REKEY.
         - Yes RENEW or REKEY scenario - Then check if certificate with mentioned keyAlias is present or not.
           - Yes if either of the certifiders(.der/.pem) exists - Store the key along with certificate in certStore.
           - No None of the certificates not present - Throw error certificate not found.
         - NO its not RENEW or REKEY scenario - Simply store only the key in the certstore.
    */
    if ((DIGI_STRCMP((const sbyte*)estc_keyAlias1, (const sbyte*)pKeyAlias) == 0) &&
        (((NULL != est_fullcmcReqType) &&
          ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
          (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))) ||
         ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) &&
          (NULL != estc_keyAlias2))))
    {
        if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, keyAliasLen + 5)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, keyAliasLen + 5)))
        {
            goto exit;
        }
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pKeyAlias);
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_DER);

        pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                            (char **)&pFullPath), &pContents, &contentsLen, TRUE, DPM_CERTS)))
#else
        if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                            (char **)&pFullPath), &pContents, &contentsLen)))
#endif
        {/*Certificate(.der) not found. check for .pem */
            ubyte *pPemCert = NULL;
            ubyte4 pemCertLen = 0;
            if (pCertFileName)
                DIGI_FREE((void **)&pCertFileName);
            if (pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if (pFullPath)
                DIGI_FREE((void **)&pFullPath);
            if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, keyAliasLen + 5)))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, keyAliasLen + 5)))
            {
                goto exit;
            }
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)pKeyAlias);
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_PEM);
            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            if (OK > (status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                                (char **)&pFullPath), &pPemCert, &pemCertLen, TRUE, DPM_CERTS)))
#else
            if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                                (char **)&pFullPath), &pPemCert, &pemCertLen)))
#endif
            {/*.pem file does not exists. Generate a new certificate */
                verbosePrintError("Certificate with keyAlias name not found.", status);
                goto exit;
            }
            else
            {
                if (OK > (status = CA_MGMT_decodeCertificate(pPemCert, pemCertLen, &pContents, &contentsLen)))
                {
                    goto exit;
                }

            }
            if (pPemCert)
                DIGI_FREE((void **)&pPemCert);
        }
#if (defined(__ENABLE_DIGICERT_TAP__))
        if (useTAP)
        {
            if (OK != (status = EST_EXAMPLE_storeMocKeyInCertstore(pKeyBlob, keyBlobLen, pKeyAlias, keyAliasLen, pContents, contentsLen)))
            {
                goto exit;
            }
        }
        else
        {
#endif
            if (OK > (status = CERT_STORE_addIdentityEx(pCertStore,
                            pKeyAlias, keyAliasLen,
                            pContents, contentsLen,
                            pKeyBlob, keyBlobLen)))
            {
#if (defined(__ENABLE_DIGICERT_TAP__))
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "Failed to load the keys - please cleanup hardware keys from keystore if any");
#endif
                verbosePrintError("Unable to load the keys. Please cleanup hardware keys from keystore if any.", status);
                goto exit;
            }
#if (defined(__ENABLE_DIGICERT_TAP__))
        }
#endif
    }
    else
    {
#if (defined(__ENABLE_DIGICERT_TAP__))
        if (useTAP)
        {
            if (OK != (status = EST_EXAMPLE_storeMocKeyInCertstore(pKeyBlob, keyBlobLen, pKeyAlias, keyAliasLen, pContents, contentsLen)))
            {
                goto exit;
            }
        }
        else
        {
#endif
            /*Add the key to the EST Client Cert Store*/
            if(OK > (status = CERT_STORE_addIdentityNakedKeyEx(pCertStore,
                            pKeyAlias, keyAliasLen,
                            pKeyBlob, keyBlobLen)))
            {
#if (defined(__ENABLE_DIGICERT_TAP__))
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "Failed to load the keys - please cleanup hardware keys from keystore if any");
#endif
                verbosePrintError("Unable to load the keys. Please cleanup hardware keys from keystore if any.", status);
                goto exit;
            }
#if (defined(__ENABLE_DIGICERT_TAP__))
        }
#endif
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    /* Add certificate policy for primary keys based on key usage and
     * signature scheme */
    if (TRUE == estc_tapKeyPrimary)
    {
        if (0 == DIGI_STRCMP(estc_keySource, KEY_SOURCE_TPM2))
        {
            if (TAP_KEY_USAGE_ATTESTATION == estc_tapKeyUsage)
            {
                estc_extEnrollFlow = EXT_ENROLL_FLOW_TPM2_IAK;
            }
            else
            {
                estc_extEnrollFlow = EXT_ENROLL_FLOW_TPM2_IDEVID;
            }
        }
    }
#endif

exit:
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (NULL != pPassFileName)
    {
        DIGI_FREE((void **)&pPassFileName);
    }
    if (NULL != pFullPathP)
    {
        DIGI_FREE((void **)&pFullPathP);
    }
#endif
    if (pKeyBlob)
        DIGI_FREE((void **)&pKeyBlob);
    if (pKeyPath)
        DIGI_FREE((void **)&pKeyPath);
    if (pFullPathR)
        DIGI_FREE((void **)&pFullPathR);
    if (pFullPathW)
        DIGI_FREE((void **)&pFullPathW);
    if (pFullPathPemR)
        DIGI_FREE((void **)&pFullPathPemR);
    if (pFullPathPemW)
        DIGI_FREE((void **)&pFullPathPemW);
    if (pFileName)
        DIGI_FREE((void **)&pFileName);
    if (pPemFileName)
        DIGI_FREE((void **)&pPemFileName);
    if(pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if(pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pCertFileName)
        DIGI_FREE((void **)&pCertFileName);
    if (pContents)
        DIGI_FREE((void **)&pContents);
    if (pSerializedPemKey)
        DIGI_FREE((void**)&pSerializedPemKey);
    if (pRsaKey)
        RSA_freeKeyTemplate(pRsaKey, &rsaTemplate);

    return status;
}

/* ------------------------------------------------------------- */

static int EST_EXAMPLE_addTLSCert(struct certStore* pCertStore)
{
    certDescriptor certDesc = {0};
    SizedBuffer *pCertificates = NULL;
    SizedBuffer certificate;
    ubyte4 certCount = 0;
    MSTATUS status;
    char *pCertPath = NULL;
    char *pFullPath = NULL;
    ubyte *pCertFileName = NULL;
    AsymmetricKey asymKey = {0};
    ubyte4 contentsLen;
    ubyte *pContents = NULL;
    ubyte *pPemCert = NULL;
    ubyte4 pemCertLen = 0;
    ubyte4 isPEMFile = 1;
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    ubyte *pPassFileName = NULL, *pPw = NULL, *pDecoded = NULL;
    ubyte4 pwLen = 0, decodedLen = 0;
#ifdef __ENABLE_DIGICERT_TAP__
    ubyte *pTapFile = NULL;
#endif
#endif

    if (estc_tlscert == NULL)
    {
        /* we are using the same certificate for tls auth that we want to renew */
        estc_tlscert = estc_keyAlias1;
    }

    /* Get TLS Certificate - Find cert file name using its alias */
    /* Create CertFile Name using alias */
    /* First Check for DER cert existance */
    if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, DIGI_STRLEN(estc_tlscert) + 5)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, DIGI_STRLEN(estc_tlscert) + 5)))
    {
        goto exit;
    }
    DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)estc_tlscert);
    DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_PEM);

    pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, CERTS_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (OK > (status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pCertFileName, &pFullPath), &pPemCert, &pemCertLen, TRUE, DPM_CERTS)))
#else
    if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pCertFileName, &pFullPath), &pPemCert, &pemCertLen)))
#endif
    {
        /* PEM file not found, so check for DER */
        isPEMFile = 0;
        if (pCertFileName)
            DIGI_FREE((void **)&pCertFileName);
        if (pCertPath)
            DIGI_FREE((void **)&pCertPath);
        if (pFullPath)
            DIGI_FREE((void **)&pFullPath);
        if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, DIGI_STRLEN(estc_tlscert) + 5)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, DIGI_STRLEN(estc_tlscert) + 5)))
        {
            goto exit;
        }
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)estc_tlscert);
        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_DER);
        pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                            (char **)&pFullPath), &certDesc.pCertificate, &certDesc.certLength, TRUE, DPM_CERTS)))
#else
        if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pCertFileName,
                            (char **)&pFullPath), &certDesc.pCertificate, &certDesc.certLength)))
#endif
        {
            /* Given TLS Cert with alias not found */
            verbosePrintError("TLS Certificate with keyAlias name not found.", status);
            goto exit;
        }
    }
    else
    {
        if (OK > (status = CRYPTO_UTILS_readCertificates(MOC_ASYM(gHwAccelCtx)
            pPemCert, pemCertLen, &pCertificates, &certCount)))
        {
            verbosePrintError("Unable to parse PEM certificate(s).", status);
            goto exit;
        }
        if (pPemCert)
            DIGI_FREE((void **)&pPemCert);
    }

    if (pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);

    /* Get Key */
    /* Try with same file format of cert, if not exist then look for other format */
    pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, KEYS_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (OK > (status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pCertFileName, &pFullPath), &pContents, &contentsLen, TRUE, DPM_KEYS)))
#else
    if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)pCertFileName, &pFullPath), &pContents, &contentsLen)))
#endif
    {

        if (pCertFileName)
            DIGI_FREE((void **)&pCertFileName);
        if (pCertPath)
            DIGI_FREE((void **)&pCertPath);
        if (pFullPath)
            DIGI_FREE((void **)&pFullPath);

        if (OK > (status = DIGI_MALLOC((void**)&pCertFileName, DIGI_STRLEN(estc_tlscert) + 5)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCertFileName, 0x00, DIGI_STRLEN(estc_tlscert) + 5)))
        {
            goto exit;
        }

        DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)estc_tlscert);
        if (isPEMFile == 1)
        {
            /* try for other format */
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_DER);
        }
        else
        {
            DIGI_STRCAT((sbyte*)pCertFileName, (const sbyte *)ESTC_EXT_PEM);
        }

        pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, KEYS_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (OK > (status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                            (const char *)pCertFileName, &pFullPath), &pContents, &contentsLen, TRUE, DPM_KEYS)))
#else
        if (OK > (status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                            (const char *)pCertFileName, &pFullPath), &pContents, &contentsLen)))
#endif
        {
            verbosePrintStringError("Unable to read TLS key file", (sbyte *)pFullPath);
            verbosePrintError("Unable to read TLS key file.", status);
            goto exit;
        }
    }
    if(pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if(pFullPath)
        DIGI_FREE((void **)&pFullPath);

    /* Check to see if the .pass file exists */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = DIGI_CALLOC(
        (void **) &pPassFileName, 1,
        DIGI_STRLEN(estc_tlscert) + DIGI_STRLEN((sbyte *)ESTC_EXT_TAP_PASS) + 1);
    if (OK != status)
    {
        verbosePrintError("Unable to allocate password file name.", status);
        goto exit;
    }

    DIGI_STRCAT((sbyte *) pPassFileName, (const sbyte *) estc_tlscert);
    DIGI_STRCAT((sbyte *) pPassFileName, (const sbyte *) ESTC_EXT_TAP_PASS);

    pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *) estc_certPath, KEYS_PKI_COMPONENT);
    EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pPassFileName, &pFullPath);

    /* If the .pass file exists then load in the password */
    if (TRUE == FMGMT_pathExists((sbyte *)pFullPath, NULL))
    {
        status = DIGICERT_readFileEx(pFullPath, &pPw, &pwLen, TRUE);
        if (OK != status)
        {
            verbosePrintError("Failed to read in password file.", status);
            goto exit;
        }

        /* If TAP is enabled check if the password is for a TAP key or for a
         * PKCS#8 encrypted key */
#ifdef __ENABLE_DIGICERT_TAP__
        status = DIGI_CALLOC(
            (void **) &pTapFile, 1,
            DIGI_STRLEN(estc_tlscert) + DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) + 1);
        if (OK != status)
        {
            verbosePrintError("Unable to allocate TAP key file name.", status);
            goto exit;
        }

        DIGI_STRCAT((sbyte *) pTapFile, (const sbyte *) estc_tlscert);
        DIGI_STRCAT((sbyte *) pTapFile, (const sbyte *) ESTC_EXT_TAPKEY);

        DIGI_FREE((void **) &pFullPath);
        EST_CERT_UTIL_getFullPath((const char *)pCertPath, (const char *)pTapFile, &pFullPath);

        /* If the TAP key file exists then load in the TAP key password */
        if (TRUE == FMGMT_pathExists(pFullPath, NULL))
        {
            status = DIGI_MALLOC((void **) &estc_tap_keyPassword, pwLen + 1);
            if (OK != status)
            {
                verbosePrintError("Unable to allocate TAP password buffer.", status);
                goto exit;
            }

            DIGI_MEMCPY((ubyte *)estc_tap_keyPassword, pPw, pwLen);
            estc_tap_keyPassword[pwLen] = '\0';

            /* Clear and free the password so it is not used as the PKCS#8
             * encrypted password */
            DIGI_MEMSET_FREE(&pPw, pwLen);
            pwLen = 0;
        }
#endif
    }
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    /* if we don't know the keySource apriori we then we'll retrieve it from the key itself */
    if (NULL == estc_keySource || 0 == DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)ESTC_DEF_KEYSOURCE))
    {
        byteBoolean isTap = FALSE;
        ubyte4 provider = 0;
        ubyte4 module = 0;

        /* see if it is a tap key and get the TAP provider and module from the key */
        status = CRYPTO_getKeyTapInfo(pContents, contentsLen, NULL, &isTap, &provider, &module);
        if (OK != status)
            goto exit;

        if (isTap)
        {
            estc_tapProvider = (ubyte2) provider;
            estc_tapModuleId = (ubyte2) module;
            estc_tapKeySourceRuntime = TRUE;
        }
        /* not a tap key anyway, go on */
    }
#endif

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
        goto exit;

    status = EST_EXAMPLE_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
        pContents, contentsLen,
        (ubyte *) estc_pkcs8Pw, estc_pkcs8Pw ? DIGI_STRLEN(estc_pkcs8Pw) : 0, &asymKey);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if ( (OK != status) && (NULL != pPw) )
    {
        status = CA_MGMT_decodeCertificate(
            pContents, contentsLen, &pDecoded, &decodedLen);
        if (OK == status)
        {
            DIGI_FREE((void **) &pContents);
            pContents = pDecoded;
            contentsLen = decodedLen;
            pDecoded = NULL;
        }

        status = PKCS_getPKCS8KeyEx(
            MOC_HW(gHwAccelCtx) pContents, contentsLen, pPw, pwLen, &asymKey);
    }
#endif
    if (OK != status)
    {
        verbosePrintError("Unable to deserialize TLS key.", status);
        goto exit;
    }

    /* Serialize the key */
    status = CRYPTO_serializeAsymKey(
        MOC_ASYM(gHwAccelCtx) &asymKey, mocanaBlobVersion2,
        &certDesc.pKeyBlob, &certDesc.keyBlobLength);
    if (OK != status)
    {
        verbosePrintError("Unable to serialize TLS key.", status);
        goto exit;
    }

    if (NULL != pCertificates)
    {
        status = CERT_STORE_addGenericIdentity (
            pCertStore, (ubyte *)estc_tlscert, DIGI_STRLEN(estc_tlscert), certDesc.pKeyBlob, certDesc.keyBlobLength,
            CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, pCertificates, certCount, NULL);
        if (OK != status)
        {
            myPrintError("EST_EXAMPLE_addTLSCert::CERT_STORE_addGenericIdentity::status ", status);
            goto exit;
        }
    }
    else
    {
        certificate.data = certDesc.pCertificate;
        certificate.length = certDesc.certLength;

        status = CERT_STORE_addGenericIdentity (
            pCertStore, (ubyte *)estc_tlscert, DIGI_STRLEN(estc_tlscert), certDesc.pKeyBlob, certDesc.keyBlobLength,
            CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, &certificate, 1, NULL);
        if (OK != status)
        {
            myPrintError("EST_EXAMPLE_addTLSCert::CERT_STORE_addGenericIdentity::status ", status);
            goto exit;
        }
    }

exit:
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#ifdef __ENABLE_DIGICERT_TAP__
    if (pTapFile);
        DIGI_FREE((void **) &pTapFile);
#endif
    if (pPw)
        DIGI_MEMSET_FREE(&pPw, pwLen);
    if (pPassFileName)
        DIGI_FREE((void **)&pPassFileName);
#endif
    if (pCertFileName)
        DIGI_FREE((void **)&pCertFileName);
    if(pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if(pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pContents)
        DIGI_FREE((void **)&pContents);
    if (pCertificates)
        CRYPTO_UTILS_freeCertificates(&pCertificates, certCount);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

    return status;
}

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__

static sbyte4
myAlertCallback(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass)
{
    MOC_UNUSED(connectionInstance);


    myPrintError("Tpec: AlertId: ", alertId);
    myPrintError("Tpec: AlertClass: ", alertClass);

    return 0;
}

#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
static sbyte4
myOcspCallback(sbyte4 connectionInstance, intBoolean certStatus)
{
    MSTATUS status = OK;

    MOC_UNUSED(connectionInstance);

    if (estc_ocsp_required)
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_DEFAULT, "myOcspCallback::");
        if (TRUE == certStatus)
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "OCSP Extension Recieved");
            status = OK;
        }
        else
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "OCSP Extension Missing");
            status = ERR_OCSP;
        }
    }

    return status;
}
#endif

MOC_STATIC int
EST_EXAMPLE_initUpcallsAndCertStores(void)
{
    certDescriptor certDesc = {0};
    certDescriptor skgCertDesc = {0};
    SizedBuffer skgCertificate = {0};
    MSTATUS status = OK;

    char *pFullPath = NULL;
    char *pCertPath = NULL;
    ubyte *pPskSecret = NULL;
    ubyte4 pskSecretLen = 0;
    ubyte4 pskAliasLen = 0;
    ubyte4 keyAliasLen = 0;
    ubyte *pCertBuf = NULL;
    ubyte4 certBufLen = 0;
    sbyte *pCleanCertPath = NULL;
    ubyte4 pathLen = 0;
    ubyte4 i = 0;
    const sbyte *pSrc = NULL;

    if (NULL == estc_certPath)
    {
        verbosePrintError("Certificate path is not set.", ERR_NULL_POINTER);
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pSrc = estc_certPath;
    while (pSrc && pSrc[pathLen] != '\0')
    {
        pathLen++;
        if (pathLen > 1024)
        {
            verbosePrintError("Certificate path too long.", ERR_INVALID_ARG);
            status = ERR_INVALID_ARG;
            goto exit;
        }
    }

    pCleanCertPath = MALLOC(pathLen + 8);
    if (NULL == pCleanCertPath)
    {
        verbosePrintError("Failed to allocate memory for certificate path.", ERR_MEM_ALLOC_FAIL);
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(pCleanCertPath, 0, pathLen + 8);
    DIGI_MEMCPY(pCleanCertPath, estc_certPath, pathLen);
    pCleanCertPath[pathLen] = '\0';

    EST_CERT_UTIL_createPkiDB(pCleanCertPath);
    pPkiDatabase = EST_CERT_UTIL_getPkiDBPtr();

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    SSL_sslSettings()->funcPtrAlertCallback = myAlertCallback;
#endif
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    SSL_sslSettings()->funcPtrCertStatusCallback = myOcspCallback;
#endif

    if (OK > (status = HTTP_initClient(MAX_NUM_HTTP_CLIENT_SESSIONS)))
        goto exit;

    HTTP_httpSettings()->funcPtrHttpTcpSend = EST_EXAMPLE_HttpTcpSend;
    HTTP_httpSettings()->funcPtrHttpTcpSend = EST_EXAMPLE_HttpSslSend;

    HTTP_httpSettings()->funcPtrRequestBodyCallback = EST_EXAMPLE_http_requestBodyCallback;
    HTTP_httpSettings()->funcPtrPasswordPrompt = EST_EXAMPLE_passwordPrompt;
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = EST_EXAMPLE_http_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = EST_EXAMPLE_http_responseBodyCallback;

    if(!pCertStore)
    {
        if (OK > (status = CERT_STORE_createStore(&pCertStore)))
        {
            verbosePrintError("Unable to create certstore.", status);
            goto exit;
        }

        if (OK > (status = EST_EXAMPLE_constructCertStoreFromDir(pCertStore)))
        {
            verbosePrintError("Unable to load in CA certificates.", status);
        }
    }

    /* Don't create keyAlias1 in case of cacerts and csrattrs request urls */
    if ((NULL == strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)) &&
        (NULL == strstr((const char *)estc_ServerURL, EST_CACERTS_CMD)) &&
        (NULL == strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD)) &&
        ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_ENROLL_CMD)) ||
        (NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) ||
        (NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD))))
    {
        keyAliasLen = DIGI_STRLEN((sbyte*)estc_keyAlias1);
        if (NULL == strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD))
        {
            if (OK != (status = EST_EXAMPLE_loadCertsAndKeysIntoCertStore((ubyte*)estc_keyAlias1, keyAliasLen, (ubyte*)estc_keyType, estc_keySize)))
            {
                verbosePrintError("Unable to load keyalias into certstore.", status);
                goto exit;
            }
        }
    }

    /* Create keyAlias2 only in case of fullcmc rekey case or simplereenroll
     * rekey case */
    if ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
        ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) &&
         (NULL != estc_keyAlias2)))
    {
        keyAliasLen = DIGI_STRLEN((sbyte*)estc_keyAlias2);
        if (OK != (status = EST_EXAMPLE_loadCertsAndKeysIntoCertStore((ubyte*)estc_keyAlias2, keyAliasLen, (ubyte*)estc_newKeyType, estc_newKeySize)))
        {
            verbosePrintError("Unable to load re-key alias into certstore.", status);
            goto exit;
        }
    }

    if ((NULL == strstr((const char *)estc_ServerURL, EST_SIMPLE_ENROLL_CMD)) &&
        (NULL == strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD)) &&
        (NULL == strstr((const char *)estc_ServerURL, EST_CACERTS_CMD)))
    {
        /* If est_tls_cert enabled for Mutual Auth */
        if (OK > (status = EST_EXAMPLE_addTLSCert(pCertStore)))
        {
            verbosePrintError("Unable to add TLS certificate into certstore.", status);
            goto exit;
        }
    }

    /* Load client cert, client key and psk only in case of serverkeygen */
    if ((NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)))
    {
        if(estc_pskFile)
        {
            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, PSK_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            status = DIGICERT_readFileEx(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)estc_pskFile, &pFullPath), &pPskSecret, &pskSecretLen, TRUE);
#else
            status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)estc_pskFile, &pFullPath), &pPskSecret, &pskSecretLen);
#endif
            if (OK > status)
            {
                verbosePrintStringError("Unable to read PSK", (sbyte *)pFullPath);
                verbosePrintError("Unable to read PSK.", status);
                goto exit;
            }
            if(pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if(pFullPath)
                DIGI_FREE((void **)&pFullPath);

            pskAliasLen = DIGI_STRLEN((const sbyte *) estc_pskFile);
            while (pskAliasLen > 0 && estc_pskFile[pskAliasLen - 1] != '.')
            {
                pskAliasLen--;
            }
            if (pskAliasLen < 2)
            {
                status = ERR_BAD_LENGTH;
                verbosePrintStringError("Unable to get PSK alias", estc_pskFile);
                goto exit;
            }
            pskAliasLen--;

            if (OK > (status = CERT_STORE_addIdentityPSK(pCertStore, (ubyte*)estc_pskFile, pskAliasLen, NULL,
                            0, (ubyte*)pPskSecret, pskSecretLen)))
            {
                verbosePrintError("Unable to add PSK into certstore.", status);
                goto exit;
            }
        }
        else if(estc_skg_clientcert && estc_skg_clientkey)
        {
            DIGI_MEMSET((ubyte *)&skgCertificate, 0x00, sizeof(SizedBuffer));

            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, CERTS_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)estc_skg_clientcert, &pFullPath), &skgCertDesc.pCertificate, &skgCertDesc.certLength, TRUE, DPM_CERTS);
#else
            status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)estc_skg_clientcert, &pFullPath), &skgCertDesc.pCertificate, &skgCertDesc.certLength);
#endif
            if (OK > status)
            {
                verbosePrintStringError("Unable to read est_skg_clientcert", (sbyte *)pFullPath);
                verbosePrintError("Unable to read est_skg_clientcert.", status);
                goto exit;
            }
            if(pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if(pFullPath)
                DIGI_FREE((void **)&pFullPath);

            pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, KEYS_PKI_COMPONENT);
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            status = EST_readFileFp(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)estc_skg_clientkey, &pFullPath), &skgCertDesc.pKeyBlob, &skgCertDesc.keyBlobLength, TRUE, DPM_KEYS);
#else
            status = DIGICERT_readFile(EST_CERT_UTIL_getFullPath((const char *)pCertPath,
                        (const char *)estc_skg_clientkey, &pFullPath), &skgCertDesc.pKeyBlob, &skgCertDesc.keyBlobLength);
#endif
            if (OK > status)
            {
                verbosePrintStringError("Unable to read est_skg_clientkey", (sbyte *)pFullPath);
                verbosePrintError("Unable to read est_skg_clientkey.", status);
                goto exit;
            }
            if(pCertPath)
                DIGI_FREE((void **)&pCertPath);
            if(pFullPath)
                DIGI_FREE((void **)&pFullPath);
            /* Check if the certificate or key is in PEM format if so convert it to decoded format */
            if (0 == DIGI_STRNICMP((sbyte*)ESTC_EXT_PEM, estc_skg_clientkey+DIGI_STRLEN(estc_skg_clientkey)-DIGI_STRLEN((sbyte*)ESTC_EXT_PEM),
                                  DIGI_STRLEN((sbyte*)ESTC_EXT_PEM)))
            {
                AsymmetricKey asymKey = {0};

                if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
                {
                    verbosePrintError("Unable to initialize asymmetric key.", status);
                    goto exit;
                }
                status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
                    skgCertDesc.pKeyBlob, skgCertDesc.keyBlobLength, NULL,
                    &asymKey);
                if (OK != status)
                {
                    verbosePrintError("Unable to deserialize est_skg_clientkey.", status);
                    goto exit;
                }

                estc_skg_clientkeytype = asymKey.type;

                DIGI_FREE((void**)&skgCertDesc.pKeyBlob);
                status = KEYBLOB_makeKeyBlobEx(&asymKey, &skgCertDesc.pKeyBlob, &skgCertDesc.keyBlobLength);
                CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
                if (OK != status)
                {
                    verbosePrintError("Unable to make est_skg_clientkey keyblob.", status);
                    goto exit;
                }
            }
            else
            {
                if (0 != DIGI_STRNICMP((sbyte*)ESTC_EXT_DER, estc_skg_clientkey+DIGI_STRLEN(estc_skg_clientkey)-DIGI_STRLEN((sbyte*)ESTC_EXT_DER),
                                      DIGI_STRLEN((sbyte*)ESTC_EXT_DER)))
                {
                    status = ERR_BAD_KEY;
                    verbosePrintError("Invalid est_skg_clientkey.", status);
                    goto exit;
                }
            }
            if (0 == DIGI_STRNICMP((sbyte*)ESTC_EXT_PEM, estc_skg_clientcert+DIGI_STRLEN(estc_skg_clientcert)-DIGI_STRLEN((sbyte*)ESTC_EXT_PEM),
                                  DIGI_STRLEN((sbyte*)ESTC_EXT_PEM)))
            {
                ubyte4 length = 0;
                /* PEM file deocde the content*/
                status = CA_MGMT_decodeCertificate(skgCertDesc.pCertificate, skgCertDesc.certLength,
                                        &skgCertificate.data, &length);
                skgCertificate.length = length;
                DIGI_FREE((void**)&skgCertDesc.pCertificate);
                if (OK != status)
                {
                    verbosePrintError("Unable to decode est_skg_clientcert.", status);
                    goto exit;
                }
                /* Assign the skgCertificate.data address to skgCertDesc.pCertificate so that it gets freed below. */
                skgCertDesc.pCertificate = skgCertificate.data;
            }
            else if (0 == DIGI_STRNICMP((sbyte*)ESTC_EXT_DER, estc_skg_clientcert+DIGI_STRLEN(estc_skg_clientcert)-DIGI_STRLEN((sbyte*)ESTC_EXT_DER),
                                       DIGI_STRLEN((sbyte*)ESTC_EXT_DER)))
            {
                skgCertificate.length = skgCertDesc.certLength;
                skgCertificate.data = skgCertDesc.pCertificate;
            }
            else
            {
                status = ERR_CERT;
                verbosePrintError("Invalid est_skg_clientcert.", status);
                goto exit;
            }

            status = CERT_STORE_addIdentityWithCertificateChainEx(pCertStore,
                            (ubyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS,
                            DIGI_STRLEN((const sbyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS),
                            &skgCertificate, 1,
                            skgCertDesc.pKeyBlob, skgCertDesc.keyBlobLength);

            if(skgCertDesc.pCertificate)
                DIGI_FREE((void **)&skgCertDesc.pCertificate);
            if(skgCertDesc.pKeyBlob)
                DIGI_FREE((void **)&skgCertDesc.pKeyBlob);
            if (OK != status)
            {
                verbosePrintError("Unable to add est_skg_clientcert and est_skg_clientkey into certstore.", status);
                goto exit;
            }

        }
    }

exit:
    if (pCleanCertPath)
        DIGI_FREE((void **)&pCleanCertPath);
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pCertPath)
        DIGI_FREE((void **)&pCertPath);
    if (certDesc.pCertificate)
        DIGI_FREE((void **)&certDesc.pCertificate);
    if (certDesc.pKeyBlob)
        DIGI_FREE((void **)&certDesc.pKeyBlob);
    if (pPskSecret)
        DIGI_FREE((void **)&pPskSecret);
    return status;
}

MOC_STATIC MSTATUS
getKeyIdentifiderFromCSR(ubyte *pCsr, ubyte4 csrLen, ubyte4 *pKeyId)
{
    ASN1_ITEMPTR pReqRoot       = NULL;
    ASN1_ITEMPTR pAsnAttrItem   = NULL;
    ASN1_ITEMPTR pCertReqInfo   = NULL;
    CStream      reqStream;
    MemFile      mf;
    ubyte        *pDecodedData  = NULL;
    ubyte4       decodedDataLen = 0;
    MSTATUS      status         = OK;
    ubyte decryptKeyIdentifier_OID[] = { 11, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x25 };
    ubyte asymmetricDecryptKeyIdentifier_OID[] = { 11, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x36 };

    /* Decode the key data from Base64 */
    if (OK > (status = CA_MGMT_decodeCertificate(pCsr, csrLen, &pDecodedData, &decodedDataLen)))
    {
        goto exit;
    }

    MF_attach(&mf, decodedDataLen, (ubyte*)pDecodedData );
    CS_AttachMemFile(&reqStream, &mf);
    if (OK > (status = ASN1_Parse(reqStream, &pReqRoot)))
    {
        goto exit;
    }

    /*Read attributes part of certificate request*/
    pAsnAttrItem = ASN1_FIRST_CHILD(pReqRoot);
    pAsnAttrItem = ASN1_FIRST_CHILD(pAsnAttrItem);
    if (OK > (status = ASN1_GetChildWithTag(pAsnAttrItem, 0, &pCertReqInfo)))
    {
        goto exit;
    }
    if (pCertReqInfo != NULL)
    {
        do
        {
            /* Find the DecryptKeyIdentifier Attrribute */
            pAsnAttrItem = ASN1_FIRST_CHILD(pCertReqInfo);
            if (pAsnAttrItem->tag == OID)
            {
                ubyte* oid = (ubyte *)CS_memaccess(reqStream, pAsnAttrItem->dataOffset - 1, pAsnAttrItem->length + 1);
                if (EqualOID(decryptKeyIdentifier_OID, oid))
                {
                    *pKeyId = DECRYPT_KEY_ID;
                }
                else if (EqualOID(asymmetricDecryptKeyIdentifier_OID, oid))
                {
                    *pKeyId = ASYM_DECRYPT_KEY_ID;
                }
            }
        } while ((pCertReqInfo = ASN1_NEXT_SIBLING(pCertReqInfo)) != NULL);
    }
exit:
    if(pReqRoot)
        TREE_DeleteTreeItem((TreeItem*)pReqRoot);
    if(pDecodedData)
        DIGI_FREE((void **)&pDecodedData);
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS EST_addExtension(
    ubyte *pFile, ubyte *pExt, ubyte **ppRetFile)
{
    MSTATUS status;
    ubyte *pNewFile = NULL, *pIter;

    status = DIGI_MALLOC(
        (void **) &pNewFile, DIGI_STRLEN((sbyte *)pFile) + DIGI_STRLEN((sbyte *)pExt) + 1);
    if (OK != status)
    {
        goto exit;
    }

    pIter = pNewFile;

    status = DIGI_MEMCPY(pIter, pFile, DIGI_STRLEN((sbyte *)pFile));
    if (OK != status)
    {
        goto exit;
    }
    pIter += DIGI_STRLEN((sbyte *)pFile);

    status = DIGI_MEMCPY(pIter, pExt, DIGI_STRLEN((sbyte *)pExt));
    if (OK != status)
    {
        goto exit;
    }
    pIter += DIGI_STRLEN((sbyte *)pExt);

    *pIter = '\0';

    *ppRetFile = pNewFile;
    pNewFile = NULL;

exit:

    if (NULL != pNewFile)
    {
        DIGI_FREE((void **) &pNewFile);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS EST_copyFile(
    ubyte *pComponent, ubyte *pCurFile, ubyte *pCopyFile)
{
    MSTATUS status = OK;
    ubyte *pPath, *pCurFilePath, *pCopyFilePath;
    intBoolean fileExist;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    ubyte *pSigFile = NULL, *pCopySigFile = NULL;
#endif

    pPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, (char *)pComponent);
    pCurFilePath = (ubyte *) EST_CERT_UTIL_getFullPath(
        (char *)pPath, (char *) pCurFile, (char **) &pCurFilePath);
    pCopyFilePath = (ubyte *) EST_CERT_UTIL_getFullPath(
        (char *)pPath, (char *) pCopyFile, (char **) &pCopyFilePath);

    /* Only copy the file if it exists.
     */
    status = DIGICERT_checkFile((char *)pCurFilePath, NULL, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        status = DIGICERT_copyFile((char *) pCurFilePath, (char *) pCopyFilePath);
        if (OK != status)
        {
            goto exit;
        }
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = EST_addExtension(
        pCurFilePath, (ubyte *) MOC_FP_SIG_SUFFIX, &pSigFile);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the signature file if it exists.
     */
    status = DIGICERT_checkFile((char *)pSigFile, NULL, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        status = EST_addExtension(
            pCopyFilePath, (ubyte *) MOC_FP_SIG_SUFFIX, &pCopySigFile);
        if (OK != status)
        {
            goto exit;
        }
        status = DIGICERT_copyFile((char *) pSigFile, (char *) pCopySigFile);
        if (OK != status)
        {
            goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

exit:

    if (NULL != pPath)
    {
        FREE(pPath);
    }

    if (NULL != pCurFilePath)
    {
        FREE(pCurFilePath);
    }

    if (NULL != pCopyFilePath)
    {
        FREE(pCopyFilePath);
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    if (NULL != pSigFile)
    {
        DIGI_FREE((void **) &pSigFile);
    }

    if (NULL != pCopySigFile)
    {
        DIGI_FREE((void **) &pCopySigFile);
    }
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

    return status;
}

static MSTATUS EST_copyFileByAlias(
    ubyte *pCurFile, ubyte *pCopyFile, ubyte4 fileBaseLength,
    ubyte4 copyBaseLen, ubyte *pExt, ubyte *pCopyExt)
{
    MSTATUS status;

    status = DIGI_MEMCPY(
        pCurFile + fileBaseLength, pExt, DIGI_STRLEN((sbyte *)pExt));
    if (OK != status)
    {
        goto exit;
    }
    pCurFile[fileBaseLength + DIGI_STRLEN((sbyte *)pExt)] = '\0';

    status = DIGI_MEMCPY(
        pCopyFile + copyBaseLen, pCopyExt, DIGI_STRLEN((sbyte *)pCopyExt));
    if (OK != status)
    {
        goto exit;
    }
    pCopyFile[copyBaseLen + DIGI_STRLEN((sbyte *)pCopyExt)] = '\0';

    status = EST_copyFile((ubyte *) CERTS_PKI_COMPONENT, pCurFile, pCopyFile);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_copyFile((ubyte *) KEYS_PKI_COMPONENT, pCurFile, pCopyFile);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS EST_backupKeysAndCert(
    ubyte *pKeyAlias, ubyte4 keyAliasLen)
{
    MSTATUS status;
    ubyte *pOldFile = NULL, *pCurFile = NULL;
    ubyte4 extLen, oldExtLen;

    /* Get the largest extension length for the existing file.
     */
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Get the largest extension length for the old key file. This will just be
     * the largest extension length of the existing file + the length of the
     * extension used to specify that the file is old.
     */
    oldExtLen = extLen + DIGI_STRLEN((sbyte *)ESTC_EXT_OLD);

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate a buffer for the file that will be created.
     */
    status = DIGI_CALLOC((void **) &pOldFile, 1, keyAliasLen + oldExtLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pOldFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .der key and cert with .der.old extension if they
     * exist.
     */
    status = EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .pem key and cert with .pem.old extension if they
     * exist.
     */
    status = EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PEM,
        (ubyte *) ESTC_EXT_PEM ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .der key and cert with .der.old extension if they
     * exist.
     */
    status = EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .tapkey key and cert with .tapkey.old extension if they
     * exist.
     */
    status = EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY,
        (ubyte *) ESTC_EXT_TAPKEY ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    /* Create a copy of .pfx key/cert with .pfx.old extension if they
     * exist.
     */
    status = EST_copyFileByAlias(
        pCurFile, pOldFile, keyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12,
        (ubyte *) ESTC_EXT_PKCS12 ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    if (NULL != pOldFile)
    {
        DIGI_FREE((void **) &pOldFile);
    }

    return status;
}

/*------------------------------------------------------------------*/

/* Method loads in the specified certificate which must be DER encoded and
 * checks whether the certificate is within the renew window or if the
 * certificate is expired. If the certificate is within the renew window or if
 * the certificate is expired then pExpiring is set to TRUE otherwise it is
 * FALSE.
 */
static MSTATUS EST_validateCertRenewWindow(
    ubyte *pCert, ubyte4 certLen, intBoolean *pExpiring)
{
    MSTATUS status;
    certDistinguishedName *pCertInfo = NULL;
    TimeDate certEndTime = { 0 };
    TimeDate renewWindow = { 0 };
    TimeDate curTime = { 0 };
    sbyte4 renewSeconds, certExpSeconds = 0;
    ubyte2 renewCmp, certCmp;

    if ( (NULL == pCert) || (NULL == pExpiring) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    /* Extract certficiate time information.
     */
    status = CA_MGMT_extractCertTimes(pCert, certLen, pCertInfo);
    if (OK != status)
    {
        goto exit;
    }

    status = DATETIME_convertFromValidityString(
        pCertInfo->pEndDate, &certEndTime);
    if (OK != status)
    {
        goto exit;
    }

    status = RTOS_timeGMT(&curTime);
    if (OK != status)
    {
        goto exit;
    }

    /* Convert days to seconds.
     */
    renewSeconds = estc_renewWindow * (60 * 60 * 24);

    /* Get the rewew window date.
     */
    status = DATETIME_getNewTime(&curTime, renewSeconds, &renewWindow);
    if (OK != status)
    {
        goto exit;
    }

    /* If the certificate is expired or the certificate expiration is within the
     * renew window then set the expiring flag to TRUE otherwise set it to
     * FALSE.
     */
    if (DIGI_cmpTimeDate(&certEndTime, &renewWindow) <= 0)
    {
        *pExpiring = TRUE;
    }
    else
    {
        *pExpiring = FALSE;
    }

exit:

    if (pCertInfo != NULL)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }

    return status;
}

/*------------------------------------------------------------------*/

/* Method checks whether the certificate is within the renew window time and
 * sets the pReOp flag accordingly. If the certificate is within the renew
 * window time or it is expired then the pReOp flag is set to TRUE, otherwise it
 * is set to false.
 */
static MSTATUS EST_checkCertificateRenewWindow(intBoolean *pReOp)
{
    MSTATUS status;
    ubyte *pPath = NULL, *pBasePath = NULL, *pFullPath = NULL;
    intBoolean fileBool;
    ubyte *pCert = NULL, *pDecodedCert = NULL;
    ubyte4 certLen = 0, decodedCertLen = 0;

    if ( (NULL == pReOp) || (NULL == estc_keyAlias1) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath(
        (char *) pPkiDatabase, CERTS_PKI_COMPONENT);
    EST_CERT_UTIL_getFullPath((char *) pPath, (char *) estc_keyAlias1, (char **) &pBasePath);

    status = EST_addExtension(pBasePath, (ubyte *) ESTC_EXT_DER, &pFullPath);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_checkFile((char *) pFullPath, NULL, &fileBool);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == fileBool)
    {
        DIGI_FREE((void **) &pFullPath);

        status = EST_addExtension(pBasePath, (ubyte *) ESTC_EXT_PEM, &pFullPath);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGICERT_checkFile((char *) pFullPath, NULL, &fileBool);
        if (OK != status)
        {
            goto exit;
        }

        if (FALSE == fileBool)
        {
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }

        /* Set to FALSE to indicate that this file is PEM.
         */
        fileBool = FALSE;
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = EST_readFileFp((char *) pFullPath, &pCert, &certLen, TRUE, DPM_CERTS);
#else
    status = DIGICERT_readFile((char *) pFullPath, &pCert, &certLen);
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == fileBool)
    {
        status = CA_MGMT_decodeCertificate(
            pCert, certLen, &pDecodedCert, &decodedCertLen);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pCert);
        pCert = pDecodedCert;
        certLen = decodedCertLen;
    }

    status = EST_validateCertRenewWindow(pCert, certLen, pReOp);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    if (NULL != pPath)
    {
        FREE(pPath);
    }

    if (NULL != pBasePath)
    {
        FREE(pBasePath);
    }

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS EST_deleteFile(ubyte *pComponent, ubyte *pFile)
{
    MSTATUS status = OK;
    ubyte *pPath, *pCurFilePath;
    intBoolean fileExist;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    ubyte *pSigFile = NULL;
#endif

    pPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, (char *) pComponent);
    pCurFilePath = (ubyte *) EST_CERT_UTIL_getFullPath(
        (char *) pPath, (char *) pFile, (char **) &pCurFilePath);

    /* Only delete the file if it exists.
     */
    status = DIGICERT_checkFile((char *) pCurFilePath, NULL, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        status = DIGICERT_deleteFile((char *) pCurFilePath);
        if (OK != status)
        {
            goto exit;
        }
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = EST_addExtension(
        pCurFilePath, (ubyte *) MOC_FP_SIG_SUFFIX, &pSigFile);
    if (OK != status)
    {
        goto exit;
    }

    /* Delete this signature file if it exists.
     */
    status = DIGICERT_checkFile((char *) pSigFile, NULL, &fileExist);
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == fileExist)
    {
        status = DIGICERT_deleteFile((char *) pSigFile);
        if (OK != status)
        {
            goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

exit:

    if (NULL != pPath)
    {
        FREE(pPath);
    }

    if (NULL != pCurFilePath)
    {
        FREE(pCurFilePath);
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    if (NULL != pSigFile)
    {
        DIGI_FREE((void **) &pSigFile);
    }
#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

    return status;
}

static MSTATUS EST_deleteFileByAlias(
    ubyte *pFile, ubyte4 baseLen, ubyte *pExt)
{
    MSTATUS status;

    status = DIGI_MEMCPY(
        pFile + baseLen, pExt, DIGI_STRLEN((sbyte *)pExt));
    if (OK != status)
    {
        goto exit;
    }
    pFile[baseLen + DIGI_STRLEN((sbyte *)pExt)] = '\0';

    status = EST_deleteFile((ubyte *)CERTS_PKI_COMPONENT, pFile);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFile((ubyte *)KEYS_PKI_COMPONENT, pFile);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS EST_rekeyOverrideAliasFile(
    ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte *pNewKeyAlias,
    ubyte4 newKeyAliasLen)
{
    MSTATUS status;
    ubyte *pNewFile = NULL, *pCurFile = NULL;
    ubyte4 extLen;

    /* Get the largest extension length for the existing file.
     */
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate a buffer for the file that will be created.
     */
    status = DIGI_CALLOC((void **) &pNewFile, 1, newKeyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the new key alias name.
     */
    status = DIGI_MEMCPY(pNewFile, pNewKeyAlias, newKeyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Delete the files with the extension if they exist.
     */
    status = EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PEM);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(pCurFile, keyAliasLen,(ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PEM,
        (ubyte *) ESTC_EXT_PEM);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_DER,
        (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY,
        (ubyte *) ESTC_EXT_TAPKEY);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_copyFileByAlias(
        pNewFile, pCurFile, newKeyAliasLen, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12,
        (ubyte *) ESTC_EXT_PKCS12);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    if (NULL != pNewFile)
    {
        DIGI_FREE((void **) &pNewFile);
    }

    return status;
}

static void EST_deleteCertsAndKeys(
    ubyte *pKeyAlias, ubyte4 keyAliasLen)
{
    MSTATUS status;
    ubyte *pCurFile = NULL;
    ubyte4 extLen;

    /* Get the largest extension length for the existing file.
     */
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > extLen)
    {
        extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + extLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Delete the files with the extension if they exist.
     */
    status = EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PEM);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    return;
}

static void EST_deleteOldCertsAndKeys(
    ubyte *pKeyAlias, ubyte4 keyAliasLen)
{
    MSTATUS status;
    ubyte *pCurFile = NULL;
    ubyte4 oldExtLen;

    /* Get the largest extension length for the existing file.
     */
    oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) > oldExtLen)
    {
        oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_DER) > oldExtLen)
    {
        oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_DER);
    }
    if (DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY) > oldExtLen)
    {
        oldExtLen = DIGI_STRLEN((sbyte *)ESTC_EXT_TAPKEY);
    }

    /* Get the largest extension length for the old key file. This will just be
     * the largest extension length of the existing file + the length of the
     * extension used to specify that the file is old.
     */
    oldExtLen += DIGI_STRLEN((sbyte *)ESTC_EXT_OLD);

    /* Allocate a buffer for the existing file.
     */
    status = DIGI_CALLOC((void **) &pCurFile, 1, keyAliasLen + oldExtLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    /* Copy the key alias name.
     */
    status = DIGI_MEMCPY(pCurFile, pKeyAlias, keyAliasLen);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PEM ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_DER ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_TAPKEY ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

    status = EST_deleteFileByAlias(
        pCurFile, keyAliasLen, (ubyte *) ESTC_EXT_PKCS12 ESTC_EXT_OLD);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pCurFile)
    {
        DIGI_FREE((void **) &pCurFile);
    }

    return;
}

typedef struct {
    sbyte *pCmdArg;
    sbyte *pOid;
} EstPskList;

static MSTATUS EST_getPskAlgId(
    sbyte *pAlg, ubyte **ppAlgId, ubyte4 *pAlgIdLen)
{
    MSTATUS status;
    ubyte i;
    EstPskList pAlgStrings[] = {
        {
            (sbyte *) "aes192",
            (sbyte *) ESTC_ENC_ALGO_ID_AES_192
        },
        {
            (sbyte *) "3des",
            (sbyte *) ESTC_ENC_ALGO_ID_3DES
        }
    };

    /* Check if the caller provided an algorithm. If not then use the default.
     */
    if (NULL != pAlg)
    {
        for (i = 0; i < COUNTOF(pAlgStrings); i++)
        {
            if ((DIGI_STRLEN(pAlg) == DIGI_STRLEN(pAlgStrings[i].pCmdArg)) &&
                0 == DIGI_STRNICMP((const sbyte *) pAlgStrings[i].pCmdArg, pAlg, DIGI_STRLEN(pAlg)))
            {
                break;
            }
        }

        if (i == COUNTOF(pAlgStrings))
        {
            status = ERR_UNKNOWN_DATA;
            goto exit;
        }

        if (NULL != ppAlgId)
        {
            *ppAlgId = (ubyte *) pAlgStrings[i].pOid;
            *pAlgIdLen = DIGI_STRLEN(pAlgStrings[i].pOid);
        }
    }
    else
    {
        if (NULL != ppAlgId)
        {
            *ppAlgId = (ubyte *) ESTC_DEF_ENC_ALGO_ID;
            *pAlgIdLen = DIGI_STRLEN((const sbyte *) ESTC_DEF_ENC_ALGO_ID);
        }
    }

    status = OK;

exit:

    return status;
}

static MSTATUS EST_writeTrustedCerts(
    struct SizedBuffer *pCerts, ubyte4 certCount)
{
    MSTATUS status;
    ubyte4 i;
    sbyte j;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    ubyte2 offset = 0;
    ubyte pCertFileName[MAX_FILE_NAME];
    sbyte *pPkiComponentPath = NULL;
    sbyte *pFullPath = NULL;
    intBoolean fileExist;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    byteBoolean signFile;
#endif

    if (NULL == pCerts)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
    pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath(
        (char *)pPkiDatabase, CA_PKI_COMPONENT);
#else
    pPkiComponentPath = EST_getTrustStorePathCopy();
#endif

    for (i = 0; i < certCount; i++)
    {
        DIGI_FREE((void **) &pDerCert);

        /* Retrieve the DER certificate.
         */
        status = CA_MGMT_decodeCertificate(
            pCerts[i].data, pCerts[i].length, &pDerCert, &derCertLen);
        if (OK != status)
        {
            goto exit;
        }

        /* Compute the "fingerprint" of the certificate. This will be the
            * file name used to store the certificate.
            */
        status = SHA1_completeDigest(MOC_HASH(gHwAccelCtx) pDerCert, derCertLen, pCertFileName);
        if (OK != status)
        {
            goto exit;
        }

        /* Convert the SHA-1 result into an ASCII string.
            */
        for (j = SHA1_RESULT_SIZE - 1; j >= 0; j--)
        {
            pCertFileName[(2 * j) + 1] = returnHexDigit(pCertFileName[j]);
            pCertFileName[2 * j] = returnHexDigit(pCertFileName[j] >> 4);
        }

        DIGI_MEMCPY(
            pCertFileName + (2 * SHA1_RESULT_SIZE), (ubyte *) ESTC_EXT_DER,
            DIGI_STRLEN((sbyte *)ESTC_EXT_DER));
        pCertFileName[(2 * SHA1_RESULT_SIZE) + DIGI_STRLEN((sbyte *)ESTC_EXT_DER)] = '\0';

        DIGI_FREE((void **) &pFullPath);
        EST_CERT_UTIL_getFullPath(
            (char *) pPkiComponentPath, (char *) pCertFileName, (char **) &pFullPath);

        /* Check if the .der file exists. If it does not then write out the
            * certificate, otherwise the certificate will not be written out
            * since its already on the file system.
            */
        status = DIGICERT_checkFile((char *) pFullPath, NULL, &fileExist);
        if (OK != status)
        {
            goto exit;
        }

        if (TRUE == fileExist)
        {
            verbosePrintString(
                ESTC_VERBOSE_LEVEL_INFO, "Certificate file ");
            verbosePrintStringLength(
                ESTC_VERBOSE_LEVEL_INFO, (char *) pCertFileName,
                DIGI_STRLEN((sbyte *)pCertFileName) - DIGI_STRLEN((sbyte *)ESTC_EXT_DER));
            verbosePrintNL(
                ESTC_VERBOSE_LEVEL_INFO, " already exists");
        }

        if (FALSE == fileExist)
        {
            status = DIGICERT_writeFile( (char *)
                pFullPath, pDerCert, derCertLen);
            if (OK != status)
            {
                verbosePrintStringError(
                    "Unable to write DER-formatted CA certificate to file",
                    pFullPath);
                verbosePrintError(
                    "Unable to write DER-formatted CA certificate to file.",
                    status);
                goto exit;
            }

            verbosePrintStringNL(
                ESTC_VERBOSE_LEVEL_INFO, "Writing certificate in DER format: ",
                pFullPath);

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DPM_checkStatus(DPM_CA_CERTS, &signFile);
            if (OK != status)
            {
                verbosePrintError(
                    "Unable to get data protect CA certificate file status", status);
                goto exit;
            }

            if (TRUE == signFile)
            {
                status = DIGICERT_signFile((char *) pFullPath, TRUE);
                if (OK != status)
                {
                    verbosePrintStringError(
                        "Unable to sign DER CA certificate", pFullPath);
                    goto exit;
                }
            }
#endif
            offset = (2 * SHA1_RESULT_SIZE);
            if (offset + DIGI_STRLEN((sbyte *)ESTC_EXT_PEM) + 1 > MAX_FILE_NAME)
            {
                status = ERR_BUFFER_OVERFLOW;
                verbosePrintError("Certificate filename too long for buffer", status);
                goto exit;
            }
            DIGI_MEMCPY(
                pCertFileName + offset, (ubyte *) ESTC_EXT_PEM,
                DIGI_STRLEN((sbyte *)ESTC_EXT_PEM));
            pCertFileName[offset + DIGI_STRLEN((sbyte *) ESTC_EXT_PEM)] = '\0';

            DIGI_FREE((void **) &pFullPath);
            EST_CERT_UTIL_getFullPath(
                (char *) pPkiComponentPath, (char *) pCertFileName, (char **) &pFullPath);

            status = DIGICERT_writeFile( (char *)
                pFullPath, pCerts[i].data, pCerts[i].length);
            if (OK != status)
            {
                verbosePrintStringError(
                    "Unable to write PEM-formatted CA certificate to file",
                    pFullPath);
                verbosePrintError(
                    "Unable to write PEM-formatted CA certificate to file.",
                    status);
                goto exit;
            }

            verbosePrintStringNL(
                ESTC_VERBOSE_LEVEL_INFO, "Writing certificate in PEM format: ",
                pFullPath);

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DPM_checkStatus(DPM_CA_CERTS, &signFile);
            if (OK != status)
            {
                verbosePrintStringError(
                    "Unable to get data protect CA certificate file status", pFullPath);
                goto exit;
            }

            if (TRUE == signFile)
            {
                status = DIGICERT_signFile((char *) pFullPath, TRUE);
                if (OK != status)
                {
                    verbosePrintStringError(
                        "Unable to sign PEM CA certificate", pFullPath);
                    goto exit;
                }
            }
#endif
        }
    }

    status = OK;

exit:

    if (NULL != pDerCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

    if (NULL != pPkiComponentPath)
    {
        DIGI_FREE((void **) &pPkiComponentPath);
    }

    return status;
}

ubyte     *g_pAuthStr           = NULL;
ubyte4    g_authStrLen          = 0;
ubyte4    g_index               = 0;
MOC_STATIC MSTATUS
EST_EXAMPLE_prepareAndSendRequest(ubyte *pCsrConfigFile, ubyte *pExtAttrFile, ubyte4 config_type, ubyte *pHashType, ubyte4 hashTypeLen, int mode, ubyte **ppCsrReqBytes, ubyte4 *pCsrReqLen)
{
    MSTATUS   status              = OK;
    char     *pPkiComponentPath  = NULL;
    ubyte     *pFullPath          = NULL;
    char    *pCSRFile	  	  = NULL;
    ubyte     *pAlgoId            = NULL;
    ubyte4    algoIdLen           = 0;
    ubyte *pKeyAlias              = NULL;
    ubyte4 keyAliasLen			  = 0;
    ubyte4 keyType				  = akt_undefined;
    ubyte *pNewKeyAlias = NULL;
    ubyte4 newKeyAliasLen = 0;
    ubyte4 newKeyType = akt_rsa;

    if(DIGI_STRCMP((const sbyte *)estc_newKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
    {
        newKeyType = akt_ecc;
    }

    if ((gRequestType == SIMPLE_ENROLL) || (gRequestType == SIMPLE_REENROLL))
    {
        pCSRFile = (gRequestType == SIMPLE_ENROLL) ? SIMPLE_ENROLL_CSR_FILE : SIMPLE_REENROLL_CSR_FILE;
        if (estc_keyAlias1 != NULL)
        {
            pKeyAlias = estc_keyAlias1;
            keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        }
        else
        {
            status = ERR_INTERNAL_ERROR;
            verbosePrintError("Missing simple enroll/re-enroll alias.", status);
            goto exit;
        }

        /* For simple re-enroll, if a rekey alias is provided then use that to
         * perform a rekey operation.
         */
        if ( (SIMPLE_REENROLL == gRequestType) && (NULL != estc_keyAlias2) )
        {
            pKeyAlias = estc_keyAlias2;
            keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        }
        keyType = akt_rsa;

#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_rsa;
#endif
        if(DIGI_STRCMP((const sbyte *)estc_keyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {

            keyType = akt_ecc;
#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_ecc;
#endif
        }

        if ((NULL == *ppCsrReqBytes) || (*pCsrReqLen == 0))
        { /* New Request generation */
            /* Generate CSR Request */
            if (OK > (status = EST_generateCSRRequestFromConfigWithPolicy(MOC_HW(gHwAccelCtx) pCertStore,
                            gSslConnectionInstance,
                            pCsrConfigFile,
                            pExtAttrFile, config_type,
                            pKeyAlias, keyAliasLen, gpPrevAsymKey, keyType,
                            certEnrollAlgUndefined,
                            pHashType, hashTypeLen,
                            ppCsrReqBytes, pCsrReqLen, estc_extEnrollFlow, NULL, NULL)))
            {
                verbosePrintError("Unable to create CSR from CSR config file.", status);
                goto exit;
            }
        }
    }
    else if (gRequestType == FULLCMC)
    {
        if (estc_keyAlias1 != NULL)
        {
            pKeyAlias = estc_keyAlias1;
        }
        else
        {
            status = ERR_INTERNAL_ERROR;
            verbosePrintError("Missing fullcmc alias.", status);
            goto exit;
        }
        keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        keyType = akt_rsa;
#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_rsa;
#endif
        if(DIGI_STRCMP((const sbyte *)estc_keyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {

            keyType = akt_ecc;
#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_ecc;
#endif
        }

        pCSRFile = FULLCMC_CSR_FILE;
        if (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL) == 0)
        {
            gFullCMCRequestType = ENROLL;
        }
        else if (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0)
        {
            gFullCMCRequestType = RENEW;
        }
        else if (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0)
        {
            gFullCMCRequestType = REKEY;
        }
        else
        {
            status = ERR_NOT_FOUND;
            verbosePrintError("Provided FullCMC request type is not supported.", status);
            goto exit;
        }
        if (REKEY == gFullCMCRequestType)
        {
            if (estc_keyAlias2 != NULL)
            {
                pNewKeyAlias = estc_keyAlias2;
            }
            else
            {
                status = ERR_INTERNAL_ERROR;
                verbosePrintError("The re-key alias is required for FullCMC rekey operation.", status);
                goto exit;
            }
            newKeyAliasLen = DIGI_STRLEN((const sbyte*)pNewKeyAlias);
        }

        if ((NULL == *ppCsrReqBytes) || (*pCsrReqLen == 0))
        {
            if (OK > (status = EST_createPKCS7RequestFromConfigWithPolicy(MOC_HW(gHwAccelCtx) pCertStore, pCsrConfigFile, pExtAttrFile, config_type,
                            pKeyAlias, keyAliasLen, gpPrevAsymKey, keyType,
                            certEnrollAlgUndefined,
                            pNewKeyAlias, newKeyAliasLen, newKeyType, pHashType, hashTypeLen,
                            gSslConnectionInstance, gFullCMCRequestType, estc_renewinlinecert, ppCsrReqBytes, pCsrReqLen, estc_extEnrollFlow, NULL, NULL)))
            {
                verbosePrintError("Unable to create CSR from CSR config file.", status);
                goto exit;
            }
        }
    }
    else if (gRequestType == SERVER_KEYGEN)
    {
        pCSRFile = SERVERKEYGEN_CSR_FILE;
        if(estc_pskFile || estc_skg_clientcert)
        {
            /* Get the encryption algorithm ID.
             */
            status = EST_getPskAlgId(estc_skgAlg, &pAlgoId, &algoIdLen);
            if (OK != status)
            {
                verbosePrintError("Unable to retrieve encryption algorithm.", status);
                goto exit;
            }

            if(estc_skg_clientcert)
            {
                keyType = estc_skg_clientkeytype;
                pKeyAlias = (ubyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS;
                keyAliasLen = DIGI_STRLEN((const sbyte*)ESTC_DEF_SKG_CLIENTKEY_ALIAS);
            }
            else
            {
                keyType = akt_custom;
                pKeyAlias = (ubyte *) estc_pskFile;
                keyAliasLen = DIGI_STRLEN((const sbyte *) estc_pskFile);
                while (keyAliasLen > 0 && pKeyAlias[keyAliasLen - 1] != '.')
                {
                    keyAliasLen--;
                }
                if (keyAliasLen < 2)
                {
                    status = ERR_BAD_LENGTH;
                    verbosePrintStringError("Unable to get PSK alias", estc_pskFile);
                    goto exit;
                }
                keyAliasLen--;
            }
        }

        if ((NULL == *ppCsrReqBytes) || (*pCsrReqLen == 0))
        {
            /* Generate CSR Request */
            if (OK > (status = EST_generateCSRRequestFromConfigExWithPolicy(MOC_HW(gHwAccelCtx) pCertStore, pCsrConfigFile,
                            pExtAttrFile, config_type, pAlgoId, algoIdLen,
                            pKeyAlias, keyAliasLen,
                            keyType, certEnrollAlgUndefined, pHashType, hashTypeLen,
                            gSslConnectionInstance, ppCsrReqBytes, pCsrReqLen,
                            estc_extEnrollFlow, NULL, NULL)))
            {
                verbosePrintError("Unable to create CSR from CSR config file.", status);
                goto exit;
            }
        }
    }

#if  !defined(__FREERTOS_RTOS__) && !defined(__AZURE_RTOS__)
    /* Write CSR to a file */
    pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, REQ_PKI_COMPONENT);
    if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath((const char*)pPkiComponentPath,
                        (const char *) pCSRFile, (char **)&pFullPath), *ppCsrReqBytes, *pCsrReqLen)))
    {
        verbosePrintStringError("Unable to write CSR to file", (sbyte *)pFullPath);
        verbosePrintError("Unable to write CSR to file.", status);
    }
#endif

    if (mode == 1)
    {
        DIGI_FREE((void **)&g_pAuthStr);
        if (OK > (status = HTTP_AUTH_generateAuthorization(gHttpContext, &g_index, &g_pAuthStr, &g_authStrLen)))
        {
            verbosePrintError("HTTP auth generation failed.", status);
            goto exit;
        }
    }
    if ((mode == 1) || (mode == 2))
    {
        if (OK > (status = HTTP_CONTEXT_resetContext(gHttpContext)))
        {
            verbosePrintError("HTTP context reset failed.", status);
            goto exit;
        }
        if (g_authStrLen > 0)
        {
            if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(gHttpContext, g_index, g_pAuthStr, g_authStrLen)))
            {
                verbosePrintError("HTTP failed to set auth header.", status);
                goto exit;
            }
        }
    }

    if (OK > (status = EST_setCookie(gHttpContext, *ppCsrReqBytes, *pCsrReqLen)))
    {
        verbosePrintError("EST client failed to set cookie.", status);
        goto exit;
    }

    if ((gRequestType == SIMPLE_ENROLL) || (gRequestType == SIMPLE_REENROLL))
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_ALL, "Sending simple enroll/re-enroll request\n");
        if (OK > (status = EST_sendSimpleEnrollRequest(gHttpContext,
                        gSslConnectionInstance,  (ubyte*)estc_ServerURL, DIGI_STRLEN(estc_ServerURL),
                        *pCsrReqLen, (ubyte*)estc_serverName, DIGI_STRLEN(estc_serverName), estc_userAgent)))
        {
            goto exit;
        }
    }
    else if (gRequestType == FULLCMC)
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_ALL, "Sending fullcmc request\n");
        if (OK > (status = EST_sendFullCmcRequest(gHttpContext, gSslConnectionInstance,
                        (ubyte*)estc_ServerURL, DIGI_STRLEN(estc_ServerURL), *pCsrReqLen,
                        (ubyte*)estc_serverName, DIGI_STRLEN(estc_serverName), gFullCMCRequestType, estc_userAgent)))
        {
            goto exit;
        }
    }
    else if (gRequestType == SERVER_KEYGEN)
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_ALL, "Sending server keygen request\n");
        if (OK > (status = EST_sendServerKeyGenRequest(gHttpContext, gSslConnectionInstance,
                        (ubyte*)estc_ServerURL, DIGI_STRLEN(estc_ServerURL), *pCsrReqLen,
                        (ubyte*)estc_serverName, DIGI_STRLEN(estc_serverName), estc_userAgent)))
        {
            goto exit;
        }
    }

exit:
    EST_freeCookie(gHttpContext);
    if (pPkiComponentPath)
        DIGI_FREE((void **)&pPkiComponentPath);
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);
    return status;
}

static MSTATUS EST_EXAMPLE_writeKey(ubyte *pKeyBlob, ubyte4 keyBlobLen)
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};
    ubyte *pKeyFile = NULL;
    char  *pPkiComponentPath = NULL;
    ubyte *pFullPath = NULL;
    ubyte *pContents = NULL;
    ubyte4 contentsLen = 0;
    ubyte *pDerKey = NULL;
    ubyte4 derKeyLen = 0;

    if (estc_keyAlias1 != NULL)
    {
        if (OK != (status = DIGI_CALLOC((void**)&pKeyFile, 1, DIGI_STRLEN((sbyte*)estc_keyAlias1) + 5))) /* .pem + '/0'*/
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMCPY((ubyte*)pKeyFile, estc_keyAlias1, DIGI_STRLEN((sbyte*)estc_keyAlias1))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pKeyFile+DIGI_STRLEN((sbyte*)estc_keyAlias1), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK != (status = DIGI_CALLOC((void**)&pKeyFile, 1, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE) + 5))) /* .pem + '/0' */
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMCPY((ubyte*)pKeyFile, SERVERKEYGEN_KEY_FILE, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pKeyFile+DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }
    }

    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gHwAccelCtx)
        pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != estc_pkcs8Pw)
    {
        status = PKCS8_encodePrivateKeyPEM(
            g_pRandomContext, pKeyBlob, keyBlobLen,
            estc_pkcs8EncType, PKCS8_PrfType_undefined /* uses default */,
            (ubyte *) estc_pkcs8Pw, DIGI_STRLEN(estc_pkcs8Pw),
            &pContents, &contentsLen);
    }
    else
    {
        status = CRYPTO_serializeAsymKey (
            MOC_ASYM(gHwAccelCtx) &asymKey, privateKeyPem,
            &pContents, &contentsLen);
    }
    if (OK != status)
    {
        goto exit;
    }

    pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, KEYS_PKI_COMPONENT);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (OK > (status = EST_writeFileFp((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                        (const char *) pKeyFile, (char**)&pFullPath), pContents, contentsLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
    if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                        (const char *) pKeyFile, (char**)&pFullPath), pContents, contentsLen)))
#endif
    {
        verbosePrintStringError("Unable to write PEM key to file", (sbyte *)pFullPath);
        verbosePrintError("Unable to write PEM key to file.", status);
    }
    verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing key in PEM format: ", (sbyte *)pFullPath);
    if(pFullPath) DIGI_FREE((void **)&pFullPath);

    status = CA_MGMT_decodeCertificate(
        pContents, contentsLen, &pDerKey, &derKeyLen);
    if (OK != status)
    {
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pKeyFile+DIGI_STRLEN((sbyte*)pKeyFile)-4, (ubyte *) ESTC_EXT_DER, 4)))
    {
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (OK > (status = EST_writeFileFp((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                    (const char *) pKeyFile, (char**)&pFullPath), pDerKey, derKeyLen, TRUE, estc_fp_nocrypt, DPM_KEYS)))
#else
    if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                    (const char *) pKeyFile, (char**)&pFullPath), pDerKey, derKeyLen)))
#endif
    {
        verbosePrintStringError("Unable to write DER key to file", (sbyte *)pFullPath);
        verbosePrintError("Unable to write DER key to file.", status);
    }
    verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing key in DER format: ", (sbyte *)pFullPath);
    if(pFullPath) DIGI_FREE((void **)&pFullPath);

exit:
    if (pDerKey) DIGI_FREE((void**)&pDerKey);
    if(pPkiComponentPath) DIGI_FREE((void **)&pPkiComponentPath);
    if (pContents) DIGI_FREE((void**)&pContents);
    if (pKeyFile)  DIGI_FREE((void**)&pKeyFile);
    CRYPTO_uninitAsymmetricKey (&asymKey, NULL);
    return status;
}

/*---------------------------------------------------------------------------*/

/**
 * Response from EST server will be as follows
 *
 *     certificates
 *         Newly issued certificate
 *         Other certificates
 *
 * This API takes in a SizedBuffer which contains the Newly issued certificate
 * and the Other certificates, and returns a SizedBuffer with just the newly
 * issued certificate and any intermediate certificate(s) which correspond to
 * the issued certificate. The SizedBuffer will contain the certificate chain
 * in the correct order (issued certificate starting at index 0 with the
 * remaining chain following in subsequent indexes).
 */
static MSTATUS EST_removeOtherCertificates(
    SizedBuffer **ppCerts, ubyte4 *pCertCount)
{
    MSTATUS status;
    sbyte4 *pParents = NULL;
    sbyte4 index;
    ubyte4 i, j, count;
    CStream cs, parentCs;
    MemFile mf, parentMf;
    ASN1_ITEMPTR pCertRoot = NULL, pParentRoot = NULL;
    SizedBuffer *pNewCerts = NULL;
    ubyte *pDerCert = NULL, *pDerParent = NULL;
    ubyte4 derCertLen = 0, derParentLen = 0;
    byteBoolean noMoreCerts = FALSE;

    if ( (NULL == ppCerts ) || (NULL == pCertCount) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Must contain at least 1 certificate */
    if (0 == *pCertCount)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* If there is only 1 certificate then the SizedBuffer can remain
     * the same */
    if (1 == *pCertCount)
    {
        status = OK;
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &pParents, 1, sizeof(sbyte4) * (*pCertCount));
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(
        (*ppCerts)[0].data, (*ppCerts)[0].length, &pDerCert, &derCertLen);
    if (OK != status)
    {
        goto exit;
    }

    MF_attach(&mf, derCertLen, pDerCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pCertRoot);
    if (OK != status)
    {
        goto exit;
    }

    /* Check if the issued certificate is self-signed. If it is self-signed then
     * there is no need to process the remaining certificates. Set the count to 1
     * and pParent index appropriately so only the issued certificate is copied
     * over.
     *
     * If the certificate is not self-signed then check if any intermediate
     * certificates are provided corresponding to the issued certificate. */
    status = X509_isRootCertificate(ASN1_FIRST_CHILD(pCertRoot), cs);
    if (OK == status)
    {
        count = 1;
        pParents[0] = -1;
    }
    else if (ERR_FALSE == status)
    {
        /* By default initialize to -1 to identify that no parent has been found. */
        for (i = 0; i < *pCertCount; i++)
        {
            pParents[i] = -1;
        }

        /* This while loop attempts to find the certificate chain corresponding
         * to the issued certificate. The index of the current certificate (i)
         * starts at the issued certificate. The loop will search the Other Certificates
         * provided in the EST server response for the issuer. Once the issuer is found,
         * if the issuer is a CA certificate then the loop exits otherwise the loop
         * set the current certificate to the issuer and then searches for the next
         * issuer certificate. */
        i = 0;
        count = 1;
        do
        {
            /* If the parent is already found then the certificate chain is cyclic which
             * is an error condition. */
            if (-1 != pParents[i])
            {
                status = ERR_CERT_BUFFER_OVERFLOW;
                goto exit;
            }

            /* Search for the issuer certificate. We know the issued certificate is at index
             * 0 so the search can start at index 1 where the Other Certificates from the EST
             * response are stored. */
            for (j = 1; j < *pCertCount; j++)
            {
                /* If j and i match then no need to check if the link is valid since they
                 * are the same certificate. */
                if (j != i)
                {
                    status = CA_MGMT_decodeCertificate(
                        (*ppCerts)[j].data, (*ppCerts)[j].length, &pDerParent, &derParentLen);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    MF_attach(&parentMf, derParentLen, pDerParent);
                    CS_AttachMemFile(&parentCs, &parentMf);

                    status = X509_parseCertificate(parentCs, &pParentRoot);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    /* Check if the link is valid. There are 3 possibilities
                     * here.
                     *
                     * 1 - Link is valid and the issuer is not a root certificate. In
                     *     this case mark the parent in the pParents array and increment
                     *     the count of certificates in the chain. Exit the this inner
                     *     loop since the issuer was found.
                     * 2 - Link is valid and the issuer is a root certificate. In this
                     *     case exit both the inner for loop and outer while loop. The
                     *     chain is complete and there are no more certificates to process.
                     *     Note that we do not want to increment the count of certificates
                     *     in the chain since we don't want to include CA certificates
                     *     in our chain.
                     * 3 - Link is not valid. Check the link with the next certificate.
                     */
                    status = X509_validateLink(
                        ASN1_FIRST_CHILD(pCertRoot), cs,
                        ASN1_FIRST_CHILD(pParentRoot), parentCs, 0);
                    if (OK == status)
                    {
                        status = X509_isRootCertificate(
                            ASN1_FIRST_CHILD(pParentRoot), parentCs);
                        if (OK == status)
                        {
                            /* Link is valid and the issuer is a root certificate.
                             * Exit the outer loop. */
                            noMoreCerts = TRUE;
                            break;
                        }
                        else if (ERR_FALSE == status)
                        {
                            /* Link is valid and the issuer is not a root certificate. */

                            /* Free current certificate and transfer ASN.1 variables of the
                             * issuer to the current certificate to prepare for the next
                             * iteration. Avoids parsing the entire ASN.1 structure again. */
                            TREE_DeleteTreeItem((TreeItem *) pCertRoot);
                            pCertRoot = NULL;
                            DIGI_FREE((void **) &pDerCert);
                            pDerCert = pDerParent;
                            pDerParent = NULL;
                            derCertLen = derParentLen;
                            mf = parentMf;
                            cs = parentCs;
                            pCertRoot = pParentRoot;
                            pParentRoot = NULL;

                            /* Set the current increment the count of certificates in the chain
                             * and store the index to the issuer certificate in the pParents
                             * array. */
                            count++;
                            pParents[i] = j;

                            /* Set the issuer certificate as the current certificate
                             * for the next iteration.
                             */
                            i = j;
                            status = OK;
                            break;
                        }
                        else
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        TREE_DeleteTreeItem((TreeItem *) pParentRoot);
                        pParentRoot = NULL;
                        DIGI_FREE((void **) &pDerParent);
                        status = OK;
                    }
                }
            }

            /* If no issuer was found in the for loop above then exit the main
             * while loop. */
            if (j == *pCertCount)
            {
                noMoreCerts = TRUE;
            }

        } while ( (OK == status) && (noMoreCerts == FALSE) );

        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        goto exit;
    }

    TREE_DeleteTreeItem((TreeItem *) pCertRoot);
    pCertRoot = NULL;
    DIGI_FREE((void **) &pDerCert);

    /* Allocate the new SizedBuffer which will only hold the issued certificate and
     * corresponding intermediate certificate(s). */
    status = DIGI_CALLOC((void **) &pNewCerts, 1, count * sizeof(SizedBuffer));
    if (OK != status)
    {
        goto exit;
    }

    /* Loop through the new SizedBuffer and copy over each certificate from the original
     * SizedBuffer. Free the certificates from the original SizedBuffer as we go to avoid
     * extraneous memory usage. */
    index = 0;
    for (i = 0; i < count; i++)
    {
        /* Copy over certificate */
        status = DIGI_MALLOC_MEMCPY(
            (void **) &(pNewCerts[i].data), (*ppCerts)[index].length,
            (*ppCerts)[index].data, (*ppCerts)[index].length);
        if (OK != status)
        {
            goto exit;
        }
        pNewCerts[i].length = (*ppCerts)[index].length;

        /* Free certificate from original buffer */
        DIGI_FREE((void **) &((*ppCerts)[index].data));
        (*ppCerts)[index].length = 0;

        index = pParents[index];
    }

    /* Free any remaining certificates from the original SizedBuffer */
    for (i = 0; i < *pCertCount; i++)
    {
        if (NULL != (*ppCerts)[i].data)
        {
            DIGI_FREE((void **) &((*ppCerts)[i].data));
            (*ppCerts)[i].length = 0;
        }
    }
    DIGI_FREE((void **) ppCerts);

    *ppCerts = pNewCerts;
    *pCertCount = count;
    pNewCerts = NULL;

exit:

    if (NULL != pNewCerts)
    {
        for (i = 0; i < count; i++)
        {
            if (NULL != pNewCerts[i].data)
            {
                DIGI_FREE((void **) &(pNewCerts[i].data));
            }
        }
        DIGI_FREE((void **) &pNewCerts);
    }

    if (NULL != pParentRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pParentRoot);
    }

    if (NULL != pDerParent)
    {
        DIGI_FREE((void **) &pDerParent);
    }

    if (NULL != pCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);
    }

    if (NULL != pDerCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }

    if (NULL != pParents)
    {
        DIGI_FREE((void **) &pParents);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS EST_EXAMPLE_getTrustedChainPem(
    ubyte *pCert, ubyte4 certLen, SizedBuffer **ppChain, ubyte4 *pChainCount)
{
    MSTATUS status;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    SizedBuffer *pDerChain = NULL;
    SizedBuffer *pRetChain = NULL;
    ubyte4 derChainCount = 0, retChainCount = 0, i;
    intBoolean hasSelfSigned = 1;

    if ( (NULL == ppChain) || (NULL == pChainCount) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Release the certstore to fix Memory leak for Trust point.*/
    if (NULL == pCertStore)
    {
        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
        {
            verbosePrintError("Unable to create certstore for getting trust chain.", status);
            goto exit;
        }

        status = EST_EXAMPLE_constructCertStoreFromDir(pCertStore);
        if (OK != status)
        {
            verbosePrintError("Unable to load in CA certificates.", status);
            goto exit;
        }

    }

    status = CA_MGMT_decodeCertificate(
        pCert, certLen, &pDerCert, &derCertLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_getTrustedChain(MOC_ASYM(gHwAccelCtx)
        pDerCert, derCertLen, pCertStore, &pDerChain, &derChainCount);
    if (OK != status)
    {
        verbosePrintError("Unable to get trusted certificates.", status);
        goto exit;
    }

    if (NULL != pDerChain)
    {
        status = CRYPTO_UTILS_isRootCertificate(
            (pDerChain + derChainCount - 1)->data,
            (pDerChain + derChainCount - 1)->length);
        if (ERR_FALSE == status)
        {
            hasSelfSigned = 0;
            status = OK;
        }
        if (OK != status)
        {
            verbosePrintError("Unable to get trusted certificates.", status);
            goto exit;
        }

        retChainCount = derChainCount - hasSelfSigned;

        if (0 != retChainCount)
        {
            status = CRYPTO_UTILS_createPemChainFromDerChain(
                pDerChain, retChainCount, &pRetChain);
            if (OK != status)
            {
                verbosePrintError("Unable to convert DER certificate to PEM certificate.", status);
                goto exit;
            }
        }
    }

    *ppChain = pRetChain;
    *pChainCount = retChainCount;
    pRetChain = NULL;

exit:

    CRYPTO_UTILS_freeCertificates(&pRetChain, retChainCount);
    CRYPTO_UTILS_freeCertificates(&pDerChain, derChainCount);
    DIGI_FREE((void **) &pDerCert);

    return status;
}

static MSTATUS EST_EXAMPLE_handleServerkeygenResponse(ubyte *pCsrReqBytes, ubyte4 csrReqLen, int httpStatusCode, byteBoolean isRetry)
{
    MSTATUS status = OK;
    ubyte *pContentType = NULL;
    ubyte4 contentTypeLen = 0;
    ubyte *pHttpResp = NULL;
    ubyte4 httpRespLen = 0;
    ubyte *pKey = NULL;
    ubyte4 keyLength = 0;
    ubyte *pKeyContentType = NULL;
    ubyte4 keyContentTypeLen = 0;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;

    if (OK > (status = HTTP_REQUEST_getContentType(gHttpContext, (const ubyte**)&pContentType, &contentTypeLen)))
    {
        verbosePrintError("Unable to get response content type.", status);
        goto exit;
    }

    if(NULL == pContentType)
    {
        status = ERR_HTTP;
        goto exit;
    }

    if (OK > (status = HTTP_REQUEST_getResponseContent(gHttpContext, &pHttpResp, &httpRespLen)))
    {
        verbosePrintError("Unable to get response content.", status);
        goto exit;
    }

    /* Separate the key and certificate parts */
    if (OK > (status = EST_filterMultiPartContent(pHttpResp, httpRespLen, (ubyte *)pContentType, contentTypeLen,
                    &pKey, &keyLength, &pKeyContentType,
                    &keyContentTypeLen, NULL, NULL, NULL, NULL, isRetry, httpStatusCode)))
    {
        verbosePrintError("Unable to get multi-part content response.", status);
        goto exit;
    }

    if (0 == DIGI_STRNICMP((const sbyte*)EST_PKCS8, (const sbyte*)pKeyContentType, keyContentTypeLen))
    {
        pKeyBlob = pKey;
        keyBlobLen = keyLength;
        pKey = NULL;
    }
    else if (0 == DIGI_STRNICMP((const sbyte*)EST_FULL_CMC_PKCS_MIME, (const sbyte*)pKeyContentType, keyContentTypeLen))
    {
        int keyId = -1;
        if (OK > (status = getKeyIdentifiderFromCSR(pCsrReqBytes, csrReqLen, (ubyte4*)&keyId)))
        {
            verbosePrintError("Unable to get key identifier from CSR.", status);
            goto exit;
        }
        if (keyId == DECRYPT_KEY_ID)
        {
            if (OK > (status = EST_getPemKeyFromPkcs7EnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
            {
                verbosePrintError("Unable to extract key from PKCS7 envelop data.", status);
                goto exit;
            }
        }
        else if (keyId == ASYM_DECRYPT_KEY_ID)
        {
            if (OK > (status = EST_getPemKeyFromCmsEnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
            {
                verbosePrintError("Unable to extract key from CMS envelop data.", status);
                goto exit;
            }
        }
    }

    if (OK != (status = EST_EXAMPLE_writeKey(pKeyBlob, keyBlobLen)))
    {
        verbosePrintError("Unable to write serverkeygen keyblob to file.", status);
        goto exit;
    }

    /* Irrespective of verbose enabled or debug log enabled. this log should get printed */
    verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\nKey file received successfully.");

exit:
    if (pHttpResp) DIGI_FREE((void **)&pHttpResp);
    if (pKeyContentType) DIGI_FREE((void **)&pKeyContentType);
    if (pKey) DIGI_FREE((void **)&pKey);
    if (pKeyBlob) DIGI_FREE((void**)&pKeyBlob);

    return status;
}

static MSTATUS EST_EXAMPLE_constructCertStoreFromDir(struct certStore* pCertStoreForValidation)
{
    MSTATUS status;
    char *pCertPath = NULL;
    byteBoolean validateCerts = TRUE;

    /* Get the full CA directory path */
#ifdef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
    pCertPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, CA_PKI_COMPONENT);
#else
    pCertPath = (char *)EST_getTrustStorePathCopy();
#endif

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = DPM_checkStatus(DPM_CA_CERTS, &validateCerts);
    if (OK != status)
    {
        verbosePrintError(
            "Unable to get data protect CA certificate file status", status);
        goto exit;
    }
#endif

    /* Load in certificates from the CA directory */
    status = CRYPTO_UTILS_addTrustPointCertsByDir(
        pCertStoreForValidation, NULL, (sbyte *) pCertPath, validateCerts);
    if (OK != status)
    {
        verbosePrintError("Unable to load trusted certificates by directory.", status);
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
exit:
#endif

    if (pCertPath)
    {
        DIGI_FREE((void **)&pCertPath);
    }

    return status;
}

static MSTATUS EST_EXAMPLE_verifyFullcmcResponse(ASN1_ITEMPTR pRoot, CStream pkcs7Stream, ASN1_ITEMPTR *pSignerIssuer, ASN1_ITEMPTR *pSignerSerial)
{
    MSTATUS      status = OK;
    sbyte4       numKnownSigners    = 0;
    ASN1_ITEMPTR pkcs7Content = NULL;
    ASN1_ITEMPTR signerInfo = NULL;
    WalkerStep   asn1WalkerStep[] =
    {
        {GoFirstChild, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNextSibling, 0, 0},
        { VerifyType, MOC_SET, 0},
        {GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        {GoFirstChild, 0, 0},
        { VerifyType, INTEGER, 0},
        {GoNextSibling, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { Complete, 0, 0}
    };

    if (OK > (status = ASN1_GetChildWithTag(ASN1_FIRST_CHILD(pRoot), 0, &pkcs7Content)))
    {
        goto exit;
    }
    if (OK > (status = PKCS7_VerifySignedData(MOC_RSA(gHwAccelCtx) pkcs7Content, pkcs7Stream,
             NULL,
             NULL,
             EST_EXAMPLE_CB_validateRootCertificate,
             NULL,
             0,
             &numKnownSigners)))
    {
        verbosePrintError("Unable to verify FullCMC response data.", status);
        goto exit;
    }
    if (OK > (status = ASN1_WalkTree(pkcs7Content, pkcs7Stream, asn1WalkerStep, &signerInfo)))
    {
        verbosePrintError("Unable to get signer info from response data.", status);
        goto exit;
    }

    *pSignerIssuer = ASN1_FIRST_CHILD(signerInfo);
    *pSignerSerial = ASN1_NEXT_SIBLING(*pSignerIssuer);

exit:
    return status;
}

static MSTATUS EST_getParentCertificate(
    ubyte *pCert, ubyte4 certLen, const ubyte **ppParent, ubyte4 *pParentLen)
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRoot = NULL, pIssuer = NULL;

    if (NULL == pCertStore)
    {
        status = CERT_STORE_createStore(&pCertStore);
        if (OK != status)
            goto exit;

        status = EST_EXAMPLE_constructCertStoreFromDir(pCertStore);
        if (OK != status)
            goto exit;
    }

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
        goto exit;

    status = X509_getCertificateIssuerSerialNumber(
        ASN1_FIRST_CHILD(pRoot), &pIssuer, NULL);
    if (OK != status)
        goto exit;

    status = CERT_STORE_findTrustPointBySubjectFirst(
        pCertStore, pCert + pIssuer->dataOffset, pIssuer->length,
        ppParent, pParentLen, NULL);
    if (OK != status)
        goto exit;



exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS12__
static MSTATUS EST_EXAMPLE_writeP12File(
    sbyte *pKeyAlias, SizedBuffer *pCerts, ubyte4 certsCount,
    SizedBuffer *pTrustedCerts, ubyte4 trustedCertCount)
{
    MSTATUS status;
    SizedBuffer *pAllCerts = NULL;
    ubyte4 allCertsCount = 0, hasSelfSigned = 0, i;
    ubyte *pKey = NULL, *pKeyFile = NULL, *pKeyPath = NULL, *pFullPath = NULL;
    const ubyte *pCA = NULL;
    ubyte4 keyLen = 0, caLen = 0;
    sbyte4 aliasLen, extLen;
    ubyte *pPkcs12Data = NULL;
    ubyte4 pkcs12DataLen = 0;

    if (NULL == pKeyAlias || NULL == pCerts)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certsCount)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    allCertsCount = certsCount + trustedCertCount;
    status = DIGI_MALLOC(
        (void **) &pAllCerts, sizeof(SizedBuffer) * allCertsCount);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < certsCount; i++)
    {
        status = CA_MGMT_decodeCertificate(
            pCerts[i].data, pCerts[i].length, &(pAllCerts[i].data),
            &(pAllCerts[i].length));
        if (OK != status)
            goto exit;
    }
    for (i = 0; i < trustedCertCount; i++)
    {
        status = CA_MGMT_decodeCertificate(
            pTrustedCerts[i].data, pTrustedCerts[i].length,
            &(pAllCerts[i + certsCount].data),
            &(pAllCerts[i + certsCount].length));
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_UTILS_isRootCertificate(
        pAllCerts[allCertsCount - 1].data, pAllCerts[allCertsCount - 1].length);
    if (OK == status)
    {
        pCA = pAllCerts[allCertsCount - 1].data;
        caLen = pAllCerts[allCertsCount - 1].length;
        hasSelfSigned = 1;
    }
    else if (ERR_FALSE == status)
    {
        status = EST_getParentCertificate(
            pAllCerts[allCertsCount - 1].data,
            pAllCerts[allCertsCount - 1].length, &pCA, &caLen);
        if (OK != status)
            goto exit;
    }
    else
    {
        goto exit;
    }

    aliasLen = DIGI_STRLEN((sbyte *) pKeyAlias);
    extLen = DIGI_STRLEN((sbyte *)ESTC_EXT_PEM);

    status = DIGI_MALLOC((void **) &pKeyFile, aliasLen + extLen + 1);
    if (OK != status)
        goto exit;

    DIGI_MEMCPY(pKeyFile, pKeyAlias, aliasLen);
    DIGI_MEMCPY(pKeyFile + aliasLen,  (ubyte *) ESTC_EXT_PEM, extLen);
    pKeyFile[aliasLen + extLen] = '\0';

    pKeyPath = (ubyte *) EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, KEYS_PKI_COMPONENT);
    EST_CERT_UTIL_getFullPath((char *) pKeyPath, (char *) pKeyFile, (char **) &pFullPath);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = EST_readFileFp((char *) pFullPath, &pKey, &keyLen, TRUE, DPM_KEYS);
#else
    status = DIGICERT_readFile((char *) pFullPath, &pKey, &keyLen);
#endif
    if (OK != status)
        goto exit;

    status = PKCS12_EncryptPFXPduPwMode(
        g_pRandomContext, pAllCerts, allCertsCount - hasSelfSigned,
        pKey, keyLen, (ubyte *) pCA, caLen,
        (ubyte *) estc_pkcs12KeyPw, estc_pkcs12KeyPw ? DIGI_STRLEN(estc_pkcs12KeyPw) : 0,
        estc_pkcs12EncType,
        (ubyte *) estc_pkcs12PriPw, estc_pkcs12PriPw ? DIGI_STRLEN(estc_pkcs12PriPw) : 0,
        (ubyte *) estc_pkcs12IntPw, estc_pkcs12IntPw ? DIGI_STRLEN(estc_pkcs12IntPw) : 0,
        &pPkcs12Data, &pkcs12DataLen);
    if (OK != status)
    {
        goto exit;
    }

    /* PKCS12 extension of .pfx is same length as .pem extension */
    DIGI_MEMCPY(pKeyFile + aliasLen, ESTC_EXT_PKCS12, extLen);

    DIGI_FREE((void **) &pFullPath);
    EST_CERT_UTIL_getFullPath((char *) pKeyPath, (char *) pKeyFile, (char **) &pFullPath);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    status = EST_writeFileFp(
        (char *) pFullPath, pPkcs12Data, pkcs12DataLen, TRUE, TRUE, DPM_CERTS);
#else
    status = DIGICERT_writeFile((char *)pFullPath, pPkcs12Data, pkcs12DataLen);
#endif

exit:

    if (OK == status)
    {
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing certificate and key in DER format: ", (sbyte *) pFullPath);
    }
    else
    {
        verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "warning: unable to generate PKCS12 file");
    }

    if (NULL != pPkcs12Data)
    {
        DIGI_FREE((void **) &pPkcs12Data);
    }
    if (NULL != pKeyFile)
    {
        DIGI_FREE((void **) &pKeyFile);
    }
    if (NULL != pKeyPath)
    {
        DIGI_FREE((void **) &pKeyPath);
    }
    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }
    if (NULL != pKey)
    {
        DIGI_MEMSET_FREE(&pKey, keyLen);
    }
    if (NULL != pAllCerts)
    {
        CRYPTO_UTILS_freeCertificates(&pAllCerts, allCertsCount);
    }

    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS EST_writeKeyById(
    sbyte *pKeyAlias, ubyte4 keyAliasLen, TAP_Buffer *pKeyId,
    TAP_KeyInfo *pKeyInfo)
{
    MSTATUS status;
    sbyte *pKeyPath = NULL;
    sbyte *ppExtensions[] = {
        ESTC_EXT_DER,
        ESTC_EXT_PEM,
        ESTC_EXT_TAPKEY,
        NULL
    };
    sbyte **ppExt;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    ubyte *pBlob = NULL;
    ubyte4 blobLen = 0;
    sbyte *pFileName = NULL;
    ubyte4 fileNameLen = 0;
    sbyte *pFullPath = NULL;

    if ( (NULL == pKeyAlias) || (NULL == pKeyId) || (NULL == pKeyId->pBuffer) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKeyPath = (sbyte *) EST_CERT_UTIL_buildKeyStoreFullPath(
        (char *) pPkiDatabase, KEYS_PKI_COMPONENT);

    ppExt = ppExtensions;
    while (NULL != *ppExt)
    {
        if (NULL != pKeyBlob)
        {
            DIGI_FREE((void **) &pKeyBlob);
            keyBlobLen = 0;
        }

        if (NULL != pFileName)
        {
            DIGI_FREE((void **) &pFileName);
        }

        if (NULL != pFullPath)
        {
            DIGI_FREE((void **) &pFullPath);
        }

        if (0 == DIGI_STRCMP(*ppExt, (sbyte *) ESTC_EXT_DER))
        {
            status = CRYPTO_INTERFACE_TAP_serializeKeyById(
                g_pEstTapContext->pTapContext,
                g_pEstTapContext->pEntityCredentialList,
                g_pEstTapContext->pKeyCredentialList, pKeyInfo, pKeyId->pBuffer,
                pKeyId->bufferLen, privateKeyInfoDer, &pKeyBlob, &keyBlobLen);
            if (OK != status)
            {
                verbosePrintError("Failed to retrieve DER key blob by ID", status);
                goto exit;
            }

            pBlob = pKeyBlob;
            blobLen = keyBlobLen;
        }
        else if (0 == DIGI_STRCMP(*ppExt, (sbyte *) ESTC_EXT_PEM))
        {
            status = CRYPTO_INTERFACE_TAP_serializeKeyById(
                g_pEstTapContext->pTapContext,
                g_pEstTapContext->pEntityCredentialList,
                g_pEstTapContext->pKeyCredentialList, pKeyInfo, pKeyId->pBuffer,
                pKeyId->bufferLen, privateKeyPem, &pKeyBlob, &keyBlobLen);
            if (OK != status)
            {
                verbosePrintError("Failed to retrieve PEM key blob by ID", status);
                goto exit;
            }

            pBlob = pKeyBlob;
            blobLen = keyBlobLen;
        }
        else if (0 == DIGI_STRCMP(*ppExt, (sbyte *) ESTC_EXT_TAPKEY))
        {
            status = CRYPTO_INTERFACE_TAP_serializeKeyById(
                g_pEstTapContext->pTapContext,
                g_pEstTapContext->pEntityCredentialList,
                g_pEstTapContext->pKeyCredentialList, pKeyInfo, pKeyId->pBuffer,
                pKeyId->bufferLen, mocanaBlobVersion2, &pKeyBlob, &keyBlobLen);
            if (OK != status)
            {
                verbosePrintError("Failed to retrieve Mocana key blob by ID", status);
                goto exit;
            }

            if (TAP_KEY_ALGORITHM_ECC == pKeyInfo->keyAlgorithm)
            {
                pBlob = pKeyBlob + MOC_ECC_TAP_BLOB_START_LEN;
                blobLen = keyBlobLen - MOC_ECC_TAP_BLOB_START_LEN;
            }
            else
            {
                pBlob = pKeyBlob + MOC_RSA_TAP_BLOB_START_LEN;
                blobLen = keyBlobLen - MOC_RSA_TAP_BLOB_START_LEN;
            }
        }

        fileNameLen = keyAliasLen + DIGI_STRLEN(*ppExt);
        status = DIGI_CALLOC((void **) &pFileName, 1, fileNameLen + 1);
        if (OK != status)
        {
            verbosePrintError("Failed to allocate file name", status);
            goto exit;
        }
        DIGI_STRCAT(pFileName, pKeyAlias);
        DIGI_STRCAT(pFileName, *ppExt);
        pFileName[fileNameLen] = '\0';

        EST_CERT_UTIL_getFullPath(pKeyPath, pFileName, (char **) &pFullPath);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        status = EST_writeFileFp( (char *)
            pFullPath, pBlob, blobLen, TRUE, estc_fp_nocrypt, DPM_KEYS);
#else
        status = DIGICERT_writeFile( (char *)
            pFullPath, pBlob, blobLen);
#endif
        if (OK != status)
        {
            verbosePrintError("Failed to write out key blob file", status);
            goto exit;
        }

        ppExt++;
    }

exit:

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

    if (NULL != pFileName)
    {
        DIGI_FREE((void **) &pFileName);
    }

    if (NULL != pKeyBlob)
    {
        DIGI_FREE((void **) &pKeyBlob);
    }

    if (NULL != pKeyPath)
    {
        DIGI_FREE((void **) &pKeyPath);
    }

    return status;
}

static MSTATUS EST_persistKey(
    TAP_Buffer *pKeyId, sbyte *pKeyAlias, ubyte4 keyAliasLen,
    struct certStore *pStore)
{
    MSTATUS status;
    AsymmetricKey *pKey = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_KeyInfo keyInfo = { 0 };

    status = CERT_STORE_findIdentityByAlias(
        pStore, pKeyAlias, keyAliasLen, &pKey, NULL, NULL);
    if (OK != status)
    {
        verbosePrintError("Failed to retrieve key by alias", status);
        goto exit;
    }

    status = CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
    if (OK != status)
    {
        verbosePrintError("Failed to retrieve TAP key from Asymmetric key object", status);
        goto exit;
    }

    status = TAP_loadKey(
        g_pEstTapContext->pTapContext, g_pEstTapContext->pEntityCredentialList,
        pTapKey, g_pEstTapContext->pKeyCredentialList, NULL, NULL);
    if (OK != status)
    {
        verbosePrintError("Failed to load TAP key object", status);
        /* Set pTapKey to NULL to avoid TAP_unloadKey in exit leg */
        pTapKey = NULL;
        goto exit;
    }

    status = TAP_persistObject(
        g_pEstTapContext->pTapContext, pTapKey, pKeyId, NULL);
    if (OK != status)
    {
        verbosePrintError("Failed to persist TAP key object", status);
        goto exit;
    }

    keyInfo.keyAlgorithm = pTapKey->keyData.keyAlgorithm;
    keyInfo.keyUsage = pTapKey->keyData.keyUsage;
    keyInfo.algKeyInfo = pTapKey->keyData.algKeyInfo;

    TAP_unloadKey(pTapKey, NULL);
    pTapKey = NULL;

    status = EST_writeKeyById(
        pKeyAlias, keyAliasLen, pKeyId, &keyInfo);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pTapKey)
    {
        TAP_unloadKey(pTapKey, NULL);
    }

    if (OK == status)
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "Persisted key at index (or id): ");
    }
    else
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Unable to persist key at index (or id): ");
    }

    if (estc_isIdHex)
    {
        ubyte4 i = 0;

        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "0x");
        for (i = 0; i < pKeyId->bufferLen; i++)
        {
            verbosePrintString1Hex(ESTC_VERBOSE_LEVEL_INFO, pKeyId->pBuffer[i]);
        }
    }
    else
    {
        verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, (sbyte *) pKeyId->pBuffer);
    }
    verbosePrintString(ESTC_VERBOSE_LEVEL_INFO, "\n");

    return status;
}

#endif

MOC_STATIC MSTATUS EST_EXAMPLE_executeRequest(void)
{
    ubyte       *pHttpResp = NULL;
    ubyte4      httpRespLen;
    ubyte       *pPkcs7Out = NULL;
    ubyte4      pkcs7OutLen = 0;
    byteBoolean armorDetected = FALSE;
    const ubyte *pContentType = NULL;
    ubyte4 		contentTypeLen;
    char  		*pFullPath = NULL;
    char 		*pPkiComponentPath = NULL;
    ubyte4 filteredLen = 0;
    ubyte4 httpStatusCode = 0;
    struct SizedBuffer *pCerts = NULL;
    ubyte4              numCerts = 0;
    ubyte4 i = 0;
    ubyte *pFinalResponse = NULL;
    ubyte4 finalResponseLen = 0;
    ubyte4 finalResponseCopiedLen = 0;
    MSTATUS status = OK;
    int retryCount = 0;
    int mode = 0;
    ubyte *pCsrConfigFile = NULL;
    ubyte *pExtConfigFile = NULL;
    ubyte *pKey = NULL;
    ubyte4 keyLength = 0;
    ubyte *pPKeyContentType = NULL;
    ubyte4 keyContentTypeLen = 0;
    ubyte *pCertContentType = NULL;
    ubyte4 certContentTypeLen = 0;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen = 0;
    ubyte  *pCsrReqBytes = NULL;
    ubyte4 csrReqLen = 0;
    ubyte *pEntityType   = NULL;
    ubyte4 entityTypeLen = 0;
    ubyte *pRetryAfter   = NULL;
    sbyte4 retryAfter    = 0;
    char *pRespFile = NULL;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;
    ubyte *pPemKey = NULL;
    ubyte4 pemKeyLen = 0;
    byteBoolean isRetry = FALSE;
    ASN1_ITEMPTR pPkcs7Root         = NULL;
    ASN1_ITEMPTR pSignerIssuer = NULL;
    ASN1_ITEMPTR pSignerSerial = NULL;
    MemFile      mfPkcs7;
    ubyte        *pDecodedPkcs7  = NULL;
    ubyte4       decodedPkcs7Len = 0;
    CStream      pkcs7Stream;
    SizedBuffer  *pTrustedChain = NULL;
    ubyte4       trustedChainCount = 0;

#ifdef __ENABLE_DIGICERT_TAP__
    byteBoolean tapAttest = FALSE;
    AsymmetricKey *pAsymKey = NULL;
#endif

    if (TRUE == estc_backup)
    {
        switch (gRequestType)
        {
            case FULLCMC:
                if (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL) != 0)
                {
                    break;
                }

                /* fall-through */

            case SIMPLE_ENROLL:
                if (NULL != estc_keyAlias1)
                {
                    status = EST_backupKeysAndCert(
                        estc_keyAlias1, DIGI_STRLEN((sbyte *) estc_keyAlias1));
                    if (OK != status)
                    {
                        goto exit;
                    }
                }
                break;

            default:
                break;
        }
    }

    switch (gRequestType)
    {
        case FULLCMC:
            if ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) != 0) &&
                (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) != 0))
            {
                break;
            }

            /* fall-through */

        case SIMPLE_REENROLL:
            if (NULL != estc_keyAlias1)
            {
                status = EST_backupKeysAndCert(
                    estc_keyAlias1, DIGI_STRLEN((sbyte *) estc_keyAlias1));
                if (OK != status)
                {
                    goto exit;
                }
            }

        default:
            break;
    }

    if (gRequestType == CA_CERTS || gRequestType == CERTS_DOWNLOAD)
    {
        if (OK > (status = EST_sendCaCertsRequest(gHttpContext, gSslConnectionInstance,  (ubyte*)estc_ServerURL, DIGI_STRLEN(estc_ServerURL), (ubyte*)estc_serverName, DIGI_STRLEN(estc_serverName), estc_userAgent)))
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Failed to get CA Certificates");
            verbosePrintError("Unable to get CA Certificates.", status);
            if (OK <= HTTP_REQUEST_getStatusCode(gHttpContext, &httpStatusCode))
            {
                verboseDumpResponse(
                    ESTC_VERBOSE_LEVEL_INFO, NULL, 0, httpStatusCode);
            }
            goto exit;
        }
    }
    else if (gRequestType == CSR_ATTRS)
    {
        if (OK > (status = EST_sendCsrAttrsRequest(gHttpContext, gSslConnectionInstance,  (ubyte*)estc_ServerURL, DIGI_STRLEN(estc_ServerURL), (ubyte*)estc_serverName, DIGI_STRLEN(estc_serverName), estc_userAgent)))
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Failed to get CSR attributes");
            verbosePrintError("Unable to get CSR attributes.", status);
            goto exit;
        }
        pRespFile = CSRATTRS_RESP_FILE;
    }
    else
    {
        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CONF_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char *)estc_confFile, (char **)&pCsrConfigFile);
        pExtConfigFile = (ubyte *)estc_extattrs_confFile;

        while(retryCount < MAX_RETRY_COUNT)
        {
            httpStatusCode = 0;

            status = EST_EXAMPLE_prepareAndSendRequest(pCsrConfigFile,
                    pExtConfigFile, estc_config_type,
                    (ubyte*)estc_digestName, DIGI_STRLEN(estc_digestName),
                    mode, &pCsrReqBytes, &csrReqLen);
            if (status != OK)
            {
                if (ERR_EST_MISSING_REQUEST_INFO == status)
                {
                    verbosePrintError("Mandatory attribute [commonName or localityName] missing in CSR config", status);
                    goto exit;
                }
                HTTP_REQUEST_getStatusCode(gHttpContext, (ubyte4*)&httpStatusCode);
                /* Irrespective of verbose or debug enabled. These below logs should get printed.*/
                if (202 != httpStatusCode && 200 != httpStatusCode)
                {
                    if (OK <= HTTP_REQUEST_getResponseContent(gHttpContext, &pHttpResp, &httpRespLen) && NULL != pHttpResp)
                    {
                        if ((0 != mode) || (401 != httpStatusCode))
                        {
                            verboseDumpResponse(ESTC_VERBOSE_LEVEL_INFO,
                                    pHttpResp, httpRespLen, httpStatusCode);
                        }
                        DIGI_FREE((void **)&pHttpResp);
                    }
                }

                /* Retry behaviour checks
                 *
                 * - Retry if an error occurred due to networking issue
                 * - Retry if HTTP status code is 401, this time with auth credentials
                 * - Retry if HTTP status code is 202 in case of server keygen
                 */
                if ( (ERR_TCP_SOCKET_CLOSED == status) ||
                     (ERR_TCP_READ_ERROR == status) ||
                     (ERR_TCP_READ_TIMEOUT == status) )
                {
                    int ret = 0;

                    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);

                    /* Re-open the connection here. Loop here in case network
                     * error occurs, update retry accordingly */
                    while (++retryCount < MAX_RETRY_COUNT)
                    {
                        verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_DEFAULT, "WARNING: Retrying request connection, previous attempt status= ", status);
                        ret = EST_reOpenSSLConnection(pCertStore, gHttpContext,
                                estc_serverName, DIGI_STRLEN(estc_serverName),
                                (ubyte*)estc_ServerIpAddr, DIGI_STRLEN(estc_ServerIpAddr),
                                estc_ServerPort, &gSslConnectionInstance, estc_ocsp_required, FALSE);
                        if (OK <= ret || ERR_TCP_CONNECT_ERROR != ret)
                        {
                            if (OK <= ret)
                            {
                                if (OK > (status = HTTP_CONTEXT_resetContext(gHttpContext)))
                                {
                                    verbosePrintError("HTTP context reset failed.", status);
                                    goto exit;
                                }
                            }
                            break;
                        }
                    }

                    if (ret < 0)
                    {
                        status = ret;
                        verbosePrintError("Network error, failed to reopen connection.", status);
                        goto exit;
                    }
                }
                else if (httpStatusCode == 401)
                {
                    int ret = 0;
                    int firstTry = 1;
                    mode = 1;

                    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);

                    /* Re-open the connection here. Loop here in case network
                     * error occurs, update retry accordingly */
                    while (++retryCount < MAX_RETRY_COUNT)
                    {
                        if (0 == firstTry)
                        {
                            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_DEFAULT, "WARNING: Retrying connection, previous attempt status= ", ret);
                        }
                        ret = EST_reOpenSSLConnection(pCertStore, gHttpContext,
                                estc_serverName, DIGI_STRLEN(estc_serverName),
                                (ubyte*)estc_ServerIpAddr, DIGI_STRLEN(estc_ServerIpAddr),
                                estc_ServerPort, &gSslConnectionInstance, estc_ocsp_required, FALSE);
                        if (OK <= ret || ERR_TCP_CONNECT_ERROR != ret)
                        {
                            break;
                        }
                        firstTry = 0;
                    }

                    if (ret < 0)
                    {
                        status = ret;
                        verbosePrintError("HTTP 401: Failed to reopen connection.", status);
                        goto exit;
                    }
                }
                else if (httpStatusCode == 202)
                {
                    mode = 2;
                    isRetry = TRUE;
                    /* Special case to handle the 202 scenario for serverkeygen */
                    verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "HTTP status code= ", httpStatusCode);
                    if (gRequestType == SERVER_KEYGEN)
                    {
                        /* If the request is serverkeygen and the status code is 202.
                           Then server may send the empty multipart message or multi-part
                           message containing a private key with out certificate in the response.
                           Key will be sent at first response itself and from the second retry
                           no key will be sent.
                         */
                        if (retryCount == 1)
                        {
                            if (OK != (status = EST_EXAMPLE_handleServerkeygenResponse(pCsrReqBytes,
                                            csrReqLen, httpStatusCode, isRetry)))
                            {
                                verbosePrintError("Unable to handle serverkeygen pending response.", status);
                                goto exit;
                            }
                        }
                    }

                    retryCount++;
                    if (retryCount == MAX_RETRY_COUNT)
                    {
                        /* Already reached max retry count, exit loop with
                         * current error status */
                        verbosePrintError("HTTP 202: Max retries reached.", status);
                        break;
                    }

                    if (OK > (status = HTTP_REQUEST_getEntityByIndex(gHttpContext, 3, (const ubyte**)&pEntityType, &entityTypeLen)))
                    {
                        verbosePrintError("Unable to get Retry-After info.", status);
                        goto exit;
                    }
                    if (pEntityType == NULL)
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }
                    if (pRetryAfter != NULL)
                    {
                        DIGI_FREE((void**)&pRetryAfter);
                    }
                    if (OK > (status = DIGI_MALLOC((void**)&pRetryAfter, entityTypeLen+1)))
                    {
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMSET(pRetryAfter, 0x00, entityTypeLen+1)))
                    {
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMCPY(pRetryAfter, pEntityType, entityTypeLen)))
                    {
                        goto exit;
                    }

                    retryAfter = DIGI_ATOL((const sbyte *)pRetryAfter, NULL);

                    if (retryAfter < ESTC_RETRY_WAIT_SECONDS_MAX)
                    {
                        SLEEP(retryAfter);
                    }
                    else
                    {
                        verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Certificate enroll pending on CA");
                        status = ERR_INTERNAL_ERROR;
                        verbosePrintError("Retry-After value is greater than maximum wait time.", status);
                        goto exit;
                    }
                }
                else
                {
                    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);
                    break;
                }
            }
            else
            {
                /* Authentication error or other error could've occurred and
                 * retry attempt might succeed.
                 */
                break;/*SUCCESS */
            }
        }

        if (OK != status)
        {
            verbosePrintError("HTTP request/response failure.", status);
        }

        if(pPkiComponentPath) DIGI_FREE((void **)&pPkiComponentPath);
    }


    /* Get http status code */
    if (OK > (status = HTTP_REQUEST_getStatusCode(gHttpContext, (ubyte4*)&httpStatusCode)))
    {
        verbosePrintError("Unable to get HTTP response code.", status);
        goto exit;
    }

    if (gRequestType == SERVER_KEYGEN || gRequestType == SIMPLE_ENROLL ||
            gRequestType == SIMPLE_REENROLL || gRequestType == FULLCMC)
    {
        if (httpStatusCode == 200)
        {
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "HTTP status code= ", httpStatusCode);
            if (OK > (status = HTTP_REQUEST_getContentType(gHttpContext, (const ubyte**)&pContentType, &contentTypeLen)))
            {
                verbosePrintError("Unable to get response content type.", status);
                goto exit;
            }

            if(NULL == pContentType)
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(gHttpContext, &pHttpResp, &httpRespLen)))
            {
                verbosePrintError("Unable to get response content.", status);
                goto exit;
            }

            if (gRequestType == SERVER_KEYGEN)
            {
                /* Separate the key and certificate parts */
                if (OK > (status = EST_filterMultiPartContent(pHttpResp, httpRespLen, (ubyte *)pContentType, contentTypeLen,
                                &pKey, &keyLength, &pPKeyContentType,
                                &keyContentTypeLen, &pPkcs7Out, &pkcs7OutLen,
                                &pCertContentType, &certContentTypeLen,
                                isRetry, httpStatusCode)))
                {
                    verbosePrintError("Unable to get multi-part content from response", status);
                    goto exit;
                }
                pContentType = pCertContentType;
                contentTypeLen = certContentTypeLen;
                /* In case of pending retry pKey will be NULL */
                if (pKey != NULL)
                {
                    if (0 == DIGI_STRNICMP((const sbyte*)EST_PKCS8, (const sbyte*)pPKeyContentType, keyContentTypeLen))
                    {
                        pKeyBlob = pKey;
                        keyBlobLen = keyLength;
                    }
                    else if (0 == DIGI_STRNICMP((const sbyte*)EST_FULL_CMC_PKCS_MIME, (const sbyte*)pPKeyContentType, keyContentTypeLen))
                    {
                        int keyId = -1;
                        if (OK > (status = getKeyIdentifiderFromCSR(pCsrReqBytes, csrReqLen, (ubyte4*)&keyId)))
                        {
                            verbosePrintError("Unable to get key identifier from CSR.", status);
                            goto exit;
                        }
                        if (keyId == DECRYPT_KEY_ID)
                        {
                            if (OK > (status = EST_getPemKeyFromPkcs7EnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
                            {
                                verbosePrintError("Unable to get PEM key from PKCS7 envelop data.", status);
                                goto exit;
                            }
                        }
                        else if (keyId == ASYM_DECRYPT_KEY_ID)
                        {
                            if (OK > (status = EST_getPemKeyFromCmsEnvelopeData(MOC_HW(gHwAccelCtx) pCertStore, pKey, keyLength, &pKeyBlob, &keyBlobLen)))
                            {
                                verbosePrintError("Unable to get PEM key from CMS envelop data.", status);
                                goto exit;
                            }
                        }
                        if(pKey) DIGI_FREE((void **)&pKey);
                    }

                    if (keyBlobLen > 0)
                    {
                        /* Irrespective of verbose enabled or debug log enabled. this log should get printed */
                        verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\nKey file received successfully.");
                    }
                }
                filteredLen = 0;

            }
            else
            {
                if (OK > (status = EST_filterPkcs7Banner(pHttpResp, httpRespLen, &pPkcs7Out, &pkcs7OutLen, &armorDetected)))
                {
                    verbosePrintError("Unable to filter PKCS7 banner from HTTP response data.", status);
                    goto exit;
                }

                if (armorDetected == 0)
                {
                    if (pHttpResp == pPkcs7Out)
                    {
                        pHttpResp = NULL; /* To avoid double free corruption */
                    }
                }
            }

            if (gRequestType == FULLCMC)
            {
                if (OK > (status = CA_MGMT_decodeCertificate(pPkcs7Out, pkcs7OutLen, &pDecodedPkcs7, &decodedPkcs7Len)))
                {
                    goto exit;
                }

                MF_attach(&mfPkcs7, decodedPkcs7Len, (ubyte*)pDecodedPkcs7);
                CS_AttachMemFile(&pkcs7Stream, &mfPkcs7);
                if (OK > (status = ASN1_Parse(pkcs7Stream, &pPkcs7Root)))
                {
                    goto exit;
                }

                if (OK > (status = EST_EXAMPLE_verifyFullcmcResponse(pPkcs7Root, pkcs7Stream, &pSignerIssuer, &pSignerSerial)))
                {
                    verbosePrintError("Unable to verify FullCMC response data signature.", status);
                    verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "FullCMC response data signature verification failed.");
#ifndef __ENABLE_DIGICERT_FORCE_DUMP_CERT__
                    goto exit;
#endif
                }
            }

            if (OK > (status = EST_filterPkcs7Message(pPkcs7Out, pkcs7OutLen, &filteredLen)))
            {
                verbosePrintError("Unable to filter PKCS7 message from HTTP response data.", status);
                goto exit;
            }
#ifdef __ENABLE_DIGICERT_TAP__
            if (useTAP)
            {
                if ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
                        (NULL != est_fullcmcReqType) &&
                        ( (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL))))
                {
                    TAP_Key *pTapKey = NULL;

                    /*Get the AIK private key from the certstore */
                    if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                                    estc_keyAlias1, DIGI_STRLEN((sbyte*)estc_keyAlias1),
                                    &pAsymKey,
                                    NULL, NULL)))
                    {
                        goto exit;
                    }

                    status = CRYPTO_INTERFACE_getTapKey(pAsymKey, &pTapKey);
                    if (OK != status)
                        goto exit;

                    if (pTapKey->keyData.keyUsage == TAP_KEY_USAGE_ATTESTATION)
                    {
                        tapAttest = TRUE;
                    }

                }
            }
            if (tapAttest == TRUE)
            {
                if (OK > (status = EST_handleFullcmcEnrollResponse(MOC_HW(gHwAccelCtx) pAsymKey,
                                pPkcs7Out, filteredLen,
                                (ubyte*)pContentType, contentTypeLen,
                                &pCerts, &numCerts)))
                {
                    verbosePrintError("EST_handleFullcmcEnrollResponse failed with status: ", status);
                    goto exit;
                }
            }
            else
            {

                if (OK > (status = EST_receiveResponse((ubyte *)pContentType, contentTypeLen, pPkcs7Out, filteredLen,
                                pAsymKey, &pCerts, &numCerts)))
                {
                    verbosePrintError("Unable to parse PKCS7 response data.", status);
                    goto exit;
                }
#else
               if (OK > (status = EST_receiveResponse((ubyte *)pContentType, contentTypeLen, pPkcs7Out, filteredLen,
                                NULL, &pCerts, &numCerts)))
                {
                    verbosePrintError("Unable to parse PKCS7 response data.", status);
                    goto exit;
                }
#endif
#ifdef __ENABLE_DIGICERT_TAP__
            }
#endif

            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\nCertificate enrolled successfully.");

            if (OK > (status = EST_removeOtherCertificates(&pCerts, &numCerts)))
            {
                verbosePrintError("Unable to remove other certificates.", status);
                goto exit;
            }

            for (; i < numCerts; i++)
            {
                finalResponseLen += pCerts[i].length;
            }
            if (OK > (status = EST_EXAMPLE_getTrustedChainPem(
                pCerts[numCerts-1].data, pCerts[numCerts-1].length, &pTrustedChain, &trustedChainCount)))
            {
                goto exit;
            }
            for (i = 0; i < trustedChainCount; i++)
            {
                finalResponseLen += pTrustedChain[i].length;
            }
            if (OK != status)
            {
                goto exit;
            }
            if (OK > (status = DIGI_MALLOC((void **)&pFinalResponse, finalResponseLen)))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMSET(pFinalResponse, 0x00, finalResponseLen)))
            {
                goto exit;
            }
            finalResponseCopiedLen = 0;
            for (i = 0; i < numCerts; i++)
            {
                if (OK > (status = DIGI_MEMCPY(pFinalResponse + finalResponseCopiedLen, pCerts[i].data, pCerts[i].length)))
                {
                    goto exit;
                }
                finalResponseCopiedLen += pCerts[i].length;
            }
            for (i = 0; i < trustedChainCount; i++)
            {
                if (OK > (status = DIGI_MEMCPY(pFinalResponse + finalResponseCopiedLen, pTrustedChain[i].data, pTrustedChain[i].length)))
                {
                    goto exit;
                }
                finalResponseCopiedLen += pTrustedChain[i].length;
            }
            if (!estc_disable_cacert)
            {
                struct certStore* pCertStoreForValidation = NULL;

                if (NULL != pCertStore)
                {
                    CERT_STORE_releaseStore(&pCertStore);
                    if (OK > (status = CERT_STORE_createStore(&pCertStore)))
                    {
                        verbosePrintError("Unable to create certstore for cacerts.", status);
                        goto exit;
                    }

                    if (OK > (status = EST_EXAMPLE_constructCertStoreFromDir(pCertStore)))
                    {
                        verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\nCA certificate is not available to validate received certificate.");
                    }
                }

                if(OK > (status = EST_validateReceivedCertificate(MOC_HW(gHwAccelCtx) pCertStore, pFinalResponse, finalResponseCopiedLen, NULL)))
                {
                    switch (status)
                    {
                        case ERR_CERT_START_TIME_VALID_IN_FUTURE:
                            verbosePrintError("\nIssued certificate validity time is in the future: ", status);
                            break;

                        default:
                            verbosePrintError("\nIssued certificate is not validated with its CA Certs: ", status);
                    }
                }
                else
                {
                    verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\nIssued certificate is validated with CA Certs.");
                }
            }

            char pOutCertFile[MAX_FILE_NAME];
            if (OK > (status = DIGI_MEMSET((ubyte*)pOutCertFile, 0x00, MAX_FILE_NAME)))
            {
                goto exit;
            }
            if ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
                ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) &&
                 (NULL != estc_keyAlias2)))
            {
                ubyte4 aliasLen = DIGI_STRLEN((sbyte*)estc_keyAlias2);
                if (aliasLen >= MAX_FILE_NAME)
                {
                    status = ERR_BUFFER_OVERFLOW;
                    verbosePrintError("Key alias2 too long for output buffer", status);
                    goto exit;
                }
                if (OK > (status = DIGI_MEMCPY(pOutCertFile, estc_keyAlias2, aliasLen)))
                {
                    goto exit;
                }
            }
            else
            {

                if (estc_keyAlias1 != NULL)
                {
                    ubyte4 aliasLen = DIGI_STRLEN((sbyte*)estc_keyAlias1);
                    if (aliasLen >= MAX_FILE_NAME)
                    {
                        status = ERR_BUFFER_OVERFLOW;
                        verbosePrintError("Key alias1 too long for output buffer", status);
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMCPY(pOutCertFile, estc_keyAlias1, aliasLen)))
                    {
                        goto exit;
                    }
                }
                else
                {
                    if (gRequestType == SERVER_KEYGEN)
                    {
                        /* If it is a serverkeygen case. estc_keyAlias1 might be null, in case if not passed
                           as command line argument */
                        if (OK > (status = DIGI_MEMCPY(pOutCertFile, SERVERKEYGEN_KEY_FILE, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE))))
                        {
                            goto exit;
                        }
                    }
                }
            }

            /* Write to .pem format */
            if (OK > (status = DIGI_MEMCPY(pOutCertFile+DIGI_STRLEN((sbyte*)pOutCertFile), (ubyte *) ESTC_EXT_PEM, 4)))
            {
                goto exit;
            }
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CERTS_PKI_COMPONENT);

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            if (OK > (status = EST_writeFileFp((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) pOutCertFile, &pFullPath), pFinalResponse, finalResponseCopiedLen, TRUE, estc_fp_nocrypt, DPM_CERTS)))
#else
            if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) pOutCertFile, &pFullPath), pFinalResponse, finalResponseCopiedLen)))
#endif
            {
                verbosePrintStringError("Unable to write issued certificate PEM data to file", (sbyte *)pFullPath);
                verbosePrintError("Unable to write issued certificate PEM data to file.", status);
            }
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing certificate in PEM format: ", (sbyte *)pFullPath);
            if(pFullPath) DIGI_FREE((void **)&pFullPath);

            /*Write to .der format */
            if (OK > (status = CA_MGMT_decodeCertificate(pFinalResponse, finalResponseCopiedLen, &pDerCert, &derCertLen)))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMCPY(pOutCertFile+DIGI_STRLEN((sbyte*)pOutCertFile)-4, (ubyte *) ESTC_EXT_DER, 4)))
            {
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            if (OK > (status = EST_writeFileFp((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) pOutCertFile, &pFullPath), pDerCert, derCertLen, TRUE, estc_fp_nocrypt, DPM_CERTS)))
#else
            if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) pOutCertFile, &pFullPath), pDerCert, derCertLen)))
#endif
            {
                verbosePrintStringError("Unable to write issued certificate DER data to file", (sbyte *)pFullPath);
                verbosePrintError("Unable to write issued certificate DER data to file.", status);
            }
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing certificate in DER format: ", (sbyte *)pFullPath);
            if(pPkiComponentPath) DIGI_FREE((void **)&pPkiComponentPath);
            if(pFullPath) DIGI_FREE((void **)&pFullPath);

            if (estc_pkcs12Gen)
            {
#ifdef __ENABLE_DIGICERT_PKCS12__
                /* Do not exit here with a fatal error, PKCS12 file is
                 * optional. The function will warn the user if the file was
                 * unable to be generated. */
                (void) EST_EXAMPLE_writeP12File(
                    (sbyte *) estc_keyAlias1, pCerts, numCerts, pTrustedChain,
                    trustedChainCount);
#else
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
#endif
            }

            if (gRequestType == SERVER_KEYGEN)
            {
                /* In case of pending retry. pKeyBlob will be NULL. */
                if (pKeyBlob != NULL)
                {
                    if (OK != (status = EST_EXAMPLE_writeKey(pKeyBlob, keyBlobLen)))
                    {
                        verbosePrintError("Unable to write server generated key data to file.", status);
                        goto exit;
                    }
                }
            }

#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_TEE__)
            if (!useTEE)
#endif
            {
                /* Only persist non-primary keys at this point. Primary keys are
                * persisted during creation */
                if (TRUE == estc_tapKeyHandleSet && FALSE == estc_tapKeyPrimary)
                {
                    (void) EST_persistKey(&estc_tapKeyHandle, estc_keyAlias1, DIGI_STRLEN(estc_keyAlias1), pCertStore);
                }

                if (TRUE == estc_tapCertificateNvIndexSet)
                {
                    /* Do not override status here */
                    if (OK == EST_persistDataAtNVIndex(
                        estc_tapCertificateNvIndex, pDerCert, derCertLen, TRUE == estc_tapKeyPrimary ? TAP_AUTH_CONTEXT_PLATFORM : TAP_AUTH_CONTEXT_NONE))
                    {
                        verbosePrintString1Hex1NL(ESTC_VERBOSE_LEVEL_INFO, "Persisted certificate at index: 0x", estc_tapCertificateNvIndex);
                    }
                    else
                    {
                        verbosePrintString1Hex1NL(ESTC_VERBOSE_LEVEL_INFO, "WARNING: Unable to persist certificate at index: 0x", estc_tapCertificateNvIndex);
                    }
                }
            }
#endif
        }
        else
        {
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "\nCertificate enroll failed");
        }
    }
    else
    {
        if (OK > (status = HTTP_REQUEST_getContentType(gHttpContext, (const ubyte**)&pContentType, &contentTypeLen)))
        {
            verbosePrintError("Unable to get response content type.", status);
            goto exit;
        }

        if(NULL == pContentType)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (OK > (status = HTTP_REQUEST_getResponseContent(gHttpContext, &pHttpResp, &httpRespLen)))
        {
            verbosePrintError("Unable to get response content.", status);
            goto exit;
        }

        if (gRequestType == CA_CERTS || gRequestType == CERTS_DOWNLOAD)
        {
            if (OK > (status = EST_filterPkcs7Banner(pHttpResp, httpRespLen, &pPkcs7Out, &pkcs7OutLen, &armorDetected)))
            {
                verbosePrintError("Unable to filter PKCS banners from response.", status);
                goto exit;
            }
            if (armorDetected == 0)
            {
                if (pHttpResp == pPkcs7Out)
                    pHttpResp = NULL; /* To avoid double free corruption */
            }
            if (OK > (status = EST_filterPkcs7Message(pPkcs7Out, pkcs7OutLen, &filteredLen)))
            {
                verbosePrintError("Unable to filter PKCS message from response.", status);
                goto exit;
            }

            if (OK > (status = EST_receiveResponse((ubyte *)pContentType, contentTypeLen, pPkcs7Out, filteredLen,
                            NULL, &pCerts, &numCerts)))
            {
                verbosePrintError("Unable to parse PKCS7 response data.", status);
                goto exit;
            }

            status = EST_writeTrustedCerts(pCerts, numCerts);
            if (OK != status)
            {
                verbosePrintError("Unable to write CA certificates.", status);
                goto exit;
            }

            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Got CA Certificates successfully");
        }
        else
        {
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CONF_PKI_COMPONENT);
            if (OK > (status = DIGICERT_writeFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) pRespFile, &pFullPath), pHttpResp, httpRespLen)))
            {
                verbosePrintStringError("Unable to write csratts response data to file", (sbyte *)pFullPath);
                verbosePrintError("Unable to write csratts response data to file.", status);
                goto exit;
            }

            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing file: ", (sbyte *)pFullPath);
            verbosePrintNL(ESTC_VERBOSE_LEVEL_DEFAULT, "Got CSR attributes successfully");
        }
    }

    if (((FULLCMC == gRequestType) && (REKEY == gFullCMCRequestType)) ||
        ((gRequestType == SIMPLE_REENROLL) && (NULL != estc_keyAlias2)))
    {
        if (OK == status)
        {
            status = EST_rekeyOverrideAliasFile(
                estc_keyAlias1, DIGI_STRLEN((sbyte *) estc_keyAlias1),
                estc_keyAlias2, DIGI_STRLEN((sbyte *) estc_keyAlias2));
        }
        else
        {
            EST_deleteCertsAndKeys(
                estc_keyAlias2, DIGI_STRLEN((sbyte *) estc_keyAlias2));
            EST_deleteOldCertsAndKeys(
                estc_keyAlias1, DIGI_STRLEN((sbyte *) estc_keyAlias1));
        }
    }

    if ((((FULLCMC == gRequestType) && (RENEW == gFullCMCRequestType)) ||
        (SIMPLE_REENROLL == gRequestType)) && ((OK != status)))
    {
        EST_deleteOldCertsAndKeys(
            estc_keyAlias1, DIGI_STRLEN((sbyte *) estc_keyAlias1));
    }

exit:
    if(OK > status)
    {
            verbosePrintError("EST client request failed.", status);
    }
    if (OK > (status = HTTP_CONTEXT_resetContext(gHttpContext)))
    {
        verbosePrintError("Unable to reset HTTP context.", status);
    }
    if (OK > (status = EST_closeConnection(gHttpContext, gSslConnectionInstance)))
    {
        verbosePrintError("Unable to close connection", status);
    }
    gHttpContext = NULL;
    if (pRetryAfter != NULL)
        DIGI_FREE((void**)&pRetryAfter);

    if(pHttpResp)
    {
        DIGI_FREE((void **)&pHttpResp);
    }
    if (pFinalResponse)
    {
        DIGI_FREE((void **)&pFinalResponse);
    }
    if(estc_config_type == EST_CONFIG_FILE)
    {
        if (pCsrConfigFile)
            DIGI_FREE((void **)&pCsrConfigFile);
    }
    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);
    if (pPkiComponentPath)
        DIGI_FREE((void **)&pPkiComponentPath);
    if(pCerts)
    {
        for(i = 0; i < numCerts; i++)
        {
            if(pCerts[i].data) DIGI_FREE((void **)&pCerts[i].data);
        }
        DIGI_FREE((void **)&pCerts);
    }
    if(pPKeyContentType) DIGI_FREE((void **)&pPKeyContentType);
    if(pPkcs7Out) DIGI_FREE((void **)&pPkcs7Out);
    if(pCertContentType) DIGI_FREE((void **)&pCertContentType);
    if(pCsrReqBytes) DIGI_FREE((void **)&pCsrReqBytes);
    if(pKeyBlob) DIGI_FREE((void **)&pKeyBlob);
    if (pDerCert) DIGI_FREE((void**)&pDerCert);
    if (pPemKey) DIGI_FREE((void **)&pPemKey);

    if (pPkcs7Root)
    {
        TREE_DeleteTreeItem((TreeItem*)pPkcs7Root);
    }
    if(pDecodedPkcs7) DIGI_FREE((void **)&pDecodedPkcs7);
    if(pTrustedChain) CRYPTO_UTILS_freeCertificates(&pTrustedChain, trustedChainCount);
    return status;
}

MOC_STATIC MSTATUS
EST_EXAMPLE_processRequest(void)
{
    MSTATUS status = OK;

    if (NULL != strstr((const char *)estc_ServerURL, EST_CACERTS_CMD))
    {
        gRequestType = CA_CERTS;
    }
    else if (NULL != strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD))
    {
        gRequestType = CSR_ATTRS;
    }
    else if (NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD))
    {
        gRequestType = SERVER_KEYGEN;
    }
    else if (NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_ENROLL_CMD))
    {
        gRequestType = SIMPLE_ENROLL;
    }
    else if (NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD))
    {
        gRequestType = SIMPLE_REENROLL;
    }
    else if (NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD))
    {
        gRequestType = FULLCMC;
    }
    else
    {
        gRequestType = CERTS_DOWNLOAD;
        /*verbosePrintStringError("This operation is not supported", (sbyte *)estc_ServerURL);
        status = ERR_EST_BAD_REQUEST;
        goto exit;*/
    }

    if (OK > (status = EST_EXAMPLE_executeRequest()))
    {
        verbosePrintError("Unable to execute request.", status);
        goto exit;
    }
exit:
    return status;

}

extern int
EST_EXAMPLE_uninitUpcallsAndCertStores()
{
    MSTATUS status = OK;
    if(pCertStore)
        CERT_STORE_releaseStore(&pCertStore);
    if(pPkiDatabase)
        DIGI_FREE((void **)&pPkiDatabase);

    /* zero any globally registered vars,
       pointers were set and not allocated */
    gpPrevAsymKey = NULL;

    return status;
}


extern sbyte4
EST_EXAMPLE_freeArgs()
{
    /* Free all the parameter that we put on the heap.*/
    if (estc_ServerIpAddr != NULL) {
        DIGI_FREE((void **)&estc_ServerIpAddr);
        estc_ServerIpAddr = NULL;
    }
    if (estc_ServerURL != NULL) {
        DIGI_FREE((void **)&estc_ServerURL);
        estc_ServerURL = NULL;
    }
    if (estc_User != NULL) {
        DIGI_MEMSET((ubyte *)estc_User, 0, DIGI_STRLEN((const sbyte *)estc_User));
        DIGI_FREE((void **)&estc_User);
        estc_User = NULL;
    }
    if (estc_Pass != NULL) {
        DIGI_MEMSET((ubyte *)estc_Pass, 0, DIGI_STRLEN((const sbyte *)estc_Pass));
        DIGI_FREE((void **)&estc_Pass);
        estc_Pass = NULL;
    }
    if (estc_certPath != NULL) {
        DIGI_FREE((void **)&estc_certPath);
        estc_certPath = NULL;
    }
#ifndef __ENABLE_DIGICERT_EST_RUNTIME_KEYSTORE__
    if (estc_truststorePath != NULL) {
        DIGI_FREE((void **)&estc_truststorePath);
        estc_truststorePath = NULL;
    }
#endif
    if (estc_http_proxy != NULL) {
        DIGI_FREE((void **)&estc_http_proxy);
        estc_http_proxy = NULL;
    }
    if (estc_rootCA != NULL) {
        DIGI_FREE((void **)&estc_rootCA);
        estc_rootCA = NULL;
    }
    if (estc_serverName != NULL) {
        DIGI_FREE((void **)&estc_serverName);
        estc_serverName = NULL;
    }
    if (estc_confFile != NULL) {
        DIGI_FREE((void **)&estc_confFile);
        estc_confFile = NULL;
    }
    if (estc_extattrs_confFile != NULL) {
        DIGI_FREE((void **)&estc_extattrs_confFile);
        estc_extattrs_confFile = NULL;
    }
    if (estc_keyType != NULL) {
        DIGI_FREE((void **)&estc_keyType);
        estc_keyType = NULL;
    }
#ifdef __ENABLE_DIGICERT_PQC__
    if (estc_qskeytype != NULL) {
        DIGI_FREE((void **)&estc_qskeytype);
        estc_qskeytype = NULL;
    }
    if (estc_curve != NULL) {
        DIGI_FREE((void **)&estc_curve);
        estc_curve = NULL;
    }
#endif
    if (estc_newKeyType != NULL) {
        DIGI_FREE((void **)&estc_newKeyType);
        estc_newKeyType = NULL;
    }
    if (estc_keySource != NULL) {
        DIGI_FREE((void **)&estc_keySource);
        estc_keySource = NULL;
    }
    if (estc_pkcs8Pw != NULL) {
        DIGI_MEMSET((ubyte *)estc_pkcs8Pw, 0, DIGI_STRLEN((const sbyte *)estc_pkcs8Pw));
        DIGI_FREE((void **)&estc_pkcs8Pw);
        estc_pkcs8Pw = NULL;
    }
    if (estc_pkcs8EncAlg != NULL) {
        DIGI_FREE((void **)&estc_pkcs8EncAlg);
        estc_pkcs8EncAlg = NULL;
    }
    if (estc_pkcs12EncAlg != NULL) {
        DIGI_FREE((void **)&estc_pkcs12EncAlg);
        estc_pkcs12EncAlg = NULL;
    }
    if (estc_pkcs12IntPw != NULL) {
        DIGI_MEMSET((ubyte *)estc_pkcs12IntPw, 0, DIGI_STRLEN((const sbyte *)estc_pkcs12IntPw));
        DIGI_FREE((void **)&estc_pkcs12IntPw);
        estc_pkcs12IntPw = NULL;
    }
    if (estc_pkcs12PriPw != NULL) {
        DIGI_MEMSET((ubyte *)estc_pkcs12PriPw, 0, DIGI_STRLEN((const sbyte *)estc_pkcs12PriPw));
        DIGI_FREE((void **)&estc_pkcs12PriPw);
        estc_pkcs12PriPw = NULL;
    }
    if (estc_pkcs12KeyPw != NULL) {
        DIGI_MEMSET((ubyte *)estc_pkcs12KeyPw, 0, DIGI_STRLEN((const sbyte *)estc_pkcs12KeyPw));
        DIGI_FREE((void **)&estc_pkcs12KeyPw);
        estc_pkcs12KeyPw = NULL;
    }
    if (estc_keyAlias1 != NULL)
    {
        DIGI_FREE((void **)&estc_keyAlias1);
        estc_keyAlias1 = NULL;
    }
    if (estc_skg_clientkey != NULL)
    {
        DIGI_FREE((void**)&estc_skg_clientkey);
    }
    if (estc_digestName != NULL)
    {
        DIGI_FREE((void**)&estc_digestName);
    }
    if (est_fullcmcReqType != NULL)
    {
        DIGI_FREE((void**)&est_fullcmcReqType);
    }
    if (estc_skg_clientcert != NULL)
    {
        DIGI_FREE((void**)&estc_skg_clientcert);
    }
    if (estc_pskFile != NULL)
    {
        DIGI_FREE((void**)&estc_pskFile);
    }
    if (estc_skgAlg != NULL)
    {
        DIGI_FREE((void**)&estc_skgAlg);
    }
    if (estc_userAgent != NULL)
    {
        DIGI_FREE((void**)&estc_userAgent);
    }
    if (estc_keyAlias2 != NULL)
    {
        DIGI_FREE((void **)&estc_keyAlias2);
    }
#ifdef __ENABLE_DIGICERT_TAP__
    if (estc_tap_confFile != NULL)
    {
        DIGI_FREE((void**)&estc_tap_confFile);
    }
    if (estc_tap_keyPassword != NULL)
    {
        DIGI_FREE((void**)&estc_tap_keyPassword);
    }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    if (estc_tap_serverName != NULL)
    {
        DIGI_FREE((void**)&estc_tap_serverName);
    }
#endif
    if (NULL != estc_tapKeyHandleStr)
    {
        DIGI_FREE((void**)&estc_tapKeyHandleStr);
    }
    if (NULL != estc_tapKeyHandle.pBuffer)
    {
        DIGI_FREE((void**)&estc_tapKeyHandle.pBuffer);
    }
    if (NULL != estc_tapCertificateNvIndexStr)
    {
        DIGI_FREE((void**)&estc_tapCertificateNvIndexStr);
    }
    if (NULL != estc_tapKeyNonceNvIndexStr)
    {
        DIGI_FREE((void**)&estc_tapKeyNonceNvIndexStr);
    }
    if (NULL != estc_tapTokenHierarchyStr)
    {
        DIGI_FREE((void**)&estc_tapTokenHierarchyStr);
    }
#endif
    if (pCertStore != NULL)
    {
        CERT_STORE_releaseStore(&pCertStore);
    }
    return OK;
}

/*
@brief    Validates the keysize and the keyType arguments passed.

@details   This function validates the keysize and keyType arguments passed
           from the command line.

@param keySize size of the key
@param keyTpe  type of key. Possible values:
               \ref RSA
               \ref ECDSA

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
static
MSTATUS EST_validateKeySizeArgument(ubyte2 keySize, sbyte* keyType)
{
    MSTATUS status = OK;

    /*Validate keySize argument */
    if ((0 == DIGI_STRCMP(estc_keySource, (const sbyte*)KEY_SOURCE_SW)))
    {
        if(DIGI_STRCMP((const sbyte *)keyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            /*Supported keySize 2048, 3072 */
            if (!(keySize == 2048 || keySize == 3072 || keySize == 4096))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("Invalid keysize argument. Supported key sizes: 2048, 3072, 4096.", status);
                goto exit;
            }
        }
        else if (DIGI_STRCMP((const sbyte *)keyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            /* All curve ids are supported except 192 */
            if (!((keySize == 256) || (keySize == 224) ||
                (keySize == 384) || (keySize == 521)))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("Invalid curve ID argument. Supported curves: 224, 256, 384 and 521.", status);
                goto exit;
            }
        }
        else if (DIGI_STRCMP((const sbyte *)keyType, (const sbyte *)KEY_TYPE_EDDSA) == 0)
        {
            /* Either curve25519 or curve448 */
            if (!((keySize == 255) || (keySize == 448)))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("Invalid curve ID argument. Supported curves: 255 (for curve25519) or 448 (for curve448).", status);
                goto exit;
            }
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (DIGI_STRCMP((const sbyte *)keyType, (const sbyte *)KEY_TYPE_HYBRID) == 0)
        {
            if (NULL == estc_curve)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("Missing -est_curve argument for hybrid key type. Supported curves: P256, P384 and P521.", status);
                goto exit;
            }
            else if(DIGI_STRCMP((const sbyte *)estc_curve, (const sbyte *)CURVE_P256))
            {
                estc_curveId = cid_EC_P256;
            }
            else if(DIGI_STRCMP((const sbyte *)estc_curve, (const sbyte *)CURVE_P384))
            {
                estc_curveId = cid_EC_P384;
            }
            else if(DIGI_STRCMP((const sbyte *)estc_curve, (const sbyte *)CURVE_P521))
            {
                estc_curveId = cid_EC_P521;
            }
            else
            {
                status = ERR_INVALID_ARG;
                verbosePrintStringError("Invalid -est_curve argument for hybrid key type. Supported curves: P256, P384 and P521. ", estc_curve);
                goto exit;
            }

            if (NULL == estc_qskeytype)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("Missing -est_qskeytype argument for HYBRID key type.", status);
                goto exit;
            }
            else
            {
                /* validate it's a valid qs type and set the qsAlgId */
                if (qsKeyTypeToAlgId(estc_qskeytype, &estc_qsAlg))
                {
                    verbosePrintStringError("Invalid -est_qskeytype argument", estc_qskeytype);
                    goto exit;
                }
            }
        }
#endif
        else
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("Invalid key type argument.", status);
            goto exit;
        }
    }

exit:

    return status;
}

/*
@brief    Validates the arguments.

@details   This function validates the arguments passed
           from the command line.

@return  \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
static
MSTATUS EST_validateArguments()
{
    MSTATUS status = OK;
    char *pPkiComponentPath = NULL;
    ubyte *pContents = NULL;
    ubyte4 contentsLen = 0;
    char *pFullPath = NULL;
    ubyte file[MAX_FILE_NAME];
    ubyte pemFile[MAX_FILE_NAME];
    byteBoolean foundEncAlg;
    ubyte4 encAlgLen;

    /*Validate keySource argument */
    if (estc_keySource != NULL)
    {
#ifdef __ENABLE_DIGICERT_TAP__
        /* TAP Build - supported keysources are TPM2 and SW */
        if (!((DIGI_STRCMP(estc_keySource, (const sbyte*)KEY_SOURCE_TPM2) == 0) ||
            (DIGI_STRCMP(estc_keySource, (const sbyte*)KEY_SOURCE_SW) == 0) ||
             (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_NXPA71) == 0) ||
             (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TPM1_2) == 0) ||
             (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_TEE) == 0) ||
             (DIGI_STRCMP((const sbyte *)estc_keySource, (const sbyte *)KEY_SOURCE_PKCS11) == 0 )))
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("Invalid keysource argument.", status);
            goto exit;
        }
#else
        /* Software key Build - supported keysource is only SW */
        if ((0 != DIGI_STRCMP(estc_keySource, (const sbyte*)KEY_SOURCE_SW)))
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("Invalid keysource argument.", status);
            goto exit;
        }
#endif
    }

    if (estc_verboseLevel < 0 || estc_verboseLevel > 2)
    {
        status = ERR_INVALID_ARG;
        verbosePrintError("Invalid verbose level argument. Valid values: 0, 1 or 2.", status);
        goto exit;
    }

    /*Validate keySize argument*/
    if (estc_keyType)
    {
        if (OK != (status = EST_validateKeySizeArgument(estc_keySize, estc_keyType)))
        {
            goto exit;
        }
    }

    /*Validate rekeySize argument*/
    if (NULL != est_fullcmcReqType)
    {
        if ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
            ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) &&
             (NULL != estc_keyAlias2)))
        {
            if (NULL == estc_keyAlias2)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The rekeyAlias parameter is missing in arguments.", status);
                goto exit;
            }
            if (OK != (status = EST_validateKeySizeArgument(estc_newKeySize, estc_newKeyType)))
            {
                goto exit;
            }
        }
    }

    /* For serverkeygen case, check if keyalias file already exists in keystore */
    if ((NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)))
    {
        ubyte *pFile = NULL;

        /* Free the resource before using it */
        DIGI_FREE((void**)&pPkiComponentPath);
        DIGI_FREE((void**)&pFullPath);

        if (NULL != estc_skgAlg)
        {
            status = EST_getPskAlgId(estc_skgAlg, NULL, NULL);
            if (OK != status)
            {
                verbosePrintError("Invalid server keygen encryption algorithm.", status);
                goto exit;
            }
        }

        if (estc_skg_clientcert || estc_skg_clientkey)
        {
            if ( (NULL == estc_skg_clientcert) || (NULL == estc_skg_clientkey) )
            {
                status = ERR_INVALID_INPUT;
                verbosePrintError("Asymmetric server keygen must provide key and certificate ", status);
                goto exit;
            }
        }

#if !defined(__ENABLE_DIGICERT_TRUSTPOINT_LOCAL__)
        if (estc_keyAlias1 != NULL)
        {
            if (OK != (status = DIGI_CALLOC((void**)&pFile, 1, DIGI_STRLEN((sbyte*)estc_keyAlias1) + 5))) /* .pem + '\0'*/
            {
                goto exit;
            }
            if (OK != (status = DIGI_MEMCPY((ubyte*)pFile, estc_keyAlias1, DIGI_STRLEN((sbyte*)estc_keyAlias1))))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMCPY(pFile+DIGI_STRLEN((sbyte*)estc_keyAlias1), (ubyte *) ESTC_EXT_PEM, 4)))
            {
                goto exit;
            }
        }
        else
        {
            if (OK != (status = DIGI_CALLOC((void**)&pFile, 1, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE) + 5))) /* .pem + '\0' */
            {
                goto exit;
            }
            if (OK != (status = DIGI_MEMCPY((ubyte*)pFile, SERVERKEYGEN_KEY_FILE, DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE))))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMCPY(pFile+DIGI_STRLEN((sbyte*)SERVERKEYGEN_KEY_FILE), (ubyte *) ESTC_EXT_PEM, 4)))
            {
                goto exit;
            }
        }

        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, KEYS_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char*)pFile, (char**)&pFullPath);

        /* Check if file is already present. If present then throw error */
        if (TRUE == FMGMT_pathExists (pFullPath, NULL))
        {
            status = ERR_FILE_EXISTS;
            verbosePrintError("Key file with same name already exists ", status);
        }
        DIGI_FREE((void**)&pFullPath);
        DIGI_FREE((void**)&pPkiComponentPath);
        if (OK != status)
        {
            goto exit;
        }

        /* Check if cert file is already present. If present then throw error */
        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, CERTS_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char*)pFile, (char**)&pFullPath);
        if (TRUE == FMGMT_pathExists (pFullPath, NULL))
        {
            status = ERR_FILE_EXISTS;
            verbosePrintError("Certificate file with same name already exists ", status);
        }

        DIGI_FREE((void**)&pFile);
        DIGI_FREE((void**)&pFullPath);
        DIGI_FREE((void**)&pPkiComponentPath);
        if (OK != status)
        {
            goto exit;
        }
#endif
    }

    /*Validate fullcmc reqtype arguments */
    if ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
        (NULL != est_fullcmcReqType) &&
        (!( (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW)) ||
            (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) ||
            (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_ENROLL)) )))
    {
        status = ERR_INVALID_ARG;
        verbosePrintError("Invalid FullCMC request type argument.", status);
        goto exit;
    }

    /* Validation of keyAlias argument */
    /* For Simple-reenroll, Fullcmc (renew/rekey) requests keyAlias is Madatory */
    if ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) ||
        ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
         ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
         (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))))
    {
        /* keyAlias is a Mandatory Argument in case of simple-reenroll fullcmc rekey and fullcmc renew requests */
        /* Simple-reenroll, renew, rekey */
        if (NULL == estc_keyAlias1)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("The keyAlias parameter is missing in arguments.", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)file, 0x00, MAX_FILE_NAME)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(file, estc_keyAlias1, DIGI_STRLEN((sbyte*)estc_keyAlias1))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pemFile, 0x00, MAX_FILE_NAME)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pemFile, estc_keyAlias1, DIGI_STRLEN((sbyte*)estc_keyAlias1))))
        {
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY(pemFile+DIGI_STRLEN((sbyte*)estc_keyAlias1), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }

        if ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
            (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
            ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) &&
             (NULL != estc_keyAlias2)))
        {/*fullcmc renew/rekey */
            if (OK > (status = DIGI_MEMCPY(file+DIGI_STRLEN((sbyte*)estc_keyAlias1), (ubyte *) ESTC_EXT_DER, 4)))
            {
                goto exit;
            }

            /* Check if either the .pem or .der certifcate path is present in the keystore with mentioned alias name */
            pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, CERTS_PKI_COMPONENT);
            if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                (const char *) file, &pFullPath), &pContents, &contentsLen)))
            {
                DIGI_FREE((void**)&pFullPath);

                if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                                    (const char *) pemFile, &pFullPath), &pContents, &contentsLen)))
                {
                    verbosePrintError("Unable to read DER-formatted key with given alias.", status);
                }
            }
            DIGI_FREE((void**)&pFullPath);
            if (pContents == NULL)
            {
                status = (status != OK) ? status : ERR_NOT_FOUND;
                verbosePrintError("No certificate found with provided alias.", status);
                goto exit;
            }
            DIGI_FREE((void**)&pContents);
        }

        /* Check if either the .pem or .der key path is present in the keystore with mentioned alias name */
        if (OK > (status = DIGI_MEMCPY(file+DIGI_STRLEN((sbyte*)estc_keyAlias1), (ubyte *) ESTC_EXT_DER, 4)))
        {
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY(pemFile+DIGI_STRLEN((sbyte*)estc_keyAlias1), (ubyte *) ESTC_EXT_PEM, 4)))
        {
            goto exit;
        }

        DIGI_FREE((void**)&pPkiComponentPath);
        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)estc_certPath, KEYS_PKI_COMPONENT);
        if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath(pPkiComponentPath,
                            (const char *) file, &pFullPath), &pContents, &contentsLen)))
        {
            DIGI_FREE((void**)&pFullPath);

            if (OK > (status = DIGICERT_readFile((const char *) EST_CERT_UTIL_getFullPath((char*)pPkiComponentPath,
                                (const char *) pemFile, &pFullPath), &pContents, &contentsLen)))
            {
                verbosePrintError("Unable to read PEM-formatted key with provided alias.", status);
            }
        }
        DIGI_FREE((void**)&pFullPath);
        if (pContents == NULL)
        {
            status = (status != OK) ? status : ERR_NOT_FOUND;
            verbosePrintError("No key file found with provided alias.", status);
            goto exit;
        }
    }

    if ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) ||
        ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
         ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
         (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))))
    {
        if (TRUE == estc_renewWindowSet)
        {
            /* Renew window must be non-negative.
             */
            if (0 > estc_renewWindow)
            {
                status = ERR_INVALID_INPUT;
                verbosePrintError("Negative renew windows value not allowed.", status);
                goto exit;
            }

#if ESTC_MAX_RENEW_WINDOW_SIZE != 0
            /* Check against maximum allowed renew window size
             */
            if (ESTC_MAX_RENEW_WINDOW_SIZE < estc_renewWindow)
            {
                status = ERR_INVALID_INPUT;
                verbosePrintError("Renew window value to large.", status);
                goto exit;
            }
#endif
        }
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if ( (NULL != strstr((const char *)estc_ServerURL, EST_CACERTS_CMD)) ||
         (NULL != strstr((const char *)estc_ServerURL, EST_CSR_ATTRS_CMD)) ||
         (NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)) )
    {
        useTAP = 0;
    }

    if (useTAP)
    {
        sbyte *pKeyType = estc_keyType;
        if ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
                (0 == DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) )
        {
            pKeyType = estc_newKeyType;
        }
        if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
        {
            if (estc_tapKeyUsage < 1 || estc_tapKeyUsage > 4)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The estc_tapKeyUsage parameter value is invalid. Supported values: 1, 2, 3, 4.", status);
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "   1 = TAP_KEY_USAGE_SIGNING, 2 = TAP_KEY_USAGE_DECRYPT, 3 = TAP_KEY_USAGE_GENERAL, 4 = TAP_KEY_USAGE_ATTESTATION");
                goto exit;
            }
            if (estc_tapEncScheme < 0 || estc_tapEncScheme > 3)
            {
                status = ERR_INVALID_ARG;

                verbosePrintError("The estc_tapEncScheme parameter value is invalid. Supported values: 1, 2, 3.", status);
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "   1 = TAP_ENC_SCHEME_PKCS1_5, 2 = TAP_ENC_SCHEME_OAEP_SHA1, 3 = TAP_ENC_SCHEME_OAEP_SHA256");
                goto exit;
            }
            if (estc_tapSignScheme < 0 || estc_tapSignScheme > 6)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The estc_tapSignScheme parameter value is invalid. Supported values for RSA: 1 to 6.", status);
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "   1 = TAP_SIG_SCHEME_PKCS1_5, 2 = TAP_SIG_SCHEME_PSS_SHA1, 3 = TAP_SIG_SCHEME_PSS_SHA256,\n \
                        4 = TAP_SIG_SCHEME_PKCS1_5_SHA1, 5 = TAP_SIG_SCHEME_PKCS1_5_SHA256, 6 = TAP_SIG_SCHEME_PKCS1_5_DER ");
                goto exit;
            }
        }
        else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {
            if ((estc_tapKeyUsage != TAP_KEY_USAGE_SIGNING) && (estc_tapKeyUsage != TAP_KEY_USAGE_ATTESTATION)
                                                            && (estc_tapKeyUsage != TAP_KEY_USAGE_GENERAL))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The estc_tapKeyUsage parameter value is invalid. Supported values: 1, 3 or 4.", status);
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "   1 = TAP_KEY_USAGE_SIGNING\n 3 = TAP_KEY_USAGE_GENERAL\n 4 = TAP_KEY_USAGE_ATTESTATION");
                goto exit;
            }
            if ((0 != estc_tapSignScheme) && ((estc_tapSignScheme < 7) || (estc_tapSignScheme > 11)))
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("The estc_tapSignScheme parameter value is invalid. Supported values for ECDSA: 7 to 11.", status);
                verbosePrintNL(ESTC_VERBOSE_LEVEL_INFO, "   7 = TAP_SIG_SCHEME_ECDSA_SHA1, 8 = TAP_SIG_SCHEME_ECDSA_SHA224, 9 = TAP_SIG_SCHEME_ECDSA_SHA256,\n \
                        10 = TAP_SIG_SCHEME_ECDSA_SHA384, 11 = TAP_SIG_SCHEME_ECDSA_SHA512 ");
                goto exit;
            }
        }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        if (NULL == estc_tap_serverName)
        {
            status = ERR_EST;
            verbosePrintError("Mandatory argument -est_tapservername is not set.", status);
            goto exit;
        }
        if (-1 == estc_tap_serverPort)
        {
            status = ERR_EST;
            verbosePrintError("Mandatory argument -est_tapserverport is not set.", status);
            goto exit;
        }
#endif
    }
#endif

    if (estc_pkcs8Pw && estc_pkcs8EncAlg)
    {
        foundEncAlg = FALSE;
        encAlgLen = DIGI_STRLEN(estc_pkcs8EncAlg);
#if defined(__ENABLE_DIGICERT_PKCS5__)
#if defined(__ENABLE_DES_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_DES) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_DES))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_sha1_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_RC2) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_SHA1_RC2))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_sha1_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_DES_CIPHER__) && defined(__ENABLE_DIGICERT_MD2__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_DES) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_DES))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md2_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_RC2) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD2_RC2))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md2_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_DES_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_DES) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_DES))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md5_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_RC2) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V1_MD5_RC2))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v1_md5_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_3DES_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_3DES) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_3DES))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_3des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_DES_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_DES) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_DES))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_des;
            foundEncAlg = TRUE;
        }
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_RC2) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg,(sbyte *) PKCS8_ENC_ALG_P5_V2_RC2))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_rc2;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_AES_CIPHERS__)
#if !defined(__DISABLE_AES128_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_AES128) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_AES128))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_aes128;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_AES192_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_AES192) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_AES192))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_aes192;
            foundEncAlg = TRUE;
        }
#endif
#if !defined(__DISABLE_AES256_CIPHER__)
        if (encAlgLen == DIGI_STRLEN((sbyte *) PKCS8_ENC_ALG_P5_V2_AES256) && 0 == DIGI_STRCMP(estc_pkcs8EncAlg, (sbyte *) PKCS8_ENC_ALG_P5_V2_AES256))
        {
            estc_pkcs8EncType = PCKS8_EncryptionType_pkcs5_v2_aes256;
            foundEncAlg = TRUE;
        }
#endif
#endif /* !defined(__DISABLE_AES_CIPHERS__) */
#endif /*  __ENABLE_DIGICERT_PKCS5__  */
        if (FALSE == foundEncAlg)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS8 encryption algorithm is not valid.", status);
            goto exit;
        }
    }

    if (TRUE == estc_pkcs12Gen)
    {
        if (estc_pkcs12EncAlg)
        {
            foundEncAlg = FALSE;
            encAlgLen = DIGI_STRLEN(estc_pkcs12EncAlg);
    #ifdef __ENABLE_DIGICERT_2KEY_3DES__
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_2DES) && 0 == DIGI_STRCMP(estc_pkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_2DES))
            {
                estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_2des;
                foundEncAlg = TRUE;
            }
    #endif
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_3DES) && 0 == DIGI_STRCMP(estc_pkcs12EncAlg, (sbyte *) PKCS12_ENC_ALG_SHA_3DES))
            {
                estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_3des;
                foundEncAlg = TRUE;
            }
    #ifdef __ENABLE_ARC2_CIPHERS__
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC2_40) && 0 == DIGI_STRCMP(estc_pkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC2_40))
            {
                estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc2_40;
                foundEncAlg = TRUE;
            }
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC2_128) && 0 == DIGI_STRCMP(estc_pkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC2_128))
            {
                estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc2_128;
                foundEncAlg = TRUE;
            }
    #endif
#ifndef __DISABLE_ARC4_CIPHERS__
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC4_40) && 0 == DIGI_STRCMP(estc_pkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC4_40))
            {
                estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc4_40;
                foundEncAlg = TRUE;
            }
            if (encAlgLen == DIGI_STRLEN((sbyte *)PKCS12_ENC_ALG_SHA_RC4_128) && 0 == DIGI_STRCMP(estc_pkcs12EncAlg, (sbyte *)PKCS12_ENC_ALG_SHA_RC4_128))
            {
                estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_rc4_128;
                foundEncAlg = TRUE;
            }
#endif
            if (FALSE == foundEncAlg)
            {
                status = ERR_INVALID_ARG;
                verbosePrintError("PKCS12 encryption algorithm is not valid.", status);
                goto exit;
            }
        }
        else
        {
            estc_pkcs12EncType = PCKS8_EncryptionType_pkcs12_sha_3des;
        }

        if (estc_pkcs12IntPw && DIGI_STRLEN((sbyte *)estc_pkcs12IntPw) < 4)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS12 integrity password must be at least 4 characters.", status);
            goto exit;
        }
        if (estc_pkcs12PriPw && DIGI_STRLEN((sbyte *)estc_pkcs12PriPw) < 4)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS12 privacy password must be at least 4 characters.", status);
            goto exit;
        }
        if (estc_pkcs12KeyPw && DIGI_STRLEN((sbyte *)estc_pkcs12KeyPw) < 4)
        {
            status = ERR_INVALID_ARG;
            verbosePrintError("PKCS12 key password must be at least 4 characters.", status);
            goto exit;
        }
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    if (TRUE == estc_tapKeyHandleSet)
    {
        status = EST_utilReadId(estc_tapKeyHandleStr, &estc_tapKeyHandle);
        if (OK != status)
        {
            verbosePrintError("Failed to process key handle.", status);
            goto exit;
        }
    }

    if (TRUE == estc_tapCertificateNvIndexSet)
    {
        status = EST_utilStrToInt(
            estc_tapCertificateNvIndexStr, &estc_tapCertificateNvIndex);
        if (OK != status)
        {
            verbosePrintError("Failed to process certificate NV index.", status);
            goto exit;
        }
    }

    if (TRUE == estc_tapKeyPrimary)
    {
        if (FALSE == estc_tapKeyHandleSet)
        {
            status = ERR_INVALID_INPUT;
            verbosePrintError("Primary key requires key handle to be provided.", status);
            goto exit;
        }

        if (TRUE == estc_tapKeyNonceNvIndexSet)
        {
            status = EST_utilStrToInt(
                estc_tapKeyNonceNvIndexStr, &estc_tapKeyNonceNvIndex);
            if (OK != status)
            {
                verbosePrintError("Failed to process key nonce NV index.", status);
                goto exit;
            }
        }

        if (TRUE == estc_tapTokenHierarchySet)
        {
            status = EST_convertTapHierarchyString(
                estc_tapTokenHierarchyStr, &estc_tapTokenHierarchy);
            if (OK != status)
            {
                verbosePrintError("Failed to process TAP token hierarchy.", status);
                goto exit;
            }
        }
    }
#endif

exit:
    if (OK != status)
    {
        (void) DIGI_FREE((void **)&estc_keySource);
        (void) DIGI_FREE((void **)&estc_keyType);
        (void) DIGI_FREE((void **)&estc_newKeyType);
        (void) DIGI_FREE((void **)&estc_keyAlias1);
        (void) DIGI_FREE((void **)&est_fullcmcReqType);
        (void) DIGI_FREE((void **)&estc_digestName);
        (void) DIGI_FREE((void **)&estc_User);
        (void) DIGI_FREE((void **)&estc_Pass);
        (void) DIGI_FREE((void **)&estc_ServerURL);
        (void) DIGI_FREE((void **)&estc_serverName);
        (void) DIGI_FREE((void **)&estc_ServerIpAddr);
        (void) DIGI_FREE((void **)&estc_confFile);
        (void) DIGI_FREE((void **)&estc_serverName);
        (void) DIGI_FREE((void **)&estc_keySource);
        (void) DIGI_FREE((void **)&estc_keyAlias1);
        (void) DIGI_FREE((void **)&estc_certPath);
        (void) DIGI_FREE((void **)&estc_truststorePath);
        (void) DIGI_FREE((void **)&estc_http_proxy);
        (void) DIGI_FREE((void **)&estc_pkcs8Pw);
        (void) DIGI_FREE((void **)&estc_pkcs8EncAlg);
    }
    DIGI_FREE((void**)&pPkiComponentPath);
    DIGI_FREE((void**)&pContents);
    return status;
}

#ifdef  __ENABLE_DIGICERT_TAP__
extern EST_getTapContext g_pGetTapContext;
MSTATUS EST_registerTapCtxCallback(EST_getTapContext getTapContext)
{
    MSTATUS status = OK;
    if (getTapContext == NULL)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        g_pGetTapContext = getTapContext;
    }

    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
int main(int argc, char *argv[])
{
    void* dummy = NULL;

	MOC_UNUSED(dummy);
#else
extern MSTATUS
EST_CLIENT_main(sbyte4 dummy)
{
#endif
    MSTATUS status = OK;
    ubyte *pCsrConfigFile = NULL;
    intBoolean reOp;
    int retryCount = 0;
#ifndef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
    gMocanaAppsRunning++;
#endif

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
    if (OK > (status = FMGMT_changeCWD(MANDATORY_BASE_PATH)))
        goto exit;
#endif

    /* On Windows we need to call this as we don't use mocana_example.c */
    /* Making sure that DIGICERT_initDigicert is not called multiple times */
#if(defined(__RTOS_WIN32__))
    if (OK > (status = DIGICERT_initDigicert()))
    {
        verbosePrintError("\n Error in Mocana libraries initializing - ", status);
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
    if (OK > ( status = EST_EXAMPLE_getArgs(argc, argv))) /* Initialize parameters to default values */
    {
        return status;
    }
#endif

    if (OK > (status = EST_validateArguments()))
    {
#ifndef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
        gMocanaAppsRunning--;
#endif
#if defined( __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__ )
        RTOS_semSignal(g_tpla_sem);
#if defined(__FREERTOS_RTOS__)
        RTOS_destroyThread(NULL);
#endif
#endif /* if defined( __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__ ) */
        return status;
    }

    if (VERBOSE_DEBUG)
    {
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_ServerIpAddr: ", estc_ServerIpAddr);
        verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_ServerPort: ", estc_ServerPort);
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_ServerURL: ", estc_ServerURL);
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_User: ", estc_User);
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_certPath: ", estc_certPath);
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_serverName: ", estc_serverName);
        if ((NULL != estc_ServerURL) &&
                (NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_ENROLL_CMD) ||
                NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD) ||
                NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD) ||
                NULL != strstr((const char *)estc_ServerURL, EST_KEYGEN_CMD)))
        {
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_keyType: ", estc_keyType);
#ifdef __ENABLE_DIGICERT_PQC__
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_qskeytype: ", estc_qskeytype);
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_curve: ", estc_curve);
#endif
#ifdef __ENABLE_DIGICERT_TAP__
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapModuleId: ", estc_tapModuleId);
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapKeyPrimary: ", estc_tapKeyPrimary);
            if (NULL != estc_tapTokenHierarchyStr)
            {
                verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapTokenHierarchy: ", estc_tapTokenHierarchyStr);
            }
            if (NULL != estc_tapKeyHandleStr)
            {
                verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapKeyHandleStr: ", estc_tapKeyHandleStr);
            }
            if (NULL != estc_tapKeyNonceNvIndexStr)
            {
                verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapKeyNonceNvIndexStr: ", estc_tapKeyNonceNvIndexStr);
            }
            if (NULL != estc_tapCertificateNvIndexStr)
            {
                verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapCertificateNvIndexStr: ", estc_tapCertificateNvIndexStr);
            }
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapKeyUsage: ", estc_tapKeyUsage);
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapSignScheme: ", estc_tapSignScheme);
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_tapEncScheme: ", estc_tapEncScheme);
#endif
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_keySource: ", estc_keySource);
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_keySize: ", estc_keySize);
            verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_INFO, "estc_hasAttrib: ", estc_hasAttrib);
            verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_conf: ", estc_confFile);

            if (NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD))
            {
                verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "estc_fullcmcReqType: ", est_fullcmcReqType);
            }
        }
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if (useTAP)
    {
        if (OK != (status = DIGI_MALLOC((void**)&g_pEstTapContext, sizeof(EST_TapContext))))
        {
            goto exit;
        }
        if (OK != (status = DIGI_MEMSET((ubyte*)g_pEstTapContext, 0x00, sizeof(EST_TapContext))))
        {
            goto exit;
        }
    }
#endif
    if (OK > (status = HTTP_init()))
    {
        verbosePrintError("\nError in HTTP initialization - ", status);
        goto exit;
    }

    if(!estc_skip_ssl_init)
    {
        if (OK > (status = SSL_init(MAX_SSL_SERVER_CONNECTIONS_ALLOWED, MAX_SSL_CLIENT_CONNECTIONS_ALLOWED)))
        {
            verbosePrintError("\nError in SSL initialization - ", status);
            goto exit;
        }
    }


#ifndef __ENABLE_DIGICERT_AIDE_SERVER__
#ifdef __ENABLE_DIGICERT_TAP__
    /* Register this callback with Crypto Wrapper to get TAPContext.*/
    CRYPTO_INTERFACE_registerTapCtxCallback(EST_EXAMPLE_getTapContext);
    EST_registerTapCtxCallback(EST_EXAMPLE_getTapVariables);

    if (useTAP)
    {
	    /* Initialize */
		if (OK != (status = EST_EXAMPLE_tapInitialize((ubyte*)estc_tap_confFile, g_pEstTapContext)))
		{
			verbosePrintError("\n Error in TAP initilization - ", status);
			goto exit;
		}
    }
#endif
#endif /* __ENABLE_DIGICERT_AIDE_SERVER__ */

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EST, &gHwAccelCtx);
    if (OK != status)
        goto exit;

    if (!estc_genselfsignedcert)
    {
        if (OK > (status = EST_EXAMPLE_initUpcallsAndCertStores()))
        {
            verbosePrintError("\nError in initializing certstore - ", status);
            goto exit;
        }
    }

    if ((0 == DIGI_STRCMP((const sbyte *)estc_ServerURL, (const sbyte*)SIMPLEENROLL_KEYGEN_AND_CSRGEN)))
    {
        /*Special case to handle keygeneration and csr generation of simpleenroll*/
        ubyte *pKeyAlias = NULL;
        ubyte4 keyAliasLen = 0;
        ubyte *pCsrReqBytes = NULL;
        ubyte4 csrReqLen = 0;
        ubyte4 keyType = 0;
        char *pPkiComponentPath  = NULL;
        ubyte *pExtConfigFile = NULL;
        ubyte *pFullPath = NULL;

        if (estc_keyAlias1 != NULL)
        {
            pKeyAlias = estc_keyAlias1;
            keyAliasLen = DIGI_STRLEN((const sbyte*)pKeyAlias);
        }
        else
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }
        keyType = akt_rsa;

#ifdef __ENABLE_DIGICERT_TAP__
        if (useTAP)
            keyType = akt_tap_rsa;
#endif
        if(DIGI_STRCMP((const sbyte *)estc_keyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
        {

            keyType = akt_ecc;
#ifdef __ENABLE_DIGICERT_TAP__
            if (useTAP)
                keyType = akt_tap_ecc;
#endif
        }

        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, CONF_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath(pPkiComponentPath, (const char *)estc_confFile, (char **)&pCsrConfigFile);
        DIGI_FREE((void**)&pPkiComponentPath);
        pExtConfigFile = (ubyte *)estc_extattrs_confFile;

        if (OK > (status = EST_generateCSRRequestFromConfigWithPolicy(MOC_HW(gHwAccelCtx) pCertStore,
                        gSslConnectionInstance,
                        pCsrConfigFile,
                        pExtConfigFile, estc_config_type,
                        pKeyAlias, keyAliasLen, gpPrevAsymKey, keyType,
                        certEnrollAlgUndefined,
                        (ubyte*)estc_digestName, DIGI_STRLEN(estc_digestName),
                        &pCsrReqBytes, &csrReqLen, estc_extEnrollFlow, NULL, NULL)))
        {
            verbosePrintError("Error while creating CSR request - ", status);
            goto exit;
        }

        /* Write CSR to a file */
        pPkiComponentPath = EST_CERT_UTIL_buildKeyStoreFullPath((char *)pPkiDatabase, REQ_PKI_COMPONENT);
        EST_CERT_UTIL_getFullPath((const char*)pPkiComponentPath,
                      (const char *) SIMPLE_ENROLL_CSR_FILE, (char **)&pFullPath);
        verbosePrintStringNL(ESTC_VERBOSE_LEVEL_INFO, "Writing CSR File in PEM format: ", (sbyte *)pFullPath);
        if (OK > (status = DIGICERT_writeFile((const char *) pFullPath, pCsrReqBytes, csrReqLen)))
        {
            verbosePrintStringError("Unable to write CSR data to file", (sbyte *)pFullPath);
            verbosePrintError("\nUnable to write CSR data to file. ", status);
        }
        DIGI_FREE((void**)&pPkiComponentPath);
        DIGI_FREE((void**)&pCsrReqBytes);
        DIGI_FREE((void**)&pFullPath);
    }
    else
    {
        ubyte4 tlsCertLen = ((estc_tlscert != NULL) ? DIGI_STRLEN(estc_tlscert) : 0);

        if ((NULL != strstr((const char *)estc_ServerURL, EST_SIMPLE_REENROLL_CMD)) ||
        ((NULL != strstr((const char *)estc_ServerURL, EST_FULL_CMC_CMD)) &&
         ((DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_RENEW) == 0) ||
         (DIGI_STRCMP(est_fullcmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0))))
        {
            if (TRUE == estc_renewWindowSet)
            {
                /* If the -est_renew_window argument was provided then check
                 * if the rekey/renew/simplereenroll operations need to be
                 * performed.
                 */
                status = EST_checkCertificateRenewWindow(&reOp);
                if (OK != status)
                {
                    verbosePrintError(
                        "Failed to check certificate renew window.", status);
                    goto exit;
                }

                /* If the renewal operation is not required based on the window
                 * then exit.
                 */
                if (FALSE == reOp)
                {
                    verbosePrintNL(
                        ESTC_VERBOSE_LEVEL_DEFAULT,
                        "Certificate renewal operation not required");
                    goto exit;
                }
            }
        }

        while (retryCount < MAX_RETRY_COUNT)
        {
            status = EST_openConnection(pCertStore, (ubyte*)estc_ServerIpAddr, DIGI_STRLEN(estc_ServerIpAddr),
                                estc_ServerPort, (ubyte*)estc_serverName, DIGI_STRLEN(estc_serverName),
                                &gSslConnectionInstance, &gHttpContext, estc_tlscert, tlsCertLen, estc_ocsp_required, FALSE);
            retryCount++;
            if (OK > status)
            {
                if (retryCount == MAX_RETRY_COUNT || ERR_TCP_CONNECT_ERROR != status)
                {
                    verbosePrintError("\nUnable to connect to the server. ", status);
                    goto exit;
                }
                else
                {
                    verbosePrintString1Int1NL(ESTC_VERBOSE_LEVEL_DEFAULT, "WARNING: Retrying initial connection, previous attempt status= ", status);
                }
            }
            else
            {
                break;
            }
        }
        if (OK > (status = EST_EXAMPLE_processRequest()))
        {
            verbosePrintError("\nUnable to process the request. ", status);
            goto exit;
        }
    }

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EST, &gHwAccelCtx);

    /* If the build is for TPLA, let TPLA free the proxy */
#if !defined(__ENABLE_DIGICERT_TRUSTPOINT_LOCAL__) && defined(__ENABLE_DIGICERT_HTTP_PROXY__)
    (void) HTTP_PROXY_freeProxyUrl();
#endif

    if(gHttpContext)
    {
    	if (OK > (status = HTTP_CONTEXT_releaseContext(&gHttpContext)))
    	{
    	    verbosePrintError("\nUnable to release HTTP context. ", status);
    	}
    }

    if (g_pAuthStr)
         DIGI_FREE((void **)&g_pAuthStr);

    if(EST_CONFIG_FILE == estc_config_type)
    {
        DIGI_FREE((void**)&pCsrConfigFile);
    }
    EST_EXAMPLE_freeArgs();
    EST_EXAMPLE_uninitUpcallsAndCertStores();
#ifdef __ENABLE_DIGICERT_TAP__
    if (NULL != g_pEstTapContext)
    {
		if (NULL != g_pEstTapContext->pEntityCredentialList)
		{
			status = TAP_UTILS_clearEntityCredentialList(g_pEstTapContext->pEntityCredentialList);
			if (OK != status)
				verbosePrintError("\nError while clearing TAP entity credentials - ", status);
            DIGI_FREE((void**)&g_pEstTapContext->pEntityCredentialList);
		}

        if (g_pEstTapContext->pKeyCredentialList != NULL)
        {
            int i = 0;
            for (i = 0; i < g_pEstTapContext->pKeyCredentialList->numCredentials; i++)
            {
                if (g_pEstTapContext->pKeyCredentialList->pCredentialList[i].credentialData.pBuffer != NULL)
                    DIGI_FREE((void**)&(g_pEstTapContext->pKeyCredentialList->pCredentialList[i].credentialData.pBuffer));
            }
            DIGI_FREE((void**)&(g_pEstTapContext->pKeyCredentialList->pCredentialList));
            DIGI_FREE((void**)&(g_pEstTapContext->pKeyCredentialList));
        }

        if (OK != (status = EST_EXAMPLE_tapUninitialize(g_pEstTapContext)))
        {
            verbosePrintError("\nError in TAP uninitialze - ", status);
        }
        if (NULL != g_pEstTapContext)
        {
            DIGI_FREE((void**)&g_pEstTapContext);
        }
    }
#endif
    if(!estc_skip_ssl_init)
    {
#ifndef __DISABLE_DIGICERT_STACK_SHUTDOWN__
        if (OK > (status = SSL_shutdownStack()))
        {
            verbosePrintError("\nError in SSL shutdown - ", status);
        }
#endif
    }
    if (OK > (status = HTTP_stop()))
    {
        verbosePrintError("\nError while stopping HTTP - ", status);
    }
#ifndef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
    if(gMocanaAppsRunning)
        gMocanaAppsRunning--;
#endif
#if(defined(__RTOS_WIN32__))
    if (OK > (status = DIGICERT_freeDigicert()))
    {
        verbosePrintError("\n Error in Mocana libraries cleanup - ", status);
        goto exit;
    }
#endif
#if defined( __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__ )
    RTOS_semSignal(g_tpla_sem);
#if defined(__FREERTOS_RTOS__)
    RTOS_destroyThread(NULL);
#endif
#endif /* #if defined( __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__ ) */
    return status;
}

static MSTATUS EST_EXAMPLE_CB_validateRootCertificate(const void* arg,
    CStream cs,
    struct ASN1_ITEM* pCertificate,
    sbyte4 chainLength)
{
    MSTATUS status = OK;
    ubyte* buffer = NULL;
    ubyte* pEncodedCert = NULL;
    ubyte4 encodedCertLen = 0;

    buffer = (ubyte*)CS_memaccess(cs, (/*FSL*/sbyte4)(pCertificate->dataOffset - pCertificate->headerSize),
        (/*FSL*/sbyte4)(pCertificate->length + pCertificate->headerSize));

    if (OK > (status = BASE64_encodeMessage(buffer, pCertificate->length + pCertificate->headerSize,
        &pEncodedCert, &encodedCertLen)))
    {
        verbosePrintError("Unable to encode root certificate.", status);
        goto exit;
    }
    if (!pCertStore)
    {
        if (OK > (status = CERT_STORE_createStore(&pCertStore)))
        {
            verbosePrintError("Unable to create certstore for validating root certificate.", status);
            goto exit;
        }
        if (OK > (status = EST_EXAMPLE_constructCertStoreFromDir(pCertStore)))
        {
            verbosePrintError("Unable to construct certstore for validating root certificate.", status);
            goto exit;
        }
    }
    if (OK > (status = EST_validateReceivedCertificate(MOC_HW(gHwAccelCtx) pCertStore, pEncodedCert, encodedCertLen, NULL)))
    {
        verbosePrintError("Unable to validate certificate.", status);
        goto exit;
    }


exit:
    if (pEncodedCert)
    {
        DIGI_FREE((void **)&pEncodedCert);
    }
    if (buffer)
        CS_stopaccess(cs, buffer);
    return status;
}
