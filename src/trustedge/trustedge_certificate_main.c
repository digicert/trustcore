/**
 * trustedge_certificate_main.c
 *
 * @brief Trustedge key and certificate generation tool
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

#include "../common/moptions.h"
#include "../common/mfmgmt.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mjson.h"
#include "../common/debug_console.h"
#include "../common/msg_logger.h"
#include "../common/mocana.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/arg_parser.h"
#include "../common/common_utils.h"
#include "../common/datetime.h"
#include "../common/mterm.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs_key.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs10.h"
#include "../crypto/cert_store.h"
#include "../asn1/oiddefs.h"
#include "../cert_enroll/cert_enroll.h"

#include <stdio.h>
#include <signal.h>
#include <string.h>

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

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../trustedge/utils/trustedge_tap.h"
#include "../tap/tap_smp.h"
#ifdef __ENABLE_DIGICERT_TEE__
#include "../smp/smp_tee/smp_tap_tee.h"
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
#include "../smp/smp_nanoroot/smp_nanoroot.h"
#include "../tap/tap_common.h"
#endif
#endif

#include "../crypto/tools/crypto_keygen.h"
#include "../trustedge/certificate/trustedge_certificate.h"
#include "../http/http_context.h"
#include "../http/http.h"
#include "../http/http_common.h"
#include "../trustedge/utils/trustedge_utils.h"
#ifndef __DISABLE_TRUSTEDGE_SCEP__
#include "../trustedge/scep/trustedge_scep_defn.h"
#include "../trustedge/scep/trustedge_scep_api.h"
#include "../trustedge/scep/trustedge_scep.h"
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
#include "../trustedge/est/trustedge_est_include.h"
#endif
#ifndef __DISABLE_TRUSTEDGE_REST_API__
#include "../trustedge/trustedge_main.h"
#include "../common/hash_value.h"
#endif


/*----------------------------------------------------------------------------*/

#define TRUSTEDGE_CERTIFICATE_PROG_NAME         "certificate"
#define TRUSTEDGE_CERTIFICATE_SCEP_PROG_NAME    "certificate scep"
#define TRUSTEDGE_CERTIFICATE_LOG_LABEL         "TRUSTEDGE-CERTIFICATE"

#define FORMAT_PEM 0
#define FORMAT_DER 1
#define FORMAT_SSH 2

#define NOT_SPECIFIED (-1)


#ifdef __ENABLE_DIGICERT_PQC__
void SERIALQS_setOqsCompatibleFormat(byteBoolean format);
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
void MLDSA_setLongFormPrivKeyFormat(byteBoolean format);
#endif
#endif

#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
#define TRUSTEDGE_TAP_PROVIDER_NAME ""
#else
#if defined(__ENABLE_DIGICERT_SMP_PKCS11__)
#define TRUSTEDGE_TAP_PROVIDER_NAME " PKCS11"
#elif defined(__ENABLE_DIGICERT_TPM2__)
#define TRUSTEDGE_TAP_PROVIDER_NAME " TPM2"
#elif defined(__ENABLE_DIGICERT_TEE__)
#define TRUSTEDGE_TAP_PROVIDER_NAME " TEE"
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
#define TRUSTEDGE_TAP_PROVIDER_NAME " NanoROOT"
#else
#define KEYGEN_TAP_PROVIDER_NAME ""
#endif
#endif
#endif /* __ENABLE_DIGICERT_TAP__ */

static sbyte *gpKeyStoreDefault = (sbyte *) ".";
#ifdef __ENABLE_DIGICERT_TAP__
static KeyGenTapArgs tapArgs = {0};
#endif
extern RTOS_MUTEX gCertMutex;

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
#define SCEP_REQ_FILE       "scep_request"
#define EST_REQ_FILE        "est_request"
#define PROTOCOL_JSTR       "protocol"

static sbyte *gpKeyAliasDefault = (sbyte *) "GenKey";
extern volatile sig_atomic_t gIsProcessInterrupted;
#endif

#ifndef __DISABLE_TRUSTEDGE_SCEP__
static sbyte *gpScepPkiDefault = (sbyte *) "PKCSReq";
static sbyte *gpScepCepDefaultPem = (sbyte *) "moc_CEP.pem";
static sbyte *gpScepCepDefaultDer = (sbyte *) "moc_CEP.der";
#endif

#ifndef __DISABLE_TRUSTEDGE_EST__
static sbyte *gpReKeyAliasDefault = (sbyte *) "GenReKey";
MSTATUS TRUSTEDGE_EST_utilStrToInt(sbyte *pStr, ubyte8 *pInt);
MSTATUS TRUSTEDGE_EST_main(KeyGenArgs *pKeyArgs, TrustEdgeEstCtx *pEstArgs, TrustEdgeServiceCtx *pSrvCtx, void *pTapArgs);
#endif

#ifndef __DISABLE_TRUSTEDGE_REST_API__
extern TrustEdgeRestApiCtx gRestApiCtx;
#endif

typedef struct
{
    KeyGenArgs keyGenArgs;
    sbyte *pDebugDir;
    MsgLogLevel logLevel;
    byteBoolean exit;
    E_CertEnrollMode mode;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
    TrustEdgeScepCtx scepCtx;
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
    TrustEdgeEstCtx estCtx;
#endif
#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    TrustEdgeServiceCtx srvCtx;
    byteBoolean isInvalidSrvDir;
    funcPtrResourceUpdateHandler pResourceUpdateHandler;
#endif
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    byteBoolean isKeyGenApiOp;
    sbyte *pOutputMode;
#endif
    TrustEdgeConfig *pTEConfig;
    byteBoolean isValidTEConfig;
} TrustEdgecertificateMainCtx;

/*----------------------------------------------------------------------------*/

static RTOS_MUTEX TRUSTEDGE_getCertMutex()
{
    if (NULL == gCertMutex)
    {
        RTOS_mutexCreate(&gCertMutex, 0, 0);
    }

    return gCertMutex;
}

static MSTATUS TRUSTEDGE_getHashIdOrOid(sbyte *pHash, ubyte4 *pHashId, const ubyte **ppOid)
{
#ifndef __DISABLE_TRUSTEDGE_SCEP__
    /* pHashId should not be NULL, ok for ppOid to be null */
    if (NULL != ppOid)
    {
        *ppOid = NULL;
    }
#endif

    if (0 == DIGI_STRCMP(pHash, (sbyte *)"MD5") || 0 == DIGI_STRCMP(pHash, (sbyte *)"md5"))
    {
        *pHashId = ht_md5;
    }
    else if (0 == DIGI_STRCMP(pHash, (sbyte *)"SHA1") || 0 == DIGI_STRCMP(pHash, (sbyte *)"sha1"))
    {
        *pHashId = ht_sha1;
    }
    else if (0 == DIGI_STRCMP(pHash, (sbyte *)"SHA224") || 0 == DIGI_STRCMP(pHash, (sbyte *)"sha224"))
    {
        *pHashId = ht_sha224;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        if (NULL != ppOid)
        {
            *ppOid = sha224_OID;
        }
#endif
    }
    else if (0 == DIGI_STRCMP(pHash, (sbyte *)"SHA256") || 0 == DIGI_STRCMP(pHash, (sbyte *)"sha256"))
    {
        *pHashId = ht_sha256;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        if (NULL != ppOid)
        {
            *ppOid = sha256_OID;
        }
#endif
    }
    else if (0 == DIGI_STRCMP(pHash, (sbyte *)"SHA384") || 0 == DIGI_STRCMP(pHash, (sbyte *)"sha384"))
    {
        *pHashId = ht_sha384;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        if (NULL != ppOid)
        {
            *ppOid = sha384_OID;
        }
#endif
    }
    else if (0 == DIGI_STRCMP(pHash, (sbyte *)"SHA512") || 0 == DIGI_STRCMP(pHash, (sbyte *)"sha512"))
    {
        *pHashId = ht_sha512;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        if (NULL != ppOid)
        {
            *ppOid = sha512_OID;
        }
#endif
    }
    else
    {
        return ERR_INVALID_ARG;
    }

    return OK;
}

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_TRUSTEDGE_EST__
#ifdef __ENABLE_DIGICERT_TAP__
typedef struct
{
    sbyte *pStr;
    ubyte2 value;
} EstStrMapping;

static MSTATUS TRUSTEDGE_EST_convertTapHierarchyString(sbyte *pStr, TAP_TokenId *pValue)
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
        status = TRUSTEDGE_EST_utilStrToInt(pStr, pValue);
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* __DISABLE_TRUSTEDGE_EST__ */

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
static void TRUSTEDGE_certificateDisplayGenericArgs(sbyte *pProg, E_CertEnrollMode mode)
{
    DB_PRINT("Usage: %s [Options]\n", pProg);
    DB_PRINT("\n");
  if (CERT_MODE == mode)
  {
    DB_PRINT("TrustEdge Certificate Mode\n");
  }
  else if (SCEP_MODE == mode)
  {
    DB_PRINT("TrustEdge Certificate SCEP Mode\n");
  }
  else if (EST_MODE == mode)
  {
    DB_PRINT("TrustEdge Certificate EST Mode\n");
  }
    DB_PRINT("\n");
    DB_PRINT("Generic Options:\n");
    DB_PRINT("  -h, --help            Display this help menu\n");
    DB_PRINT("  --log-level           Verbosity level of the message logs\n");
    DB_PRINT("                        Possible values are [NONE | ERROR | WARNING | DEBUG | INFO | VERBOSE]\n");
    DB_PRINT("                        (Default is applied through the trustedge configuration)\n");
#if defined(__ENABLE_DIGICERT_PQC__)
  if (EST_MODE == mode)
  {
    DB_PRINT("  --require-pqc         Enforce usage of PQC algorithms\n");
  }
#endif
    DB_PRINT("  -k, --key-store-path  Path to the keystore used for both input and output files\n");
    DB_PRINT("                        (Default is applied through the trustedge configuration or is \".\")\n");
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_CERTIFICATE_DEBUG_INTERNALS__) && 0
    DB_PRINT("  -dd, --debug-dir      Debug directory where messages are stored\n");
#endif
}
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
static void TRUSTEDGE_certificateDisplayKeyGenArgs(E_CertEnrollMode mode)
{
    DB_PRINT("\n");
    DB_PRINT("Key Generation Options:\n");
    DB_PRINT("  -a, --algorithm       Crypto algorithm type\n");
  if (CERT_MODE == mode)
  {
#if defined(__ENABLE_DIGICERT_PQC__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    DB_PRINT("                        Possible values are [ECC | RSA | DSA | QS | HYBRID ]\n");
#elif defined(__ENABLE_DIGICERT_PQC__)
    DB_PRINT("                        Possible values are [ECC | RSA | QS | HYBRID ]\n");
#elif !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    DB_PRINT("                        Possible values are [ECC | RSA | DSA]\n");
#else
    DB_PRINT("                        Possible values are [ECC | RSA]\n");
#endif
  }
  else if (EST_MODE == mode)
  {
    DB_PRINT("                        Possible values are [ECC | RSA | QS | HYBRID]\n");
  }
  else /* SCEP_MODE */
  {
    DB_PRINT("                        Possible values are [ECC | RSA]\n");
  }
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT("  -t, --tap                [Optional] Generate a hardware-based%s TAP key\n", TRUSTEDGE_TAP_PROVIDER_NAME);
    DB_PRINT("                           If omitted, software-based key is generated\n");
    DB_PRINT("  -tpr, --tap-provider     [Optional] Tap provider\n");
    DB_PRINT("                           Possible values are [TPM2 | PKCS11 | TEE | nanoroot]\n");
    DB_PRINT("                           depending on the build configuration.\n");
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    DB_PRINT("  -ts, --tap-server        [Required with -t/--tap] Tap server address or ip\n");
    DB_PRINT("  -tp, --tap-port          [Optional] Tap server port. (Default is 8277)\n");
#endif
    DB_PRINT("  -tm, --tap-modnum        [Optional] TAP module to use. (Default is 1)\n");
    DB_PRINT("  -tku, --tap-key-usage    [Optional] TAP key usage\n");
    DB_PRINT("                           Possible values are\n");
    DB_PRINT("                           TAP_KEY_USAGE_GENERAL\n");
    DB_PRINT("                           TAP_KEY_USAGE_SIGNING\n");
    DB_PRINT("                           TAP_KEY_USAGE_DECRYPT\n");
    DB_PRINT("                           (Default is TAP_KEY_USAGE_GENERAL)\n");
#ifndef __DISABLE_TRUSTEDGE_EST__
  if (EST_MODE == mode)
  {
    DB_PRINT("                           TAP_KEY_USAGE_ATTESTATION\n");
  }
#endif
    DB_PRINT("  -tss, --tap-sig-scheme   [Optional] Tap key signing scheme\n");
    DB_PRINT("                           Possible values are\n");
    DB_PRINT("                           TAP_SIG_SCHEME_NONE\n");
    DB_PRINT("                           TAP_SIG_SCHEME_PKCS1_5\n");
    DB_PRINT("                           TAP_SIG_SCHEME_PKCS1_5_SHA1\n");
    DB_PRINT("                           TAP_SIG_SCHEME_PKCS1_5_SHA256\n");
  if (EST_MODE != mode)
  {
    DB_PRINT("                           TAP_SIG_SCHEME_PKCS1_5_SHA384\n");
    DB_PRINT("                           TAP_SIG_SCHEME_PKCS1_5_SHA512\n");
  }
    DB_PRINT("                           TAP_SIG_SCHEME_PKCS1_5_DER\n");
  if (EST_MODE != mode)
  {
    DB_PRINT("                           TAP_SIG_SCHEME_PSS\n");
  }
    DB_PRINT("                           TAP_SIG_SCHEME_PSS_SHA1\n");
    DB_PRINT("                           TAP_SIG_SCHEME_PSS_SHA256\n");
  if (EST_MODE != mode)
  {
    DB_PRINT("                           TAP_SIG_SCHEME_PSS_SHA384\n");
    DB_PRINT("                           TAP_SIG_SCHEME_PSS_SHA512\n");
  }
    DB_PRINT("                           TAP_SIG_SCHEME_ECDSA_SHA1\n");
    DB_PRINT("                           TAP_SIG_SCHEME_ECDSA_SHA224\n");
    DB_PRINT("                           TAP_SIG_SCHEME_ECDSA_SHA256\n");
    DB_PRINT("                           TAP_SIG_SCHEME_ECDSA_SHA384\n");
    DB_PRINT("                           TAP_SIG_SCHEME_ECDSA_SHA512\n");
    DB_PRINT("                           (Default is TAP_SIG_SCHEME_NONE)\n");
    DB_PRINT("  -tes, --tap-enc-scheme   [Optional] Tap key encryption scheme\n");
    DB_PRINT("                           Possible values are\n");
    DB_PRINT("                           TAP_ENC_SCHEME_NONE\n");
    DB_PRINT("                           TAP_ENC_SCHEME_PKCS1_5\n");
    DB_PRINT("                           TAP_ENC_SCHEME_OAEP_SHA1\n");
    DB_PRINT("                           TAP_ENC_SCHEME_OAEP_SHA256\n");
  if (EST_MODE != mode)
  {
    DB_PRINT("                           TAP_ENC_SCHEME_OAEP_SHA384\n");
    DB_PRINT("                           TAP_ENC_SCHEME_OAEP_SHA512\n");
  }
    DB_PRINT("                           (Default is TAP_ENC_SCHEME_NONE)\n");
    DB_PRINT("  -tpri, --tap-primary     [Optional] Generate TAP primary key. Default is non-primary key\n");
    DB_PRINT("                           Possible values\n");
    DB_PRINT("                           0 - Generate non-primary key\n");
    DB_PRINT("                           1 - Generate primary key\n");
    DB_PRINT("  -th, --tap-hierarchy     [Optional] Specify hierarchy to generate the TAP key under. Default is dependent on the underlying SMP\n");
    DB_PRINT("                           TPM2 Default - STORAGE\n");
    DB_PRINT("                           Possible values\n");
    DB_PRINT("                           STORAGE\n");
    DB_PRINT("                           ENDORSEMENT\n");
    DB_PRINT("                           PLATFORM\n");
    DB_PRINT("  -tkh, --tap-key-handle   [Optional] Specify handle identifier for the new key.\n");
    DB_PRINT("                           Begin with a leading '0x' if the identifier is hex,\n");
    DB_PRINT("                           otherwise it'll be treated as a string.\n");
    DB_PRINT("  -tknh, --tap-key-nonce-handle   [Optional] Specify handle where key nonce is stored for primary keys\n");
    DB_PRINT("                                  Possible values are 4 byte hexadecimal value starting with 0x\n");
    DB_PRINT("  -tch, --tap-cert-handle  [Optional] Specify handle where issued certificate is stored\n");
    DB_PRINT("                           Possible values are 4 byte hexadecimal value starting with 0x\n");
#ifndef __DISABLE_TRUSTEDGE_EST__
  if (EST_MODE == mode)
  {
    DB_PRINT("  -tde, --tpm2-idevid-enrollment  [Optional] Perform TPM2 IDevID enrollment\n");
    DB_PRINT("  -tae, --tpm2-iak-enrollment     [Optional] Perform TPM2 IAK enrollment\n");
  }
#endif
#endif /* __ENABLE_DIGICERT_TAP__ */
#ifdef __ENABLE_DIGICERT_PQC__
    DB_PRINT("  -c, --curve           [Required for ECC] Elliptic curve type\n");
    DB_PRINT("                        Possible values are [P192 | P224 | P256 | P384 | P521 | CURVE25519 | CURVE448]\n");
  if (SCEP_MODE != mode)
  {
    DB_PRINT("  -g, --pq-alg          [Required for QS or HYBRID] Post-Quantum crypto algorithm type\n");
    DB_PRINT("                        Possible values are\n");
    DB_PRINT("                        MLDSA_44\n");
    DB_PRINT("                        MLDSA_65\n");
    DB_PRINT("                        MLDSA_87\n");
    DB_PRINT("                        SLHDSA_SHA2_128S\n");
    DB_PRINT("                        SLHDSA_SHA2_128F\n");
    DB_PRINT("                        SLHDSA_SHA2_192S\n");
    DB_PRINT("                        SLHDSA_SHA2_192F\n");
    DB_PRINT("                        SLHDSA_SHA2_256S\n");
    DB_PRINT("                        SLHDSA_SHA2_256F\n");
    DB_PRINT("                        SLHDSA_SHAKE_128S\n");
    DB_PRINT("                        SLHDSA_SHAKE_128F\n");
    DB_PRINT("                        SLHDSA_SHAKE_192S\n");
    DB_PRINT("                        SLHDSA_SHAKE_192F\n");
    DB_PRINT("                        SLHDSA_SHAKE_256S\n");
    DB_PRINT("                        SLHDSA_SHAKE_256F\n");
    DB_PRINT("                        \n");
    DB_PRINT("  -qsf, --qs-format-oqs [Optional] Format keys as per oqs format (non-rfc draft compatible)\n");
  }
#else
    DB_PRINT("  -c, --curve           [Required for ECC] Elliptic curve type\n");
    DB_PRINT("                        Possible values are [P192 | P224 | P256 | P384 | P521 | CURVE25519 | CURVE448]\n");
#endif
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
  if (CERT_MODE == mode)
  {
    DB_PRINT("  -s, --size            [Required for RSA or DSA] Key size\n");
    DB_PRINT("                        For RSA: Possible values are in the range [2048 - 8192] and must be a multiple of 128)\n");
    DB_PRINT("                        For DSA: Possible values are [1024 | 2048]\n");
    DB_PRINT("  -q, --q-size          [Required for DSA] Bit size of the prime q\n");
    DB_PRINT("                        Possible values are [160 | 224 | 256]\n");
    DB_PRINT("                        160 is for 1024 primes\n");
    DB_PRINT("                        224 or 256 is for 2048-bit primes\n");
  }
  else
  {
    DB_PRINT("  -s, --size            [Required for RSA] Key size\n");
    DB_PRINT("                        Possible values are in the range [2048 - 8192] and must be a multiple of 128)\n");
  }
#else
    DB_PRINT("  -s, --size            [Required for RSA] Key size\n");
    DB_PRINT("                        Possible values are in the range [2048 - 8192] and must be a multiple of 128)\n");
#endif
  if (EST_MODE != mode)
  {
    DB_PRINT("  -pss, --pss           [Optional] RSA-PSS signing scheme\n");
    DB_PRINT("  -kd, --key-digest     [Optional] Both hash and mgf-hash algorithms for RSA-PSS keys\n");
    DB_PRINT("                        Possible values are [MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512]\n");
    DB_PRINT("  -kslt, --key-salt     [Optional] Salt length in bytes for RSA-PSS keys\n");
    DB_PRINT("                        (Default is the key digest output size in bytes)\n");
  }
}
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
static void TRUSTEDGE_certificateDisplayCsrArgs(E_CertEnrollMode mode)
{ //TODO CLARIFY which digests mean what and where they are used
    DB_PRINT("\n");
    DB_PRINT("Certificate Generation Options:\n");
  if (CERT_MODE == mode)
  {
    DB_PRINT("  -i, --csr-conf        [Required with -x/--x509-cert] CSR configuration file name\n");
    DB_PRINT("                        File must be in \"conf\" folder under the keystore directory.\n");
    DB_PRINT("                        used to generate a certificate for the newly generated key pair\n");
    DB_PRINT("  -d, --digest          [Required with -csr/--cert-sign-req] Digest for the signing algorithm\n");
    DB_PRINT("                        Possible values are [MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512]. If omitted, a default\n");
    DB_PRINT("                        digest will be chosen based on the signing key size\n");
  }
  else
  {
    DB_PRINT("  -i, --csr-conf        [Required] CSR configuration file name\n");
    DB_PRINT("                        File must be in \"conf\" folder under the keystore directory.\n");
  }
  if (SCEP_MODE == mode)
  {
    DB_PRINT("  -d, --digest          [Optional] Digest for SCEP\n");
    DB_PRINT("                        Possible values are [SHA224 | SHA256 | SHA384 | SHA512]. (Default is SHA256)\n");
  }
  if (EST_MODE != mode)
  {
    DB_PRINT("  -slt, --salt          [Optional] Salt length in bytes for RSA-PSS signing keys\n");
    DB_PRINT("                        (Default is the digest output size in bytes)\n");
    DB_PRINT("  -da, --days           [Optional] Number of days for which a generated certificate\n");
    DB_PRINT("                        is valid. (Default is from today)\n");
    DB_PRINT("  -sd, --start-date     [Optional] Starting date for a generated certificate, MMDDYYYY format\n");
    DB_PRINT("                        (Default is today)\n");
  }
  if (CERT_MODE == mode)
  {
    DB_PRINT("  -sc, --signing-cert   [Optional] Signing certificate. If omitted, the generated certificate\n");
    DB_PRINT("                        will be self-signed\n");
    DB_PRINT("  -sk, --signing-key    [Required with -csr/--cert-sign-req] Signing key. If omitted, the generated\n");
    DB_PRINT("                        certificate will be self-signed\n");
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT("  -skt, --signing-key-tap [Optional] Must be provided if signing key (-sk) is a Tap key\n");
#endif
    DB_PRINT("  -skp, --signing-key-pw  [Optional] Prompt user for the signing key's password\n");
    DB_PRINT("  -csr, --cert-sign-req   [Optional] Create a signed CSR from a signing key, and input csr or input cert\n");
    DB_PRINT("  -if, --input-form       [Optional] Format of the signing certificate and key\n");
    DB_PRINT("                          Possible values are [PEM | DER]. (Default is PEM)\n");
  }
  else if (SCEP_MODE == mode)
  {
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT("  -skt, --signing-key-tap [Optional] Must be provided if signing key (-sk) is a Tap key\n");
#endif
    DB_PRINT("  -okp, --original-key-pw [Optional] Prompt user for the original key's password\n");
    DB_PRINT("  -if, --input-form       [Optional] Format of the certificates and keys\n");
    DB_PRINT("                          Possible values are [PEM | DER]. (Default is PEM)\n");
  }
}
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
static void TRUSTEDGE_certificateDisplayOutputArgs(E_CertEnrollMode mode)
{
    DB_PRINT("\n");
    DB_PRINT("Output Options:\n");
  if (SCEP_MODE == mode)
  {
    DB_PRINT("  -ka, --key-alias      [Optional] Alias for keys, certs and files placed in the keystore\n");
    DB_PRINT("                        (Default is GenKey)\n");
  }
  else if (EST_MODE == mode)
  {
    DB_PRINT("  -ka, --key-alias      [Optional] Alias for keys, certs and files placed in the keystore. (Default is GenKey)\n");
    DB_PRINT("                        In case of FullCMC and simplereenroll, key alias to be used for CSR signing\n");
    DB_PRINT("                        Key must be in \"keys\" folder and certificate must be in \"certs\" folder\n");
  }
  else
  {
    DB_PRINT("  -o, --output-file     [Optional] Output file name\n");
    DB_PRINT("  -u, --output-pub-file [Optional] Path to public key output file to be generated\n");
    DB_PRINT("  -x, --x509-cert       [Optional] Path to the certificate to be generated using the input CSR file\n");
  }
  if (EST_MODE != mode)
  {
    DB_PRINT("  -p12, --pkcs12          [Optional] Path to the pkcs12 PFX file to be generated containing\n");
    DB_PRINT("                          the certificate and key pair. Options -x, -i and -da must be given\n");
    DB_PRINT("                          Output format for this file is always DER\n");
  }
  else
  {
    DB_PRINT("  -p12, --pkcs12          [Optional] Output a PKCS12 file with the issued key and certificate\n");
    DB_PRINT("                             0 - Do not output a PKCS12 file (Default)\n");
    DB_PRINT("                             1 - Generate PKCS12 file\n");
  }
    DB_PRINT("  -p12e, --pkcs12-encryption-type [Optional] Encryption type for PKCS12 file\n");
    DB_PRINT("                                  Possible values are\n");
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
    DB_PRINT("                                  sha_2des\n");
#endif
    DB_PRINT("                                  sha_3des\n");
#ifdef __ENABLE_ARC2_CIPHERS__
    DB_PRINT("                                  sha_rc2_40\n");
    DB_PRINT("                                  sha_rc2_128\n");
#endif
    DB_PRINT("                                  sha_rc4_40\n");
    DB_PRINT("                                  sha_rc4_128\n");
    DB_PRINT("                                  (Default is sha_3des)\n");
  if (EST_MODE != mode)
  {
    DB_PRINT("  -p12i, --pkcs12-integrity-pw    [Optional] Prompt user for the pkcs12 integrity password\n");
    DB_PRINT("  -p12p, --pkcs12-privacy-pw      [Optional] Prompt user for the pkcs12 privacy password\n");
    DB_PRINT("  -p12k, --pkcs12-key-pw          [Optional] Prompt user for the pkcs12 key password\n");
  }
  else
  {
    DB_PRINT("  -p12i, --pkcs12-integrity-pw    [Optional] Provide integrity password for PKCS12 file. Only used when -p12/--pkcs12\n");
    DB_PRINT("                                  is provided (must be at least 4 characters). It will generate a PKCS12 file with a mac\n");
    DB_PRINT("  -p12p, --pkcs12-privacy-pw      [Optional] Provide privacy password for PKCS12 file. Only used when -p12/--pkcs12\n");
    DB_PRINT("                                  is provided (must be at least 4 characters). It will protect any data output to the pkcs12 file\n");
    DB_PRINT("  -p12k, --pkcs12-key-pw          [Optional] Provide private key password for keys stored in the PKCS12 file. Only used when\n");
    DB_PRINT("                                  -p12/--pkcs12 is provided (must be at least 4 characters). It will protect the private key\n");
    DB_PRINT("                                  stored in the PKCS12 file.\n");
  }
  if (CERT_MODE == mode)
  {
    DB_PRINT("  -f, --output-form     [Optional] If omitted, the output file(s) will be generated in PEM format\n");
    DB_PRINT("                        Possible values are [PEM | DER | SSH]\n");
    DB_PRINT("                        For SSH: private key (and generated certificate) will be in PEM format and \n");
    DB_PRINT("                        public key will be in SSH format\n");
  }
  else if (SCEP_MODE == mode)
  {
    DB_PRINT("  -f, --output-form     [Optional] If omitted, output file(s) will be generated in PEM format\n");
    DB_PRINT("                        Possible values are [PEM | DER]\n");
  }
  if (EST_MODE == mode)
  {
    DB_PRINT("  -p, --protect         [Optional] Prompts user for password to protect the key. For SW (non-TAP) keys this provides PKCS8 password\n");
    DB_PRINT("                        Without any argument this flag prompts for the passowrd. Password can also be provided on the CLI as argument\n");
    DB_PRINT("                        and then must be prefixed with pw: i.e., pw:secret_password\n");
    DB_PRINT("  -p8a, --pkcs8-enc-alg PKCS8 encryption algorithm. Only used when -p/--protect is provided. This option is not\n");
    DB_PRINT("                        valid with TAP keys\n");
    DB_PRINT("                        Possible values are\n");
#if defined(__ENABLE_DIGICERT_PKCS5__)
#if defined(__ENABLE_DES_CIPHER__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V1_SHA1_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V1_SHA1_RC2 "\n");
#endif
#if defined(__ENABLE_DES_CIPHER__) && defined(__ENABLE_DIGICERT_MD2__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V1_MD2_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V1_MD2_RC2 "\n");
#endif
#if defined(__ENABLE_DES_CIPHER__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V1_MD5_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V1_MD5_RC2 "\n");
#endif
#if !defined(__DISABLE_3DES_CIPHERS__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V2_3DES "\n");
#endif
#if defined(__ENABLE_DES_CIPHER__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V2_DES "\n");
#endif
#if defined(__ENABLE_ARC2_CIPHERS__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V2_RC2 "\n");
#endif
#if !defined(__DISABLE_AES_CIPHERS__)
#if !defined(__DISABLE_AES128_CIPHER__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V2_AES128 "\n");
#endif
#if !defined(__DISABLE_AES192_CIPHER__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V2_AES192 "\n");
#endif
#if !defined(__DISABLE_AES256_CIPHER__)
    DB_PRINT("                        " PKCS8_ENC_ALG_P5_V2_AES256 "\n");
#endif
#endif /* !defined(__DISABLE_AES_CIPHERS__) */
#endif /*  __ENABLE_DIGICERT_PKCS5__  */
    DB_PRINT("                        (Default is " PKCS8_ENC_ALG_DEFAULT  ")\n");
  }
  else
  {
#ifdef __ENABLE_DIGICERT_TAP__
    DB_PRINT("  -p, --protect         [Optional] Prompt user for PKCS8 password to protect the new TAP or software key\n");
#else
    DB_PRINT("  -p, --protect         [Optional] Promt user for PKCS8 password to protect the private/public key pair\n");
    DB_PRINT("                        for PEM or SSH output formats\n");
#endif
  }
#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
  DB_PRINT(" -pc, --print-cert [Optional] Print a certificate or CSR in readable form. Follow with it path and name of existing certificate or CSR\n");
#endif
}
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__) && !defined(__DISABLE_TRUSTEDGE_SCEP__)
static void TRUSTEDGE_certificateDisplayScepArgs(void)
{
    DB_PRINT("\n");
    DB_PRINT("SCEP Options:\n");
	DB_PRINT("  -sco, --scepc-pkiOperation   [Required] Specifies the pkioperation\n");
    DB_PRINT("                               Possible values are [PKCSReq | RenewalReq | RekeyReq | GetCACert | GetCACaps]\n");
    DB_PRINT("                               (Default is PKCSReq)\n");
    DB_PRINT("  -scu, --scepc-serverURL      [Required] SCEP server url\n");
    DB_PRINT("  -sct, --scepc-serverType     [Optional] SCEP server type\n");
    DB_PRINT("                               Possible values are [MOC | EJBCA | ECDSA | WIN2003 | WIN2008 | WIN2012 | WIN2016 | GEN_GET | GEN_POST]\n");
    DB_PRINT("                               (Default is MOC)\n");
    DB_PRINT("  -scp, --scepc-challengePass  [Required] SCEP challenge password\n");
    DB_PRINT("  -sca, --scepc-encalgo        [Optional] Symmetric key encryption algorithm for SCEP\n");
    DB_PRINT("                               Possible values are [desEDE3CBC | aes128CBC | aes192CBC | aes256CBC]\n");
    DB_PRINT("                               (Default is desEDE3CBC)\n");
    DB_PRINT("  -scd, --scepc-digest         [Optional] Digest Algorithm for SCEP encryption steps\n");
    DB_PRINT("  -scoa, --scepc-oaep          [Optional] Use OAEP for RSA pkcs7 encryption. (Default is SHA256)\n");
    DB_PRINT("  -scod, --scepc-oaepDigest    [Optional] Digest for OAEP encrption steps. (Default is SHA256)\n");
    DB_PRINT("  -scl, --scepc-label          [Optional] Label for OAEP encryption\n");
    DB_PRINT("  -scce, --scepc-cepcert       [Optional] CEP Cert Filename\n");
    DB_PRINT("                               (Default is moc_CEP.<pem|der>)\n");
}
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__) && defined(__ENABLE_DIGICERT_CV_CERT__)
static void TRUSTEDGE_certificateDisplayCvcArgs(void)
{
    DB_PRINT("\n");
    DB_PRINT("Card Verifiable Certificate Options:\n");
    DB_PRINT("  -cvc, --cv-cert         [Optional] Path to the CV certificate to be generated\n");
    DB_PRINT("  -cve, --cv-eff-date     [Required with -cv/--cv-cert] CV certificate's effective date in YYMMDD format\n");
    DB_PRINT("  -cvo, --cv-country-code [Optional] CV certificate's country code. (Default is US)\n");
    DB_PRINT("  -cvm, --cv-mnemonic     [Required with -cv/--cv-cert] CV certificate's mnemonic\n");
    DB_PRINT("  -cvs, --cv-seqnum       [Required with -cv/--cv-cert] CV certificate's sequence number\n");
    DB_PRINT("  -cva, --cv-holder-auth-temp [Required with -cv/--cv-cert] CV certificate's holder auth template\n");
    DB_PRINT("  -cvx, --cv-extensions   [Optional] CV certificate's extensions in CV serialized form\n");
    DB_PRINT("  -pcvc, --print-cvcert   [Optional] Print certificate in readable form. Follow with it path and name of existing cert\n");
}
#endif

/*----------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__) && !defined(__DISABLE_TRUSTEDGE_EST__)
static void TRUSTEDGE_certificateDisplayEstArgs(void)
{
    DB_PRINT("\n");
    DB_PRINT("EST Options:\n");
    DB_PRINT("  --uri                                     [Required] Complete EST endpoint URL\n");
    DB_PRINT("  -host, --estc-server-dn                   [Required if --uri is not provided] The EST server's distinguished name\n");
    DB_PRINT("  -url, --estc-server-url                   [Required if --uri is not provided] The EST operation URL path. Possible values are\n");
    DB_PRINT("                                               /.well-known/est/<groupid/policyid>/cacerts\n");
    DB_PRINT("                                               /.well-known/est/<groupid/policyid>/simpleenroll\n");
    DB_PRINT("                                               /.well-known/est/<groupid/policyid>/simplereenroll\n");
    DB_PRINT("                                               /.well-known/est/<groupid/policyid>/serverkeygen\n");
    DB_PRINT("                                               /.well-known/est/<groupid/policyid>/fullcmc\n");
    DB_PRINT("                                               /.well-known/est/<groupid/policyid>/csrattrs\n");
    DB_PRINT("  -user, --estc-user                        [Optional] The HTTP authentication username\n");
    DB_PRINT("  -pass, --estc-pass                        [Required] The HTTP authentication password\n");
    DB_PRINT("  -ip, --estc-server-ip                     [Optional] The EST server's IP address\n");
    DB_PRINT("                                            If provided, dns resolution of server's FQDN will be skipped\n");
    DB_PRINT("  -port, --estc-server-port                 [Optional] The EST server's listening port\n");
    DB_PRINT("  -authscheme, --estc-authentication-mode   [Optional] Authentication mechanism to use\n");
    DB_PRINT("                                            Possible values are [BASIC | DIGEST]\n");
    DB_PRINT("  -noverify, --estc-disable-ca-cert         [Optional] Flag to disable validating the issued certificate against the certificate store\n");
#if 0
    DB_PRINT("  -extattr, --estc-ext-attrs-conf           [Optional] Config file containing Extended CSR attributes\n");
    DB_PRINT("                                            File must be in \"conf\" folder under the keystore directory.\n");
#endif
    DB_PRINT("  -hash, --estc-digest-algo                 [Optional] Digest algorithm to use\n");
    DB_PRINT("                                            Possible values are  [SHA1 | SHA224 | SHA256 | SHA384 | SHA512]\n");
    DB_PRINT("  -mtls, --estc-tls-cert                    [Optional] Alias of mutual authentication key and certificate\n");
    DB_PRINT("                                            Key must be in \"keys\" folder and certificate must be in \"certs\" folder\n");
    DB_PRINT("  -caprefix, --estc-cacerts-alias           [Optional] Alias of EST CA certificates\n");
    DB_PRINT("                                            This alias will be prepended to the truncated sha1 fingerprint of the downloaded certificates\n");
#if 0
    DB_PRINT("                                            In case of FullCMC, file must be in \"keys\" folder under the keystore directory.\n");
    DB_PRINT("  -rktype, --estc-rekey-type                [Optional] Rekey type (used with FullCMC re-key operation). Possible values are [RSA | ECDSA]\n");
    DB_PRINT("  -rksize, --estc-rekey-size                [Optional] Rekey size (used with FullCMC re-key operation)\n");
#endif
    DB_PRINT("  -renewdays, --estc-renew-window           [Optional] Number of days to check against the certificate when performing a renew, rekey\n");
    DB_PRINT("                                            or simplereenroll operation. If the certificate is expired or if the certificate\n");
    DB_PRINT("                                            will expire within the number of days specified then the renew, rekey, or\n");
    DB_PRINT("                                            simplereenroll is performed. Maximum window is %d days\n", ESTC_MAX_RENEW_WINDOW_SIZE);
    DB_PRINT("  -cmcreq, --estc-full-cmc-req-type         [Optional] FullCMC operation type. Possible values are [enroll | renew | rekey]\n");
    DB_PRINT("                                            Default is enroll\n");
    DB_PRINT("  -rkalias, --estc-rekey-alias              [Optional] Alias of rekey in the cert store (used with FullCMC rekey or simplereenroll operation)\n");
#if 0
    DB_PRINT("  -psk, --estc-psk-alias                    [Optional] Pre-shared key to load in cert store\n");
    DB_PRINT("                                            File must be in \"psks\" folder under the keystore directory with no whitespaces in the name\n");
    DB_PRINT("  -skgcrt, --estc-skg-client-cert           [Optional] Client certificate to load in cert store (used with ServerKeyGen operation)\n");
    DB_PRINT("                                            File must be in \"certs\" folder under the keystore directory\n");
    DB_PRINT("  -skgkey, --estc-skg-client-key            [Optional] Client key to load in cert store (used with ServerKeyGen operation)\n");
    DB_PRINT("                                            File must be in /keys folder under the keystore directory\n");
    DB_PRINT("  -skgalg, --estc-skg-algorithm             [Optional] Encryption algorithm used for ServerKeyGen operation\n");
    DB_PRINT("                                            Possible values are [aes192 | 3des]\n");
    DB_PRINT("  -inlinecrt, --estc-renew-inline-cert      [Optional] Whether to add old certificate in renew CSR\n");
    DB_PRINT("                                               1 - Add old certificate in CSR\n");
    DB_PRINT("                                               0 - Don't add old certificate in CSR\n");
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    DB_PRINT("  -ocsp, --estc-ocsp-required               [Optional] Check for an OCSP response from the server\n");
    DB_PRINT("                                               0 - Do not send an OCSP status request to the server\n");
    DB_PRINT("                                               1 - Send an OCSP status request to the server and enforce that it is provided\n");
#endif
#endif
    DB_PRINT("\n");
    return;
}
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
static void TRUSTEDGE_certificateDisplayHelp(
    sbyte *pProg, E_CertEnrollMode mode)
{
    TRUSTEDGE_certificateDisplayGenericArgs(pProg, mode);
    TRUSTEDGE_certificateDisplayKeyGenArgs(mode);
    TRUSTEDGE_certificateDisplayCsrArgs(mode);
#ifdef __ENABLE_DIGICERT_CV_CERT__
    TRUSTEDGE_certificateDisplayCvcArgs();
#endif
#ifndef __DISABLE_TRUSTEDGE_SCEP__
    if (SCEP_MODE == mode)
    {
        TRUSTEDGE_certificateDisplayScepArgs();
    }
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
    if (EST_MODE == mode)
    {
        TRUSTEDGE_certificateDisplayEstArgs();
    }
#endif
    TRUSTEDGE_certificateDisplayOutputArgs(mode);
}
#endif

static MSTATUS TRUSTEDGE_certificateMainProcessArgs(
    int argc,
    sbyte *ppArgv[],
    TrustEdgecertificateMainCtx *pMainCtx)
{
    MSTATUS status = OK;
    int i;
    /* make a simple local copy of the actual arg structs */
    KeyGenArgs *pArgs = &pMainCtx->keyGenArgs;
    FileDescriptorInfo fileInfo;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
    TrustEdgeScepCtx *pScepArgs = &pMainCtx->scepCtx;
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
    sbyte *pTemp, *pEnd;
    TrustEdgeEstCtx *pEstArgs = &pMainCtx->estCtx;
    pEstArgs->pKeySource = KEY_SOURCE_SW;
    pEstArgs->pUserAgent = "TrustEdge";
    pEstArgs->estEndpointProvided = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_CV_CERT__
    ubyte4 numReqArg = 0;
#endif

    pMainCtx->exit = TRUE;

#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (TRUE == pMainCtx->isKeyGenApiOp)
    {
        goto skip_validations;
    }
#endif

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    if ((FALSE == pScepArgs->serviceCtx.serviceMode) && (FALSE == pEstArgs->serviceCtx.serviceMode))
    {
#endif
        if (0 == argc || 1 == argc)
        {
            status = ERR_TRUSTEDGE_CERTIFICATE_NO_ARG;
#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
            TRUSTEDGE_certificateDisplayHelp(1 == argc ? ppArgv[0] : (sbyte *) TRUSTEDGE_CERTIFICATE_PROG_NAME, pMainCtx->mode);
#endif
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "No arguments provided, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    }
    else if (argc < 2)
    {
        goto skip_validations;
    }
#endif

    /* Process user provided arguments */
    for (i = 1; i < argc; i++)
    {
#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
        if ((TRUE == pMainCtx->scepCtx.serviceCtx.serviceMode) && (argc > 1))
        {
            status = ERR_INVALID_INPUT;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "--daemon has to be the only argument, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#endif /* !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__) */
        if (0 == DIGI_STRCMP((sbyte *) "--log-level", ppArgv[i]))
        {
            i++;
            continue;
        }
#ifndef __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *) "--help") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *) "-h") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *) "?"))
        {
            TRUSTEDGE_certificateDisplayHelp(ppArgv[0], pMainCtx->mode);
            goto exit;
        }
#endif
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_CERTIFICATE_DEBUG_INTERNALS__) || defined(__ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__)
        else if (0 == DIGI_STRCMP((sbyte *) "--debug-dir", ppArgv[i]) || 0 == DIGI_STRCMP((sbyte *) "-dd", ppArgv[i]))
        {
            status = ARG_PARSER_getStringValue(
                (char **) ppArgv, argc, &i, &pMainCtx->pDebugDir);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "Unable to process debug directory argument, status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
#endif /* __ENABLE_DIGICERT_TRUSTEDGE_CERTIFICATE_DEBUG_INTERNALS__ || __ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__ */
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-a") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--algorithm"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"ECC") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"ecc"))
                {
                    pArgs->gKeyType = akt_ecc; /* Note, key creation method will know to change this to akt_ecc_ed if need be */
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pKeyType = KEY_TYPE_ECDSA;
#ifdef __ENABLE_DIGICERT_TAP__
                        if (TRUE == pArgs->gTap)
                        {
                            pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                        }
#endif
                    }
#endif
                }
                else if(0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"RSA") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"rsa"))
                {
                    pArgs->gKeyType = akt_rsa;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pKeyType = KEY_TYPE_RSA;
                    }
#endif
                }
#ifdef __ENABLE_DIGICERT_PQC__
                else if((SCEP_MODE != pMainCtx->mode) && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"QS") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"qs")))
                {
                    pArgs->gKeyType = akt_qs;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pKeyType = KEY_TYPE_QS;
                    }
#endif
                }
                else if((SCEP_MODE != pMainCtx->mode) && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"HYBRID") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"hybrid")))
                {
                    pArgs->gKeyType = akt_hybrid;
                }
#endif
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
                else if((CERT_MODE == pMainCtx->mode) && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"DSA") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"dsa")))
                {
                    pArgs->gKeyType = akt_dsa;
                }
#endif
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -a or --algorithm option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-o") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--output-file"))
        {
            if (++i < argc)
            {
                pArgs->gpOutFile = ppArgv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-k") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--key-store-path"))
        {
            if (++i < argc)
            {
                pArgs->gpKeyStorePath = ppArgv[i];
            }
            continue;
        }
#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-ka") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--key-alias"))
        {
            if (++i < argc)
            {
                if (SCEP_MODE == pMainCtx->mode)
                {
                    pScepArgs->pKeyAlias = ppArgv[i];
                }
                else if (EST_MODE == pMainCtx->mode)
                {
                    pEstArgs->pKeyAlias = ppArgv[i];
                }
            }
            continue;
        }
#endif
#ifdef __ENABLE_DIGICERT_TAP__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-t") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap"))
        {
            pArgs->gTap = TRUE;
#ifdef __ENABLE_DIGICERT_TEE__
            pArgs->gTapProvider = TAP_PROVIDER_TEE;
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode)
            {
                pEstArgs->pKeySource = KEY_SOURCE_TEE;
                pEstArgs->useTEE = 1;
            }
#endif
#elif __ENABLE_DIGICERT_SMP_NANOROOT__
            pArgs->gTapProvider = TAP_PROVIDER_NANOROOT;
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode)
            {
                pEstArgs->pKeySource = KEY_SOURCE_NANOROOT;
                pEstArgs->useNanoRoot = 1;
            }
#endif
#else
            pArgs->gTapProvider = TAP_PROVIDER_TPM2;
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode)
            {
                if (0 == DIGI_STRCMP(pEstArgs->pKeySource, KEY_SOURCE_TPM2))
                {
                    pEstArgs->pKeySource = KEY_SOURCE_TPM2;
                }
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
                else if (0 == DIGI_STRCMP(pEstArgs->pKeySource, KEY_SOURCE_PKCS11))
                {
                    pEstArgs->pKeySource = KEY_SOURCE_PKCS11;
                }
#endif
                if (0 == DIGI_STRCMP(pEstArgs->pKeyType, KEY_TYPE_ECDSA))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
            }
#endif
#endif /* else of __ENABLE_DIGICERT_TEE__ */
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tm") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-modnum"))
        {
            if (++i < argc)
            {
                pArgs->gModNum = (ubyte4) DIGI_ATOL(ppArgv[i], NULL);
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-ts") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-server"))
        {
            if (++i < argc)
            {
                pArgs->gpServer = ppArgv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tp") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-port"))
        {
            if (++i < argc)
            {
                pArgs->gPort = (ubyte4) DIGI_ATOL(ppArgv[i], NULL);
            }
            continue;
        }
#endif
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tpr") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-provider"))
        {
            if (++i < argc)
            {
#ifdef __ENABLE_DIGICERT_TEE__
                /* pArgs->gTapProvider is already set to TAP_PROVIDER_TEE, just make sure they don't try to change it */
                if (!(0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TEE") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"tee")))
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -tpr or --tap-provider option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
#elif __ENABLE_DIGICERT_SMP_NANOROOT__
                /* pArgs->gTapProvider is already set to TAP_PROVIDER_NANOROOT, just make sure they don't try to change it */
                if (!(0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"NANOROOT") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"nanoroot") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"NanoRoot") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"NanoROOT")))
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -tpr or --tap-provider option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
#else
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TPM2") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"tpm2"))
                {
                    pArgs->gTapProvider = TAP_PROVIDER_TPM2;
                }
#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"PKCS11") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"pkcs11"))
                {
                    pArgs->gTapProvider = TAP_PROVIDER_PKCS11;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pKeySource = KEY_SOURCE_PKCS11;
                    }
#endif
                }
#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */
                /* else leave default */
#endif /* __ENABLE_DIGICERT_TEE__ */
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tku") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-key-usage"))
        {
            if (++i < argc)
            {
                /* gKeyUsage already TAP_KEY_USAGE_GENERAL by default */
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_KEY_USAGE_SIGNING"))
                {
                    pArgs->gKeyUsage = TAP_KEY_USAGE_SIGNING;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_KEY_USAGE_DECRYPT"))
                {
                    pArgs->gKeyUsage = TAP_KEY_USAGE_DECRYPT;
                }
#ifndef __DISABLE_TRUSTEDGE_EST__
                else if (EST_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_KEY_USAGE_ATTESTATION"))
                {
                    pArgs->gKeyUsage = TAP_KEY_USAGE_ATTESTATION;
                }
#endif
                else if (0 != DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_KEY_USAGE_GENERAL"))
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -tku or --tap-key-usage option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tss") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-sig-scheme"))
        {
            if (++i < argc)
            {
                /* gSigScheme already TAP_SIG_SCHEME_NONE by default */
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PKCS1_5"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA1"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA256"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA384"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA512"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_DER"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PSS"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PSS_SHA1"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA1;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PSS_SHA256"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA256;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PSS_SHA384"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA384;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_PSS_SHA512"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_PSS_SHA512;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA1"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA224"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA256"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA384"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA512"))
                {
                    pArgs->gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                }
                else if (0 != DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_SIG_SCHEME_NONE"))
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -tss or --tap-sig-scheme option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tes") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-enc-scheme"))
        {
            if (++i < argc)
            {
                /* gEncScheme already TAP_ENC_SCHEME_NONE by default */
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_ENC_SCHEME_PKCS1_5"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA1"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA256"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA384"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA512"))
                {
                    pArgs->gEncScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                }
                else if (0 != DIGI_STRCMP(ppArgv[i], (sbyte *)"TAP_ENC_SCHEME_NONE"))
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -tes or --tap-enc-scheme option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tpri")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-primary"))))
        {
            if (++i < argc)
            {
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == pMainCtx->mode)
                {
                    pTemp = ppArgv[i];
                    pEstArgs->tapKeyPrimary = (intBoolean) DIGI_ATOL((const sbyte *) pTemp, NULL);
                }
                else
#endif
                {
                    status = ERR_NOT_IMPLEMENTED;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Argument -tpri or --tap-primary not supported option: %s, status = %s (%d)\n", ppArgv[i],
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-th")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-hierarchy"))))
        {
            if (++i < argc)
            {
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == pMainCtx->mode)
                {
                    pEstArgs->pTapKeyTokenHierarchy = ppArgv[i];
                    pEstArgs->tapTokenHierarchySet = TRUE;
                }
                else
#endif
                {
                    status = ERR_NOT_IMPLEMENTED;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Argument -tpri or --tap-primary not supported option: %s, status = %s (%d)\n", ppArgv[i],
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tkh")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-key-handle"))))
        {
            if (++i < argc)
            {
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == pMainCtx->mode)
                {
                    pEstArgs->pTapKeyHandleStr = ppArgv[i];
                    status = KEYGEN_readId((sbyte *) pEstArgs->pTapKeyHandleStr, &pEstArgs->tapKeyHandle, &pEstArgs->isIdHex);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key handle, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                    pEstArgs->tapKeyHandleSet = TRUE;
                }
                else
#endif
#ifdef __ENABLE_DIGICERT_TEE__
                {
                    status = KEYGEN_readId((sbyte *) ppArgv[i], &pArgs->tapKeyHandle, NULL);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -tkh or --tap-key-handle option: %s, status = %s (%d)\n", ppArgv[i],
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
#else
                {
                    status = ERR_NOT_IMPLEMENTED;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Argument -tkh or --tap-key-handle not supported option: %s, status = %s (%d)\n", ppArgv[i],
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
#endif /* __ENABLE_DIGICERT_TEE__ */
            }
            continue;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tknh")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-key-nonce-handle"))))
        {
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode)
            {
                if (++i < argc)
                {
                    pEstArgs->pTapKeyNonceNvIndex = ppArgv[i];
                    pEstArgs->tapKeyNonceNvIndexSet = TRUE;
                }
            }
            else
#endif
            {
                status = ERR_NOT_IMPLEMENTED;
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Argument -tknh or --tap-key-nonce-handle not supported option: %s, status = %s (%d)\n", ppArgv[i],
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
            continue;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tch")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tap-cert-handle"))))
        {
            if (++i < argc)
            {
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == pMainCtx->mode)
                {
                    pEstArgs->pTapCertificateNvIndexStr = ppArgv[i];
                    status = TRUSTEDGE_EST_utilStrToInt(
                        pEstArgs->pTapCertificateNvIndexStr, &pEstArgs->tapCertificateNvIndex);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process certificate NV index, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                    pEstArgs->tapCertificateNvIndexSet = TRUE;
                }
                else
#endif
                {
                    status = ERR_NOT_IMPLEMENTED;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Argument -tch or --tap-cert-handle not supported option: %s, status = %s (%d)\n", ppArgv[i],
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tde")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tpm2-idevid-enrollment"))))
        {
            pEstArgs->flow = EXT_ENROLL_FLOW_TPM2_IDEVID;
        }
        else if (((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-tae")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--tpm2-iak-enrollment"))))
        {
            pEstArgs->flow = EXT_ENROLL_FLOW_TPM2_IAK;
        }
#endif
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-c") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--curve"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"P192") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"p192"))
                {
                    pArgs->gCurve = cid_EC_P192;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"P224") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"p224"))
                {
                    pArgs->gCurve = cid_EC_P224;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->usKeySize = 224;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"P256") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"p256"))
                {
                    pArgs->gCurve = cid_EC_P256;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->usKeySize = 256;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"P384") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"p384"))
                {
                    pArgs->gCurve = cid_EC_P384;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->usKeySize = 384;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"P521") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"p521"))
                {
                    pArgs->gCurve = cid_EC_P521;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->usKeySize = 521;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"curve25519") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"CURVE25519"))
                {
                    pArgs->gCurve = cid_EC_Ed25519;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->usKeySize = 255;
                        pEstArgs->pKeyType = KEY_TYPE_EDDSA;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"curve448") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"CURVE448"))
                {
                    pArgs->gCurve = cid_EC_Ed448;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->usKeySize = 448;
                        pEstArgs->pKeyType = KEY_TYPE_EDDSA;
                    }
#endif
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -c or --curve option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-g") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pq-alg"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"MLDSA_44"))
                {
                    pArgs->gQsAlg = cid_PQC_MLDSA_44;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"MLDSA_65"))
                {
                    pArgs->gQsAlg = cid_PQC_MLDSA_65;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"MLDSA_87"))
                {
                    pArgs->gQsAlg = cid_PQC_MLDSA_87;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"FNDSA_512"))
                {
                    pArgs->gQsAlg = cid_PQC_FNDSA_512;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"FNDSA_1024"))
                {
                    pArgs->gQsAlg = cid_PQC_FNDSA_1024;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHA2_128S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_128S;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHA2_192S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_192S;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHA2_256S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_256S;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHA2_128F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_128F;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHA2_192F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_192F;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHA2_256F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHA2_256F;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHAKE_128S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_128S;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHAKE_192S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_192S;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHAKE_256S"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_256S;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHAKE_128F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_128F;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHAKE_192F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_192F;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SLHDSA_SHAKE_256F"))
                {
                    pArgs->gQsAlg = cid_PQC_SLHDSA_SHAKE_256F;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -g or --pq-alg option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-qsf") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--qs-format-oqs"))
        {
            SERIALQS_setOqsCompatibleFormat(TRUE);
#ifdef __ENABLE_MLDSA_LONG_FORM_PRIV_KEY_SER__
            MLDSA_setLongFormPrivKeyFormat(TRUE);
#endif
        }
#endif /* __ENABLE_DIGICERT_PQC__ */
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-s") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--size"))
        {
            if (++i < argc)
            {
                sbyte4 mTemp = DIGI_ATOL(ppArgv[i], NULL);
                if (2048 > mTemp || 8192 < mTemp || mTemp & 0x7f)
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -s or --size option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                pArgs->gKeySize = (ubyte4) mTemp;
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == pMainCtx->mode)
                {
                    pEstArgs->usKeySize = pArgs->gKeySize;
                }
#endif
            }
            continue;
        }
#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-q") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--q-size"))
        {
            if (++i < argc)
            {
                sbyte4 mTemp = DIGI_ATOL(ppArgv[i], NULL);
                if (160 != mTemp && 224 != mTemp && 256 != mTemp)
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -q or --q-size option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                pArgs->gQSize = (ubyte4) mTemp;
            }
            continue;
        }
#endif
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-u") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--output-pub-file"))
        {
            if (++i < argc)
            {
                pArgs->gpOutPubFile = ppArgv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-x") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--x509-cert"))
        {
            if (++i < argc)
            {
                pArgs->gpOutCertFile = ppArgv[i];
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-pc") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--print-cert"))
        {
            if (++i < argc)
            {
                /* reuse gpSigningCert for cert path */
                pArgs->gpSigningCert = ppArgv[i];
                pArgs->gIsPrintCert = TRUE;
            }
            continue;
        }
#endif
#ifdef __ENABLE_DIGICERT_CV_CERT__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cvc") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-cert"))
        {
            if (++i < argc)
            {
                pArgs->gpOutCertFile = ppArgv[i];
                pArgs->gIsCvc = TRUE;
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cve") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-eff-date"))
        {
            if (++i < argc)
            {
                sbyte temp[3] = {0};
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (6 == len)  /* date is 6 chars YYMMDD */
                {
                    (void) DIGI_MEMCPY(temp, (ubyte *) ppArgv[i], 2);
                    pArgs->gCvcData.effectiveDate.m_year = (ubyte2) DIGI_ATOL( (sbyte *) temp, NULL);
                    pArgs->gCvcData.effectiveDate.m_year += 30; /* stored date begins in 1970, not 2000, so add 30 */

                    (void) DIGI_MEMCPY(temp, (ubyte *) ppArgv[i] + 2, 2);
                    pArgs->gCvcData.effectiveDate.m_month = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);

                    (void) DIGI_MEMCPY(temp, (ubyte *) ppArgv[i] + 4, 2);
                    pArgs->gCvcData.effectiveDate.m_day = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cve or --cve-eff-date option, should be YYMMDD format: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }

            pArgs->gHasStartDate = TRUE;
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cvo") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-country-code"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (2 == len)
                {
                     (void) DIGI_MEMCPY(pArgs->gCvcData.countryCode, (ubyte *) ppArgv[i], 2);
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cvo or --cv-country-code option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cvm") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-mnemonic"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (len < 10) /* max of 9 chars */
                {
                     (void) DIGI_MEMCPY(pArgs->gCvcData.mnemonic, (ubyte *) ppArgv[i], len);
                     pArgs->gCvcData.mnemonicLen = len;
                     numReqArg++;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cvm or --cv-mnemonic option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cvs") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-seqnum"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (5 == len) /* must be 5 chars */
                {
                     (void) DIGI_MEMCPY(pArgs->gCvcData.seqNum, (ubyte *) ppArgv[i], len);
                     numReqArg++;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cvs or --cv-seqnum option: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cva") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-holder-auth-temp"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (len > 1)
                {
                    status = DIGI_MALLOC((void **) &pArgs->gCvcData.pCertHolderAuthTemplate, len/2);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Out of memory, status = %s (%d)\n",
                                  MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    status = DIGI_ATOH((ubyte *) ppArgv[i], len, pArgs->gCvcData.pCertHolderAuthTemplate);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cva or --cv-holder-auth-temp option. Should be hex, no leading 0x: %s, status = %s (%d)\n", ppArgv[i],
                                  MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                    pArgs->gCvcData.certHolderAuthTemplateLen = len/2;
                    numReqArg++;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cva or --cv-holder-auth-temp option. Should be hex, no leading 0x: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cvx") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cv-extensions"))
        {
            if (++i < argc)
            {
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (len > 1)
                {
                    status = DIGI_MALLOC((void **) &pArgs->gCvcData.pExtensions, len/2);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Out of memory, status = %s (%d)\n",
                                  MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }

                    status = DIGI_ATOH((ubyte *) ppArgv[i], len, pArgs->gCvcData.pExtensions);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cvx or --cv-extensions option. Should be hex, no leading 0x: %s, status = %s (%d)\n", ppArgv[i],
                                    MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                    pArgs->gCvcData.extLen = len/2;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -cvx or --cv-extensions option. Should be hex, no leading 0x: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-pcvc") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--print-cvcert"))
        {
            if (++i < argc)
            {
                /* reuse gpSigningCert for cert path */
                pArgs->gpSigningCert = ppArgv[i];
                pArgs->gIsPrintCVCert = TRUE;
            }
            continue;
        }
#endif /* __ENABLE_DIGICERT_CV_CERT__ */
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p12") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pkcs12"))
        {
            if (++i < argc)
            {
                pArgs->gpPkcs12File = ppArgv[i];
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == pMainCtx->mode)
                {
                    pEstArgs->pkcs12Gen = DIGI_ATOL(ppArgv[i], NULL);
                    if (0 != pEstArgs->pkcs12Gen && 1 != pEstArgs->pkcs12Gen)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -p12 or --pkcs12 option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    }

                    if (1 == pEstArgs->pkcs12Gen)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_3DES;
                    }
                }
#endif
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p12e") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pkcs12-encryption-type"))
        {
            if (++i < argc)
            {
                pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_undefined;
#if !defined(__DISABLE_3DES_CIPHERS__)
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"sha_3des") || DIGI_STRCMP(ppArgv[i], (sbyte *)"SHA_3DES"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_3des;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_3DES;
                    }
#endif
                }
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"sha_2des") || DIGI_STRCMP(ppArgv[i], (sbyte *)"SHA_2DES"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_2des;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_2DES;
                    }
#endif
                }
#endif
#endif /* !defined(__DISABLE_3DES_CIPHERS__) */
#ifdef __ENABLE_ARC2_CIPHERS__
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"sha_rc2_40") || DIGI_STRCMP(ppArgv[i], (sbyte *)"SHA_RC2_40"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc2_40;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC2_40;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"sha_rc2_128") || DIGI_STRCMP(ppArgv[i], (sbyte *)"SHA_RC2_128"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc2_128;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC2_128;
                    }
#endif
                }
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"sha_rc4_40") || DIGI_STRCMP(ppArgv[i], (sbyte *)"SHA_RC4_40"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc4_40;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC4_40;
                    }
#endif
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"sha_rc4_128") || DIGI_STRCMP(ppArgv[i], (sbyte *)"SHA_RC4_128"))
                {
                    pArgs->gPkcs12EncryptionType = PCKS8_EncryptionType_pkcs12_sha_rc4_128;
#ifndef __DISABLE_TRUSTEDGE_EST__
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pEstArgs->pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC4_128;
                    }
#endif
                }
#endif
                if (pArgs->gPkcs12EncryptionType == PCKS8_EncryptionType_undefined)
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -p12e or --pkcs12-encryption-type option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p12i") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pkcs12-integrity-pw"))
        {
            pArgs->gPkcs12GetIntegrityPw = TRUE;
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode && ++i < argc)
            {
                pEstArgs->pPkcs12IntPw = ppArgv[i];
                continue;
            }
#endif
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p12p") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pkcs12-privacy-pw"))
        {
            pArgs->gPkcs12GetPrivacyPw = TRUE;
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode && ++i < argc)
            {
                pEstArgs->pPkcs12PriPw = ppArgv[i];
                continue;
            }
#endif
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p12k") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pkcs12-key-pw"))
        {
            pArgs->gPkcs12GetKeyPw = TRUE;
#ifndef __DISABLE_TRUSTEDGE_EST__
            if (EST_MODE == pMainCtx->mode && ++i < argc)
            {
                pEstArgs->pPkcs12KeyPw = ppArgv[i];
                continue;
            }
#endif
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-i") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--csr-conf"))
        {
            if (++i < argc)
            {
                pArgs->gpInCsrFile = ppArgv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-kd") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--key-digest"))
        {
            if (++i < argc)
            {
                status = TRUSTEDGE_getHashIdOrOid(ppArgv[i], (ubyte4 *) &pArgs->gKeyHashAlgo, NULL);
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -kd or --key-digest option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-d") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--digest"))
        {
            if (++i < argc)
            {
                status = TRUSTEDGE_getHashIdOrOid(ppArgv[i], (ubyte4 *) &pArgs->gHashAlgo, NULL);
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -d or --digest option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
#ifndef __DISABLE_TRUSTEDGE_EST__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-kslt") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--key-salt"))
        {
            if (++i < argc)
            {
                pArgs->gKeySaltLen = DIGI_ATOL(ppArgv[i], (const sbyte **) &pEnd);
                if (*pEnd != '\0' || pArgs->gKeySaltLen < 0)
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -kslt or --key-salt option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-slt") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--salt"))
        {
            if (++i < argc)
            {
                pArgs->gSaltLen = DIGI_ATOL(ppArgv[i], (const sbyte **) &pEnd);
                if (*pEnd != '\0' || pArgs->gSaltLen < 0)
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -slt or --salt option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
#endif
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-pss") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pss"))
        {
            pArgs->gKeyIsPss = TRUE;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-sd") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--start-date"))
        {
            if (++i < argc)
            {
                sbyte temp[5] = {0};
                ubyte4 len = DIGI_STRLEN(ppArgv[i]);
                if (8 == len)  /* date is 8 chars MMDDYYYY */
                {
                    (void) DIGI_MEMCPY(temp, (sbyte *) ppArgv[i], 2);
                    pArgs->gStartDate.m_month = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);

                    (void) DIGI_MEMCPY(temp, (sbyte *) ppArgv[i] + 2, 2);
                    pArgs->gStartDate.m_day = (ubyte) DIGI_ATOL( (sbyte *) temp, NULL);

                    (void) DIGI_MEMCPY(temp, (sbyte *) ppArgv[i] + 4, 4);
                    pArgs->gStartDate.m_year = (ubyte2) DIGI_ATOL( (sbyte *) temp, NULL);
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -sd or --start-date option, should be MMDDYYYY format: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            pArgs->gHasStartDate = TRUE;
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-da") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--days"))
        {
            if (++i < argc)
            {
                sbyte4 mTemp = DIGI_ATOL(ppArgv[i], NULL);
                if (mTemp < 1)
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -da or --days option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                pArgs->gDays = (ubyte4) mTemp;
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-f") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--output-form"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"PEM") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"pem"))
                {
                    pArgs->gOutForm = FORMAT_PEM;
                    pArgs->gOutPubForm = FORMAT_PEM;
                }
                else if(0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"DER") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"der"))
                {
                    pArgs->gOutForm = FORMAT_DER;
                    pArgs->gOutPubForm = FORMAT_DER;
                }
                else if(0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"SSH") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"ssh"))
                {
                    pArgs->gOutForm = FORMAT_PEM;
                    pArgs->gOutPubForm = FORMAT_SSH;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -f or --output-form option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-sc") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--signing-cert"))
        {
            if (++i < argc)
            {
                pArgs->gpSigningCert = ppArgv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-sk") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--signing-key"))
        {
            if (++i < argc)
            {
                pArgs->gpSigningKey = ppArgv[i];
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_TAP__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-skt") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--signing-key-tap"))
        {
            pArgs->gSignKeyTap = TRUE;
        }
#endif
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-skp") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--signing-key-pw"))
        {
            pArgs->gGetSigningKeyPw = TRUE;
        }
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-okp") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--original-key-pw"))
        {
            pArgs->gGetSigningKeyPw = TRUE;
        }
#endif
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-if") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--input-form"))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"PEM") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"pem"))
                {
                    pArgs->gInForm = FORMAT_PEM;
                }
                else if(0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"DER") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"der"))
                {
                    pArgs->gInForm = FORMAT_DER;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -if or --input-form option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-csr") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--cert-sign-req"))
        {
            pArgs->gCreateCsr = TRUE;
        }
#ifndef __DISABLE_TRUSTEDGE_EST__
        else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--protect"))
        {
            pArgs->gProtected = TRUE;
            pEstArgs->pPkcs8EncAlg = PKCS8_ENC_ALG_P5_V2_AES256;
            if (EST_MODE == pMainCtx->mode && ++i < argc)
            {
                if (i + 1 < argc)
                {
                    if (0 == DIGI_STRNICMP(ppArgv[i + 1], (sbyte *)"pw:", DIGI_STRLEN((const sbyte *)"pw:")))
                    {
                        if (DIGI_STRLEN(ppArgv[i + 1]) > 3)
                        {
                            pEstArgs->pPkcs8Pw = ppArgv[i + 1] + 3;
                        }
                        else
                        {
                            status = ERR_INVALID_INPUT;
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Please provide a valid password: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                        ++i;
                    }
                    else
                    {
                        pEstArgs->pkcs8InteractivePass = TRUE;
                    }
                }
                else
                {
                    pEstArgs->pkcs8InteractivePass = TRUE;
                }
                continue;
            }
        }
        else if (EST_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-p8a") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--pkcs8-enc-alg")))
        {
            if (++i < argc)
            {
                pEstArgs->pPkcs8EncAlg = ppArgv[i];
            }
            continue;
        }
#endif
#ifndef __DISABLE_TRUSTEDGE_SCEP__
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scu") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-serverURL")))
        {
            if (++i < argc)
            {
                pScepArgs->pScepServerUrl = ppArgv[i];
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-sct") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-serverType")))
        {
            if (++i < argc)
            {
                /* Set the SCEP_SERVER type based on the string. */
                if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)MOC_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = MOC_SCEP_SERVER;
                    pScepArgs->supportsPost = TRUE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)EJBCA_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = EJBCA_SCEP_SERVER;
                    pScepArgs->supportsPost = TRUE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)ECDSA_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = ECDSA_SCEP_SERVER;
                    pScepArgs->supportsPost = TRUE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)WIN2003_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = WIN2003_SCEP_SERVER;
                    pScepArgs->supportsPost = FALSE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)WIN2008_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = WIN2008_SCEP_SERVER;
                    pScepArgs->supportsPost = FALSE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)WIN2012_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = WIN2012_SCEP_SERVER;
                    pScepArgs->supportsPost = FALSE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)WIN2016_SCEP_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = WIN2016_SCEP_SERVER;
                    pScepArgs->supportsPost = TRUE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)GEN_GET_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = GEN_GET_SERVER;
                    pScepArgs->supportsPost = FALSE;
                }
                else if (0 == DIGI_STRNICMP(ppArgv[i], (sbyte *)GEN_POST_SERVER_STR, DIGI_STRLEN(ppArgv[i])))
                {
                    pScepArgs->serverType = GEN_POST_SERVER;
                    pScepArgs->supportsPost = TRUE;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -sct or --scepc-serverType option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scp") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-challengePass")))
        {
            if (++i < argc)
            {
                pScepArgs->pChallengePass = ppArgv[i];
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-sco") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-pkiOperation")))
        {
            if (++i < argc)
            {
                pScepArgs->pPkiOperation = ppArgv[i];
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-sca") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-encalgo")))
        {
            if (++i < argc)
            {
                if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"desEDE3CBC"))
                {
                    pScepArgs->pEncAlgoOid = desEDE3CBC_OID;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"aes128CBC"))
                {
                    pScepArgs->pEncAlgoOid = aes128CBC_OID;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"aes192CBC"))
                {
                    pScepArgs->pEncAlgoOid = aes192CBC_OID;
                }
                else if (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"aes256CBC"))
                {
                    pScepArgs->pEncAlgoOid = aes256CBC_OID;
                }
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scd") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-digest")))
        {
            if (++i < argc)
            {
                status = TRUSTEDGE_getHashIdOrOid(ppArgv[i], &pScepArgs->hashId, &pScepArgs->pHashOid);
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -scd or --scepc-digest option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scoa") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-oaep")))
        {
            pScepArgs->oaep = TRUE;
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scod") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-oaepDigest")))
        {
            if (++i < argc)
            {
                status = TRUSTEDGE_getHashIdOrOid(ppArgv[i], &pScepArgs->oaepHashId, NULL);
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid -scod or --scepc-oaepDigest option: %s, status = %s (%d)\n", ppArgv[i],
                                MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scl") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-label")))
        {
            if (++i < argc)
            {
                pScepArgs->pLabel = ppArgv[i];
            }
            continue;
        }
        else if (SCEP_MODE == pMainCtx->mode && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-scce") || 0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--scepc-cepcert")))
        {
            if (++i < argc)
            {
                pScepArgs->pCepCertFileName = ppArgv[i];
            }
            continue;
        }
#endif /* __DISABLE_TRUSTEDGE_SCEP__ */
#ifndef __DISABLE_TRUSTEDGE_EST__
        else if ((EST_MODE == pMainCtx->mode) && (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--uri")))
        {
            if (++i < argc)
            {
                status = TRUSTEDGE_EST_parseEndpoint(ppArgv[i], &pEstArgs->pServerName, &pEstArgs->pUrl);
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid --uri: %s, status = %s (%d)\n", ppArgv[i],
                              MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                pEstArgs->estEndpointProvided = TRUE;
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-host")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-server-dn"))))
        {
            if (++i < argc)
            {
                if (FALSE == pEstArgs->estEndpointProvided)
                {
                    pEstArgs->pServerName = ppArgv[i];
                }
                else
                {
                    MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE",
                        "Ignoring -host/--estc-server-dn because --uri was provided.%s", "\n");
                }
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-ip")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-server-ip"))))
        {
            if (++i < argc)
            {
                pEstArgs->pServerIp = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-port")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-server-port"))))
        {
            if (++i < argc)
            {
                pEstArgs->usServerPort = (ubyte2) DIGI_ATOL((const sbyte *)ppArgv[i], NULL);
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-authscheme")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-authentication-mode"))))
        {
            if (++i < argc)
            {
                pEstArgs->pAuthScheme = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-url")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-server-url"))))
        {
            if (++i < argc)
            {
                if (FALSE == pEstArgs->estEndpointProvided)
                {
                    pEstArgs->pUrl = ppArgv[i];
                }
                else
                {
                    MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE",
                        "Ignoring -url/--estc-server-url because --uri was provided.%s", "\n");
                }
            }

            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-user")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-user"))))
        {
            if (++i < argc)
            {
                pEstArgs->pUserName = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-pass")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-pass"))))
        {
            if (++i < argc)
            {
                pEstArgs->pUserPasswd = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-mtls")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-tls-cert"))))
        {
            if (++i < argc)
            {
               pEstArgs->pTlsCert = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-caprefix")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-cacerts-alias"))))
        {
            if (++i < argc)
            {
               pEstArgs->pCAPrefix = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-rktype")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-rekey-type"))))
        {
            if (++i < argc)
            {
                pEstArgs->pNewKeyType = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-noverify")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-disable-ca-cert"))))
        {
            pEstArgs->disableCACert = 1;
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-extattr")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-ext-attrs-conf"))))
        {
            if (++i < argc)
            {
                pEstArgs->pExtAttrConfFile = ppArgv[i];
                pEstArgs->hasAttrib = 1;
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-rkalias")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-rekey-alias"))))
        {
            if (++i < argc)
            {
                pEstArgs->pKeyAlias2 = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-rksize")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-rekey-size"))))
        {
            if (++i < argc)
            {
                pEstArgs->newKeySize = (unsigned short) DIGI_ATOL((const sbyte *)ppArgv[i], NULL);
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-hash")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-digest-algo"))))
        {
            if (++i < argc)
            {
                pEstArgs->pDigestName = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-renewdays")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-renew-window"))))
        {
            if (++i < argc)
            {
                pTemp = ppArgv[i];
                pEstArgs->renewWindow = (unsigned short) DIGI_ATOL((const sbyte *)pTemp, (const sbyte **)&pEnd);
                pEstArgs->renewWindowSet = TRUE;
                /* If the range is invalid then set it to the default value.
                 */
                if ( (NULL == pEnd) || ('\0' != *pEnd) || (pTemp == pEnd) )
                {
                    pEstArgs->renewWindow = 0;
                }
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-cmcreq")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-full-cmc-req-type"))))
        {
            if (++i < argc)
            {
                pEstArgs->fullCmcReq.pFullCmcReqType = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-inlinecrt")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-renew-inline-cert"))))
        {
            if (++i < argc)
            {
                pEstArgs->renewinlinecert = (unsigned short) DIGI_ATOL((const sbyte *)ppArgv[i], NULL);
            }
            continue;
        }
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-ocsp")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-ocsp-required"))))
        {
            if (++i < argc)
            {
                pEstArgs->isOcspRequired = (intBoolean) DIGI_ATOL((const sbyte *) ppArgv[i], NULL);
            }
            continue;
        }
#endif
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-psk")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-psk-alias"))))
        {
            if (++i < argc)
            {
                pEstArgs->pSkPskAlias = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-skgalgo")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-skg-algorithm"))))
        {
            if (++i < argc)
            {
                pEstArgs->pSkAlg = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-skgcrt")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-skg-client-cert"))))
        {
            if (++i < argc)
            {
                pEstArgs->pSkClntCert = ppArgv[i];
            }
            continue;
        }
        else if ((EST_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"-skgkey")) || (0 == DIGI_STRCMP(ppArgv[i], (sbyte *)"--estc-skg-client-key"))))
        {
            if (++i < argc)
            {
                pEstArgs->pSkClntKey = ppArgv[i];
            }
            continue;
        }
#endif
#if defined(__ENABLE_DIGICERT_PQC__)
        else if ((EST_MODE == pMainCtx->mode) && (0 == DIGI_STRCMP(ppArgv[i], "--require-pqc")))
        {
            status = ERR_TRUSTEDGE_AGENT_FEATURE_NOT_AVAILABLE;
            DB_PRINT(
                "\nERROR: --require-pqc functionality is not implemented currently, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#endif
        else
        {
            status = ERR_TRUSTEDGE_CERTIFICATE_UNKNOWN_ARG;
#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
            TRUSTEDGE_certificateDisplayHelp(ppArgv[0], pMainCtx->mode);
#endif
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "Argument \"%s\" not recognized, status = %s (%d)\n",
                ppArgv[i], MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    /* skip validations if print cert */
    if (pArgs->gIsPrintCVCert)
        goto skip_validations;
#endif
#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
    if (pArgs->gIsPrintCert)
        goto skip_validations;
#endif

    /* validate SCEP args or set default */
    status = ERR_INVALID_ARG;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
    if (SCEP_MODE == pMainCtx->mode)
    {
        if (NULL == pScepArgs->pScepServerUrl)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a scep server url, -scu <url>. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (NULL == pScepArgs->pKeyAlias)
        {
            pScepArgs->pKeyAlias = gpKeyAliasDefault;
        }
        /* Set all defaults */
        pScepArgs->pCertAlias = pScepArgs->pKeyAlias;

        if (NULL == pScepArgs->pPkiOperation)
        {
            pScepArgs->pPkiOperation = gpScepPkiDefault;
        }
        if (((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pScepArgs->pPkiOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pScepArgs->pPkiOperation)) ||
            (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pScepArgs->pPkiOperation))) && NULL == pScepArgs->pChallengePass)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a scep challenge password, -scp <password>. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        if (0 == pScepArgs->serverType) /* Default, ie "MOC" */
        {
            pScepArgs->supportsPost = TRUE;
        }
        if (NULL == pScepArgs->pCepCertFileName)
        {
            if (FORMAT_PEM == pArgs->gInForm)
                pScepArgs->pCepCertFileName = gpScepCepDefaultPem;
            else
                pScepArgs->pCepCertFileName = gpScepCepDefaultDer;
        }

        if (NOT_SPECIFIED == pArgs->gHashAlgo)
        {
            pArgs->gHashAlgo = ht_sha256;
        }

        if (!(ht_sha256 == pArgs->gHashAlgo || ht_sha384 == pArgs->gHashAlgo || ht_sha512 == pArgs->gHashAlgo))
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "-d or --digest must be SHA256, SHA384, or SHA512 for the SCEP CSR request. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (NULL == pScepArgs->pHashOid)
        {
            /* need both forms */
            pScepArgs->pHashOid = sha256_OID;
            pScepArgs->hashId = ht_sha256;
        }
        if (NULL == pScepArgs->pEncAlgoOid)
        {
            pScepArgs->pEncAlgoOid = desEDE3CBC_OID;
        }
        if (0 == pScepArgs->oaepHashId)
        {
            pScepArgs->oaepHashId = ht_sha256;
        }
        if (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pScepArgs->pPkiOperation))
        {
            pScepArgs->serviceCtx.reuseKey = FALSE;
        }
        if (((0 != DIGI_STRCMP(PKI_OPERATION_ENROLL, pScepArgs->pPkiOperation)) && (0 != DIGI_STRCMP(PKI_OPERATION_RENEW, pScepArgs->pPkiOperation)) &&
            (0 != DIGI_STRCMP(PKI_OPERATION_REKEY, pScepArgs->pPkiOperation))))
        {
            goto skip_validations;
        }
    }
#endif

#ifndef __DISABLE_TRUSTEDGE_EST__
    if (EST_MODE == pMainCtx->mode)
    {
        if (NULL == pEstArgs->pServerName)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "Must specify est server name, -host/--estc-server-dn, or provide complete endpoint using --uri. status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        if (NULL == pEstArgs->pServerIp)
        {
            pEstArgs->pServerIp = pEstArgs->pServerName;
        }
        if (0 == pEstArgs->usServerPort)
        {
            MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "EST server port address missing or invalid, using default port %d\n", 443);
            pEstArgs->usServerPort = ESTC_DEF_PORT;
        }
        if (NULL == pEstArgs->pUrl)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "Must specify est server url address, -url/--estc-server-url, or provide complete endpoint using --uri. status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        else
        {
            if ((NULL == strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD)) &&
                (NULL == strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD)) &&
                (NULL == strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) &&
                (NULL == strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD)) &&
                (NULL == strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD)) &&
                (NULL == strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)))
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a valid est operation in url. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        if (NULL == pEstArgs->fullCmcReq.pFullCmcReqType)
        {
            pEstArgs->fullCmcReq.pFullCmcReqType = FULL_CMC_REQ_TYPE_ENROLL;
        }

        pEstArgs->cacertTag = 1;

#if defined(__ENABLE_DIGICERT_TEE__) || defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
        if (TRUE == pEstArgs->pkcs8InteractivePass)
#else
        if (TRUE == pEstArgs->pkcs8InteractivePass && FALSE == pArgs->gTap)
#endif
        {
            ubyte4 passwordLen = 0;
            do
            {
                if (NULL != pEstArgs->pPkcs8Pw)
                {
                    DIGI_MEMSET_FREE((ubyte **)&pEstArgs->pPkcs8Pw, passwordLen);
                }

                status = KEYGEN_getPassword((ubyte **)&pEstArgs->pPkcs8Pw, &passwordLen, "PEM", "private key");
                if (OK != status)
                {
                    goto exit;
                }

                if (!passwordLen)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "PKCS8 key password cannot be empty string.%s\n","");
                    continue;
                }
            } while (0 == passwordLen);
        }

        if (NULL == strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD))
        {
            if (NULL == pArgs->gpInCsrFile)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify csr conf file, -i/--csr-conf. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if ((NULL == pEstArgs->pTlsCert) && (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD)))
            {
                /* If username is not provided, set it to empty string */
                if (NULL == pEstArgs->pUserName)
                {
                    pEstArgs->pUserName = "";
                }

                /* If no TLS cert provided, then we are doing username/password auth */
#if !defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
                if (NULL == pEstArgs->pUserPasswd)
                {
                    if ((NULL != pEstArgs->pUrl) &&
                            NULL == strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD) &&
                            (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_ENROLL_CMD) ||
                            NULL != strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD) ||
                            NULL != strstr((const char *)pEstArgs->pUrl, EST_KEYGEN_CMD)))
                    {
                        /* Try to get from User by prompting for password. */
                        int passwdLoopCount = 0;
                        int passwdLen = 0;
        #ifdef __RTOS_WIN32__
                        char c;
                        int idx = 0;
        #endif
                        if (OK > (status = DIGI_MALLOC((void**)&pEstArgs->pUserPasswd, USER_PASSWORD_LENGTH)))
                        {
                            goto exit;
                        }

                        do
                        {
                            DIGI_MEMSET((ubyte *)pEstArgs->pUserPasswd, '\0', USER_PASSWORD_LENGTH);
                            passwdLoopCount++;
                            DB_PRINT("\nPlease enter password for the user \"%s\" \n", pEstArgs->pUserName);
#if defined(__RTOS_WIN32__) || defined(__RTOS_LINUX__)
                            passwdLen = TERM_promptPassword(pEstArgs->pUserPasswd, USER_PASSWORD_LENGTH, '*');
#endif
                            DB_PRINT("\n"); /* Just to move cursor to next line */
                            if (passwdLen > 0)
                            {
                                break;
                            }
                        } while (passwdLoopCount < 3);

                        if (NULL == pEstArgs->pUserPasswd)
                        {
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify user password, -pass/--estc-pass. status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                        else
                        {
                            pMainCtx->estCtx.isEnteredPass = TRUE;
                        }
                    }
                    else
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify user password, -pass/--estc-pass. status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
#endif /* library mode */
            }
            else
            {
                MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s\n", "TLS Authentication selected for enrollment");
            }
            if ((NULL != pEstArgs->pAuthScheme) && (NULL == strstr((const char *)pEstArgs->pUrl, EST_CACERTS_CMD)) &&
                (NULL == strstr((const char *)pEstArgs->pUrl, EST_CSR_ATTRS_CMD)) && (NULL == strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)))
            {
                if ((0 != DIGI_STRCMP(pEstArgs->pAuthScheme, "BASIC")) && (0 != DIGI_STRCMP(pEstArgs->pAuthScheme, "basic")) &&
                    (0 != DIGI_STRCMP(pEstArgs->pAuthScheme, "DIGEST")) && (0 != DIGI_STRCMP(pEstArgs->pAuthScheme, "digest")))
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invalid authentication scheme provided. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
            }
            /*Validate rekeySize argument*/
            if (NULL != pEstArgs->fullCmcReq.pFullCmcReqType)
            {
                if ((DIGI_STRCMP(pEstArgs->fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY) == 0) ||
                    ((NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD)) &&
                    (NULL != pEstArgs->pKeyAlias2)))
                {
                    if (NULL == pEstArgs->pKeyAlias2)
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Rekeyalias parameter is missing in arguments. status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                    /* TODO: validate newkeysize and newkeytype args */
                }
            }

            if (NULL != pEstArgs->pNewKeyType)
            {
                if (NULL == strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD) && NULL == strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD))
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "-rktype/--estc-rekey-type option required with fullcmc or simplereenroll operation, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                else
                {
                    if (0 == pEstArgs->newKeySize)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Missing rekey size, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
            }
            if (0 != pEstArgs->newKeySize)
            {
                if (NULL == strstr((const char *)pEstArgs->pUrl, EST_FULL_CMC_CMD) && NULL == strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD))
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "-rksize/--estc-rekey-size option required with fullcmc or simplereenroll operation, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                else
                {
                    if (NULL == pEstArgs->pNewKeyType)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Missing rekey type, status = %s (%d)\n",
                                MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
            }
            if (NULL != pEstArgs->pNewKeyType && 0 != pEstArgs->newKeySize)
            {
                pEstArgs->pKeyAlias2 = gpReKeyAliasDefault;
            }
            if (NULL == pEstArgs->pNewKeyType)
            {
                pEstArgs->pNewKeyType = pEstArgs->pKeyType;
            }
            if (0 == pEstArgs->newKeySize)
            {
                pEstArgs->newKeySize = pEstArgs->usKeySize;
            }
            if (NULL == pEstArgs->pDigestName)
            {
                pEstArgs->pDigestName = DEFAULT_DIGEST_NAME;
            }
            if (NULL == pEstArgs->pKeyAlias)
            {
                pEstArgs->pKeyAlias = gpKeyAliasDefault;
            }
            if (NULL != strstr((const char *)pEstArgs->pUrl, EST_SIMPLE_REENROLL_CMD))
            {
                pEstArgs->pTlsCert = pEstArgs->pKeyAlias;
            }
#ifdef __ENABLE_DIGICERT_TAP__
            if (TRUE == pEstArgs->tapKeyPrimary)
            {
                if (FALSE == pEstArgs->tapKeyHandleSet)
                {
                    status = ERR_INVALID_INPUT;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Primary key requires key handle to be provided, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (TRUE == pEstArgs->tapKeyNonceNvIndexSet)
                {
                    status = TRUSTEDGE_EST_utilStrToInt(
                        pEstArgs->pTapKeyNonceNvIndex, &pEstArgs->tapKeyNonceNvIndex);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key nonce NV index, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }

                if (TRUE == pEstArgs->tapTokenHierarchySet)
                {
                    status = TRUSTEDGE_EST_convertTapHierarchyString(
                        pEstArgs->pTapKeyTokenHierarchy, &pEstArgs->tapTokenHierarchy);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process TAP token hierarchy, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
            }
#endif
        }
        else
        {
            goto skip_validations;
        }
    }
#endif /* !defined(__DISABLE_TRUSTEDGE_EST__) */

    /* Validate arguments */
    if (!pArgs->gKeyType && !pArgs->gCreateCsr)
    {
        if (SCEP_MODE == pMainCtx->mode)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an algorithm, -a [ECC | RSA]. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
        else if (CERT_MODE == pMainCtx->mode)
        {
#if defined(__ENABLE_DIGICERT_PQC__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an algorithm, -a [ECC | RSA | DSA | QS]. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
#elif defined(__ENABLE_DIGICERT_PQC__)
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an algorithm, -a [ECC | RSA | QS]. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
#elif !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an algorithm, -a [ECC | RSA | DSA]. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
#else
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an algorithm, -a [ECC | RSA]. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
#endif
        }
    }

    if (CERT_MODE == pMainCtx->mode && NULL == pArgs->gpOutFile)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an output file, -o <file>. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (akt_rsa == pArgs->gKeyType && !pArgs->gKeySize)
    {

        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a key size, -s <size>, for RSA algorithm. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (akt_ecc == pArgs->gKeyType && !pArgs->gCurve)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a curve, -c <curve>, for ECC algorithm. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (akt_hybrid == pArgs->gKeyType)
    {
        if (!pArgs->gCurve && !pArgs->gKeySize)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a curve, -c <curve>, or RSA size, -s <size>, for HYBRID algorithm. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (pArgs->gCurve && pArgs->gKeySize)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Cannot specify BOTH a curve (-c) and RSA size (-s) for HYBRID algorithm. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (!pArgs->gQsAlg)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a post quantum alg, -g <alg>, for HYBRID algorithm. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
    else if (akt_qs == pArgs->gKeyType && !pArgs->gQsAlg)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a post quantum alg, -g <alg>, for QS algorithm. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#endif

#ifndef  __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    if (akt_dsa == pArgs->gKeyType)
    {
        if ( !( (1024 == pArgs->gKeySize && 160 == pArgs->gQSize) || (2048 == pArgs->gKeySize && 224 == pArgs->gQSize) || (2048 == pArgs->gKeySize && 256 == pArgs->gQSize) || (3072 == pArgs->gKeySize && 256 == pArgs->gQSize) ) )
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Invlalid <prime size -s, q-size -q> options. Valid combinations are [<1024, 160> | <2048, 224> | <2048, 256> | <3072, 256>]. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (NULL != pArgs->gpOutCertFile)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Certificate generation is not valid for algorithm DSA. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
#endif

  if (CERT_MODE == pMainCtx->mode)
  {
#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (NULL != pArgs->gpOutCertFile && !pArgs->gIsCvc && NULL == pArgs->gpInCsrFile)
#else
    if (NULL != pArgs->gpOutCertFile && NULL == pArgs->gpInCsrFile)
#endif
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify an input csr file, -i <file>, to generate an x509 certificate. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (pArgs->gCreateCsr)
    {
        if (NULL == pArgs->gpSigningKey)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Signing key must be provided for a CSR request. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (NULL == pArgs->gpSigningCert && NULL == pArgs->gpInCsrFile)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Input csr OR signing certificate must be provided for a CSR request. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (NULL != pArgs->gpSigningCert && NULL != pArgs->gpInCsrFile)
        {
            MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Input csr and signing certificate provided for a CSR request. Will only use the csr file.%s","\n");
            pArgs->gpSigningCert = NULL;
        }

        if (!(ht_sha256 == pArgs->gHashAlgo || ht_sha384 == pArgs->gHashAlgo || ht_sha512 == pArgs->gHashAlgo))
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "-d or --digest must be SHA256, SHA384, or SHA512 for a CSR request. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
    else if ((NULL != pArgs->gpSigningCert && NULL == pArgs->gpSigningKey) || (NULL == pArgs->gpSigningCert && NULL != pArgs->gpSigningKey))
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Signing Certificate or Key provided without the other. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_CV_CERT__
    if ((NULL != pArgs->gpOutCertFile) && (TRUE == pArgs->gHasStartDate) && ((0 == pArgs->gStartDate.m_day) || (pArgs->gStartDate.m_day > 31) || (0 == pArgs->gStartDate.m_month) || (pArgs->gStartDate.m_month > 12) || (0 == pArgs->gStartDate.m_year)))
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify a valid -sd or --start-date option in MMDDYYYY format. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#endif

    if ((NULL != pArgs->gpOutCertFile) && (0 == pArgs->gDays))
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify the number of days -da <days> of validity, to generate an x509 or CV certificate. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (NULL != pArgs->gpPkcs12File && NULL == pArgs->gpOutCertFile)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must specify certificate generation -x in order to specify pkcs12 file generation -p12. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (!pArgs->gCreateCsr && NULL == pArgs->gpOutCertFile && NULL != pArgs->gpInCsrFile)
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Input csr file -i specified but -x not specified so no certificate will be generated.%s", "\n");
    }

    if (!pArgs->gCreateCsr && NULL == pArgs->gpOutCertFile && NOT_SPECIFIED != pArgs->gHashAlgo)
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Digest -d specified but -x not specified so no certificate will be generated.%s", "\n");
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (!pArgs->gIsCvc && NULL == pArgs->gpOutCertFile && pArgs->gDays)
#else
    if (NULL == pArgs->gpOutCertFile && pArgs->gDays)
#endif
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Days -da specified but -x not specified so no certificate will be generated.%s", "\n");
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (pArgs->gIsCvc)   /* validate and fill in other defaults */
    {
        if (akt_rsa == pArgs->gKeyType)
        {
            if (ht_sha1 != pArgs->gKeyHashAlgo && ht_sha256 != pArgs->gKeyHashAlgo)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "must specify key digest -kd [sha1 or sha256] to generate an RSA CV certificate. status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else if (akt_ecc == pArgs->gKeyType)
        {
            if (ht_sha1 != pArgs->gKeyHashAlgo && ht_sha224 != pArgs->gKeyHashAlgo && ht_sha256 != pArgs->gKeyHashAlgo && ht_sha384 != pArgs->gKeyHashAlgo && ht_sha512 != pArgs->gKeyHashAlgo)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "must specify key digest -kd to generate an ECC CV certificate. status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (cid_EC_Ed25519 == pArgs->gCurve || cid_EC_Ed448 == pArgs->gCurve)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s", "Edwards form curves are not supported with ECC CV certificates.\n");
                goto exit;
            }
        }
        else
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Key type must be ECC or RSA in order to generate a CV certificate. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (3 != numReqArg)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Missing required args -cvm, -cvs, or -cva needed in order to generate a CV certificate. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        /* get the expiration date */
        if (pArgs->gHasStartDate)
        {
            (void) DIGI_MEMCPY((ubyte *) &pArgs->gStartDate, (ubyte *) &pArgs->gCvcData.effectiveDate, sizeof(TimeDate));
            pArgs->gStartDate.m_year += 1970;
        }

        status = KEYGEN_calculateEndDate(pArgs);
        if (OK != status)
            goto exit;

        status = ERR_INVALID_ARG; /* set status back to default error case */
        (void) DIGI_MEMCPY((ubyte *) &pArgs->gCvcData.expDate, (ubyte *) &pArgs->gEndDate, sizeof(TimeDate));
        if (pArgs->gCvcData.expDate.m_year > 129)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Certificate can not be valid after year 2099. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        /* Country Code default of US */
        if(0x00 == pArgs->gCvcData.countryCode[0] && 0x00 == pArgs->gCvcData.countryCode[1])
        {
            pArgs->gCvcData.countryCode[0] = (ubyte) 'U';
            pArgs->gCvcData.countryCode[1] = (ubyte) 'S';
        }

        pArgs->gCvcData.isPss = pArgs->gKeyIsPss;
        pArgs->gCvcData.hashAlgo = pArgs->gKeyHashAlgo;

        /* For now no validation on alphanumeric properites of mnemonic or seqNum */
    }
#endif
  }  /* !isScep */

    if (akt_rsa == pArgs->gKeyType && pArgs->gCurve)
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "RSA algorithm but curve specified. It will be ignored.%s", "\n");
    }
    else if (akt_ecc == pArgs->gKeyType && pArgs->gKeySize)
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "ECC algorithm but key size specified. It will be ignored.%s", "\n");
    }

    if (akt_rsa == pArgs->gKeyType && pArgs->gKeyIsPss)
    {
#ifndef __ENABLE_DIGICERT_TEE__
        if (!pArgs->gTap)
#endif
            pArgs->gKeyType = akt_rsa_pss;
    }
    else if (akt_rsa != pArgs->gKeyType && pArgs->gKeyIsPss)
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "-pss specified but key is not an RSA key. -pss will be ignored.%s", "\n");
    }

    if ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gKeySaltLen )
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Key salt length -kslt specified but key is not an RSA-PSS key. It will be ignored.%s", "\n");
    }

    if ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gSaltLen )
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Salt length -slt specified but key is not an RSA-PSS key. It will be ignored.%s", "\n");
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (!pArgs->gIsCvc && ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gKeyHashAlgo ))
#else
    if ((akt_rsa_pss != pArgs->gKeyType || !pArgs->gKeyIsPss) && NOT_SPECIFIED != pArgs->gKeyHashAlgo )
#endif
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Key digest -kd specified but key is not an RSA-PSS key. It will be ignored.%s", "\n");
    }

#ifdef __ENABLE_DIGICERT_TAP__
#if defined(__ENABLE_DIGICERT_TEE__) || defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
#ifndef __DISABLE_TRUSTEDGE_EST__
    if (pArgs->gTap && ((EST_MODE == pMainCtx->mode && FALSE == pEstArgs->tapKeyHandleSet) || (EST_MODE != pMainCtx->mode && NULL == pArgs->tapKeyHandle.pBuffer)))
#else
    if (pArgs->gTap && NULL == pArgs->tapKeyHandle.pBuffer)
#endif
    {
        status = ERR_INVALID_ARG;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Must enter a -tkh/--tap-key-handle option. status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#else
    if (pArgs->gTap && (akt_rsa == pArgs->gKeyType || akt_ecc == pArgs->gKeyType || akt_qs == pArgs->gKeyType) )
    {
        pArgs->gKeyType |= 0x00020000; /* will modify gKeyType to akt_tap_rsa, akt_tap_ecc, or akt_tap_qs */
    }
    else if(pArgs->gTap)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "-t/--tap option only available for ECC, RSA, or MLDSA. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (NULL != pArgs->gpPkcs12File && pArgs->gTap)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Pkcs12 file generation -p12 not available for TAP keys. status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
    if (pArgs->gTap)
    {
        ubyte4 id = 0;
        ubyte4 algo = 0;
        ubyte4 subtype = 0;

        switch (pArgs->gKeyType)
        {
            case akt_tap_ecc:
                algo = NanoROOT_ALGO_ECC;
                if (cid_EC_P256 == pArgs->gCurve)
                    subtype = NanoROOT_ECC_P256;
                else if (cid_EC_P384 == pArgs->gCurve)
                    subtype = NanoROOT_ECC_P384;
                else if (cid_EC_P521 == pArgs->gCurve)
                    subtype = NanoROOT_ECC_P521;
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "ERROR: Only P256, P384, and P521 are available for TAP NanoROOT. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                break;
            
            case akt_tap_rsa:
                algo = NanoROOT_ALGO_RSA;
                switch(pArgs->gKeySize)
                {
                    case 2048:
                        subtype = NanoROOT_RSA_2048;
                        break;
                    case 3072:
                        subtype = NanoROOT_RSA_3072;
                        break;
                    case 4096:
                        subtype = NanoROOT_RSA_4096;
                        break;
                    case 8192:
                        subtype = NanoROOT_RSA_8192;
                        break;
                    default:
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "ERROR: Only RSA 2048, 3072, 4096, and 8192 is available for TAP NanoROOT. status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                }
            
                break;
            
            case akt_tap_qs:
                algo = NanoROOT_ALGO_MLDSA;
                if (cid_PQC_MLDSA_44 == pArgs->gQsAlg)
                    subtype = NanoROOT_MLDSA_44;
                else if (cid_PQC_MLDSA_65 == pArgs->gQsAlg)
                    subtype = NanoROOT_MLDSA_65;
                else if (cid_PQC_MLDSA_87 == pArgs->gQsAlg)
                    subtype = NanoROOT_MLDSA_87;
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "ERROR: Only MLDSA 44, 65, and 87 are available for TAP NanoROOT. status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }
                break;

            default:
                /* error already printed */
                status = ERR_INVALID_ARG;
                goto exit;
        }

        id = NanoROOT_MAKE_ALGO_ID(algo, subtype);
        status = DIGI_MALLOC((void *) &pArgs->tapKeyHandle.pBuffer, 4);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "ERROR: Out of memory. status = %s (%d)\n", MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        /* TODO should this be big endian instead? Or always an int or always a buffer? */
        pArgs->tapKeyHandle.pBuffer[3] = (ubyte) ((id >> 24) & 0xff);
        pArgs->tapKeyHandle.pBuffer[2] = (ubyte) ((id >> 16) & 0xff);
        pArgs->tapKeyHandle.pBuffer[1] = (ubyte) ((id >> 8) & 0xff);
        pArgs->tapKeyHandle.pBuffer[0] = (ubyte) (id & 0xff);
        pArgs->tapKeyHandle.bufferLen = 4;
    }
#endif /* __ENABLE_DIGICERT_SMP_NANOROOT__ */
#endif /* else of __ENABLE_DIGICERT_TEE__ or __ENABLE_DIGICERT_SMP_NANOROOT__ */
#endif /* __ENABLE_DIGICERT_TAP__ */

    if (FORMAT_SSH == pArgs->gOutPubForm && NULL == pArgs->gpOutPubFile)
    {
        MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "SSH output form specified but no output public key file specified. Only a PEM private/public key pair file being created.%s", "\n");
    }

#if defined(__ENABLE_DIGICERT_CV_CERT__) || !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__) || !defined(__DISABLE_TRUSTEDGE_REST_API__)
skip_validations:
#endif
    pMainCtx->exit = FALSE;
    status = OK;
exit:

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (OK != status && pArgs->gIsCvc)   /* cleanup */
    {
        if (NULL != pArgs->gCvcData.pCertHolderAuthTemplate)
        {
            (void) DIGI_FREE((void **) &pArgs->gCvcData.pCertHolderAuthTemplate);
        }
        if (NULL != pArgs->gCvcData.pExtensions)
        {
            (void) DIGI_FREE((void **) &pArgs->gCvcData.pExtensions);
        }
    }
#endif

    /* Set key store path from config if not set on CLI else set default path */
    if (NULL != pArgs)
    {
        if (NULL == pArgs->gpKeyStorePath)
        {
            if ((TRUE == pMainCtx->isValidTEConfig) && (NULL != pMainCtx->pTEConfig->pKeystoreDir) && ( 0 != DIGI_STRCMP((const sbyte *)pMainCtx->pTEConfig->pKeystoreDir, (const sbyte *)"")))
            {
                pArgs->gpKeyStorePath = pMainCtx->pTEConfig->pKeystoreDir;

            }
            else
            {
                MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "No keystore path configured. Default path \".\" in use.%s","\n");
                pArgs->gpKeyStorePath = gpKeyStoreDefault;
            }
        }

        if (FALSE == FMGMT_pathExists(pArgs->gpKeyStorePath, &fileInfo))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "keystore dir does not exist: \"%s\"\n", pArgs->gpKeyStorePath);
        }

        if (FTDirectory != fileInfo.type)
        {
            status = ERR_DIR_INVALID_PATH;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "keystore path is not a dir: \"%s\"\n", pArgs->gpKeyStorePath);
        }
    }

#ifndef __DISABLE_TRUSTEDGE_SCEP__
    /* make a copy of the key store path in the scep args as the filePath*/
    if ((SCEP_MODE == pMainCtx->mode) && (NULL != pScepArgs) && (NULL == pScepArgs->pFilePath))
    {
        pScepArgs->pFilePath = pArgs->gpKeyStorePath;
    }
#endif

    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__
static MSTATUS TAP_checkProviderModule(TrustEdgecertificateMainCtx *pMainCtx)
{
    MSTATUS status = OK;
#ifndef  __ENABLE_DIGICERT_SMP_PKCS11__
    byteBoolean isLoaded = FALSE;
#endif
    if (NULL == pMainCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((TRUE == pMainCtx->keyGenArgs.gTap) || (TRUE == pMainCtx->keyGenArgs.gSignKeyTap))
    {
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
        if (NULL != pMainCtx->keyGenArgs.gpServer)
        {
            status = ERR_NOT_IMPLEMENTED;
            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "TAP remote not initialized, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#endif
#ifndef  __ENABLE_DIGICERT_SMP_PKCS11__
        status = TRUSTEDGE_TAP_isProviderModuleLoaded(
            pMainCtx->keyGenArgs.gTapProvider, pMainCtx->keyGenArgs.gModNum,
            &isLoaded);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "TAP error on provider and module lookup, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }

        if (FALSE == isLoaded)
        {
            status = ERR_TAP_MODULE_NOT_FOUND;
            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "TAP provider or module not found, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */
    }

    status = TRUSTEDGE_TAP_getCtx(&tapArgs.gpTapCtx, &tapArgs.gpTapEntityCredList, &tapArgs.gpTapCredList,
                                NULL, 0, 1);
    if (OK != status)
        goto exit;

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
extern MSTATUS TRUSTEDGE_ENROLL_resourceUpdateHandler(void *pResource)
{
    MSTATUS retStatus = OK;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    MSTATUS status = OK;
    ubyte4 hashValue, pid;
    ubyte2 i, j;
    intBoolean foundResKey = FALSE, foundPidKey;
    TrustEdgePidCtx *pFoundPidCtx;
    TrustEdgeResourceCtx *pFoundResCtx;

    if (NULL != gRestApiCtx.pHashTableResourceKey)
    {
        HASH_VALUE_hashGen(pResource, DIGI_STRLEN(pResource) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValue);

        status = HASH_TABLE_findPtr(gRestApiCtx.pHashTableResourceKey, hashValue, NULL, NULL, (void **)&pFoundPidCtx, &foundResKey);
        retStatus = ERR_CERT_NOT_FOUND;

        if (TRUE == foundResKey)
        {
            for (i = 0; i < pFoundPidCtx->numPids; i++)
            {
                foundPidKey = FALSE;
                pid = DIGI_ATOL(pFoundPidCtx->pPidVal[i], NULL);

#ifdef __RTOS_LINUX__
                if (0 != kill((pid_t)pid, SIGUSR1)) {
                    MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "Failed to send signal to pid: %d, status = %d\n", pid, status);
                }
#endif /* __RTOS_LINUX__ */
                HASH_VALUE_hashGen(pFoundPidCtx->pPidVal[i], DIGI_STRLEN(pFoundPidCtx->pPidVal[i]) + 1, TRUSTEDGE_REST_API_HASH_VALUE_BASE, &hashValue);

                status = HASH_TABLE_findPtr(gRestApiCtx.pHashTablePidKey, hashValue, NULL, NULL, (void **)&pFoundResCtx, &foundPidKey);

                if (TRUE == foundPidKey)
                {
                    for (j = 0; j < pFoundResCtx->numResources; j++)
                    {
                        if (0 == DIGI_STRCMP((const sbyte *)pFoundResCtx->resourceCtx[j].pResourcePath, pResource))
                        {
                            retStatus = OK;
                            pFoundResCtx->resourceCtx[j].isUpdated = TRUE;
                            pFoundResCtx->numUpdatedResources += 1;
                            break;
                        }
                    }
                }
            }
        }
    }
#else
    MOC_UNUSED(pResource);
#endif
    return retStatus;
}

static MSTATUS TRUSTEDGE_ENROLL_parseRequestJson(TrustEdgecertificateMainCtx *pMainCtx, sbyte *pConfig, byteBoolean isRestApiMode)
{
    MSTATUS status = OK;
    FileDescriptorInfo fileInfo;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte4 confLen;
    ubyte4 ndxLvl1, ndxLvl2;
    JSON_TokenType token = { 0 };
    CertEnrollAlg alg = certEnrollAlgUndefined;
    sbyte *pTemp;
    ubyte *pConf = NULL;
    sbyte *pTmpURI = NULL;
    sbyte *pFullURI = NULL;
    sbyte4 cmpRes = -1;
    byteBoolean isKeyCertAttrsPresent = TRUE;
    sbyte *pTlsCertCheck = NULL;
    sbyte *pTlsCertTmp = NULL;
    sbyte4 tlsCertLen = 0;
    ubyte4 ndxKcaCheck = 0;
    sbyte *pProtocol = NULL;
#if defined(__ENABLE_DIGICERT_TAP__)
#if !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    sbyte *pKeyTokenHierarchy = NULL;
#endif
    sbyte *pHandle = NULL;
    ubyte4 ndxLvl3;
    sbyte *pExtEnrollFlow = NULL;
#endif

    if ((NULL == pMainCtx) || (NULL == pConfig))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (TRUE == isRestApiMode)
    {
        pConf = pConfig;
        confLen = DIGI_STRLEN(pConfig);
    }
    else
#endif
    {
        status = DIGICERT_readFile(pConfig, &pConf, &confLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = JSON_parse(pJCtx, pConf, confLen, &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, PROTOCOL_JSTR, &pProtocol, TRUE);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "protocol field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == DIGI_STRCMP(pProtocol, "SCEP") || 0 == DIGI_STRCMP(pProtocol, "scep"))
    {
        if ((TRUE == isRestApiMode) && (SCEP_MODE != pMainCtx->mode))
        {
            status = ERR_INVALID_ARG;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "protocol field \"SCEP\" does not match configured mode in trustedge.json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pMainCtx->mode = SCEP_MODE;
    }
    else if (0 == DIGI_STRCMP(pProtocol, "EST") || 0 == DIGI_STRCMP(pProtocol, "est"))
    {
        if ((TRUE == isRestApiMode) && (EST_MODE != pMainCtx->mode))
        {
            status = ERR_INVALID_ARG;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "protocol field \"EST\" does not match configured mode in trustedge.json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pMainCtx->mode = EST_MODE;
    }
    else
    {
        status = ERR_INVALID_ARG;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "protocol field has unrecognized value \"%s\" in request json: %s line %d status: %d = %s\n",
            pProtocol, __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "keystore", &pMainCtx->srvCtx.pKeyStore, TRUE);
    if (OK == status)
    {
        if (FALSE == FMGMT_pathExists((const sbyte *)pMainCtx->srvCtx.pKeyStore, &fileInfo))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "keystore dir does not exist: \"%s\"\n", pMainCtx->srvCtx.pKeyStore);
            goto exit;
        }

        if (FTDirectory != fileInfo.type)
        {
            status = ERR_DIR_INVALID_PATH;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "keystore path is not a dir: \"%s\"\n", pMainCtx->srvCtx.pKeyStore);
            goto exit;
        }

        status = KEYGEN_validateKeystorePath(pMainCtx->srvCtx.pKeyStore, 0x0F);
        if (OK != status)
        {
            goto exit;
        }

        MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
            "Keystore path validated\n");
    }

    if (SCEP_MODE == pMainCtx->mode)
    {
        status = JSON_getJsonObjectIndex(
            pJCtx, 0, "scepAttributes", &ndxLvl1, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "scepAttributes field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        status = JSON_getJsonObjectIndex(
            pJCtx, 0, "estAttributes", &ndxLvl1, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "estAttributes field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "URI", &pFullURI, TRUE);
        if (OK == status)
        {
            status = TRUSTEDGE_EST_parseEndpoint(pFullURI, &pMainCtx->srvCtx.pFQDN, &pMainCtx->srvCtx.pURI);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "estAttributes URI field invalid in request json: %s line %d status: %d = %s\n",
                    __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
            pMainCtx->estCtx.estEndpointProvided = TRUE;
        }
    }

    if (TRUE != pMainCtx->estCtx.estEndpointProvided)
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "serverURI", &pMainCtx->srvCtx.pURI, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "serverURI field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (SCEP_MODE == pMainCtx->mode)
    {
        pMainCtx->scepCtx.pScepServerUrl = pMainCtx->srvCtx.pURI;
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        pTmpURI = pMainCtx->srvCtx.pURI;
    }

    if (EST_MODE == pMainCtx->mode)
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "serverPort", &pMainCtx->srvCtx.pPort, TRUE);
        if (OK != status)
        {
            pMainCtx->estCtx.usServerPort = ESTC_DEF_PORT;
        }
        else
        {
            pMainCtx->estCtx.usServerPort = (ubyte2)DIGI_ATOL((const sbyte *)pMainCtx->srvCtx.pPort, NULL);
        }

        if (TRUE != pMainCtx->estCtx.estEndpointProvided)
        {
            status = JSON_getJsonStringValue(
                pJCtx, ndxLvl1, "serverFQDN", &pMainCtx->srvCtx.pFQDN, TRUE);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "serverFQDN field missing in request json: %s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        pMainCtx->estCtx.pServerName = pMainCtx->srvCtx.pFQDN;

        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "serverIP", &pMainCtx->srvCtx.pIP, TRUE);
        if (OK != status)
        {
            pMainCtx->estCtx.pServerIp = pMainCtx->estCtx.pServerName;
        }
        else
        {
            pMainCtx->estCtx.pServerIp = pMainCtx->srvCtx.pIP;
        }

        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "username", &pMainCtx->srvCtx.pName, TRUE);
        if (OK != status)
        {
            pMainCtx->estCtx.pUserName = "";
        }
        else
        {
            pMainCtx->estCtx.pUserName = pMainCtx->srvCtx.pName;
        }

#if defined(__ENABLE_DIGICERT_TAP__)
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "extendedEnrollmentFlow", &pExtEnrollFlow, TRUE);
        if (OK == status)
        {
            if (0 == DIGI_STRCMP("TPM2_IDEVID", pExtEnrollFlow))
            {
                pMainCtx->estCtx.flow = EXT_ENROLL_FLOW_TPM2_IDEVID;
            }
            else if (0 == DIGI_STRCMP("TPM2_IAK", pExtEnrollFlow))
            {
                pMainCtx->estCtx.flow = EXT_ENROLL_FLOW_TPM2_IAK;
            }
            else
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "extendedEnrollmentFlow field invalid in request json: %s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
#endif
    }

    if ((NULL != pMainCtx->srvCtx.pOperation) && (0 == DIGI_STRCMP(pMainCtx->srvCtx.pOperation, "renew")))
    {
        if (SCEP_MODE == pMainCtx->mode)
        {
            pMainCtx->scepCtx.pPkiOperation = PKI_OPERATION_RENEW;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            if (TRUE == pMainCtx->estCtx.estEndpointProvided)
            {
                status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->estCtx.pUrl, DIGI_STRLEN(pTmpURI) + 1, (void *)pTmpURI, DIGI_STRLEN(pTmpURI));
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                pMainCtx->estCtx.pUrl[DIGI_STRLEN(pTmpURI)] = '\0';
            }
            else
            {
                status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->estCtx.pUrl, DIGI_STRLEN(pTmpURI) + DIGI_STRLEN(EST_SIMPLE_REENROLL_CMD) + 2, (void *)pTmpURI, DIGI_STRLEN(pTmpURI));
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pMainCtx->estCtx.pUrl[DIGI_STRLEN(pTmpURI)] = '/';
                status = DIGI_MEMCPY((void *)(pMainCtx->estCtx.pUrl + DIGI_STRLEN(pTmpURI) + 1), (void *)EST_SIMPLE_REENROLL_CMD, DIGI_STRLEN(EST_SIMPLE_REENROLL_CMD));
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pMainCtx->estCtx.pUrl[DIGI_STRLEN(pTmpURI) + DIGI_STRLEN(EST_SIMPLE_REENROLL_CMD) + 1] = '\0';
            }
        }
    }
    else
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "operation", &pMainCtx->srvCtx.pOperation, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "operation field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (SCEP_MODE == pMainCtx->mode)
        {
            pMainCtx->scepCtx.pPkiOperation = pMainCtx->srvCtx.pOperation;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            if (TRUE == pMainCtx->estCtx.estEndpointProvided)
            {
                status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->estCtx.pUrl, DIGI_STRLEN(pTmpURI) + 1, (void *)pTmpURI, DIGI_STRLEN(pTmpURI));
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                pMainCtx->estCtx.pUrl[DIGI_STRLEN(pTmpURI)] = '\0';
            }
            else
            {
                status = DIGI_MEMCMP(pMainCtx->srvCtx.pOperation, EST_KEYGEN_CMD, DIGI_STRLEN(EST_KEYGEN_CMD), &cmpRes);
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                if (0 == cmpRes)
                {
                    status = ERR_NOT_IMPLEMENTED;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "feature not implemented, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->estCtx.pUrl, DIGI_STRLEN(pTmpURI) + DIGI_STRLEN(pMainCtx->srvCtx.pOperation) + 2, (void *)pTmpURI, DIGI_STRLEN(pTmpURI));
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pMainCtx->estCtx.pUrl[DIGI_STRLEN(pTmpURI)] = '/';
                status = DIGI_MEMCPY((void *)(pMainCtx->estCtx.pUrl + DIGI_STRLEN(pTmpURI) + 1), (void *)pMainCtx->srvCtx.pOperation, DIGI_STRLEN(pMainCtx->srvCtx.pOperation));
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pMainCtx->estCtx.pUrl[DIGI_STRLEN(pTmpURI) + DIGI_STRLEN(pMainCtx->srvCtx.pOperation) + 1] = '\0';
            }
        }
    }

    if ((SCEP_MODE == pMainCtx->mode) && ((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pMainCtx->scepCtx.pPkiOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pMainCtx->scepCtx.pPkiOperation)) ||
                (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pMainCtx->scepCtx.pPkiOperation))))
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "cepCertificate", &pMainCtx->srvCtx.pCepCert, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "cepCertificate field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pMainCtx->scepCtx.pCepCertFileName = pMainCtx->srvCtx.pCepCert;

        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "challengePassword", &pMainCtx->srvCtx.pPassword, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "challengePassword field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pMainCtx->scepCtx.pChallengePass = pMainCtx->srvCtx.pPassword;
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "password", &pMainCtx->srvCtx.pPassword, TRUE);
        if ((OK != status) && (NULL == strstr((const char *)pMainCtx->estCtx.pUrl, EST_CACERTS_CMD)))
        {
            /* Password is not required when tlsCert (mTLS) is provided in keyCertAttributes */
            if ((OK == JSON_getJsonObjectIndex(pJCtx, 0, "keyCertAttributes", &ndxKcaCheck, TRUE)) &&
                (OK == TRUSTEDGE_utilsReadJsonStrAllowNull(pJCtx, ndxKcaCheck, "tlsCert", &pTlsCertCheck)) &&
                (NULL != pTlsCertCheck) && (0 != DIGI_STRCMP(pTlsCertCheck, "")))
            {
                status = OK;
            }
            else
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "password field missing in request json: %s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        pMainCtx->estCtx.pUserPasswd = pMainCtx->srvCtx.pPassword;

        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "authScheme", &pMainCtx->srvCtx.pAuthScheme, TRUE);
        if ((OK == status) && (NULL == strstr((const char *)pMainCtx->estCtx.pUrl, EST_CACERTS_CMD)))
        {
            pMainCtx->estCtx.pAuthScheme = pMainCtx->srvCtx.pAuthScheme;
        }
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, "keyCertAttributes", &ndxLvl1, TRUE);
    if (OK != status)
    {
        if (((EST_MODE == pMainCtx->mode) && (NULL == strstr((const char *)pMainCtx->estCtx.pUrl, EST_CACERTS_CMD))) || ((SCEP_MODE == pMainCtx->mode) &&
            ((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pMainCtx->scepCtx.pPkiOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pMainCtx->scepCtx.pPkiOperation)) ||
            (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pMainCtx->scepCtx.pPkiOperation)))))
        {
            isKeyCertAttrsPresent = FALSE;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "keyCertAttributes field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (((EST_MODE == pMainCtx->mode) && (NULL == strstr((const char *)pMainCtx->estCtx.pUrl, EST_CACERTS_CMD))) || ((SCEP_MODE == pMainCtx->mode) &&
        ((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pMainCtx->scepCtx.pPkiOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pMainCtx->scepCtx.pPkiOperation)) ||
        (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pMainCtx->scepCtx.pPkiOperation)))))
    {
        status = JSON_getJsonStringValue(
            pJCtx, ndxLvl1, "algorithm", &pMainCtx->srvCtx.pAlgo, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "algorithm field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        pTemp = pMainCtx->srvCtx.pAlgo;
        if ((0 == DIGI_STRNCMP("RSA+2048", pTemp, 8)) || (0 == DIGI_STRNCMP("rsa+2048", pTemp, 8)))
        {
            alg = rsa2048;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_rsa;
                pMainCtx->keyGenArgs.gKeySize = (ubyte4)2048;
            }
            else if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_RSA;
                pMainCtx->estCtx.usKeySize = 2048;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("RSA+3072", pTemp, 8)) || (0 == DIGI_STRNCMP("rsa+3072", pTemp, 8)))
        {
            alg = rsa3072;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_rsa;
                pMainCtx->keyGenArgs.gKeySize = (ubyte4)3072;
            }
            else if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_RSA;
                pMainCtx->estCtx.usKeySize = 3072;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("RSA+4096", pTemp, 8)) || (0 == DIGI_STRNCMP("rsa+4096", pTemp, 8)))
        {
            alg = rsa4096;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_rsa;
                pMainCtx->keyGenArgs.gKeySize = (ubyte4)4096;
            }
            else if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_RSA;
                pMainCtx->estCtx.usKeySize = 4096;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("ECC+P256", pTemp, 8)) || (0 == DIGI_STRNCMP("ecc+p256", pTemp, 8)))
        {
            alg = ecdsaP256;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_ecc;
                pMainCtx->keyGenArgs.gCurve = cid_EC_P256;
            }
            else if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_ECDSA;
                pMainCtx->estCtx.usKeySize = 256;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("ECC+P384", pTemp, 8)) || (0 == DIGI_STRNCMP("ecc+p384", pTemp, 8)))
        {
            alg = ecdsaP384;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_ecc;
                pMainCtx->keyGenArgs.gCurve = cid_EC_P384;
            }
            else if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_ECDSA;
                pMainCtx->estCtx.usKeySize = 384;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("ECC+P521", pTemp, 8)) || (0 == DIGI_STRNCMP("ecc+p521", pTemp, 8)))
        {
            alg = ecdsaP521;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_ecc;
                pMainCtx->keyGenArgs.gCurve = cid_EC_P521;
            }
            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_ECDSA;
                pMainCtx->estCtx.usKeySize = 521;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("ECC+CURVE25519", pTemp, 14)) || (0 == DIGI_STRNCMP("ecc+curve25519", pTemp, 14)))
        {
            alg = eddsaEd25519;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_ecc;
                pMainCtx->keyGenArgs.gCurve = cid_EC_Ed25519;
            }
            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_EDDSA;
                pMainCtx->estCtx.usKeySize = 255;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }
        else if ((0 == DIGI_STRNCMP("ECC+CURVE448", pTemp, 12)) || (0 == DIGI_STRNCMP("ecc+curve448", pTemp, 12)))
        {
            alg = eddsaEd448;
            if (SCEP_MODE == pMainCtx->mode)
            {
                pMainCtx->keyGenArgs.gKeyType = akt_ecc;
                pMainCtx->keyGenArgs.gCurve = cid_EC_Ed448;
            }
            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeyType = KEY_TYPE_EDDSA;
                pMainCtx->estCtx.usKeySize = 448;
                pMainCtx->estCtx.pDigestName = DEFAULT_DIGEST_NAME;
            }
        }

        if (certEnrollAlgUndefined == alg)
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_ALGO;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (SCEP_MODE == pMainCtx->mode)
    {
        pMainCtx->scepCtx.pKeyAlias = gpKeyAliasDefault;
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        pMainCtx->estCtx.pKeyAlias = gpKeyAliasDefault;
    }
    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndxLvl1, "keyAlias", &pMainCtx->srvCtx.pKeyAlias);
    if ((OK == status) && (NULL != pMainCtx->srvCtx.pKeyAlias) && (0 != DIGI_STRCMP(pMainCtx->srvCtx.pKeyAlias, "")))
    {
        if (SCEP_MODE == pMainCtx->mode)
        {
            pMainCtx->scepCtx.pKeyAlias = pMainCtx->srvCtx.pKeyAlias;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            pMainCtx->estCtx.pKeyAlias = pMainCtx->srvCtx.pKeyAlias;
        }
    }
    else if (FALSE == isRestApiMode)
    {
        /* Derive key alias from the request file name */
        sbyte *pBaseName = pConfig;
        sbyte *pTmp = pConfig;
        ubyte4 baseLen;
        while ('\0' != *pTmp)
        {
            if ('/' == *pTmp || '\\' == *pTmp)
                pBaseName = pTmp + 1;
            pTmp++;
        }

        baseLen = DIGI_STRLEN(pBaseName);
        if (baseLen > DIGI_STRLEN(JSON_EXT))
        {
            baseLen -= DIGI_STRLEN(JSON_EXT);
        }

        status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->srvCtx.pKeyAlias, baseLen + 1, pBaseName, baseLen);
        if (OK != status)
        {
            goto exit;
        }

        pMainCtx->srvCtx.pKeyAlias[baseLen] = '\0';

        if (SCEP_MODE == pMainCtx->mode)
        {
            pMainCtx->scepCtx.pKeyAlias = pMainCtx->srvCtx.pKeyAlias;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            pMainCtx->estCtx.pKeyAlias = pMainCtx->srvCtx.pKeyAlias;
        }
    }

    /* Hardcoded parameters in service mode */
    if (SCEP_MODE == pMainCtx->mode)
    {
        pMainCtx->keyGenArgs.gHashAlgo = ht_sha256;
        pMainCtx->scepCtx.pHashOid = sha256_OID;
        pMainCtx->scepCtx.pEncAlgoOid = aes128CBC_OID;
        pMainCtx->scepCtx.supportsPost = TRUE;
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        pMainCtx->estCtx.pNewKeyType = pMainCtx->estCtx.pKeyType;
        pMainCtx->estCtx.newKeySize = pMainCtx->estCtx.usKeySize;
        pMainCtx->estCtx.pKeySource = KEY_SOURCE_SW;
        pMainCtx->estCtx.cacertTag = 1;
        pMainCtx->estCtx.fullCmcReq.pFullCmcReqType = FULL_CMC_REQ_TYPE_ENROLL;
        pMainCtx->estCtx.pPkcs8EncAlg = PKCS8_ENC_ALG_P5_V2_AES256;
        pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_3DES;
    }

    status = JSON_getJsonStringValue(
        pJCtx, ndxLvl1, "keySource", &pMainCtx->srvCtx.pKeySource, TRUE);
    if ((OK == status) && (NULL != pMainCtx->srvCtx.pKeySource) && (0 != DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, "")))
    {
        if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_SW))
        {
            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeySource = KEY_SOURCE_SW;
            }
        }
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TEE__
        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_TEE))
        {
            pMainCtx->keyGenArgs.gTap = TRUE;
            pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_TEE;

            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeySource = KEY_SOURCE_TEE;
                if ((DIGI_STRCMP((const sbyte *)pMainCtx->estCtx.pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0) &&
                     256 == pMainCtx->estCtx.usKeySize)
                {
                    MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "%s\n", "Setting default tap signing scheme: ECDSA_SHA256");
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
            }

            status = JSON_getJsonObjectIndex(
                pJCtx, ndxLvl1, "TAPAttributes", &ndxLvl2, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonIntegerValue(
                    pJCtx, ndxLvl2, "tapProvider", &pMainCtx->srvCtx.tapProvider, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gTapProvider = pMainCtx->srvCtx.tapProvider;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndxLvl2, "secureModuleId", &pMainCtx->srvCtx.modNum, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gModNum = pMainCtx->srvCtx.modNum;
                }

                /* TODO Is this still needed for EST mode? */
                if (EST_MODE == pMainCtx->mode)
                {
                    status = JSON_getJsonBooleanValue(
                        pJCtx, ndxLvl2, "primary", &pMainCtx->estCtx.tapKeyPrimary, TRUE);

                    status = JSON_getJsonStringValue(
                        pJCtx, ndxLvl2, "keyTokenHierarchy", &pKeyTokenHierarchy, TRUE);
                    if (OK == status)
                    {
                        if (0 == DIGI_STRCMP(pKeyTokenHierarchy, (sbyte *)"ENDORSEMENT"))
                        {
                            pMainCtx->estCtx.pTapKeyTokenHierarchy = "ENDORSEMENT";
                            pMainCtx->estCtx.tapTokenHierarchySet = TRUE;
                        }
                        else if (0 == DIGI_STRCMP(pKeyTokenHierarchy, (sbyte *)"PLATFORM"))
                        {
                            pMainCtx->estCtx.pTapKeyTokenHierarchy = "PLATFORM";
                            pMainCtx->estCtx.tapTokenHierarchySet = TRUE;
                        }
                        else if (0 == DIGI_STRCMP(pKeyTokenHierarchy, (sbyte *)"STORAGE"))
                        {
                            pMainCtx->estCtx.pTapKeyTokenHierarchy = "STORAGE";
                            pMainCtx->estCtx.tapTokenHierarchySet = TRUE;
                        }
                        else
                        {
                            status = ERR_INVALID_ARG;
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                                "keyTokenHierarchy field invalid in request json: %s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                    }
                }

                /* TODO this should likely be under the EST mode if statement too. Don't think it's used otherwise */
                status = JSON_getJsonObjectIndex(pJCtx, ndxLvl2, "handles", &ndxLvl3, TRUE);
                if (OK == status)
                {
                    status = JSON_getJsonStringValue(
                        pJCtx, ndxLvl3, "key", &pHandle, TRUE);
                    if (OK == status)
                    {
                        pMainCtx->estCtx.pTapKeyHandleStr = pHandle;
                        status = KEYGEN_readId((sbyte *) pHandle, &(pMainCtx->estCtx.tapKeyHandle), &(pMainCtx->estCtx.isIdHex));
                        if (OK != status)
                        {
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key handle in request json, status = %s (%d)\n",
                                    MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                        pMainCtx->estCtx.tapKeyHandleSet = TRUE;
                        pHandle = NULL;
                    }
                    else if (ERR_NOT_FOUND != status)
                    {
                        goto exit;
                    }
                    else
                    {
                        status = OK;
                    }

                    DIGI_FREE((void **) &pHandle);
                }
                else if (ERR_NOT_FOUND != status)
                {
                    goto exit;
                }
                else
                {
                    status = OK;
                }
            }

            status = TAP_checkProviderModule(pMainCtx);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "TAP_checkProviderModule failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (FALSE == pMainCtx->estCtx.tapKeyHandleSet)
            {
                status = ERR_INVALID_INPUT;
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TEE requires key handle to be provided, status = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
#elif __ENABLE_DIGICERT_SMP_NANOROOT__
        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_NANOROOT))
        {
            pMainCtx->keyGenArgs.gTap = TRUE;
            pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_NANOROOT;

            /* TODO EST mode, what's left is general to pMainCtx but not sure this is needed outside est.
               the code that follows is actually not used on key generation as no key is actually generated. 
               We may need this when we go to import and use the key though, say for a self-signed cert,
               so will leave this code enabled for now. TODO validate that or delete this code etc. The 
               problem is that in import we call a general CRYPTO_deserializeAsymKey API hence there is
               no way to input this information */

            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pKeySource = KEY_SOURCE_NANOROOT;
                if ((DIGI_STRCMP((const sbyte *)pMainCtx->estCtx.pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0) &&
                     256 == pMainCtx->estCtx.usKeySize)
                {
                    MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "%s\n", "Setting default tap signing scheme: ECDSA_SHA256");
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
            }

            status = JSON_getJsonObjectIndex(
                pJCtx, ndxLvl1, "TAPAttributes", &ndxLvl2, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonIntegerValue(
                    pJCtx, ndxLvl2, "tapProvider", &pMainCtx->srvCtx.tapProvider, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gTapProvider = pMainCtx->srvCtx.tapProvider;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndxLvl2, "secureModuleId", &pMainCtx->srvCtx.modNum, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gModNum = pMainCtx->srvCtx.modNum;
                }

                /* TODO this should likely be under the EST mode if statement too. Don't think it's used otherwise */
                status = JSON_getJsonObjectIndex(pJCtx, ndxLvl2, "handles", &ndxLvl3, TRUE);
                if (OK == status)
                {
                    status = JSON_getJsonStringValue(
                        pJCtx, ndxLvl3, "key", &pHandle, TRUE);
                    if (OK == status)
                    {
                        status = KEYGEN_readId((sbyte *) pHandle, &(pMainCtx->estCtx.tapKeyHandle), &(pMainCtx->estCtx.isIdHex));
                        if (OK != status)
                        {
                            DIGI_FREE((void **) &pHandle);
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key handle in request json, status = %s (%d)\n",
                                    MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                        pMainCtx->estCtx.pTapKeyHandleStr = pHandle; pHandle = NULL;
                        pMainCtx->estCtx.tapKeyHandleSet = TRUE;
                    }
                    else if (ERR_NOT_FOUND != status)
                    {
                        goto exit;
                    }
                    else
                    {
                        status = OK;
                    }

                    DIGI_FREE((void **) &pHandle);
                }
                else if (ERR_NOT_FOUND != status)
                {
                    goto exit;
                }
                else
                {
                    status = OK;
                }
            }

            status = JSON_getJsonStringValue(
                pJCtx, ndxLvl2, "keyUsage", &pMainCtx->srvCtx.pKeyUsage, TRUE);
            if (OK == status)
            {
                if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_SIGNING"))
                {
                    pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_SIGNING;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_DECRYPT"))
                {
                    pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_DECRYPT;
                }
                else if (EST_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_ATTESTATION"))
                {
                    pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_ATTESTATION;
                }
                else if (EST_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_GENERAL"))
                {
                    pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_GENERAL;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "keyUsage field invalid in request json: %s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            status = JSON_getJsonStringValue(
                pJCtx, ndxLvl2, "sigScheme", &pMainCtx->srvCtx.pSignScheme, TRUE);
            if (OK == status)
            {
                if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA1"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA256"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                }
                else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA384"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                }
                else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA512"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_DER"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                }
                else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA1"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA1;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA256"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA256;
                }
                else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA384"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA384;
                }
                else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA512"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA512;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA1"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA224"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA256"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA384"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA512"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_NONE"))
                {
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_NONE;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "sigScheme field invalid in request json: %s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            status = JSON_getJsonStringValue(
                pJCtx, ndxLvl2, "encScheme", &pMainCtx->srvCtx.pEncScheme, TRUE);
            if (OK == status)
            {
                if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_PKCS1_5"))
                {
                    pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA1"))
                {
                    pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA256"))
                {
                    pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA384"))
                {
                    pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                }
                else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA512"))
                {
                    pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                }
                else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_NONE"))
                {
                    pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_NONE;
                }
                else
                {
                    status = ERR_INVALID_ARG;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                        "encScheme field invalid in request json: %s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            status = TAP_checkProviderModule(pMainCtx);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "TAP_checkProviderModule failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
#else
        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_TPM2) || 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_PKCS11)  )
        {
            pMainCtx->keyGenArgs.gTap = TRUE;
            if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_TPM2) )
            {
                pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_TPM2;
                if (EST_MODE == pMainCtx->mode)
                {
                    pMainCtx->estCtx.pKeySource = KEY_SOURCE_TPM2;
                }
            }
            else /* PKCS11 */
            {
                pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_PKCS11;
                if (EST_MODE == pMainCtx->mode)
                {
                    pMainCtx->estCtx.pKeySource = KEY_SOURCE_PKCS11;
                }
            }

            if (EST_MODE == pMainCtx->mode)
            {
                if ((DIGI_STRCMP((const sbyte *)pMainCtx->estCtx.pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0) &&
                     256 == pMainCtx->estCtx.usKeySize)
                {
                    MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "%s\n", "Setting default tap signing scheme: ECDSA_SHA256");
                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
            }

            status = JSON_getJsonObjectIndex(
                pJCtx, ndxLvl1, "TAPAttributes", &ndxLvl2, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonIntegerValue(
                    pJCtx, ndxLvl2, "tapProvider", &pMainCtx->srvCtx.tapProvider, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gTapProvider = pMainCtx->srvCtx.tapProvider;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndxLvl2, "secureModuleId", &pMainCtx->srvCtx.modNum, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gModNum = pMainCtx->srvCtx.modNum;
                }


                if (EST_MODE == pMainCtx->mode)
                {
                    status = JSON_getJsonBooleanValue(
                        pJCtx, ndxLvl2, "primary", &pMainCtx->estCtx.tapKeyPrimary, TRUE);

                    status = JSON_getJsonStringValue(
                        pJCtx, ndxLvl2, "keyTokenHierarchy", &pKeyTokenHierarchy, TRUE);
                    if (OK == status)
                    {
                        if (0 == DIGI_STRCMP(pKeyTokenHierarchy, (sbyte *)"ENDORSEMENT"))
                        {
                            pMainCtx->estCtx.pTapKeyTokenHierarchy = "ENDORSEMENT";
                            pMainCtx->estCtx.tapTokenHierarchySet = TRUE;
                        }
                        else if (0 == DIGI_STRCMP(pKeyTokenHierarchy, (sbyte *)"PLATFORM"))
                        {
                            pMainCtx->estCtx.pTapKeyTokenHierarchy = "PLATFORM";
                            pMainCtx->estCtx.tapTokenHierarchySet = TRUE;
                        }
                        else if (0 == DIGI_STRCMP(pKeyTokenHierarchy, (sbyte *)"STORAGE"))
                        {
                            pMainCtx->estCtx.pTapKeyTokenHierarchy = "STORAGE";
                            pMainCtx->estCtx.tapTokenHierarchySet = TRUE;
                        }
                        else
                        {
                            status = ERR_INVALID_ARG;
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                                "keyTokenHierarchy field invalid in request json: %s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                    }

                    status = JSON_getJsonObjectIndex(pJCtx, ndxLvl2, "handles", &ndxLvl3, TRUE);
                    if (OK == status)
                    {
                        status = JSON_getJsonStringValue(
                            pJCtx, ndxLvl3, "key", &pHandle, TRUE);
                        if (OK == status)
                        {
                            pMainCtx->estCtx.pTapKeyHandleStr = pHandle;
                            status = KEYGEN_readId((sbyte *) pHandle, &(pMainCtx->estCtx.tapKeyHandle), &(pMainCtx->estCtx.isIdHex));
                            if (OK != status)
                            {
                                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key handle in request json, status = %s (%d)\n",
                                        MERROR_lookUpErrorCode(status), status);
                                goto exit;
                            }
                            pMainCtx->estCtx.tapKeyHandleSet = TRUE;
                            pHandle = NULL;
                        }
                        else if (ERR_NOT_FOUND != status)
                        {
                            goto exit;
                        }
                        else
                        {
                            status = OK;
                        }

                        DIGI_FREE((void **) &pHandle);
                        status = JSON_getJsonStringValue(
                            pJCtx, ndxLvl3, "keyNonceNVHandle", &pHandle, TRUE);
                        if (OK == status)
                        {
                            pMainCtx->estCtx.pTapKeyNonceNvIndex = pHandle;
                            pHandle = NULL;
                            pMainCtx->estCtx.tapKeyNonceNvIndexSet = TRUE;
                        }
                        else if (ERR_NOT_FOUND != status)
                        {
                            goto exit;
                        }
                        else
                        {
                            status = OK;
                        }

                        DIGI_FREE((void **) &pHandle);
                        status = JSON_getJsonStringValue(
                            pJCtx, ndxLvl3, "certificateNVHandle", &pHandle, TRUE);
                        if (OK == status)
                        {
                            pMainCtx->estCtx.pTapCertificateNvIndexStr = pHandle;
                            status = TRUSTEDGE_EST_utilStrToInt(
                                pHandle, &(pMainCtx->estCtx.tapCertificateNvIndex));
                            if (OK != status)
                            {
                                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process certificate NV index in request json, status = %s (%d)\n",
                                        MERROR_lookUpErrorCode(status), status);
                                goto exit;
                            }
                            pMainCtx->estCtx.tapCertificateNvIndexSet = TRUE;
                            pHandle = NULL;
                        }
                        else if (ERR_NOT_FOUND != status)
                        {
                            goto exit;
                        }
                        else
                        {
                            status = OK;
                        }
                    }
                    else if (ERR_NOT_FOUND != status)
                    {
                        goto exit;
                    }
                    else
                    {
                        status = OK;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "keyUsage", &pMainCtx->srvCtx.pKeyUsage, TRUE);
                if (OK == status)
                {
                    if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_SIGNING"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_SIGNING;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_DECRYPT"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_DECRYPT;
                    }
                    else if (EST_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_ATTESTATION"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_ATTESTATION;
                    }
                    else if (EST_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyUsage, (sbyte *)"TAP_KEY_USAGE_GENERAL"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_GENERAL;
                    }
                    else
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                            "keyUsage field invalid in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "sigScheme", &pMainCtx->srvCtx.pSignScheme, TRUE);
                if (OK == status)
                {
                    if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                    }
                    else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                    }
                    else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_DER"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                    }
                    else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA256;
                    }
                    else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA384;
                    }
                    else if (SCEP_MODE == pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA512;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA224"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pSignScheme, (sbyte *)"TAP_SIG_SCHEME_NONE"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_NONE;
                    }
                    else
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                            "sigScheme field invalid in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    if (EST_MODE == pMainCtx->mode)
                    {
                        if (TAP_SIG_SCHEME_NONE == pMainCtx->keyGenArgs.gSigScheme)
                        {
                            sbyte *pKeyType = pMainCtx->estCtx.pKeyType;
                            if ((NULL != strstr((const char *)pMainCtx->estCtx.pUrl, EST_FULL_CMC_CMD)) &&
                                    (0 == DIGI_STRCMP(pMainCtx->estCtx.fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) )
                            {
                                pKeyType = pMainCtx->estCtx.pNewKeyType;
                                if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0)
                                {
                                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                                }
                                else if(DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_ECDSA) == 0)
                                {
                                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                                }
                                else
                                {
                                    pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_NONE;
                                }
                            }
                        }

                        if (TAP_KEY_USAGE_ATTESTATION == pMainCtx->keyGenArgs.gKeyUsage)
                        {
                            sbyte *pKeyType = pMainCtx->estCtx.pKeyType;
                            if ((NULL != strstr((const char *)pMainCtx->estCtx.pUrl, EST_FULL_CMC_CMD)) &&
                                    (0 == DIGI_STRCMP(pMainCtx->estCtx.fullCmcReq.pFullCmcReqType, (const sbyte*)FULL_CMC_REQ_TYPE_REKEY)) )
                            {
                                pKeyType = pMainCtx->estCtx.pNewKeyType;
                            }

                            if ( (DIGI_STRCMP((const sbyte *)pKeyType, (const sbyte *)KEY_TYPE_RSA) == 0) &&
                                (TAP_SIG_SCHEME_PKCS1_5_SHA256 != pMainCtx->keyGenArgs.gSigScheme) )
                            {
                                MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "%s\n", "Overriding tap signing scheme for attestation");
                                pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                            }
                        }
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "encScheme", &pMainCtx->srvCtx.pEncScheme, TRUE);
                if (OK == status)
                {
                    if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_PKCS1_5"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_PKCS1_5;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                    }
                    else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                    }
                    else if (EST_MODE != pMainCtx->mode && 0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                    }
                    else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pEncScheme, (sbyte *)"TAP_ENC_SCHEME_NONE"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_NONE;
                    }
                    else
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                            "encScheme field invalid in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }
            }

            status = TAP_checkProviderModule(pMainCtx);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "TAP_checkProviderModule failed with status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            if (TRUE == pMainCtx->estCtx.tapKeyPrimary)
            {
                if (FALSE == pMainCtx->estCtx.tapKeyHandleSet)
                {
                    status = ERR_INVALID_INPUT;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Primary key requires key handle to be provided, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                    goto exit;
                }

                if (TRUE == pMainCtx->estCtx.tapKeyNonceNvIndexSet)
                {
                    status = TRUSTEDGE_EST_utilStrToInt(
                        pMainCtx->estCtx.pTapKeyNonceNvIndex, &pMainCtx->estCtx.tapKeyNonceNvIndex);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key nonce NV index, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }

                if (TRUE == pMainCtx->estCtx.tapTokenHierarchySet)
                {
                    status = TRUSTEDGE_EST_convertTapHierarchyString(
                        pMainCtx->estCtx.pTapKeyTokenHierarchy, &pMainCtx->estCtx.tapTokenHierarchy);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process TAP token hierarchy, status = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                        goto exit;
                    }
                }
            }
        }
#endif /* __ENABLE_DIGICERT_TEE__ */
#endif /* __ENABLE_DIGICERT_TAP__ */
        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeySource, KEY_SOURCE_SW_SERVER))
        {
            /* TODO: Need to implement */
        }
        else
        {
            status = ERR_INVALID_ARG;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "keySource field invalid in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = JSON_getJsonStringValue(
        pJCtx, ndxLvl1, "keyOutFormat", &pMainCtx->srvCtx.pKeyOutFormat, TRUE);
    if (OK == status)
    {
        if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyOutFormat, (sbyte*)"pkcs8") || 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyOutFormat, (sbyte*)"PKCS8"))
        {
            status = JSON_getJsonObjectIndex(
                pJCtx, ndxLvl1, "pkcs8Attributes", &ndxLvl2, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "password", &pMainCtx->srvCtx.pPkcs8Pass, TRUE);
                if (OK == status)
                {
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pMainCtx->estCtx.pPkcs8Pw = pMainCtx->srvCtx.pPkcs8Pass;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "encAlg", &pMainCtx->srvCtx.pPkcs8EncAlgo, TRUE);
                if (OK == status)
                {
                    if (EST_MODE == pMainCtx->mode)
                    {
                        if (NULL == pMainCtx->estCtx.pPkcs8Pw)
                        {
                            status = ERR_INVALID_ARG;
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                                "pkcs8Attributes password field missing in request json: %s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }

                        pMainCtx->estCtx.pPkcs8EncAlg = pMainCtx->srvCtx.pPkcs8EncAlgo;
                    }
                }
            }
        }
        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyOutFormat, (sbyte*)"pkcs12") || 0 == DIGI_STRCMP(pMainCtx->srvCtx.pKeyOutFormat, (sbyte*)"PKCS12"))
        {
            if (EST_MODE == pMainCtx->mode)
            {
                pMainCtx->estCtx.pkcs12Gen = 1;
            }

            status = JSON_getJsonObjectIndex(
                pJCtx, ndxLvl1, "pkcs12Attributes", &ndxLvl2, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "integrityPassword", &pMainCtx->srvCtx.pPkcs12IntPass, TRUE);
                if (OK == status)
                {
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pMainCtx->estCtx.pPkcs12IntPw = pMainCtx->srvCtx.pPkcs12IntPass;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "privacyPassword", &pMainCtx->srvCtx.pPkcs12PriPass, TRUE);
                if (OK == status)
                {
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pMainCtx->estCtx.pPkcs12PriPw = pMainCtx->srvCtx.pPkcs12PriPass;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "keyPassword", &pMainCtx->srvCtx.pPkcs12KeyPass, TRUE);
                if (OK == status)
                {
                    if (EST_MODE == pMainCtx->mode)
                    {
                        pMainCtx->estCtx.pPkcs12KeyPw = pMainCtx->srvCtx.pPkcs12KeyPass;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndxLvl2, "encAlg", &pMainCtx->srvCtx.pPkcs12EncAlgo, TRUE);
                if (OK == status)
                {
                    if (EST_MODE == pMainCtx->mode)
                    {
                        if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"sha_3des") || DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"SHA_3DES"))
                        {
                            if (EST_MODE == pMainCtx->mode)
                            {
                                pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_3DES;
                            }
                        }
#ifdef __ENABLE_DIGICERT_2KEY_3DES__
                        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"sha_2des") || DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"SHA_2DES"))
                        {
                            if (EST_MODE == pMainCtx->mode)
                            {
                                pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_2DES;
                            }
                        }
#endif
#ifdef __ENABLE_ARC2_CIPHERS__
                        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"sha_rc2_40") || DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"SHA_RC2_40"))
                        {
                            if (EST_MODE == pMainCtx->mode)
                            {
                                pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC2_40;
                            }
                        }
                        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"sha_rc2_128") || DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"SHA_RC2_128"))
                        {
                            if (EST_MODE == pMainCtx->mode)
                            {
                                pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC2_128;
                            }
                        }
#endif
#ifndef __DISABLE_ARC4_CIPHERS__
                        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"sha_rc4_40") || DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"SHA_RC4_40"))
                        {
                            if (EST_MODE == pMainCtx->mode)
                            {
                                pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC4_40;
                            }
                        }
                        else if (0 == DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"sha_rc4_128") || DIGI_STRCMP(pMainCtx->srvCtx.pPkcs12EncAlgo, (sbyte *)"SHA_RC4_128"))
                        {
                            if (EST_MODE == pMainCtx->mode)
                            {
                                pMainCtx->estCtx.pPkcs12EncAlg = PKCS12_ENC_ALG_SHA_RC4_128;
                            }
                        }
#endif
                        else
                        {
                            status = ERR_INVALID_ARG;
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                                "pkcs12Attributes encAlgo field invalid in request json: %s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                    }
                }
            }
        }
        else
        {
            status = ERR_INVALID_ARG;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "keyOutFormat field invalid in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = JSON_getJsonBooleanValue(
        pJCtx, ndxLvl1, "reusePreviousKey", &pMainCtx->srvCtx.reuseKey, TRUE);
    if (OK == status)
    {
        if (SCEP_MODE == pMainCtx->mode)
        {
            pMainCtx->scepCtx.serviceCtx.reuseKey = pMainCtx->srvCtx.reuseKey;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            pMainCtx->estCtx.serviceCtx.reuseKey = pMainCtx->srvCtx.reuseKey;
        }
    }
    else
    {
        if (SCEP_MODE == pMainCtx->mode)
        {
            pMainCtx->scepCtx.serviceCtx.reuseKey = TRUE;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            pMainCtx->estCtx.serviceCtx.reuseKey = TRUE;
        }
    }

    if (SCEP_MODE == pMainCtx->mode)
    {
        pMainCtx->scepCtx.pCertAlias = pMainCtx->scepCtx.pKeyAlias;
        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndxLvl1, "certAlias", &pMainCtx->srvCtx.pCertAlias);
        if ((OK == status) && (NULL != pMainCtx->srvCtx.pCertAlias) && (0 != DIGI_STRCMP(pMainCtx->srvCtx.pCertAlias, "")))
        {
            pMainCtx->scepCtx.pCertAlias = pMainCtx->srvCtx.pCertAlias;
        }
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        status = TRUSTEDGE_utilsReadJsonStrAllowNull(
            pJCtx, ndxLvl1, "tlsCert", &pMainCtx->srvCtx.pTlsCert);

        if (NULL != strstr((const char *)pMainCtx->estCtx.pUrl, EST_SIMPLE_REENROLL_CMD))
        {
            if (NULL != pMainCtx->srvCtx.pTlsCert)
            {
                (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pTlsCert);
                pMainCtx->srvCtx.pTlsCert = NULL;
            }

            status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->srvCtx.pTlsCert, DIGI_STRLEN(pMainCtx->estCtx.pKeyAlias) + 1, pMainCtx->estCtx.pKeyAlias, DIGI_STRLEN(pMainCtx->estCtx.pKeyAlias));
            if (OK != status)
            {
                goto exit;
            }
            pMainCtx->srvCtx.pTlsCert[DIGI_STRLEN(pMainCtx->estCtx.pKeyAlias)] = '\0';
            pMainCtx->estCtx.pTlsCert = pMainCtx->srvCtx.pTlsCert;

            status = TRUSTEDGE_utilsReadJsonStrAllowNull(
                pJCtx, ndxLvl1, "rekeyAlias", &pMainCtx->srvCtx.pRekeyAlias);

            if ((OK == status) && (NULL != pMainCtx->srvCtx.pRekeyAlias) && (0 != DIGI_STRCMP(pMainCtx->srvCtx.pRekeyAlias, "")))
            {
                pMainCtx->estCtx.pKeyAlias2 = pMainCtx->srvCtx.pRekeyAlias;
            }
        }
        else if (NULL != strstr((const char *)pMainCtx->estCtx.pUrl, EST_SIMPLE_ENROLL_CMD))
        {
            if ((NULL != pMainCtx->srvCtx.pTlsCert) && (0 != DIGI_STRCMP(pMainCtx->srvCtx.pTlsCert, "")))
            {
                tlsCertLen = DIGI_STRLEN(pMainCtx->srvCtx.pTlsCert);
                pTlsCertTmp = pMainCtx->srvCtx.pTlsCert;
                pMainCtx->srvCtx.pTlsCert = NULL;
                status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->srvCtx.pTlsCert, tlsCertLen + 1, pTlsCertTmp, tlsCertLen);
                if (OK != status)
                {
                    goto exit;
                }
                pMainCtx->srvCtx.pTlsCert[tlsCertLen] = '\0';
                pMainCtx->estCtx.pTlsCert = pMainCtx->srvCtx.pTlsCert;
            }
        }

        if (TRUE == isKeyCertAttrsPresent)
        {
            status = TRUSTEDGE_utilsReadJsonStrAllowNull(
                pJCtx, ndxLvl1, "caPrefix", &pMainCtx->srvCtx.pCAPrefix);
            if (OK == status)
            {
                pMainCtx->estCtx.pCAPrefix = (ubyte *)pMainCtx->srvCtx.pCAPrefix;
            }
        }
    }

    if (((EST_MODE == pMainCtx->mode) && (NULL == strstr((const char *)pMainCtx->estCtx.pUrl, EST_CACERTS_CMD))) || ((SCEP_MODE == pMainCtx->mode) &&
        ((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pMainCtx->scepCtx.pPkiOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pMainCtx->scepCtx.pPkiOperation)) ||
        (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pMainCtx->scepCtx.pPkiOperation)))))
    {
        status = JSON_getJsonObjectIndex(
            pJCtx, 0, "csrAttributes", &ndxLvl1, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "csrAttributes field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_getToken(pJCtx, ndxLvl1, &token);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (SCEP_MODE == pMainCtx->mode)
        {
            status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->scepCtx.serviceCtx.pCSRAttrBuffer, token.len, (void *)token.pStart, token.len);
            if (OK != status)
            {
                goto exit;
            }
            pMainCtx->scepCtx.serviceCtx.csrAttrBufferLen = token.len;
        }
        else if (EST_MODE == pMainCtx->mode)
        {
            status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->estCtx.serviceCtx.pCSRAttrBuffer, token.len + 1, (void *)token.pStart, token.len);
            if (OK != status)
            {
                goto exit;
            }
            pMainCtx->estCtx.serviceCtx.pCSRAttrBuffer[token.len] = '\0';
        }
    }
exit:
    if (NULL != pProtocol)
    {
        (void) DIGI_FREE((void **)&pProtocol);
    }
    if (NULL != pFullURI)
    {
        (void) DIGI_FREE((void **)&pFullURI);
    }
    if (NULL != pTlsCertCheck)
    {
        (void) DIGI_FREE((void **)&pTlsCertCheck);
    }
    if (NULL != pTlsCertTmp)
    {
        (void) DIGI_FREE((void **)&pTlsCertTmp);
    }
    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    if (FALSE == isRestApiMode)
    {
        DIGICERT_freeReadFile(&pConf);
    }

    return status;
}

static MSTATUS TRUSTEDGE_ENROLL_validateServiceDirPath(sbyte *pServiceDirPath)
{
    MSTATUS status = OK;
    sbyte *pFullPath = NULL;

    /* service dir */
    if (NULL == pServiceDirPath)
    {
        status = ERR_DIR_INVALID_PATH;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "service_dir field doesn't exist in trustedge config status = %d\n", status);
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(pServiceDirPath, "", &pFullPath);
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists(pFullPath, NULL))
    {
        status = ERR_PATH_IS_INVALID;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s dir does not exist: status = %d\n", pServiceDirPath, status);
        goto exit;
    }

    /* request dir */
    (void) DIGI_FREE((void**)&pFullPath);
    status = COMMON_UTILS_addPathComponent(pServiceDirPath, SERVICE_REQUEST_DIR, &pFullPath);
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists(pFullPath, NULL))
    {
        status = ERR_PATH_IS_INVALID;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s subdir inside service dir does not exist: status = %d\n", SERVICE_REQUEST_DIR, status);
        goto exit;
    }

    /* processing dir */
    (void) DIGI_FREE((void**)&pFullPath);
    status = COMMON_UTILS_addPathComponent(pServiceDirPath, SERVICE_PROCESSING_DIR, &pFullPath);
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists(pFullPath, NULL))
    {
        status = ERR_PATH_IS_INVALID;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s subdir inside service dir does not exist: status = %d\n", SERVICE_PROCESSING_DIR, status);
        goto exit;
    }

    /* failure dir */
    (void) DIGI_FREE((void**)&pFullPath);
    status = COMMON_UTILS_addPathComponent(pServiceDirPath, SERVICE_FAILED_DIR, &pFullPath);
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists(pFullPath, NULL))
    {
        status = ERR_PATH_IS_INVALID;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s subdir inside service dir does not exist: status = %d\n", SERVICE_FAILED_DIR, status);
        goto exit;
    }

    /* completed dir */
    (void) DIGI_FREE((void**)&pFullPath);
    status = COMMON_UTILS_addPathComponent(pServiceDirPath, SERVICE_COMPLETED_DIR, &pFullPath);
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists(pFullPath, NULL))
    {
        status = ERR_PATH_IS_INVALID;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s subdir inside service dir does not exist: status = %d\n", SERVICE_COMPLETED_DIR, status);
        goto exit;
    }

exit:
    (void) DIGI_FREE((void**)&pFullPath);
    return status;
}

static MSTATUS TRUSTEDGE_ENROLL_serviceResponseProcess(TrustEdgecertificateMainCtx *pMainCtx, sbyte *pReqFile, byteBoolean isRenewal, MSTATUS errorCode)
{
    MSTATUS status = OK;
    ubyte *pConf = NULL;
    sbyte *pConfTmpFile = NULL;
    sbyte *pConfFile = NULL;
    ubyte4 confLen;
    TimeDate t;
    FileDescriptor pFile = NULL;
    ubyte4 i;

    if ((NULL == pMainCtx) || (NULL == pMainCtx->pTEConfig) || (NULL == pReqFile))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = RTOS_timeGMT(&t);
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceProcessingDir, pReqFile, &pConfTmpFile);
    if (OK != status)
    {
        goto exit;
    }

    if (SCEP_MODE == pMainCtx->mode)
    {
        if (scep_SUCCESS == pMainCtx->scepCtx.serviceCtx.cmdStatus)
        {
            status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceCompletedDir, pReqFile, &pConfFile);
            if (OK != status)
            {
                goto exit;
            }
        }
        else if (scep_FAILURE == pMainCtx->scepCtx.serviceCtx.cmdStatus)
        {
            status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceFailedDir, pReqFile, &pConfFile);
            if (OK != status)
            {
                goto exit;
            }
        }
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        if (OK == errorCode)
        {
            status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceCompletedDir, pReqFile, &pConfFile);
            if (OK != status)
            {
                goto exit;
            }
        }
        else
        {
            status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceFailedDir, pReqFile, &pConfFile);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

    status = DIGICERT_copyFile(pConfTmpFile, pConfFile);
    if (OK != status)
    {
        goto exit;
    }

    FMGMT_remove(pConfTmpFile, FALSE);

    status = DIGICERT_readFile(pConfFile, &pConf, &confLen);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_fopen(pConfFile, "w", &pFile);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == isRenewal)
    {
        i = confLen;
        while (pConf[i--] != '}');
        while (pConf[i--] != '}');

        pConf[i + 2] = ',';
        pConf[i + 3] = '\0';
    }
    else
    {
        i = 9;
        pConf[confLen - i] = ',';
        pConf[confLen - i + 1] = '\0';
    }

    FMGMT_fprintf(pFile, (const sbyte *) "%s", pConf);
    if (FALSE == isRenewal)
    {
        FMGMT_fprintf(pFile, "\n    \"response\": [\n");
    }
    else
    {
        FMGMT_fprintf(pFile, "\n");
    }

    FMGMT_fprintf(pFile, "      {\n");
    if (SCEP_MODE == pMainCtx->mode)
    {
        if (scep_SUCCESS == pMainCtx->scepCtx.serviceCtx.cmdStatus)
        {
            FMGMT_fprintf(pFile, "        \"status\": \"SUCCESS\",\n");
            if ((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pMainCtx->scepCtx.pPkiOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pMainCtx->scepCtx.pPkiOperation)) ||
                (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pMainCtx->scepCtx.pPkiOperation)))
            {
                FMGMT_fprintf(pFile, "        \"certificateThumbPrint\": \"%s\",\n", pMainCtx->srvCtx.pCertThumbPrint);
                FMGMT_fprintf(pFile, "        \"certificateSerialNumber\": \"%s\",\n", pMainCtx->srvCtx.pCertSerialNum);
                FMGMT_fprintf(pFile, "        \"certificateExpiry\": \"%04d-%02d-%02d %02d:%02d:%02d\",\n", pMainCtx->srvCtx.pCertExpiry.m_year + 1970,
                            pMainCtx->srvCtx.pCertExpiry.m_month, pMainCtx->srvCtx.pCertExpiry.m_day, pMainCtx->srvCtx.pCertExpiry.m_hour,
                            pMainCtx->srvCtx.pCertExpiry.m_minute, pMainCtx->srvCtx.pCertExpiry.m_second);
                FMGMT_fprintf(pFile, "        \"certificateIssuer\": \"%s\",\n", pMainCtx->srvCtx.pCertIssuer);
            }
        }
        else if (scep_FAILURE == pMainCtx->scepCtx.serviceCtx.cmdStatus)
        {
            FMGMT_fprintf(pFile, "        \"status\": \"FAILURE\",\n");
            FMGMT_fprintf(pFile, "        \"errorCode\": \"%d\",\n", errorCode);
            switch (pMainCtx->scepCtx.serviceCtx.failInfo)
            {
                case scep_badAlg:
                    FMGMT_fprintf(pFile, "        \"errorDescription\": \"badAlg::Unrecognised or unsupported algorithm.\",\n");
                    break;
                case scep_badMessageCheck:
                    FMGMT_fprintf(pFile, "        \"errorDescription\": \"badMessageCheck::Integrity check failed.\",\n");
                    break;
                case scep_badRequest:
                    FMGMT_fprintf(pFile, "        \"errorDescription\": \"badRequest::Transaction not permitted or supported.\",\n");
                    break;
                case scep_badTime:
                    FMGMT_fprintf(pFile, "        \"errorDescription\": \"badTime::The signingTime attribute from the CMS authenticatedAttributes was not sufficiently close to the system time.\",\n");
                    break;
                case scep_badCertId:
                    FMGMT_fprintf(pFile, "        \"errorDescription\": \"badCertId::No certificate could be identified matching the provided criteria.\",\n");
                    break;
                default:
                    FMGMT_fprintf(pFile, "        \"errorDescription\": \"%s\",\n", MERROR_lookUpErrorCode(errorCode));
            }
        }
    }
    else if (EST_MODE == pMainCtx->mode)
    {
        if (OK == errorCode)
        {
            FMGMT_fprintf(pFile, "        \"status\": \"SUCCESS\",\n");
            if (NULL == strstr((const char *)pMainCtx->estCtx.pUrl, EST_CACERTS_CMD))
            {
                FMGMT_fprintf(pFile, "        \"certificateThumbPrint\": \"%s\",\n", pMainCtx->srvCtx.pCertThumbPrint);
                FMGMT_fprintf(pFile, "        \"certificateSerialNumber\": \"%s\",\n", pMainCtx->srvCtx.pCertSerialNum);
                FMGMT_fprintf(pFile, "        \"certificateExpiry\": \"%04d-%02d-%02d %02d:%02d:%02d\",\n", pMainCtx->srvCtx.pCertExpiry.m_year + 1970,
                            pMainCtx->srvCtx.pCertExpiry.m_month, pMainCtx->srvCtx.pCertExpiry.m_day, pMainCtx->srvCtx.pCertExpiry.m_hour,
                            pMainCtx->srvCtx.pCertExpiry.m_minute, pMainCtx->srvCtx.pCertExpiry.m_second);
                FMGMT_fprintf(pFile, "        \"certificateIssuer\": \"%s\",\n", pMainCtx->srvCtx.pCertIssuer);
            }
        }
        else
        {
            FMGMT_fprintf(pFile, "        \"status\": \"FAILURE\",\n");
            FMGMT_fprintf(pFile, "        \"errorCode\": \"%d\",\n", errorCode);
            FMGMT_fprintf(pFile, "        \"errorDescription\": \"%s\",\n", MERROR_lookUpErrorCode(errorCode));
        }
    }

    FMGMT_fprintf(pFile, "        \"timestamp\": \"%04d-%02d-%02d %02d:%02d:%02d\"\n", t.m_year + 1970, t.m_month, t.m_day, t.m_hour, t.m_minute, t.m_second);
    FMGMT_fprintf(pFile, "      }\n");
    FMGMT_fprintf(pFile, "    ]\n");
    FMGMT_fprintf(pFile, "}\n");

exit:
    DIGICERT_freeReadFile(&pConf);
    (void) DIGI_FREE((void **) &pConfFile);
    (void) DIGI_FREE((void **) &pConfTmpFile);
    if (pFile)
    {
        FMGMT_fflush(pFile);
        FMGMT_fclose(&pFile);
    }

    return status;
}

static MSTATUS TRUSTEDGE_ENROLL_serviceRequestProcess(TrustEdgecertificateMainCtx *pMainCtx, byteBoolean *pHasConf)
{
    MSTATUS status = OK;
    DirectoryDescriptor pDirDesc = NULL;
    DirectoryEntry dirEnt;
    sbyte *pConfTmpFile = NULL;
    sbyte *pConfFile = NULL;
    sbyte *pTmpFileName = NULL;
    sbyte *pModFileName = NULL;
    ubyte4 baseNameLen = 0;
    ubyte4 modFileNameLen = 0;
    sbyte4 cmpRes = -1;
    TimeDate t;
    sbyte timeStr[16];

    if ((NULL == pMainCtx) || (NULL == pMainCtx->pTEConfig))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TRUSTEDGE_ENROLL_validateServiceDirPath(pMainCtx->pTEConfig->pServiceDir);
    if (OK != status)
    {
        pMainCtx->isInvalidSrvDir = TRUE;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_validateServiceDirPath: status = %d\n", status);
        goto exit;
    }

    status = RTOS_timeGMT(&t);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_getFirstFile(pMainCtx->pTEConfig->pServiceRequestDir, &pDirDesc, &dirEnt);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory doesn't exist: %s  status = %d\n", pMainCtx->pTEConfig->pServiceRequestDir, status);
        goto exit;
    }
    do
    {
        if (FTFile == dirEnt.type && dirEnt.nameLength > DIGI_STRLEN(JSON_EXT))
        {
            DIGI_MEMCMP(dirEnt.pName + dirEnt.nameLength - DIGI_STRLEN(JSON_EXT),
                        JSON_EXT, DIGI_STRLEN(JSON_EXT), &cmpRes);
            if (0 == cmpRes)
            {
                status = DIGI_CALLOC((void **)&pTmpFileName, 1, dirEnt.nameLength + 1);
                if (OK != status)
                {
                    goto exit;
                }
                status = DIGI_MEMCPY(pTmpFileName, dirEnt.pName, dirEnt.nameLength);
                if (OK != status)
                {
                    goto exit;
                }
                *pHasConf = TRUE;
                break;
            }
        }

        status = FMGMT_getNextFile(pDirDesc, &dirEnt);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "fetching file inside dir: %s  status = %d\n", pMainCtx->pTEConfig->pServiceRequestDir, status);
            goto exit;
        }

    } while (FTNone != dirEnt.type);

    if (FALSE == *pHasConf)
    {
        goto exit;
    }

    baseNameLen = DIGI_STRLEN(pTmpFileName) - DIGI_STRLEN(JSON_EXT);

    status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceRequestDir, pTmpFileName, &pConfTmpFile);
    if (OK != status)
    {
        goto exit;
    }

    /* Processing */
    status = DATETIME_convertToValidityString(&t, timeStr);
    if (OK != status)
    {
        goto exit;
    }

    /* baseNameLen + '_' + timeStr (without null) + JSON_EXT + null */
    modFileNameLen = baseNameLen + 1 + (DIGI_STRLEN(timeStr) - 1) + DIGI_STRLEN(JSON_EXT) + 1;

    status = DIGI_CALLOC((void **)&pModFileName, 1, modFileNameLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pModFileName, pTmpFileName, baseNameLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pModFileName + baseNameLen, "_", 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pModFileName + baseNameLen + 1, timeStr, DIGI_STRLEN(timeStr) - 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pModFileName + baseNameLen + DIGI_STRLEN(timeStr), JSON_EXT, DIGI_STRLEN(JSON_EXT));
    if (OK != status)
    {
        goto exit;
    }

    status = COMMON_UTILS_addPathComponentWithLength(pMainCtx->pTEConfig->pServiceProcessingDir, pModFileName, modFileNameLen, &pConfFile);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_copyFile(pConfTmpFile, pConfFile);
    if (OK != status)
    {
        goto exit;
    }

    FMGMT_remove(pConfTmpFile, FALSE);
    pMainCtx->srvCtx.pReqFile = pModFileName;
    pModFileName = NULL;

    status = TRUSTEDGE_ENROLL_parseRequestJson(pMainCtx, pConfFile, FALSE);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_parseRequestJson: status = %d\n", status);
        goto exit;
    }

exit:
    if (NULL != pDirDesc)
    {
        if (OK != FMGMT_closeDir(&pDirDesc))
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory descriptor can't be closed: %s  status = %d\n", pMainCtx->pTEConfig->pServiceRequestDir, status);
        }
    }

    if (NULL != pModFileName)
    {
        (void) DIGI_FREE((void **)&pModFileName);
    }

    (void) DIGI_FREE((void **)&pTmpFileName);
    (void) DIGI_FREE((void **)&pConfFile);
    (void) DIGI_FREE((void **)&pConfTmpFile);
    return status;
}

static void TRUSTEDGE_SCEP_serviceResourceRelease(TrustEdgecertificateMainCtx *pMainCtx)
{
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pOperation);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pURI);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPassword);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pAuthScheme);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pAlgo);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pKeyAlias);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pKeyStore);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pReqFile);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pCertSerialNum);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pCertThumbPrint);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pCertIssuer);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pKeySource);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pKeyOutFormat);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs8Attrs);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs8Pass);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs8EncAlgo);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs12Attrs);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs12IntPass);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs12PriPass);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs12KeyPass);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPkcs12EncAlgo);

#ifdef __ENABLE_DIGICERT_TAP__
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pKeyUsage);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pSignScheme);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pEncScheme);
#endif

#ifndef __DISABLE_TRUSTEDGE_SCEP__
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pCertAlias);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pCepCert);
    (void) DIGI_FREE((void **)&pMainCtx->scepCtx.serviceCtx.pCSRAttrBuffer);
    pMainCtx->srvCtx.pOperation = NULL;

    pMainCtx->srvCtx.pCepCert = NULL;
    pMainCtx->srvCtx.pCertAlias = NULL;
    pMainCtx->scepCtx.serviceCtx.pCSRAttrBuffer = NULL;
#endif

#ifndef __DISABLE_TRUSTEDGE_EST__
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pIP);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pPort);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pName);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pFQDN);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pTlsCert);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pRekeyAlias);
    (void) DIGI_FREE((void **)&pMainCtx->srvCtx.pCAPrefix);
    (void) DIGI_FREE((void **)&pMainCtx->estCtx.serviceCtx.pCSRAttrBuffer);
    if (TRUE == pMainCtx->estCtx.serviceCtx.serviceMode)
    {
        (void) DIGI_FREE((void **)&pMainCtx->estCtx.pUrl);
        pMainCtx->estCtx.pUrl = NULL;
    }

    pMainCtx->srvCtx.pIP = NULL;
    pMainCtx->srvCtx.pPort = NULL;
    pMainCtx->srvCtx.pName = NULL;
    pMainCtx->srvCtx.pFQDN = NULL;
    pMainCtx->srvCtx.pTlsCert = NULL;
    pMainCtx->srvCtx.pRekeyAlias = NULL;
    pMainCtx->estCtx.pTlsCert = NULL;
    pMainCtx->srvCtx.pCAPrefix = NULL;
    pMainCtx->estCtx.serviceCtx.pCSRAttrBuffer = NULL;
#endif

    pMainCtx->srvCtx.pURI = NULL;
    pMainCtx->srvCtx.pPassword = NULL;
    pMainCtx->srvCtx.pAuthScheme = NULL;
    pMainCtx->srvCtx.pAlgo = NULL;
    pMainCtx->srvCtx.pKeyAlias = NULL;
    pMainCtx->srvCtx.pKeyStore = NULL;
    pMainCtx->srvCtx.pCertSerialNum = NULL;
    pMainCtx->srvCtx.pCertThumbPrint = NULL;
    pMainCtx->srvCtx.pCertIssuer = NULL;
    pMainCtx->srvCtx.pReqFile = NULL;
    pMainCtx->srvCtx.pKeySource = NULL;
    pMainCtx->srvCtx.pKeyOutFormat = NULL;
    pMainCtx->srvCtx.pPkcs8Attrs = NULL;
    pMainCtx->srvCtx.pPkcs8Pass = NULL;
    pMainCtx->srvCtx.pPkcs8EncAlgo = NULL;
    pMainCtx->srvCtx.pPkcs12Attrs = NULL;
    pMainCtx->srvCtx.pPkcs12IntPass = NULL;
    pMainCtx->srvCtx.pPkcs12PriPass = NULL;
    pMainCtx->srvCtx.pPkcs12KeyPass = NULL;
    pMainCtx->srvCtx.pPkcs12EncAlgo = NULL;

#ifdef __ENABLE_DIGICERT_TAP__
    pMainCtx->srvCtx.pKeyUsage = NULL;
    pMainCtx->srvCtx.pSignScheme = NULL;
    pMainCtx->srvCtx.pEncScheme = NULL;
#endif
}

static MSTATUS TRUSTEDGE_ENROLL_getCertRenewalStatus(sbyte *pFile, ubyte4 renewalHours)
{
    MSTATUS status = OK;
    TimeDate t;
    TimeDate certExpiry = {0};
    sbyte4 totalSec;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte4 ndx = 0, i;
    JSON_TokenType token = { 0 }, objToken = {0};
    ubyte4 confLen;
    ubyte *pConf = NULL;
    sbyte *pCertExpiry = NULL;
    sbyte *pOperation = NULL;
    sbyte *pProtocol = NULL;
    E_CertEnrollMode mode;
    ubyte retVal = 0;

    RTOS_timeGMT(&t);

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_readFile(pFile, &pConf, &confLen);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_parse(pJCtx, pConf, confLen, &numTokens);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(pJCtx, 0, PROTOCOL_JSTR, &pProtocol, TRUE);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "protocol field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == DIGI_STRCMP(pProtocol, "SCEP") || 0 == DIGI_STRCMP(pProtocol, SCEP_JSTR))
    {
        mode = SCEP_MODE;
    }
    else if (0 == DIGI_STRCMP(pProtocol, "EST") || 0 == DIGI_STRCMP(pProtocol, EST_JSTR))
    {
        mode = EST_MODE;
    }
    else
    {
        status = ERR_INVALID_ARG;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "protocol field has unrecognized value \"%s\" in request json: %s line %d status: %d = %s\n",
            pProtocol, __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (SCEP_MODE == mode)
    {
        status = JSON_getJsonObjectIndex(
            pJCtx, 0, "scepAttributes", &ndx, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "scepAttributes field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (EST_MODE == mode)
    {
        status = JSON_getJsonObjectIndex(
            pJCtx, 0, "estAttributes", &ndx, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "estAttributes field missing in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = JSON_getJsonStringValue(
        pJCtx, ndx, "operation", &pOperation, TRUE);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "operation field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (((SCEP_MODE == mode) && ((0 == DIGI_STRCMP(PKI_OPERATION_ENROLL, pOperation)) || (0 == DIGI_STRCMP(PKI_OPERATION_RENEW, pOperation)) ||
        (0 == DIGI_STRCMP(PKI_OPERATION_REKEY, pOperation)))) || ((EST_MODE == mode) && (0 != DIGI_STRCMP(EST_CACERTS_CMD, pOperation))))
    {
        status = JSON_getJsonArrayValue(pJCtx, 0, "response", &ndx, &token, TRUE);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "%s line %d status: %d = %s. Unable to read %s attribute\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status), "response");
            goto exit;
        }

        for (i = 0; i < token.elemCnt; i++)
        {
            ndx++;
            status = JSON_getToken(pJCtx, ndx, &objToken);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (JSON_Object != objToken.type)
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            /* variable i tracks which index you're at,
            * if i == token.elemCnt - 1 then this is the last object */

            /* Process each JSON object in the array here */
            (void) DIGI_FREE((void **) &pCertExpiry);
            status = JSON_getJsonStringValue(pJCtx, ndx, "certificateExpiry", &pCertExpiry, TRUE);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "certificateExpiry field missing in response json: %s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            /* Determine index of next item */
            status = JSON_getLastIndexInObject(pJCtx, ndx, &ndx);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        retVal = sscanf(pCertExpiry, "%hu-%hhu-%hhu %hhu:%hhu:%hhu", &certExpiry.m_year, &certExpiry.m_month, &certExpiry.m_day, &certExpiry.m_hour,
                                    &certExpiry.m_minute, &certExpiry.m_second);
        if (retVal != 6)
        {
            status = ERR_JSON_EXPECTED_ELEMENT_NOT_FOUND;
            goto exit;
        }

        certExpiry.m_year -= 1970;

        status = DATETIME_diffTime(&certExpiry, &t, &totalSec);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "DATETIME_diffTime status = %d\n", status);
            goto exit;
        }

        status = (totalSec <= ((sbyte4)renewalHours * 60 * 60)) ? OK : ERR_FALSE;
    }
    else
    {
        status = ERR_FALSE;
    }

exit:
    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    DIGICERT_freeReadFile(&pConf);
    (void) DIGI_FREE((void **) &pCertExpiry);
    (void) DIGI_FREE((void **) &pOperation);
    (void) DIGI_FREE((void **) &pProtocol);
    return status;
}

static MSTATUS TRUSTEDGE_ENROLL_serviceCertRenewalProcess(TrustEdgecertificateMainCtx *pMainCtx, byteBoolean *pHasConf)
{
    MSTATUS status = OK;
    DirectoryDescriptor pDirDesc = NULL;
    DirectoryEntry dirEnt;
    sbyte *pConfFile = NULL;
    sbyte *pConfTmpFile = NULL;
    sbyte *pCertDirPath = NULL;
    sbyte *pUpdatedResource = NULL;
    sbyte *pUpdatedResourcePem = NULL;
    sbyte *pUpdatedResourceDer = NULL;
    sbyte4 cmpRes = -1;

    if ((NULL == pMainCtx) || (NULL == pMainCtx->pTEConfig))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = FMGMT_getFirstFile(pMainCtx->pTEConfig->pServiceCompletedDir, &pDirDesc, &dirEnt);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory doesn't exist: %s  status = %d\n", pMainCtx->pTEConfig->pServiceCompletedDir, status);
        goto exit;
    }

    do
    {
        MSTATUS tmpStatus = OK;
        if (1 == gIsProcessInterrupted)
        {
            break;
        }

        if (FTFile == dirEnt.type)
        {
            (void) DIGI_FREE((void **)&pConfTmpFile);
            status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceCompletedDir, (sbyte *)dirEnt.pName, &pConfTmpFile);
            if (OK != status)
            {
                goto exit;
            }

            if ((dirEnt.nameLength > DIGI_STRLEN(JSON_EXT)) &&
                (OK == DIGI_MEMCMP(dirEnt.pName + dirEnt.nameLength - DIGI_STRLEN(JSON_EXT),
                        JSON_EXT, DIGI_STRLEN(JSON_EXT), &cmpRes)) && (0 == cmpRes))
            {
                tmpStatus = TRUSTEDGE_ENROLL_getCertRenewalStatus(pConfTmpFile, pMainCtx->srvCtx.renewalHours);
                if ((OK != tmpStatus) && (ERR_FALSE != tmpStatus))
                {
                    status = tmpStatus;
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_getCertRenewalStatus: status = %d\n", status);
                }

                if (OK == tmpStatus)
                {
                    *pHasConf = TRUE;
                    (void) DIGI_FREE((void **)&pConfFile);
                    status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceProcessingDir, (sbyte *)dirEnt.pName, &pConfFile);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = DIGICERT_copyFile(pConfTmpFile, pConfFile);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    FMGMT_remove(pConfTmpFile, FALSE);
                }

                if ((OK != tmpStatus) && (ERR_FALSE != tmpStatus))
                {
                    (void) DIGI_FREE((void **)&pConfFile);
                    status = COMMON_UTILS_addPathComponent(pMainCtx->pTEConfig->pServiceProcessingDir, (sbyte *)dirEnt.pName, &pConfFile);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = DIGICERT_copyFile(pConfTmpFile, pConfFile);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    FMGMT_remove(pConfTmpFile, FALSE);

                    pMainCtx->scepCtx.serviceCtx.cmdStatus = scep_FAILURE;
                    pMainCtx->scepCtx.serviceCtx.failInfo = scep_unknownError;
                    status = TRUSTEDGE_ENROLL_serviceResponseProcess(pMainCtx, (sbyte *)dirEnt.pName, TRUE, tmpStatus);
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceResponseProcess: status = %d\n", status);
                    }
                }
            }
        }

        status = FMGMT_getNextFile(pDirDesc,  &dirEnt);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "fetching file inside dir: %s  status = %d\n", pMainCtx->pTEConfig->pServiceCompletedDir, status);
            goto exit;
        }

    } while (FTNone != dirEnt.type);

    status = FMGMT_closeDir (&pDirDesc);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory descriptor can't be closed: %s  status = %d\n", pMainCtx->pTEConfig->pServiceCompletedDir, status);
        goto exit;
    }

    if (FALSE == *pHasConf)
    {
        goto exit;
    }

    status = FMGMT_getFirstFile(pMainCtx->pTEConfig->pServiceProcessingDir, &pDirDesc, &dirEnt);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory doesn't exist: %s  status = %d\n", pMainCtx->pTEConfig->pServiceProcessingDir, status);
        goto exit;
    }
    do
    {
        if (1 == gIsProcessInterrupted)
        {
            break;
        }

        if (FTFile == dirEnt.type)
        {
            status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->srvCtx.pOperation, 6, "renew", 5);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_parseRequestJson: status = %d\n", status);
                goto exit;
            }

            pMainCtx->srvCtx.pOperation[5] = '\0';
            status = TRUSTEDGE_ENROLL_parseRequestJson(pMainCtx, pConfFile, FALSE);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_parseRequestJson: status = %d\n", status);
                goto exit;
            }

            if (SCEP_MODE == pMainCtx->mode)
            {
#if !defined(__DISABLE_TRUSTEDGE_SCEP__)
#ifdef __ENABLE_DIGICERT_TAP__
                status = TRUSTEDGE_SCEP_main(&pMainCtx->keyGenArgs, &pMainCtx->scepCtx, &pMainCtx->srvCtx, &tapArgs);
#else
                status = TRUSTEDGE_SCEP_main(&pMainCtx->keyGenArgs, &pMainCtx->scepCtx, &pMainCtx->srvCtx, NULL);
#endif
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_SCEP_main: status = %d\n", status);
                    pMainCtx->scepCtx.serviceCtx.cmdStatus = scep_FAILURE;
                    pMainCtx->scepCtx.serviceCtx.failInfo = scep_unknownError;
                }
#else
                status = ERR_NOT_IMPLEMENTED;
#endif
            }
            else if (EST_MODE == pMainCtx->mode)
            {
#if !defined(__DISABLE_TRUSTEDGE_SCEP__)
#ifdef __ENABLE_DIGICERT_TAP__
                status = TRUSTEDGE_EST_main(&pMainCtx->keyGenArgs, &pMainCtx->estCtx, &pMainCtx->srvCtx, &tapArgs);
#else
                status = TRUSTEDGE_EST_main(&pMainCtx->keyGenArgs, &pMainCtx->estCtx, &pMainCtx->srvCtx, NULL);
#endif
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_EST_main: status = %d\n", status);
                    pMainCtx->scepCtx.serviceCtx.cmdStatus = ERR_GENERAL;
                }
                else
                {
                    if ((EST_MODE == pMainCtx->mode) && (OK != pMainCtx->estCtx.serviceCtx.cmdStatus))
                    {
                        status = pMainCtx->estCtx.serviceCtx.cmdStatus;
                    }
                }
#else
                status = ERR_NOT_IMPLEMENTED;
#endif
            }

            if (OK == status)
            {
                (void) DIGI_FREE((void **)&pCertDirPath); pCertDirPath = NULL;
                (void) DIGI_FREE((void **)&pUpdatedResource); pUpdatedResource = NULL;
                (void) DIGI_FREE((void **)&pUpdatedResourceDer); pUpdatedResourceDer = NULL;
                status = COMMON_UTILS_addPathComponent(pMainCtx->keyGenArgs.gpKeyStorePath, KEYGEN_FOLDER_CERTS, &pCertDirPath);
                if (OK != status)
                {
                    goto exit;
                }

                if (SCEP_MODE == pMainCtx->mode)
                {
                    status = COMMON_UTILS_addPathComponent(pCertDirPath, pMainCtx->scepCtx.pKeyAlias, &pUpdatedResource);
                }
                else if (EST_MODE == pMainCtx->mode)
                {
                    status = COMMON_UTILS_addPathComponent(pCertDirPath, pMainCtx->estCtx.pKeyAlias, &pUpdatedResource);
                }

                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MALLOC_MEMCPY((void **)&pUpdatedResourceDer, DIGI_STRLEN(pUpdatedResource) + 5, pUpdatedResource, DIGI_STRLEN(pUpdatedResource));
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY(pUpdatedResourceDer + DIGI_STRLEN(pUpdatedResource), ".der", 4);
                if (OK != status)
                {
                    goto exit;
                }

                pUpdatedResourceDer[DIGI_STRLEN(pUpdatedResource) + 4] = '\0';

                if (NULL != pMainCtx->pResourceUpdateHandler)
                {
                    if (ERR_CERT_NOT_FOUND == pMainCtx->pResourceUpdateHandler((sbyte *)pUpdatedResourceDer))
                    {
                        (void) DIGI_FREE((void **)&pUpdatedResourcePem); pUpdatedResourcePem = NULL;
                        status = DIGI_MALLOC_MEMCPY((void **)&pUpdatedResourcePem, DIGI_STRLEN(pUpdatedResource) + 5, pUpdatedResource, DIGI_STRLEN(pUpdatedResource));
                        if (OK != status)
                        {
                            goto exit;
                        }

                        status = DIGI_MEMCPY(pUpdatedResourcePem + DIGI_STRLEN(pUpdatedResource), ".pem", 4);
                        if (OK != status)
                        {
                            goto exit;
                        }

                        pUpdatedResourcePem[DIGI_STRLEN(pUpdatedResource) + 4] = '\0';

                        pMainCtx->pResourceUpdateHandler((sbyte *)pUpdatedResourcePem);
                    }
                }
            }
            else
            {
                goto exit;
            }

            status = TRUSTEDGE_ENROLL_serviceResponseProcess(pMainCtx, (sbyte *)dirEnt.pName, TRUE, status);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceResponseProcess: status = %d\n", status);
            }

            (void) TRUSTEDGE_SCEP_serviceResourceRelease(pMainCtx);
        }

        status = FMGMT_getNextFile(pDirDesc,  &dirEnt);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "fetching file inside dir: %s  status = %d\n", pMainCtx->pTEConfig->pServiceProcessingDir, status);
            goto exit;
        }

    } while (FTNone != dirEnt.type);

    status = FMGMT_closeDir (&pDirDesc);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory descriptor can't be closed: %s  status = %d\n", pMainCtx->pTEConfig->pServiceProcessingDir, status);
        goto exit;
    }

exit:
    if (NULL != pDirDesc)
    {
        if (OK != FMGMT_closeDir(&pDirDesc))
        {
            status = ERR_DIR_CLOSE_FAILED;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "directory descriptor can't be closed: %s or %s  status = %d\n", pMainCtx->pTEConfig->pServiceCompletedDir, pMainCtx->pTEConfig->pServiceProcessingDir, status);
        }
    }

    (void) DIGI_FREE((void **) &pConfTmpFile);
    (void) DIGI_FREE((void **) &pConfFile);
    (void) DIGI_FREE((void **)&pCertDirPath);
    (void) DIGI_FREE((void **)&pUpdatedResource);
    (void) DIGI_FREE((void **)&pUpdatedResourceDer);
    (void) DIGI_FREE((void **)&pUpdatedResourcePem);
    (void) TRUSTEDGE_SCEP_serviceResourceRelease(pMainCtx);
    return status;
}
#endif /* !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__) */

#ifndef __DISABLE_TRUSTEDGE_REST_API__
static MSTATUS TRUSTEDGE_ENROLL_parseKeygenApiJson(TrustEdgecertificateMainCtx *pMainCtx, sbyte *pJsonBuf)
{
    MSTATUS status = OK;
    FileDescriptorInfo fileInfo;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte4 ndx;
    CertEnrollAlg alg = certEnrollAlgUndefined;
    sbyte *pTemp;
    sbyte *pKeySource = NULL;
    sbyte *pKeyUsage = NULL;
    sbyte *pSignScheme = NULL;
    sbyte *pEncScheme = NULL;
    sbyte *pAlgo = NULL;
    sbyte *pKeyOutFormat = NULL;
    sbyte *pKeyAlias = NULL;
    sbyte *pPkcs8Pw = NULL;
#if defined(__ENABLE_DIGICERT_TEE__) || defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    sbyte *pHandle = NULL;
#endif

    if ((NULL == pMainCtx) || (NULL == pJsonBuf))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(pJCtx, pJsonBuf, DIGI_STRLEN(pJsonBuf), &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "keystore", &pMainCtx->keyGenArgs.gpKeyStorePath, TRUE);
    if (OK == status)
    {
        if (NULL != pMainCtx->pTEConfig->pKeystoreDir)
        {
            (void) DIGI_FREE((void **) &pMainCtx->pTEConfig->pKeystoreDir);
        }

        pMainCtx->pTEConfig->pKeystoreDir = pMainCtx->keyGenArgs.gpKeyStorePath;

        if (FALSE == FMGMT_pathExists((const sbyte *)pMainCtx->pTEConfig->pKeystoreDir, &fileInfo))
        {
            status = ERR_PATH_IS_INVALID;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "keystore dir does not exist: \"%s\"\n", pMainCtx->pTEConfig->pKeystoreDir);
            goto exit;
        }

        if (FTDirectory != fileInfo.type)
        {
            status = ERR_DIR_INVALID_PATH;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "keystore path is not a dir: \"%s\"\n", pMainCtx->pTEConfig->pKeystoreDir);
            goto exit;
        }

        status = KEYGEN_validateKeystorePath(pMainCtx->pTEConfig->pKeystoreDir, 0x0F);
        if (OK != status)
        {
            goto exit;
        }

        MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
            "Keystore path validated\n");
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, "keyCertAttributes", &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "keyCertAttributes field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, ndx, "algorithm", &pAlgo, TRUE);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "algorithm field missing in request json: %s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pTemp = pAlgo;
    if ((0 == DIGI_STRNCMP("RSA+2048", pTemp, 8)) || (0 == DIGI_STRNCMP("rsa+2048", pTemp, 8)))
    {
        alg = rsa2048;
        pMainCtx->keyGenArgs.gKeyType = akt_rsa;
        pMainCtx->keyGenArgs.gKeySize = (ubyte4)2048;
    }
    else if ((0 == DIGI_STRNCMP("RSA+3072", pTemp, 8)) || (0 == DIGI_STRNCMP("rsa+3072", pTemp, 8)))
    {
        alg = rsa3072;
        pMainCtx->keyGenArgs.gKeyType = akt_rsa;
        pMainCtx->keyGenArgs.gKeySize = (ubyte4)3072;
    }
    else if ((0 == DIGI_STRNCMP("RSA+4096", pTemp, 8)) || (0 == DIGI_STRNCMP("rsa+4096", pTemp, 8)))
    {
        alg = rsa4096;
        pMainCtx->keyGenArgs.gKeyType = akt_rsa;
        pMainCtx->keyGenArgs.gKeySize = (ubyte4)4096;
    }
    else if ((0 == DIGI_STRNCMP("ECC+P256", pTemp, 8)) || (0 == DIGI_STRNCMP("ecc+p256", pTemp, 8)))
    {
        alg = ecdsaP256;
        pMainCtx->keyGenArgs.gKeyType = akt_ecc;
        pMainCtx->keyGenArgs.gCurve = cid_EC_P256;
    }
    else if ((0 == DIGI_STRNCMP("ECC+P384", pTemp, 8)) || (0 == DIGI_STRNCMP("ecc+p384", pTemp, 8)))
    {
        alg = ecdsaP384;
        pMainCtx->keyGenArgs.gKeyType = akt_ecc;
        pMainCtx->keyGenArgs.gCurve = cid_EC_P384;
    }
    else if ((0 == DIGI_STRNCMP("ECC+P521", pTemp, 8)) || (0 == DIGI_STRNCMP("ecc+p521", pTemp, 8)))
    {
        alg = ecdsaP521;
        pMainCtx->keyGenArgs.gKeyType = akt_ecc;
        pMainCtx->keyGenArgs.gCurve = cid_EC_P521;
    }
        else if ((0 == DIGI_STRNCMP("ECC+CURVE25519", pTemp, 14)) || (0 == DIGI_STRNCMP("ecc+curve25519", pTemp, 14)))
    {
        alg = eddsaEd25519;
        pMainCtx->keyGenArgs.gKeyType = akt_ecc;
        pMainCtx->keyGenArgs.gCurve = cid_EC_Ed25519;

    }
    else if ((0 == DIGI_STRNCMP("ECC+CURVE448", pTemp, 12)) || (0 == DIGI_STRNCMP("ecc+curve448", pTemp, 12)))
    {
        alg = eddsaEd448;
        pMainCtx->keyGenArgs.gKeyType = akt_ecc;
        pMainCtx->keyGenArgs.gCurve = cid_EC_Ed448;
    }

    if (certEnrollAlgUndefined == alg)
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_ALGO;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_utilsReadJsonStrAllowNull(
        pJCtx, ndx, "keyAlias", &pKeyAlias);
    if ((OK != status) || (NULL == pKeyAlias) || (0 == DIGI_STRCMP(pKeyAlias, "")))
    {
        status = DIGI_MALLOC_MEMCPY((void **)&pMainCtx->keyGenArgs.gpOutFile, DIGI_STRLEN(gpKeyAliasDefault) + 1, gpKeyAliasDefault, DIGI_STRLEN(gpKeyAliasDefault));
        if (OK != status)
        {
            goto exit;
        }

        pMainCtx->keyGenArgs.gpOutFile[DIGI_STRLEN(gpKeyAliasDefault)] = '\0';
    }
    else
    {
        pMainCtx->keyGenArgs.gpOutFile = pKeyAlias;
        pKeyAlias = NULL;
    }

    pMainCtx->keyGenArgs.gTap = FALSE;
    status = JSON_getJsonStringValue(
        pJCtx, ndx, "keySource", &pKeySource, TRUE);
    if ((OK == status) && (NULL != pKeySource) && (0 != DIGI_STRCMP(pKeySource, "")))
    {
        if (0 == DIGI_STRCMP(pKeySource, KEY_SOURCE_SW))
        {
            pMainCtx->keyGenArgs.gTap = FALSE;
        }
#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TEE__
        else if (0 == DIGI_STRCMP(pKeySource, KEY_SOURCE_TEE))
        {
            pMainCtx->keyGenArgs.gTap = TRUE;
            pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_TEE;

            status = JSON_getJsonObjectIndex(
                pJCtx, 0, "TAPAttributes", &ndx, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonObjectIndex(pJCtx, ndx, "handles", &ndx, TRUE);
                if (OK == status)
                {
                    status = JSON_getJsonStringValue(
                        pJCtx, ndx, "key", &pHandle, TRUE);
                    if (OK == status)
                    {
                        status = KEYGEN_readId((sbyte *) pHandle, &(pMainCtx->keyGenArgs.tapKeyHandle), NULL);
                        if (OK != status)
                        {
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key handle in request json, status = %s (%d)\n",
                                    MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                    }
                    else if (ERR_NOT_FOUND != status)
                    {
                        goto exit;
                    }
                    else
                    {
                        status = OK;
                    }
                }
                else if (ERR_NOT_FOUND != status)
                {
                    goto exit;
                }
                else
                {
                    status = OK;
                }
            }
            /* TODO do we error if no handle? */
        }
#elif __ENABLE_DIGICERT_SMP_NANOROOT__
        else if (0 == DIGI_STRCMP(pKeySource, KEY_SOURCE_NANOROOT))
        {
            pMainCtx->keyGenArgs.gTap = TRUE;
            pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_NANOROOT;

            status = JSON_getJsonObjectIndex(
                pJCtx, 0, "TAPAttributes", &ndx, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonObjectIndex(pJCtx, ndx, "handles", &ndx, TRUE);
                if (OK == status)
                {
                    status = JSON_getJsonStringValue(
                        pJCtx, ndx, "key", &pHandle, TRUE);
                    if (OK == status)
                    {
                        status = KEYGEN_readId((sbyte *) pHandle, &(pMainCtx->keyGenArgs.tapKeyHandle), NULL);
                        if (OK != status)
                        {
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Failed to process key handle in request json, status = %s (%d)\n",
                                    MERROR_lookUpErrorCode(status), status);
                            goto exit;
                        }
                    }
                    else if (ERR_NOT_FOUND != status)
                    {
                        goto exit;
                    }
                    else
                    {
                        status = OK;
                    }
                }
                else if (ERR_NOT_FOUND != status)
                {
                    goto exit;
                }
                else
                {
                    status = OK;
                }
            }
            /* TODO do we error if no handle? */
        }
#else
        else if (0 == DIGI_STRCMP(pKeySource, KEY_SOURCE_TPM2) || 0 == DIGI_STRCMP(pKeySource, KEY_SOURCE_PKCS11))
        {
            pMainCtx->keyGenArgs.gTap = TRUE;

            if (0 == DIGI_STRCMP(pKeySource, KEY_SOURCE_TPM2))
            {
                pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_TPM2;
            }
            else /* PKCS11 */
            {
                pMainCtx->keyGenArgs.gTapProvider = TAP_PROVIDER_PKCS11;
            }

            if ((0 == DIGI_STRCMP(pMainCtx->pOutputMode, "buffered")) || (0 == DIGI_STRCMP(pMainCtx->pOutputMode, "BUFFERED")))
            {
                status = ERR_INVALID_INPUT;
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "outputMode cannot be buffered with TPM2 key: %s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = JSON_getJsonObjectIndex(
                pJCtx, 0, "TAPAttributes", &ndx, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonIntegerValue(
                    pJCtx, ndx, "tapProvider", &pMainCtx->srvCtx.tapProvider, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gTapProvider = pMainCtx->srvCtx.tapProvider;
                }

                status = JSON_getJsonIntegerValue(
                    pJCtx, ndx, "secureModuleId", &pMainCtx->keyGenArgs.gModNum, TRUE);

                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "keyUsage", &pKeyUsage, TRUE);
                if (OK == status)
                {
                    if (0 == DIGI_STRCMP(pKeyUsage, (sbyte *)"TAP_KEY_USAGE_SIGNING"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_SIGNING;
                    }
                    else if (0 == DIGI_STRCMP(pKeyUsage, (sbyte *)"TAP_KEY_USAGE_DECRYPT"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_DECRYPT;
                    }
                    else if (0 == DIGI_STRCMP(pKeyUsage, (sbyte *)"TAP_KEY_USAGE_ATTESTATION"))
                    {
                        pMainCtx->keyGenArgs.gKeyUsage = TAP_KEY_USAGE_ATTESTATION;
                    }
                    else if (0 != DIGI_STRCMP(pKeyUsage, (sbyte *)"TAP_KEY_USAGE_GENERAL"))
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                            "keyUsage field invalid in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "sigScheme", &pSignScheme, TRUE);
                if (OK == status)
                {
                    if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PKCS1_5_DER"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA256;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA384;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_PSS_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_PSS_SHA512;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA224"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                    }
                    else if (0 == DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_ECDSA_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gSigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                    }
                    else if (0 != DIGI_STRCMP(pSignScheme, (sbyte *)"TAP_SIG_SCHEME_NONE"))
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                            "sigScheme field invalid in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }

                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "encScheme", &pEncScheme, TRUE);
                if (OK == status)
                {
                    if (0 == DIGI_STRCMP(pEncScheme, (sbyte *)"TAP_ENC_SCHEME_PKCS1_5"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_PKCS1_5;
                    }
                    else if (0 == DIGI_STRCMP(pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA1"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                    }
                    else if (0 == DIGI_STRCMP(pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA256"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                    }
                    else if (0 == DIGI_STRCMP(pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA384"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                    }
                    else if (0 == DIGI_STRCMP(pEncScheme, (sbyte *)"TAP_ENC_SCHEME_OAEP_SHA512"))
                    {
                        pMainCtx->keyGenArgs.gEncScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                    }
                    else if (0 != DIGI_STRCMP(pEncScheme, (sbyte *)"TAP_ENC_SCHEME_NONE"))
                    {
                        status = ERR_INVALID_ARG;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                            "encScheme field invalid in request json: %s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }
            }
        }
#endif /* __ENABLE_DIGICERT_TEE__ */
#endif /* __ENABLE_DIGICERT_TAP__ */
        else
        {
            status = ERR_INVALID_ARG;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "keySource field invalid in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = JSON_getJsonStringValue(
        pJCtx, ndx, "keyOutFormat", &pKeyOutFormat, TRUE);
    if (OK == status)
    {
        if (0 == DIGI_STRCMP(pKeyOutFormat, (sbyte*)"pkcs8") || 0 == DIGI_STRCMP(pKeyOutFormat, (sbyte*)"PKCS8"))
        {
            status = JSON_getJsonObjectIndex(
                pJCtx, 0, "pkcs8Attributes", &ndx, TRUE);
            if (OK == status)
            {
                status = JSON_getJsonStringValue(
                    pJCtx, ndx, "password", (sbyte **)&pPkcs8Pw, TRUE);
                if (OK == status)
                {
                    pMainCtx->keyGenArgs.gpPkcs8Pw = pPkcs8Pw;
                    pMainCtx->keyGenArgs.gPkcs8PwLen = DIGI_STRLEN(pMainCtx->keyGenArgs.gpPkcs8Pw);
                    pPkcs8Pw = NULL;
                }
            }
        }
        else
        {
            status = ERR_INVALID_ARG;
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "keyOutFormat field invalid in request json: %s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = OK;
exit:
    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }
    if (NULL != pKeySource)
    {
        (void) DIGI_FREE((void **)&pKeySource);
    }
    if (NULL != pKeyUsage)
    {
        (void) DIGI_FREE((void **)&pKeyUsage);
    }
    if (NULL != pSignScheme)
    {
        (void) DIGI_FREE((void **)&pSignScheme);
    }
    if (NULL != pEncScheme)
    {
        (void) DIGI_FREE((void **)&pEncScheme);
    }
    if (NULL != pAlgo)
    {
        (void) DIGI_FREE((void **)&pAlgo);
    }
    if (NULL != pKeyOutFormat)
    {
        (void) DIGI_FREE((void **)&pKeyOutFormat);
    }
    if (NULL != pKeyAlias)
    {
        (void) DIGI_FREE((void **)&pKeyAlias);
    }
    if (NULL != pPkcs8Pw)
    {
        (void) DIGI_FREE((void **)&pPkcs8Pw);
    }
#if defined(__ENABLE_DIGICERT_TEE__) || defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    if (NULL != pHandle)
    {
        (void) DIGI_FREE((void **) &pHandle);
    }
#endif
    return status;
}
#endif

static void TRUSTEDGE_certificateMainRelease(
    TrustEdgecertificateMainCtx *pMainCtx)
{
    KeyGenArgs *pArgs = (KeyGenArgs *) &pMainCtx->keyGenArgs;

    if (NULL != pArgs->gpInCsrBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pArgs->gpInCsrBuffer, pArgs->gInCsrLen);
    }
    if (NULL != pArgs->gpSigningCertBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pArgs->gpSigningCertBuffer, pArgs->gSigningCertLen);
    }
    if (NULL != pArgs->gpSigningKeyBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pArgs->gpSigningKeyBuffer, pArgs->gSigningKeyLen);
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (pArgs->gIsCvc)
    {
        if (NULL != pArgs->gCvcData.pSignerKey && (uintptr) pArgs->gCvcData.pSignerKey != (uintptr) pArgs->gCvcData.pCertKey)
        {
            (void) CRYPTO_uninitAsymmetricKey(pArgs->gCvcData.pSignerKey, NULL);
            (void) DIGI_FREE((void **) &pArgs->gCvcData.pSignerKey);
        }

        if (NULL != pArgs->gCvcData.pSignerAuthRef)
        {
            (void) DIGI_FREE((void **) &pArgs->gCvcData.pSignerAuthRef);
        }

        if (NULL != pArgs->gCvcData.pCertHolderAuthTemplate)
        {
            (void) DIGI_FREE((void **) &pArgs->gCvcData.pCertHolderAuthTemplate);
        }

        if (NULL != pArgs->gCvcData.pExtensions)
        {
            (void) DIGI_FREE((void **) &pArgs->gCvcData.pExtensions);
        }
    }
#endif

    KEYGEN_resetArgs(pArgs);

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_CERTIFICATE_DEBUG_INTERNALS__) || defined(__ENABLE_DIGICERT_TRUSTEDGE_DEBUG_STATE__)
    DIGI_FREE((void **) &pMainCtx->pDebugDir);
#endif
}

int TRUSTEDGE_certificateMain(int argc, char *ppArgv[], sbyte *pEnrollMode, E_TEAgentMode operatingMode, TrustEdgeConfig **ppConfig)
{
    MSTATUS status = OK, tmpStatus = OK;
    TrustEdgecertificateMainCtx mainCtx = { 0 };
    AsymmetricKey key = {0};
    randomContext *pRand = NULL;
    ubyte keyStoreBitMap = 0;

    if (NULL == ppConfig || NULL == *ppConfig)
    {
        status = ERR_TRUSTEDGE_NO_CONFIG_FILE;
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "TRUSTEDGE_certificateMain failed, missing trustedge config, status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (TE_AGENT_REST_API_MODE == operatingMode)
    {
        if (NULL == gRestApiCtx.pJsonBuf)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "TRUSTEDGE_certificateMain failed, empty HTTP POST request body, status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }
#endif

    /* This mutex is freed at the end of this function, please make sure we don't return anywhere between before releasing it */
    RTOS_mutexWait(TRUSTEDGE_getCertMutex());
    /* Initialize default */
    mainCtx.logLevel = MSG_LOG_getLevel();
    mainCtx.isValidTEConfig = TRUE;
    mainCtx.pTEConfig = *ppConfig;
    *ppConfig = NULL;
#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    mainCtx.pResourceUpdateHandler = TRUSTEDGE_ENROLL_resourceUpdateHandler;
    mainCtx.srvCtx.sleepInterval = mainCtx.pTEConfig->pollingInterval;
    mainCtx.srvCtx.renewalHours = mainCtx.pTEConfig->renewalHours;
#endif
    KEYGEN_resetArgs(&mainCtx.keyGenArgs);

    if (MSG_LOG_VERBOSE == mainCtx.logLevel)
    {
        /* also set verbose flag for underlying keygen code */
        mainCtx.keyGenArgs.gVerbose = TRUE;
    }

    if (NULL == pEnrollMode)
    {
        mainCtx.mode = CERT_MODE;
        MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
            "Certificate mode running\n");
    }
#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    else
    {
        if (0 == DIGI_STRCMP(pEnrollMode, SCEP_JSTR))
        {
            mainCtx.mode = SCEP_MODE;
            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
                "Certificate scep mode running\n");
        }
        else if (0 == DIGI_STRCMP(pEnrollMode, EST_JSTR))
        {
            mainCtx.mode = EST_MODE;
            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
                "Certificate est mode running\n");
        }
    }

    if ((TE_AGENT_DAEMON_MODE == operatingMode) || (TE_AGENT_REST_API_MODE == operatingMode))
    {
        if (SCEP_MODE == mainCtx.mode)
        {
            mainCtx.scepCtx.serviceCtx.serviceMode = TRUE;
        }
        else if (EST_MODE == mainCtx.mode)
        {
            mainCtx.estCtx.serviceCtx.serviceMode = TRUE;
        }
#ifndef __DISABLE_TRUSTEDGE_REST_API__
        else if (CERT_MODE == mainCtx.mode)
        {
            mainCtx.isKeyGenApiOp = TRUE;
            mainCtx.pOutputMode = gRestApiCtx.pOutputMode;
            status = TRUSTEDGE_ENROLL_parseKeygenApiJson(&mainCtx, gRestApiCtx.pJsonBuf);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_parseKeygenApiJson failed, error code = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
#endif
    }

    if (SCEP_MODE == mainCtx.mode)
    {
        mainCtx.scepCtx.serviceCtx.maxRetryCount = mainCtx.pTEConfig->maxRetryCountCertEnroll;
        mainCtx.scepCtx.serviceCtx.reuseKey = TRUE;
    }
    else if (EST_MODE == mainCtx.mode)
    {
        mainCtx.estCtx.serviceCtx.maxRetryCount = mainCtx.pTEConfig->maxRetryCountCertEnroll;
        mainCtx.estCtx.serviceCtx.reuseKey = TRUE;
        mainCtx.estCtx.pTrustPath = mainCtx.pTEConfig->pKeystoreCADir;
        mainCtx.estCtx.requirePQC = mainCtx.pTEConfig->requirePQC;
#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
        if (NULL != mainCtx.pTEConfig->pProxyUrl)
        {
            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE",
                "proxy URL found: %s\n", mainCtx.pTEConfig->pProxyUrl);
            status = HTTP_PROXY_setProxyUrlAndPort(mainCtx.pTEConfig->pProxyUrl);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "Unable to process proxy URL from config file, failed with status  = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
#endif
    }
#endif

    MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
        "Processing certificate arguments\n");

    status = TRUSTEDGE_certificateMainProcessArgs(argc, (sbyte**) ppArgv, &mainCtx);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
            "TRUSTEDGE_certificateMainProcessArgs failed with status = %s (%d)\n",
            MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    if (TRUE == mainCtx.exit)
    {
        MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
            "Exiting certificate mode\n");
        goto exit;
    }

    if (CERT_MODE == mainCtx.mode)
    {
        if ((NULL != mainCtx.keyGenArgs.gpOutCertFile))
        {
            keyStoreBitMap |= KEYGEN_KEYSTORE_CERTS_MASK;
        }

        if ((NULL != mainCtx.keyGenArgs.gpOutFile))
        {
            keyStoreBitMap |= KEYGEN_KEYSTORE_KEYS_MASK;
        }

        if ((FALSE != mainCtx.keyGenArgs.gCreateCsr))
        {
            keyStoreBitMap |= KEYGEN_KEYSTORE_REQ_MASK;
        }

        if ((NULL != mainCtx.keyGenArgs.gpInCsrFile))
        {
            keyStoreBitMap |= KEYGEN_KEYSTORE_CONF_MASK;
        }

        status = KEYGEN_validateKeystorePath(mainCtx.keyGenArgs.gpKeyStorePath, keyStoreBitMap);
        if (OK != status)
        {
            goto exit;
        }

        MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
            "Keystore path validated\n");
    }

    /******  TAP INITIALIZATION *******/

#ifdef __ENABLE_DIGICERT_TAP__
        status = TAP_checkProviderModule(&mainCtx);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                "TAP_checkProviderModule failed with status = %s (%d)\n",
                MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
#endif /* __ENABLE_DIGICERT_TAP__ */

    /******  CV CERT PRINT ONLY *******/
#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (mainCtx.keyGenArgs.gIsPrintCVCert)
    {
        status = KEYGEN_printCvCertificate(&mainCtx.keyGenArgs);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to parse and print entire CV Certificate: %s  status = %d\n", mainCtx.keyGenArgs.gpSigningCert ,status);
        }

        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
if (mainCtx.keyGenArgs.gIsPrintCert)
{
    status = KEYGEN_printCertificateOrCsr(&mainCtx.keyGenArgs);
    if (status == ERR_INVALID_INPUT)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "%s is not a Certificate/CSR.  status = %d\n", mainCtx.keyGenArgs.gpSigningCert ,status);
    }
    else if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to parse and print entire Certificate/CSR: %s  status = %d\n", mainCtx.keyGenArgs.gpSigningCert ,status);
    }

    goto exit;
}
#endif

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    /****** ENROLL MODE (SCEP/EST) ******/
    if ((SCEP_MODE == mainCtx.mode) || (EST_MODE == mainCtx.mode))
    {
        byteBoolean hasRequestJson = TRUE;
        byteBoolean hasCompletedJson = FALSE;
        if (TE_AGENT_CLI_MODE == operatingMode)
        {
            keyStoreBitMap = 0xFF;
            status = KEYGEN_validateKeystorePath(mainCtx.keyGenArgs.gpKeyStorePath, keyStoreBitMap);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE",
                    "TRUSTEDGE_EST_main::KEYGEN_validateKeystorePath failed with status  = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
                goto exit;
            }

            MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
                "Keystore path validated\n");
        }

        /* Daemon mode loop starts here */
        do
        {
            tmpStatus = ERR_GENERAL;
            if ((TE_AGENT_DAEMON_MODE == operatingMode))
            {
                hasRequestJson = FALSE;
#ifdef __ENABLE_DIGICERT_TAP__
                status = TRUSTEDGE_ENROLL_serviceRequestProcess(&mainCtx, &hasRequestJson);
#else
                status = TRUSTEDGE_ENROLL_serviceRequestProcess(&mainCtx, &hasRequestJson);
#endif
                if (OK != status)
                {
                    MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceRequestProcess: status = %d\n", status);
                    if (TRUE == mainCtx.isInvalidSrvDir)
                    {
                        goto exit;
                    }

                    if (NULL != mainCtx.srvCtx.pReqFile)
                    {
                        if (OK != status)
                        {
                            mainCtx.scepCtx.serviceCtx.cmdStatus = scep_FAILURE;
                            mainCtx.scepCtx.serviceCtx.failInfo = scep_unknownError;
                        }

                        MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
                            "processing response\n");
                        tmpStatus = TRUSTEDGE_ENROLL_serviceResponseProcess(&mainCtx, mainCtx.srvCtx.pReqFile, FALSE, status);
                        if (OK != tmpStatus)
                        {
                            status = tmpStatus;
                            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceResponseProcess: status = %d\n", status);
                        }
                    }
                }
            }

            if (TRUE == hasRequestJson)
            {
#ifndef __DISABLE_TRUSTEDGE_SCEP__
                if (SCEP_MODE == mainCtx.mode && OK == status)
                {
#ifndef __DISABLE_TRUSTEDGE_REST_API__
                    if (TE_AGENT_REST_API_MODE == operatingMode)
                    {
#ifdef __ENABLE_DIGICERT_TAP__
                        status = TRUSTEDGE_ENROLL_parseRequestJson(&mainCtx, gRestApiCtx.pJsonBuf, TRUE);
#else
                        status = TRUSTEDGE_ENROLL_parseRequestJson(&mainCtx, gRestApiCtx.pJsonBuf, TRUE);
#endif
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR, "TRUSTEDGE_ENROLL_parseRequestJson: status = %d\n", status);
                            goto exit;
                        }
                    }
#endif

#ifdef __ENABLE_DIGICERT_TAP__
                    status = TRUSTEDGE_SCEP_main(&mainCtx.keyGenArgs, &mainCtx.scepCtx, &mainCtx.srvCtx, (void *) &tapArgs);
#else
                    status = TRUSTEDGE_SCEP_main(&mainCtx.keyGenArgs, &mainCtx.scepCtx, &mainCtx.srvCtx, NULL);
#endif
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_SCEP_main: status = %d\n", status);
                    }
                }
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
                if (EST_MODE == mainCtx.mode && OK == status)
                {
#ifndef __DISABLE_TRUSTEDGE_REST_API__
                    if (TE_AGENT_REST_API_MODE == operatingMode)
                    {
#ifdef __ENABLE_DIGICERT_TAP__
                        status = TRUSTEDGE_ENROLL_parseRequestJson(&mainCtx, gRestApiCtx.pJsonBuf, TRUE);
#else
                        status = TRUSTEDGE_ENROLL_parseRequestJson(&mainCtx, gRestApiCtx.pJsonBuf, TRUE);
#endif
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR, "TRUSTEDGE_ENROLL_parseRequestJson: status = %d\n", status);
                            goto exit;
                        }
                    }
#endif

#ifdef __ENABLE_DIGICERT_TAP__
                    status = TRUSTEDGE_EST_main(&mainCtx.keyGenArgs, &mainCtx.estCtx, &mainCtx.srvCtx, (void *) &tapArgs);
#else
                    status = TRUSTEDGE_EST_main(&mainCtx.keyGenArgs, &mainCtx.estCtx, &mainCtx.srvCtx, NULL);
#endif
                    if (OK != status)
                    {
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_EST_main: status = %d\n", status);
                    }
                }
#endif
                if ((TE_AGENT_DAEMON_MODE == operatingMode) && (NULL != mainCtx.srvCtx.pReqFile))
                {
                    if (OK != status)
                    {
                        if (SCEP_MODE == mainCtx.mode)
                        {
                            mainCtx.scepCtx.serviceCtx.cmdStatus = scep_FAILURE;
                            mainCtx.scepCtx.serviceCtx.failInfo = scep_unknownError;
                        }
                    }
                    else
                    {
                        if ((EST_MODE == mainCtx.mode) && (OK != mainCtx.estCtx.serviceCtx.cmdStatus))
                        {
                            status = mainCtx.estCtx.serviceCtx.cmdStatus;
                        }
                    }

                    tmpStatus = TRUSTEDGE_ENROLL_serviceResponseProcess(&mainCtx, mainCtx.srvCtx.pReqFile, FALSE, status);
                    if (OK != tmpStatus)
                    {
                        status = tmpStatus;
                        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceResponseProcess: status = %d\n", status);
                    }
                }

                if ((TE_AGENT_CLI_MODE == operatingMode) || (1 == gIsProcessInterrupted))
                {
                    break;
                }

                (void) TRUSTEDGE_SCEP_serviceResourceRelease(&mainCtx);
            }

            hasCompletedJson = FALSE;

#ifdef __ENABLE_DIGICERT_TAP__
            tmpStatus = TRUSTEDGE_ENROLL_serviceCertRenewalProcess(&mainCtx, &hasCompletedJson);
#else
            tmpStatus = TRUSTEDGE_ENROLL_serviceCertRenewalProcess(&mainCtx, &hasCompletedJson);
#endif
            if (OK != tmpStatus)
            {
                status = tmpStatus;
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceCertRenewalProcess: status = %d\n", status);
            }

            if (TE_AGENT_DAEMON_MODE == operatingMode && mainCtx.pTEConfig->exitClient == FALSE)
            {
                RTOS_mutexRelease(TRUSTEDGE_getCertMutex());
                RTOS_sleepMS(mainCtx.srvCtx.sleepInterval * 1000);
                RTOS_mutexWait(TRUSTEDGE_getCertMutex());
            }
            else
            {
                /* If mode other than daemon mode, we break out after performing one operation */
                break;
            }
        } while (0 == gIsProcessInterrupted);
        goto exit;
    }
#endif

    /****** CSR CREATION ******/

    if (mainCtx.keyGenArgs.gCreateCsr)
    {
        /* different flow for CSR creation, no keygen */
        status = KEYGEN_createCSR(&mainCtx.keyGenArgs);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to generate signed CSR, error code = %s (%d)\n",
                       MERROR_lookUpErrorCode(status), status);
        }
        goto exit;
    }

    /****** TRADITIONAL KEY (AND CERT) CREATION ******/

    MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
        "Generating key...\n");

    status = RANDOM_acquireContext(&pRand);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "RANDOM_acquireContext, error code = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "CRYPTO_initAsymmetricKey, error code = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_SMP_NANOROOT__
    if (FALSE == mainCtx.keyGenArgs.gTap) /* for NanoRoot we don't actually generate a key */
#endif
    {
        status = KEYGEN_generateKey(&mainCtx.keyGenArgs, (void *) &tapArgs, &key, pRand);
    }
#else
    status = KEYGEN_generateKey(&mainCtx.keyGenArgs, NULL, &key, pRand);
#endif
    if (OK != status)
    {
        MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to generate key, error code = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
        goto exit;
    }

#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if (TRUE == mainCtx.isKeyGenApiOp)
    {
        if ((0 == DIGI_STRCMP(mainCtx.pOutputMode, "file")) || (0 == DIGI_STRCMP(mainCtx.pOutputMode, "FILE")))
        {
            status = KEYGEN_outputPrivKey(&mainCtx.keyGenArgs, &key, pRand, FALSE, NULL, NULL);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to output private key, error code = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else
        {
            serializedKeyFormat privForm = privateKeyPem;
            status = CRYPTO_serializeAsymKey(&key, privForm, &gRestApiCtx.pKeyBuf, &gRestApiCtx.privLen);
            if (OK != status)
            {
                goto exit;
            }
        }
    }
    else
#endif
    {
        status = KEYGEN_outputPrivKey(&mainCtx.keyGenArgs, &key, pRand, FALSE, NULL, NULL);
        if (OK != status)
        {
            MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to output private key, error code = %s (%d)\n",
                        MERROR_lookUpErrorCode(status), status);
            goto exit;
        }
    }

    MSG_LOG_printEx(MSG_LOG_VERBOSE, "TRUSTEDGE-CERTIFICATE", "%s",
        "Key generated successfully\n");

    if (NULL != mainCtx.keyGenArgs.gpOutCertFile)
    {
#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (mainCtx.keyGenArgs.gIsCvc)
        {
            status = KEYGEN_generateCvCertificate(&mainCtx.keyGenArgs, &key); /* TODO may want to pass in pRand someday */
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to generate cv certificate, error code = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
        else
#endif
        {
            status = KEYGEN_generateCertificate(&mainCtx.keyGenArgs, &key, pRand, NULL, NULL);
            if (OK != status)
            {
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "Unable to generate certificate, error code = %s (%d)\n",
                            MERROR_lookUpErrorCode(status), status);
                goto exit;
            }
        }
    }

    if (NULL != mainCtx.keyGenArgs.gpOutPubFile)
    {
#ifdef __ENABLE_DIGICERT_PQC__
        if (akt_qs == mainCtx.keyGenArgs.gKeyType)
        {
            MSG_LOG_printEx(MSG_LOG_WARNING, "TRUSTEDGE-CERTIFICATE", "Not outputting public key for QS alg. This feature is not yet supported.%s", "\n");
        }
        else
#endif
        {
            status = KEYGEN_outputPubKey(&mainCtx.keyGenArgs, &key);
        }
    }

exit:

#if defined(__ENABLE_DIGICERT_HTTP_PROXY__)
    (void) HTTP_PROXY_freeProxyUrl();
#endif

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    if (1 == gIsProcessInterrupted)
    {
        MSG_LOG_printEx(MSG_LOG_INFO, "TRUSTEDGE-CERTIFICATE", "Exiting certificate mode: status = %s (%d)\n",
                    MERROR_lookUpErrorCode(status), status);
    }
#endif

#ifndef __DISABLE_TRUSTEDGE_REST_API__
    if ((CERT_MODE == mainCtx.mode) && (TRUE == mainCtx.isKeyGenApiOp))
    {
        (void) DIGI_FREE((void **)&mainCtx.keyGenArgs.gpOutFile);
        mainCtx.keyGenArgs.gpOutFile = NULL;

        (void) DIGI_FREE((void **)&mainCtx.keyGenArgs.gpPkcs8Pw);
        mainCtx.keyGenArgs.gpPkcs8Pw = NULL;
    }
#endif

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
    if (CERT_MODE != mainCtx.mode)
    {
        if ((NULL != mainCtx.srvCtx.pReqFile) && (OK != status))
        {
            if (SCEP_MODE == mainCtx.mode)
            {
                mainCtx.scepCtx.serviceCtx.cmdStatus = scep_FAILURE;
                mainCtx.scepCtx.serviceCtx.failInfo = scep_unknownError;
            }
            tmpStatus = TRUSTEDGE_ENROLL_serviceResponseProcess(&mainCtx, mainCtx.srvCtx.pReqFile, FALSE, status);
            if (OK != tmpStatus)
            {
                status = tmpStatus;
                MSG_LOG_printEx(MSG_LOG_ERROR, "TRUSTEDGE-CERTIFICATE", "TRUSTEDGE_ENROLL_serviceResponseProcess: status = %d\n", status);
            }
        }
        (void) TRUSTEDGE_SCEP_serviceResourceRelease(&mainCtx);
    }
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
    if (EST_MODE == mainCtx.mode && TRUE == mainCtx.estCtx.isEnteredPass)
    {
        (void) DIGI_FREE((void **)&mainCtx.estCtx.pUserPasswd);
    }
    if (EST_MODE == mainCtx.mode && TRUE == mainCtx.estCtx.pkcs8InteractivePass)
    {
        (void) DIGI_FREE((void **)&mainCtx.estCtx.pPkcs8Pw);
    }
    if (EST_MODE == mainCtx.mode && TRUE == mainCtx.estCtx.estEndpointProvided && FALSE == mainCtx.estCtx.serviceCtx.serviceMode)
    {
        if (NULL != mainCtx.estCtx.pServerName)
        {
            (void) DIGI_FREE((void **)&mainCtx.estCtx.pServerName);
        }
        if (NULL != mainCtx.estCtx.pUrl)
        {
            (void) DIGI_FREE((void **)&mainCtx.estCtx.pUrl);
        }
    }
#if defined(__ENABLE_DIGICERT_TAP__)
    if (EST_MODE == mainCtx.mode && NULL != mainCtx.estCtx.tapKeyHandle.pBuffer)
    {
        (void) DIGI_FREE((void **)&mainCtx.estCtx.tapKeyHandle.pBuffer);
    }
#endif
#endif
    (void) RANDOM_releaseContext(&pRand);
    if (NULL != mainCtx.pTEConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&mainCtx.pTEConfig);
    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (mainCtx.keyGenArgs.gIsCvc)
    {
        if (NULL != mainCtx.keyGenArgs.gCvcData.pSignerKey && (uintptr) mainCtx.keyGenArgs.gCvcData.pSignerKey != (uintptr) mainCtx.keyGenArgs.gCvcData.pCertKey)
        {
            (void) CRYPTO_uninitAsymmetricKey(mainCtx.keyGenArgs.gCvcData.pSignerKey, NULL);
            (void) DIGI_FREE((void **) &mainCtx.keyGenArgs.gCvcData.pSignerKey);
        }

        if (NULL != mainCtx.keyGenArgs.gCvcData.pSignerAuthRef)
        {
            (void) DIGI_FREE((void **) &mainCtx.keyGenArgs.gCvcData.pSignerAuthRef);
        }

        if (NULL != mainCtx.keyGenArgs.gCvcData.pCertHolderAuthTemplate)
        {
            (void) DIGI_FREE((void **) &mainCtx.keyGenArgs.gCvcData.pCertHolderAuthTemplate);
        }

        if (NULL != mainCtx.keyGenArgs.gCvcData.pExtensions)
        {
            (void) DIGI_FREE((void **) &mainCtx.keyGenArgs.gCvcData.pExtensions);
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TEE__) && !defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    /* If the generated key is a TAP key and was not used to sign a (self signed) cert, it needs to be unloaded */
    if ((CERT_MODE == mainCtx.mode) && mainCtx.keyGenArgs.gTap && (NULL == mainCtx.keyGenArgs.gpOutCertFile || (NULL != mainCtx.keyGenArgs.gpOutCertFile && NULL != mainCtx.keyGenArgs.gpSigningKey)))
    {
        TRUSTEDGE_TAP_unloadKey(&key);
    }
#endif
    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    (void) TRUSTEDGE_certificateMainRelease(&mainCtx);
    RTOS_mutexRelease(TRUSTEDGE_getCertMutex());
    return (OK == status) ? 0 : -1;
}
