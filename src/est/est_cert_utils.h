/**
 * @file  est_cert_utils.h
 * @brief EST certificate utility functions header.
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

#ifndef __EST_CERT_UTILS_HEADER__
#define __EST_CERT_UTILS_HEADER__

#include "../common/moptions.h"
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix
 *
 * Issue: The header file mqtt_client.h includes merrors.h and redefines OK to
 * MOC_OK for ESP32 builds. The ssl.h header below includes a ESP32 toolchain
 * header file which also defines OK which then gets redefined to MOC_OK causing
 * compilation errors.
 *
 * Fix: Undefine OK before including ssl.h, then redefine it back to MOC_OK
 */
#undef OK
#endif
#include "../common/moc_net_system.h"
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix - see comment above */
#define OK MOC_OK
#endif
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/moc_net.h"
#include "../common/mdefs.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mocana.h"
#include "../common/absstream.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../common/sizedbuffer.h"
#include "../common/tree.h"
#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"
#include "../common/vlong.h"
#include "../common/random.h"
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
#include "../common/msg_logger.h"
#endif
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/keyblob.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../ssl/ssl.h"
#include "../http/http_context.h"
#include "../est/est_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define  EST_RAUTH_CN       "EstRAuthority"
#define  EST_RAUTH_CN_LEN   (13)
#define  EST_SERVER_CN		"EstServer"
#define  EST_CN		        "webapptap.securitydemos.net"
#define  EST_CN_LEN         (27)


#define  CISCO_GEN_CA_CERT 	"Est_intermediateCA.der"
#define  EST_CISCO_ATTRS    "Est_attrs.der"
#define  EST_CERT	        "EST_SSLClientRSACert.der"

#define CA_PKI_COMPONENT    "ca"
#define CERTS_PKI_COMPONENT "certs"
#define CRLS_PKI_COMPONENT  "crls"
#define KEYS_PKI_COMPONENT  "keys"
#define REQ_PKI_COMPONENT   "req"
#define CONF_PKI_COMPONENT  "conf"

/* JSON CSR Config */
#define EST_CONFIG_JSON  (ubyte4)1
/* TOML CSR Config */
#define EST_CONFIG_FILE  (ubyte4)2

typedef struct RootCertInfo
{
	int indexCheck;
	const char* fileName;
	ubyte* certData;
	ubyte4 certLength;
} RootCertInfo;

typedef struct KeyFilesDescr
{
	const char* pFileNameBlob;
	const char* pFileNameDer;
    ubyte4      keyType;
    ubyte4      keySize;

} KeyFilesDescr;

enum
{
	kRSACertIdx,
};

typedef struct CertificateInfo
{

    const char*     certFileName;
    const char*     certKeyFileName;
    const char*     certKeyPemFileName;
    const char*     certKeyDerFileName;
    const char*     caCertFileName;
    certDescriptor  certDesc;
    ubyte4          keySize;
    const char*     commonName;
    const char*     orgUnit;

} CertificateInfo;
#define CERTIFICATE_INFO( cf, ks, cn, ou) { cf".der", cf"Key.dat", cf"Key.pem", cf"Key.der", NULL, { 0 }, ks, cn, ou }

#define NAME_VALUE_PAIR_SIZE               (2)
#define MAX_ASN1_OBJECTS                   (20)
#define MAX_ASN1_STRING                    (80)

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
#define myPrintNL(a) 				MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", (sbyte*)a)
#define myPrintInt(a,b) 			MSG_LOG_print(MSG_LOG_VERBOSE, "%s %d", (sbyte*)a, b)
#define myPrintIntNL(a,b) 			MSG_LOG_print(MSG_LOG_VERBOSE, "%s %d\n", (sbyte*)a,b)
#define myPrintStringNL(a,b) 		MSG_LOG_print(MSG_LOG_VERBOSE, "%s %s\n" (sbyte*)a, (sbyte*)b)
#define myPrintError(a,b) 			MSG_LOG_print(MSG_LOG_ERROR, "%s: %d\n", (sbyte*)a, b)
#define myPrintStringError(a,b) 	MSG_LOG_print(MSG_LOG_ERROR, "%s: %s\n", (sbyte*)a, (sbyte*)b)
#else
#define myPrintNL(a)
#define myPrintInt(a,b)
#define myPrintIntNL(a,b)
#define myPrintStringNL(a,b)
#define myPrintError(a,b)
#define myPrintStringError(a,b)
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN void EST_CERT_UTIL_setIsWriteExtensions(byteBoolean value);
MOC_EXTERN MSTATUS EST_CERT_UTIL_createDirectory(char *directory);
MOC_EXTERN char* EST_CERT_UTIL_getFullPath(const char* directory, const char* name, char **ppFull);
MOC_EXTERN char* EST_CERT_UTIL_buildKeyStoreFullPath(char* keystore, char* subdir);;

MOC_EXTERN MSTATUS EST_CERT_UTIL_createPkiDB(sbyte* pki_database);
MOC_EXTERN sbyte* EST_CERT_UTIL_getPkiDBPtr();

MOC_EXTERN MSTATUS EST_CERT_UTIL_generateOIDFromString(const sbyte* oidStr, ubyte** oid, ubyte4* oid_len);
MOC_EXTERN MSTATUS EST_CERT_UTIL_writeExtensionToFile(char* filename, ubyte *pData, ubyte4 dataLen);

MOC_EXTERN MSTATUS EST_CERT_UTIL_convertStringToByteArray(char *in, ubyte *results, ubyte4* count);
MOC_EXTERN MSTATUS EST_CERT_UTIL_convertStringToBmpByteArray(char *in, ubyte *results);
MOC_EXTERN MSTATUS EST_CERT_UTIL_populateExtensionWithASN1Object(int item_count,
	char asn1object[][NAME_VALUE_PAIR_SIZE][MAX_ASN1_STRING], intBoolean isCritical, extensions* pExtension);
MOC_EXTERN MSTATUS EST_CERT_UTIL_makeExtensionsFromConfigFile(char* filename, certExtensions **ppExtension);
MOC_EXTERN MSTATUS EST_CERT_UTIL_makeExtensionsFromBuffer(char *pData, ubyte4 dataLen, certExtensions **ppExtension);
MOC_EXTERN MSTATUS EST_CERT_UTIL_certStoreAddIdentityEx(certStorePtr pCertStore, ubyte *pAlias, ubyte4 aliasLen,
                                                        ubyte *pDerCert, ubyte4 derCertLength, ubyte *pKeyBlob, ubyte4 keyBlobLength);
MOC_EXTERN MSTATUS EST_CERT_UTIL_certStoreAddIdentityWithCertificateChainEx(certStorePtr pCertStore, ubyte *pAlias, ubyte4 aliasLen,
                                                        struct SizedBuffer *certificates, ubyte4 numCertificate, const ubyte *pKeyBlob, ubyte4 keyBlobLength);
#ifdef __cplusplus
}
#endif
#endif
