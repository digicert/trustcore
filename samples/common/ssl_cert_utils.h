/*
    ssl_cert_utils.h

    Copyright Mocana Corp 2006-2017. All Rights Reserved.
    Proprietary and Confidential Material.

*/

#ifndef __SSL_CERT_UTILS_HEADER__
#define __SSL_CERT_UTILS_HEADER__

#include "../common/moptions.h"
#include "../common/moc_net_system.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../ssl/ssl.h"
#include "../common/mdefs.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/absstream.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../common/sizedbuffer.h"
#include "../common/tree.h"
#include "../crypto/hw_accel.h"
#include "../crypto/crypto.h"
#include "../common/vlong.h"
#include "../common/random.h"
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
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"

#include <stdio.h>
#include <string.h>

typedef struct RootCertInfo
{
	int indexCheck;
	const char* fileName;
	ubyte* certData;
	ubyte4 certLength;
} RootCertInfo;

enum
{
	kRSACertIdx
};

typedef struct CertificateInfo
{
    ubyte4 	    keyType;
    const char*     certFileName;
    const char*     certKeyFileName;
    const char*     certKeyPemFileName;
    const char*     certKeyDerFileName;
    const char*     caCertFileName;
    const char*     orgUnit;
    certDescriptor  certDesc;
    ubyte4          keySize;
    const char*     commonName;
} CertificateInfo;

#define CERTIFICATE_INFO( kt, cf, ou, ecc) { kt, cf".der", cf"Key.dat", cf"Key.pem", cf"Key.der",  NULL, ou, { 0 }, ecc, NULL }
#define CERTIFICATE_INFO_KEY_DER( cf, ou, ecc) { cf".der", cf"Key.der", NULL, ou, { 0 }, ecc, NULL }

#define LEAF_CERTIFICATE_INFO(cf, cacf, ou, ecc) { cf".der", cf"Key.dat", cacf".der", ou, { 0 }, ecc, NULL }
#define LEAF_CERTIFICATE_INFO_CN(cf, cacf, ou, ecc, cn) { cf".der", cf"Key.dat", cacf".der", ou, { 0 }, ecc, cn }

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS SSL_CERT_UTILS_checkServerIsOnline(const sbyte* pIpAddress, ubyte2 portNo, int maxtries);
MOC_EXTERN MSTATUS SSL_CERT_UTILS_createDirectory(char *directory);
MOC_EXTERN char* SSL_CERT_UTILS_getFullPath(const char* directory, const char* name, char **ppFull);
MOC_EXTERN MSTATUS SSL_CERT_UTILS_populateCertificateDir(char* KeyStore);
MOC_EXTERN MSTATUS SSL_CERT_UTILS_createCertificate(char* KeyStore, CertificateInfo* pCI);
MOC_EXTERN MSTATUS SSL_CERT_UTILS_releaseCertificateInfos();

#ifdef __cplusplus
}
#endif

#endif
