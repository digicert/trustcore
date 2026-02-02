/*
 * ca_mgmt_example.c
 *
 * Example CA MGMT implementation
 *
 * Copyright Mocana Corp 2004-2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) || defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) || defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if (defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER_EXAMPLE__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../crypto/secmod.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/mstdlib.h"
#include "../crypto/hw_accel.h"
#include "../common/vlong.h"
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/oiddefs.h"
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
#include "../common/absstream.h"
#include "../asn1/parsecert.h"
#include "../ike/ike.h"
#endif
#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) || defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#endif


/*------------------------------------------------------------------*/

#define RSA_EXAMPLE_KEY_SIZE    (2048)

#ifdef __ENABLE_DIGICERT_ECC__
#if !defined(__DISABLE_DIGICERT_ECC_P256__)
#define ECC_EXAMPLE_KEY_SIZE    (256)
#elif !defined(__DISABLE_DIGICERT_ECC_P384__)
#define ECC_EXAMPLE_KEY_SIZE    (384)
#elif !defined(__DISABLE_DIGICERT_ECC_P521__)
#define ECC_EXAMPLE_KEY_SIZE    (521)
#endif
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
#define HOST_KEYS_FNAME         "clientkey"
#define HOST_CERT_FNAME         "client"
#elif defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
#define HOST_KEYS_FNAME         "serverkey"
#define HOST_CERT_FNAME         "server"
#elif defined(ECC_EXAMPLE_KEY_SIZE) && (defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) || defined __ENABLE_DIGICERT_SSL_SERVER__)
#define HOST_KEYS_FNAME         "ecdsakey"
#define HOST_CERT_FNAME         "ecdsa"
#else
#define HOST_KEYS_FNAME         "rsakey"
#define HOST_CERT_FNAME         "rsa"
#endif

#define CA_CERT_FNAME           "ca"
#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
#define CA_BUNDLE_CERT_NAME     "CaBundle.crt"
#endif

#if defined (__RTOS_VXWORKS__)
#define HOST_KEYS_FILE          "NVRAM:/" HOST_KEYS_FNAME
#define HOST_CERT_FILE          "NVRAM:/" HOST_CERT_FNAME
#define CA_CERT_FILE            "NVRAM:/" CA_CERT_FNAME
#elif defined (__RTOS_OSE__)
#define HOST_KEYS_FILE          "/ram/" HOST_KEYS_FNAME
#define HOST_CERT_FILE          "/ram/" HOST_CERT_FNAME
#define CA_CERT_FILE            "/ram/" CA_CERT_FNAME
#elif defined(__RTOS_WIN32__) && \
      !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__) && \
      (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#define HOST_KEYS_FILE          "C:/" HOST_KEYS_FNAME
#define HOST_CERT_FILE          "C:/" HOST_CERT_FNAME
#define CA_CERT_FILE            "C:/" CA_CERT_FNAME
#else
#define HOST_KEYS_FILE          HOST_KEYS_FNAME
#define HOST_CERT_FILE          HOST_CERT_FNAME
#define CA_CERT_FILE            CA_CERT_FNAME
#endif

#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
static char *m_pHostKeyFile   = (char *)(HOST_KEYS_FILE ".dat");
static char *m_pCertFile      = (char *)(HOST_CERT_FILE ".der");
char *g_pIKERootFile          = (char *)(CA_CERT_FILE ".der");
char *g_pIKECertFile          = NULL;
char *g_pIKEHostKeyFile       = NULL;
char *g_pIKEHostKeyExtFile    = NULL;
int   g_isHostDerFile         = 0;
#define HOST_KEYS               g_pIKEHostKeyFile
#define CERTIFICATE_DER_FILE    g_pIKECertFile
#define ROOT_DER_FILE           g_pIKERootFile
#define HOST_KEYS_DER_FILE      g_pIKEHostKeyExtFile

#else
#define HOST_KEYS               (HOST_KEYS_FILE ".dat")

#define CERTIFICATE_DER_FILE    (HOST_CERT_FILE ".der")
#define ROOT_DER_FILE           (CA_CERT_FILE ".der")
#define HOST_KEYS_DER_FILE      (HOST_KEYS_FILE ".der")
#endif

#define CERTIFICATE_PEM_FILE    (HOST_CERT_FILE ".pem")
#define HOST_KEYS_PEM_FILE      (HOST_KEYS_FILE ".pem")
#define ROOT_PEM_FILE           (CA_CERT_FILE ".pem")


/*------------------------------------------------------------------*/

#ifdef _MSC_VER

/* if we are using a DLLs, the OIDs exported from the dll are not
considered constants and contrarily to GCC the MS C compiler does not
allow the use of non constants initializers -- so we have to build
by hand */

static nameAttr pNames1[] =
{
    {NULL, 0, (ubyte*)"US", 2}                               /* country */
};
static nameAttr pNames2[] =
{
    {NULL, 0, (ubyte*)"California", 10}              /* state or providence */
};
static nameAttr pNames3[] =
{
    {NULL, 0, (ubyte*)"Menlo Park", 10}                     /* locality */
};
static nameAttr pNames4[] =
{
    {NULL, 0, (ubyte*)"Mocana Corporation", 18}         /* company name */
};
static nameAttr pNames5[] =
{
    {NULL, 0, (ubyte*)"Engineering", 11}          /* organizational unit */
};
static nameAttr pNames6[] =
{
#ifdef __DIGICERT_USE_WEBAPPTAP_CNAME__ /* for demo use only */
    {commonName_OID, 0, (ubyte*)"webapptap.securitydemos.net", 27}                        /* common name */
#else
	{commonName_OID, 0, (ubyte*)"scepclient", 10}                        /* common name */
#endif
};
static nameAttr pNames7[] =
{
    {NULL, 0, (ubyte*)"info@mocana.com", 15}          /* pkcs-9-at-emailAddress */
};

static relativeDN pRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pNames6, 1},
    {pNames7, 1}
};

certDistinguishedName exampleCertificateDescr =
{
    pRDNs,
    7,
/* Note: Internet Explorer limits a 30 year lifetime for certificates */

                                                /* time format yymmddhhmmss */
    (sbyte *)"030526000126Z",                            /* certificate start date */
    (sbyte *)"330524230126Z"                             /* certificate end date */

/* above start example, May 26th, 2003 12:01:26 AM */
/* above end example, May 24th, 2033 11:01:26 PM */

};

void InitExampleCertDescr()
{
    pNames1[0].oid = countryName_OID;                               /* country */
    pNames2[0].oid = stateOrProvinceName_OID;
    pNames3[0].oid = localityName_OID;
    pNames4[0].oid = organizationName_OID;
    pNames5[0].oid = organizationalUnitName_OID;
    pNames6[0].oid = commonName_OID;
    pNames7[0].oid = pkcs9_emailAddress_OID;
};

#else
/* use static definitions */

/*------------------------------------------------------------------*/

static nameAttr pNames1[] =
{
    {countryName_OID, 0, (ubyte*)"US", 2}                               /* country */
};
static nameAttr pNames2[] =
{
    {stateOrProvinceName_OID, 0, (ubyte*)"California", 10}              /* state or providence */
};
static nameAttr pNames3[] =
{
    {localityName_OID, 0, (ubyte*)"Menlo Park", 10}                     /* locality */
};
static nameAttr pNames4[] =
{
    {organizationName_OID, 0, (ubyte*)"Mocana Corporation", 18}         /* company name */
};
static nameAttr pNames5[] =
{
    {organizationalUnitName_OID, 0, (ubyte*)"Engineering", 11}          /* organizational unit */
};
static nameAttr pNames6[] =
{
#ifdef __DIGICERT_USE_WEBAPPTAP_CNAME__ /* for demo use only */
    {commonName_OID, 0, (ubyte*)"webapptap.securitydemos.net", 27}                        /* common name */
#else
	{commonName_OID, 0, (ubyte*)"scepclient", 10}                        /* common name */
#endif
};
static nameAttr pNames7[] =
{
    {pkcs9_emailAddress_OID, 0, (ubyte*)"info@mocana.com", 15}          /* pkcs-9-at-emailAddress */
};

static relativeDN pRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pNames6, 1},
    {pNames7, 1}
};

certDistinguishedName exampleCertificateDescr =
{
    pRDNs,
    7,
/* Note: Internet Explorer limits a 30 year lifetime for certificates */

                                                /* time format yymmddhhmmss */
    (sbyte *)"030526000126Z",                            /* certificate start date */
    (sbyte *)"330524230126Z"                             /* certificate end date */

/* above start example, May 26th, 2003 12:01:26 AM */
/* above end example, May 24th, 2033 11:01:26 PM */

};

#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
static ubyte *m_rootCertificate = NULL;
static ubyte4 m_rootCertificateLen = 0;
#endif

/* for CA Bundle certificates */
#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
certDescriptor *pCertificates = NULL;
ubyte4 numCerts;
#endif

static ubyte *m_mocanaServerCert = NULL;

/*------------------------------------------------------------------*/

#if 0 /* fedoraRootCert[] is not referenced.  Referenced in commented code */
#if !defined( __ENABLE_DIGICERT_ECC__ )

static ubyte fedoraRootCert[] =
{
    /* RSA Root Certificate */
    0x30, 0x82, 0x02, 0x28, 0x30, 0x82, 0x01, 0x91, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x05,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30,
    0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x72, 0x65, 0x64, 0x68, 0x61, 0x74, 0x2e,
    0x63, 0x6f, 0x6d, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x43, 0x65,
    0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x53, 0x68, 0x61, 0x63, 0x6b, 0x30,
    0x1e, 0x17, 0x0d, 0x30, 0x38, 0x30, 0x37, 0x32, 0x38, 0x31, 0x37, 0x33, 0x34, 0x35, 0x34, 0x5a,
    0x17, 0x0d, 0x31, 0x32, 0x30, 0x37, 0x32, 0x38, 0x31, 0x37, 0x33, 0x34, 0x35, 0x34, 0x5a, 0x30,
    0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x72, 0x65, 0x64, 0x68, 0x61, 0x74, 0x2e,
    0x63, 0x6f, 0x6d, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x43, 0x65,
    0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x53, 0x68, 0x61, 0x63, 0x6b, 0x30,
    0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb0, 0x81, 0xca, 0x1b,
    0x03, 0x04, 0xb3, 0x72, 0x7b, 0xb8, 0xad, 0x7f, 0x19, 0x12, 0x4c, 0x43, 0xf5, 0x48, 0x52, 0xbc,
    0x2e, 0x3f, 0xee, 0x0c, 0x4e, 0x46, 0x15, 0x2c, 0xaa, 0xee, 0xa6, 0xe9, 0x54, 0x64, 0xe7, 0x16,
    0x9c, 0x47, 0x11, 0xe7, 0x3b, 0x44, 0x4c, 0x5f, 0x62, 0x8d, 0xcc, 0xac, 0x9f, 0xd7, 0xe7, 0xe8,
    0xfe, 0xdc, 0x79, 0x93, 0xdd, 0x83, 0x0f, 0x13, 0xf0, 0x4d, 0xd2, 0x05, 0xd6, 0x00, 0x1b, 0x61,
    0x58, 0x3c, 0xa3, 0x27, 0xaa, 0x42, 0xc6, 0x55, 0xf2, 0xa4, 0x41, 0x8c, 0x2b, 0x78, 0xb4, 0xe3,
    0x49, 0x36, 0x48, 0xcf, 0x3b, 0xc5, 0x7c, 0x35, 0x46, 0xd3, 0x45, 0x1e, 0x1f, 0xe2, 0x6d, 0x92,
    0x1e, 0x64, 0x19, 0x1d, 0x27, 0xeb, 0xdc, 0xb7, 0x67, 0x56, 0x51, 0xcb, 0x29, 0xf6, 0x9c, 0x5c,
    0x5e, 0x75, 0x5a, 0x46, 0x43, 0x2f, 0x82, 0x24, 0xfb, 0x7b, 0x40, 0x73, 0x02, 0x03, 0x01, 0x00,
    0x01, 0xa3, 0x36, 0x30, 0x34, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42,
    0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x00, 0x07, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x0a, 0x30, 0x0b, 0x06, 0x03,
    0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x0e, 0xc2, 0xa5, 0x2b,
    0xed, 0xcc, 0xc1, 0x59, 0x86, 0xcf, 0x78, 0x38, 0x57, 0x50, 0x91, 0xb1, 0x5d, 0x91, 0xad, 0xe0,
    0xec, 0x2a, 0x26, 0x05, 0xcd, 0x8f, 0x8f, 0x99, 0x6d, 0xba, 0x1c, 0x17, 0xc7, 0x83, 0x49, 0x28,
    0xb4, 0xb7, 0xac, 0xe6, 0x75, 0x5c, 0xb9, 0x58, 0xab, 0x5d, 0xbe, 0xe6, 0x7f, 0x04, 0xc2, 0x83,
    0x94, 0xb2, 0x4f, 0x45, 0xe8, 0x4b, 0x77, 0xb7, 0xd3, 0xc0, 0x68, 0x4f, 0xc9, 0x8d, 0xea, 0xf6,
    0x7d, 0x7b, 0xdf, 0x21, 0x8c, 0xf9, 0x43, 0x30, 0xc9, 0xd9, 0x29, 0xf2, 0x2d, 0x45, 0x7d, 0x5c,
    0x9e, 0x5c, 0x11, 0x6a, 0x22, 0xba, 0x3d, 0xc4, 0x0b, 0x75, 0x4d, 0xc6, 0x0d, 0x97, 0x1f, 0xe1,
    0x4b, 0xd6, 0x44, 0xa3, 0xeb, 0x89, 0x1d, 0x44, 0x6a, 0xca, 0x2c, 0x48, 0x4d, 0x8e, 0x26, 0x8b,
    0x07, 0xfe, 0x09, 0x7e, 0xc3, 0x63, 0xe2, 0xd5, 0x02, 0xae, 0xb3, 0x45
};

#else

static ubyte fedoraRootCert[] =
{
    /* ECC Root Certificate */
    0x30, 0x82, 0x02, 0x2a, 0x30, 0x82, 0x01, 0x93, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x01, 0x0e, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30, 0x3f, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x14,
    0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1a, 0x30, 0x18,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x43, 0x65, 0x72, 0x74, 0x69,
    0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x53, 0x68, 0x61, 0x63, 0x6b,
    0x30, 0x1e, 0x17, 0x0d, 0x30, 0x36, 0x30, 0x31, 0x31, 0x38, 0x32, 0x31,
    0x31, 0x36, 0x31, 0x31, 0x5a, 0x17, 0x0d, 0x30, 0x37, 0x30, 0x34, 0x31,
    0x38, 0x32, 0x31, 0x31, 0x36, 0x31, 0x31, 0x5a, 0x30, 0x3f, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1a, 0x30,
    0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x43, 0x65, 0x72, 0x74,
    0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x53, 0x68, 0x61, 0x63,
    0x6b, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30,
    0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xba, 0x5e, 0xb9, 0xc9, 0x8a, 0xa4,
    0xae, 0x35, 0xb8, 0x59, 0x40, 0x2d, 0xbe, 0x78, 0xbb, 0x33, 0xcd, 0x62,
    0x01, 0x61, 0xa4, 0x5b, 0x74, 0xa3, 0x57, 0xc7, 0x54, 0x04, 0x10, 0xb7,
    0x03, 0x82, 0x4a, 0x0c, 0xa4, 0xca, 0x09, 0x3c, 0x88, 0x7f, 0x70, 0x7d,
    0x04, 0x14, 0xb7, 0x4b, 0x8f, 0xbf, 0xb7, 0x7b, 0x35, 0x81, 0x5b, 0x48,
    0x15, 0x38, 0x34, 0x04, 0x37, 0x72, 0xba, 0xca, 0x90, 0x1b, 0x04, 0x3c,
    0xa1, 0xe0, 0xd6, 0xb0, 0xb2, 0x4a, 0x88, 0xff, 0xd8, 0x99, 0x72, 0x64,
    0x9d, 0x8e, 0x1c, 0xdb, 0x7f, 0x08, 0x95, 0xb3, 0x21, 0x94, 0x3c, 0x0f,
    0x61, 0x9d, 0xdc, 0xaa, 0x08, 0x39, 0xe1, 0x3b, 0xa2, 0x2e, 0x00, 0x2f,
    0xef, 0x2b, 0xe6, 0x5d, 0x0d, 0xac, 0x67, 0x15, 0xbc, 0xe8, 0x8e, 0x8b,
    0x91, 0x64, 0x92, 0xc7, 0x55, 0xf7, 0x25, 0x67, 0x96, 0x41, 0xd4, 0x4b,
    0xef, 0xc9, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x36, 0x30, 0x34, 0x30,
    0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01,
    0x04, 0x04, 0x03, 0x02, 0x00, 0x07, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d,
    0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02,
    0x01, 0x0a, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03,
    0x02, 0x02, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x58, 0x83,
    0xdb, 0x42, 0x14, 0xd4, 0x05, 0x06, 0xa6, 0x31, 0xff, 0xf4, 0xbe, 0x44,
    0xd6, 0xdf, 0xf6, 0xd6, 0x95, 0xbc, 0x9c, 0xef, 0xbc, 0x8f, 0xc6, 0x4b,
    0x1d, 0xeb, 0x48, 0xb8, 0xe8, 0x5b, 0xb8, 0x27, 0xca, 0x5c, 0x61, 0x12,
    0x5c, 0x50, 0x64, 0xc3, 0xe8, 0xd4, 0xd6, 0x23, 0xb8, 0x0a, 0x55, 0x85,
    0x7a, 0x94, 0x0a, 0xaf, 0x32, 0x57, 0x7e, 0x77, 0x9b, 0xfb, 0x8e, 0x0c,
    0xa4, 0xee, 0xb3, 0x0e, 0x0e, 0xea, 0xe8, 0x88, 0x47, 0x9e, 0xca, 0x08,
    0x4e, 0x00, 0xa9, 0x5b, 0x7b, 0xf6, 0x19, 0xd7, 0x56, 0x9e, 0x9a, 0xf4,
    0x7a, 0x0e, 0x2b, 0xba, 0xe8, 0xe1, 0x01, 0xae, 0x88, 0xa8, 0x17, 0x0a,
    0xef, 0xf1, 0x1a, 0x24, 0x22, 0xea, 0xdf, 0xb5, 0x11, 0x68, 0xf2, 0x49,
    0x55, 0x7b, 0xd5, 0x08, 0x78, 0x95, 0x84, 0x5a, 0x9e, 0x59, 0x78, 0x7f,
    0x24, 0x82, 0x9a, 0x71, 0x72, 0x37
};

#endif /* !defined( __ENABLE_DIGICERT_ECC__ ) */
#endif /* fedoraRootCert[] is not referenced.  Only referenced in commented out code */

#if 0
static ubyte vrsnCertificate[] =
{
    0x30, 0x82, 0x02, 0x34, 0x30, 0x82, 0x01, 0xa1, 0x02, 0x10, 0x02, 0xad, 0x66, 0x7e, 0x4e, 0x45,
    0xfe, 0x5e, 0x57, 0x6f, 0x3c, 0x98, 0x19, 0x5e, 0xdd, 0xc0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02, 0x05, 0x00, 0x30, 0x5f, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04,
    0x0a, 0x13, 0x17, 0x52, 0x53, 0x41, 0x20, 0x44, 0x61, 0x74, 0x61, 0x20, 0x53, 0x65, 0x63, 0x75,
    0x72, 0x69, 0x74, 0x79, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x2e, 0x30, 0x2c, 0x06, 0x03,
    0x55, 0x04, 0x0b, 0x13, 0x25, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x53, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d, 0x39, 0x34,
    0x31, 0x31, 0x30, 0x39, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x30, 0x30,
    0x31, 0x30, 0x37, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x5f, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x17, 0x52, 0x53, 0x41, 0x20, 0x44, 0x61, 0x74, 0x61, 0x20, 0x53, 0x65, 0x63,
    0x75, 0x72, 0x69, 0x74, 0x79, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x2e, 0x30, 0x2c, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x13, 0x25, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x53, 0x65, 0x72,
    0x76, 0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x81, 0x9b, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x89,
    0x00, 0x30, 0x81, 0x85, 0x02, 0x7e, 0x00, 0x92, 0xce, 0x7a, 0xc1, 0xae, 0x83, 0x3e, 0x5a, 0xaa,
    0x89, 0x83, 0x57, 0xac, 0x25, 0x01, 0x76, 0x0c, 0xad, 0xae, 0x8e, 0x2c, 0x37, 0xce, 0xeb, 0x35,
    0x78, 0x64, 0x54, 0x03, 0xe5, 0x84, 0x40, 0x51, 0xc9, 0xbf, 0x8f, 0x08, 0xe2, 0x8a, 0x82, 0x08,
    0xd2, 0x16, 0x86, 0x37, 0x55, 0xe9, 0xb1, 0x21, 0x02, 0xad, 0x76, 0x68, 0x81, 0x9a, 0x05, 0xa2,
    0x4b, 0xc9, 0x4b, 0x25, 0x66, 0x22, 0x56, 0x6c, 0x88, 0x07, 0x8f, 0xf7, 0x81, 0x59, 0x6d, 0x84,
    0x07, 0x65, 0x70, 0x13, 0x71, 0x76, 0x3e, 0x9b, 0x77, 0x4c, 0xe3, 0x50, 0x89, 0x56, 0x98, 0x48,
    0xb9, 0x1d, 0xa7, 0x29, 0x1a, 0x13, 0x2e, 0x4a, 0x11, 0x59, 0x9c, 0x1e, 0x15, 0xd5, 0x49, 0x54,
    0x2c, 0x73, 0x3a, 0x69, 0x82, 0xb1, 0x97, 0x39, 0x9c, 0x6d, 0x70, 0x67, 0x48, 0xe5, 0xdd, 0x2d,
    0xd6, 0xc8, 0x1e, 0x7b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02, 0x05, 0x00, 0x03, 0x7e, 0x00, 0x65, 0xdd, 0x7e, 0xe1, 0xb2,
    0xec, 0xb0, 0xe2, 0x3a, 0xe0, 0xec, 0x71, 0x46, 0x9a, 0x19, 0x11, 0xb8, 0xd3, 0xc7, 0xa0, 0xb4,
    0x03, 0x40, 0x26, 0x02, 0x3e, 0x09, 0x9c, 0xe1, 0x12, 0xb3, 0xd1, 0x5a, 0xf6, 0x37, 0xa5, 0xb7,
    0x61, 0x03, 0xb6, 0x5b, 0x16, 0x69, 0x3b, 0xc6, 0x44, 0x08, 0x0c, 0x88, 0x53, 0x0c, 0x6b, 0x97,
    0x49, 0xc7, 0x3e, 0x35, 0xdc, 0x6c, 0xb9, 0xbb, 0xaa, 0xdf, 0x5c, 0xbb, 0x3a, 0x2f, 0x93, 0x60,
    0xb6, 0xa9, 0x4b, 0x4d, 0xf2, 0x20, 0xf7, 0xcd, 0x5f, 0x7f, 0x64, 0x7b, 0x8e, 0xdc, 0x00, 0x5c,
    0xd7, 0xfa, 0x77, 0xca, 0x39, 0x16, 0x59, 0x6f, 0x0e, 0xea, 0xd3, 0xb5, 0x83, 0x7f, 0x4d, 0x4d,
    0x42, 0x56, 0x76, 0xb4, 0xc9, 0x5f, 0x04, 0xf8, 0x38, 0xf8, 0xeb, 0xd2, 0x5f, 0x75, 0x5f, 0xcd,
    0x7b, 0xfc, 0xe5, 0x8e, 0x80, 0x7c, 0xfc, 0x50
};
#endif


#ifdef __ENABLE_DIGICERT_EXAMPLE_CERT_NOFS__
/* 737 bytes */
static ubyte rsaDerCert[] = {
    0x30, 0x82, 0x02, 0xdd, 0x30, 0x82, 0x02, 0x46, 0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x14, 0x56, 0x92, 0x2b, 0xc1, 0x1d, 0x42, 0x49, 0x03, 0x33, 0xc3, 0xab,
    0x70, 0xa2, 0x2d, 0xbc, 0x20, 0x7c, 0x18, 0x7f, 0xd7, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81,
    0xaa, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
    0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x43,
    0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0a, 0x4d, 0x65, 0x6e, 0x6c, 0x6f, 0x20,
    0x50, 0x61, 0x72, 0x6b, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x13, 0x12, 0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x20, 0x43, 0x6f, 0x72, 0x70,
    0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x04, 0x0b, 0x13, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, 0x72,
    0x69, 0x6e, 0x67, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x15, 0x73, 0x73, 0x6c, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6d,
    0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1e, 0x30, 0x1c,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0f,
    0x69, 0x6e, 0x66, 0x6f, 0x40, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63,
    0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x33, 0x30, 0x35, 0x32, 0x36, 0x30,
    0x30, 0x30, 0x31, 0x32, 0x36, 0x5a, 0x17, 0x0d, 0x33, 0x33, 0x30, 0x35, 0x32,
    0x34, 0x32, 0x33, 0x30, 0x31, 0x32, 0x36, 0x5a, 0x30, 0x81, 0xaa, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69,
    0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x07, 0x13, 0x0a, 0x4d, 0x65, 0x6e, 0x6c, 0x6f, 0x20, 0x50, 0x61, 0x72,
    0x6b, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x12, 0x4d,
    0x6f, 0x63, 0x61, 0x6e, 0x61, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x13, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, 0x72, 0x69, 0x6e, 0x67,
    0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x15, 0x73, 0x73,
    0x6c, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6d, 0x6f, 0x63, 0x61,
    0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0f, 0x69, 0x6e, 0x66,
    0x6f, 0x40, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
    0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81,
    0x81, 0x00, 0x94, 0x9c, 0x8a, 0xdb, 0xc0, 0x83, 0x1a, 0x5e, 0xb3, 0xc6, 0x0d,
    0x67, 0x85, 0x84, 0xad, 0x15, 0xb6, 0x69, 0x22, 0xf1, 0x50, 0xea, 0x19, 0x27,
    0xec, 0x7c, 0x54, 0x04, 0x83, 0x5a, 0xb0, 0x6a, 0xdf, 0xa3, 0x9c, 0xd9, 0x77,
    0xe9, 0x2a, 0x12, 0x9f, 0x8d, 0xed, 0xe3, 0xc0, 0x46, 0x79, 0x8e, 0x69, 0x23,
    0x51, 0x60, 0x42, 0x1e, 0x8d, 0xa3, 0x59, 0x7d, 0xbe, 0x3c, 0x9f, 0x4e, 0xb8,
    0x1d, 0xc6, 0x8d, 0x8d, 0xe7, 0x61, 0xa0, 0x4a, 0xcf, 0x3b, 0x00, 0xd5, 0x9d,
    0xdd, 0x86, 0xbf, 0xca, 0x08, 0x68, 0xc5, 0x56, 0x2e, 0xb1, 0xfb, 0x53, 0x8f,
    0xcc, 0xc6, 0xa0, 0x74, 0x4b, 0x0a, 0x03, 0xe8, 0xd2, 0xa6, 0x79, 0x0c, 0x16,
    0xa5, 0x7d, 0x52, 0xd3, 0x32, 0xe5, 0x25, 0xf4, 0xe7, 0x3a, 0x5d, 0x41, 0xac,
    0xe7, 0xd7, 0xbc, 0x2d, 0xd1, 0x33, 0xc6, 0x3d, 0xc8, 0xbd, 0xef, 0xbc, 0xb1,
    0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x62, 0xa0,
    0xa7, 0x03, 0x05, 0x93, 0x5f, 0xe5, 0xb2, 0x85, 0x3e, 0x99, 0xa1, 0xab, 0xa2,
    0x9f, 0x99, 0xcf, 0xf3, 0x58, 0xc3, 0x0c, 0xdb, 0xa7, 0xc7, 0x60, 0x69, 0x00,
    0x92, 0xd9, 0x69, 0xb8, 0x9f, 0x94, 0x9e, 0xbe, 0x3d, 0x77, 0x80, 0x5e, 0x9e,
    0x35, 0xae, 0x94, 0xd8, 0x51, 0x67, 0x35, 0xd7, 0x9e, 0x16, 0x34, 0xa5, 0x52,
    0x94, 0x68, 0x76, 0x39, 0x56, 0xa7, 0x94, 0xad, 0xb2, 0x61, 0xa9, 0x29, 0x2c,
    0xb0, 0x6c, 0x10, 0x3f, 0xd9, 0x20, 0x98, 0xed, 0x15, 0x5a, 0x3d, 0x7e, 0x87,
    0x15, 0x43, 0xe8, 0x10, 0x97, 0xcf, 0x7b, 0x70, 0xd7, 0x2e, 0x6a, 0x43, 0xdc,
    0x0f, 0xbf, 0xe1, 0x4e, 0xa2, 0x73, 0xc6, 0xa8, 0x11, 0x97, 0x1f, 0xab, 0xef,
    0x6f, 0x98, 0xd6, 0xf1, 0x03, 0x63, 0x5d, 0x17, 0x30, 0x13, 0xb7, 0x97, 0xe9,
    0x0d, 0x16, 0x80, 0x37, 0xf2, 0xce, 0xba, 0x6a, 0xbf };


/*1057 bytes*/
static ubyte rsaKeyDat[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x94,
    0x9c, 0x8a, 0xdb, 0xc0, 0x83, 0x1a, 0x5e, 0xb3, 0xc6, 0x0d, 0x67, 0x85, 0x84,
    0xad, 0x15, 0xb6, 0x69, 0x22, 0xf1, 0x50, 0xea, 0x19, 0x27, 0xec, 0x7c, 0x54,
    0x04, 0x83, 0x5a, 0xb0, 0x6a, 0xdf, 0xa3, 0x9c, 0xd9, 0x77, 0xe9, 0x2a, 0x12,
    0x9f, 0x8d, 0xed, 0xe3, 0xc0, 0x46, 0x79, 0x8e, 0x69, 0x23, 0x51, 0x60, 0x42,
    0x1e, 0x8d, 0xa3, 0x59, 0x7d, 0xbe, 0x3c, 0x9f, 0x4e, 0xb8, 0x1d, 0xc6, 0x8d,
    0x8d, 0xe7, 0x61, 0xa0, 0x4a, 0xcf, 0x3b, 0x00, 0xd5, 0x9d, 0xdd, 0x86, 0xbf,
    0xca, 0x08, 0x68, 0xc5, 0x56, 0x2e, 0xb1, 0xfb, 0x53, 0x8f, 0xcc, 0xc6, 0xa0,
    0x74, 0x4b, 0x0a, 0x03, 0xe8, 0xd2, 0xa6, 0x79, 0x0c, 0x16, 0xa5, 0x7d, 0x52,
    0xd3, 0x32, 0xe5, 0x25, 0xf4, 0xe7, 0x3a, 0x5d, 0x41, 0xac, 0xe7, 0xd7, 0xbc,
    0x2d, 0xd1, 0x33, 0xc6, 0x3d, 0xc8, 0xbd, 0xef, 0xbc, 0xb1, 0x00, 0x00, 0x00,
    0x40, 0xd4, 0x75, 0x8b, 0x0b, 0x38, 0xd5, 0x0d, 0x34, 0xe2, 0x63, 0x4c, 0x2b,
    0x76, 0x54, 0x0a, 0x2e, 0x5e, 0x32, 0x09, 0xbe, 0xbf, 0x5b, 0x29, 0xc9, 0x6a,
    0xee, 0x4a, 0xb4, 0x95, 0x2f, 0x3c, 0xc2, 0x1e, 0xa1, 0xc7, 0xc9, 0xdb, 0x39,
    0xea, 0x31, 0x24, 0xe1, 0x86, 0x95, 0x00, 0xa0, 0xa5, 0x9b, 0xa0, 0xa1, 0x52,
    0xb2, 0xfd, 0x44, 0xc1, 0x6f, 0x8e, 0xbb, 0x7f, 0xac, 0x5d, 0x11, 0xab, 0xc1,
    0x00, 0x00, 0x00, 0x40, 0xb3, 0x11, 0x4b, 0xb5, 0x06, 0x3f, 0xdf, 0x2d, 0x09,
    0x24, 0xaa, 0x22, 0xc2, 0xb0, 0x99, 0x8b, 0xfe, 0xfe, 0x81, 0xbb, 0x65, 0x2e,
    0xaa, 0x59, 0x70, 0x46, 0x81, 0xdd, 0x49, 0x76, 0xaa, 0xeb, 0xd0, 0x4c, 0x0b,
    0xb7, 0xbd, 0x4f, 0xa5, 0x4c, 0xec, 0xfc, 0x49, 0x49, 0xe5, 0x03, 0xb3, 0xe1,
    0xc9, 0x25, 0x59, 0x1c, 0x7f, 0xd1, 0xcc, 0x52, 0xd6, 0xed, 0x6b, 0x04, 0x5c,
    0x40, 0x0c, 0xf1, 0x00, 0x00, 0x00, 0x40, 0xbd, 0x18, 0x69, 0x4a, 0xf1, 0xa8,
    0x5e, 0x7a, 0xc5, 0x4c, 0x0f, 0xcd, 0x57, 0x21, 0xf1, 0x75, 0xd7, 0x8c, 0xbd,
    0xb3, 0xb2, 0x69, 0x17, 0x46, 0x18, 0x10, 0x43, 0x19, 0x7a, 0xf6, 0x72, 0x23,
    0x6c, 0x54, 0x1d, 0x98, 0x01, 0xb1, 0x08, 0x49, 0xf9, 0x43, 0x69, 0x1f, 0x51,
    0x51, 0xaa, 0x54, 0x5b, 0xa1, 0x7a, 0x13, 0xa8, 0xeb, 0xfb, 0x26, 0xa9, 0x69,
    0x24, 0x77, 0x6a, 0xd6, 0x81, 0x81, 0x00, 0x00, 0x00, 0x40, 0x33, 0x8c, 0xf0,
    0x21, 0x9e, 0x39, 0xf7, 0x12, 0xed, 0x05, 0xec, 0x20, 0xf3, 0xb1, 0x89, 0x92,
    0xbf, 0x07, 0x1f, 0xec, 0x05, 0xf6, 0x08, 0x3e, 0x95, 0x4f, 0x07, 0x05, 0xe0,
    0xa7, 0x54, 0x0f, 0x6d, 0x38, 0xe7, 0x4a, 0xaf, 0x2a, 0x65, 0xa9, 0x1e, 0xb4,
    0x86, 0x98, 0xca, 0x60, 0x65, 0x81, 0xc3, 0xb9, 0x87, 0xcc, 0xe7, 0x93, 0x4b,
    0x62, 0x31, 0xd3, 0xc9, 0xb2, 0x48, 0xa8, 0x7b, 0xd1, 0x00, 0x00, 0x00, 0x40,
    0x34, 0x28, 0x34, 0x71, 0xb9, 0x07, 0xa6, 0xb7, 0xa9, 0x86, 0xa8, 0xb8, 0xf0,
    0x8a, 0x4b, 0x64, 0x88, 0x64, 0xf7, 0x77, 0x8c, 0x76, 0x52, 0xbb, 0x21, 0x86,
    0x9d, 0x82, 0x70, 0x3a, 0xe7, 0x79, 0x9f, 0x2b, 0xcd, 0x88, 0x0f, 0xaa, 0xc3,
    0x72, 0x45, 0x43, 0x9e, 0x45, 0x1f, 0xb0, 0xc0, 0xc9, 0xfd, 0x5b, 0x2d, 0xed,
    0x18, 0xf0, 0xb5, 0x78, 0xed, 0x14, 0xf7, 0xdc, 0x2e, 0x10, 0xd9, 0x17, 0x00,
    0x00, 0x01, 0x16, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x41, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x86, 0x8f, 0xb6, 0x0e, 0xd5, 0x71, 0x72, 0x03, 0x2b, 0x78,
    0x66, 0x94, 0x52, 0x52, 0xcb, 0x28, 0x0b, 0x80, 0x96, 0xca, 0x3c, 0xc0, 0xc6,
    0xaf, 0xd5, 0x99, 0x3a, 0x46, 0x1e, 0xa7, 0x7d, 0xb1, 0xa2, 0x91, 0xe1, 0x09,
    0x99, 0x6b, 0xd7, 0x44, 0x2c, 0x1b, 0xf9, 0xcf, 0xaf, 0xf0, 0x31, 0xee, 0xda,
    0xd1, 0xb7, 0xae, 0x92, 0x40, 0x99, 0x88, 0x27, 0x10, 0x62, 0xb0, 0xdc, 0xda,
    0xe9, 0x24, 0x00, 0x00, 0x00, 0x40, 0xd4, 0x75, 0x8b, 0x0b, 0x38, 0xd5, 0x0d,
    0x34, 0xe2, 0x63, 0x4c, 0x2b, 0x76, 0x54, 0x0a, 0x2e, 0x5e, 0x32, 0x09, 0xbe,
    0xbf, 0x5b, 0x29, 0xc9, 0x6a, 0xee, 0x4a, 0xb4, 0x95, 0x2f, 0x3c, 0xc2, 0x1e,
    0xa1, 0xc7, 0xc9, 0xdb, 0x39, 0xea, 0x31, 0x24, 0xe1, 0x86, 0x95, 0x00, 0xa0,
    0xa5, 0x9b, 0xa0, 0xa1, 0x52, 0xb2, 0xfd, 0x44, 0xc1, 0x6f, 0x8e, 0xbb, 0x7f,
    0xac, 0x5d, 0x11, 0xab, 0xc1, 0x00, 0x00, 0x00, 0x40, 0xa2, 0x23, 0x56, 0xc1,
    0x12, 0xd1, 0xa6, 0x90, 0x89, 0xf2, 0x55, 0xf1, 0x52, 0xca, 0x45, 0x57, 0xd0,
    0xa1, 0xc1, 0xaa, 0x08, 0x1b, 0x7e, 0xfe, 0x3f, 0xff, 0xed, 0x22, 0xb7, 0xb8,
    0xec, 0x87, 0xb6, 0x35, 0xbd, 0xd7, 0x56, 0x1f, 0xc2, 0x52, 0x73, 0x09, 0xa8,
    0x19, 0x6c, 0xf0, 0x94, 0x7c, 0x0c, 0x8f, 0x4b, 0x01, 0x1a, 0x4f, 0x5b, 0x43,
    0xbe, 0xb3, 0x3a, 0x8a, 0x7d, 0x93, 0x9b, 0xbf, 0x00, 0x00, 0x01, 0x16, 0x01,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x41, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x5d,
    0xad, 0xcc, 0x58, 0xfb, 0xe6, 0x29, 0xb2, 0x0d, 0x9c, 0xc1, 0x4f, 0xcc, 0x0b,
    0xbe, 0x1e, 0x5d, 0xf9, 0x07, 0xf0, 0x3a, 0x80, 0xd3, 0x37, 0xe6, 0x95, 0xdb,
    0x7c, 0x20, 0x2d, 0x8e, 0x3b, 0xad, 0xc4, 0xd6, 0x4e, 0x75, 0x32, 0x6e, 0xc9,
    0x6f, 0x07, 0x08, 0xb9, 0xee, 0x06, 0x32, 0xef, 0xa6, 0xbd, 0x9d, 0xd2, 0xa9,
    0x4c, 0x9b, 0x36, 0x9f, 0x1c, 0xc0, 0xb2, 0x4d, 0xd8, 0xee, 0x50, 0x00, 0x00,
    0x00, 0x40, 0xb3, 0x11, 0x4b, 0xb5, 0x06, 0x3f, 0xdf, 0x2d, 0x09, 0x24, 0xaa,
    0x22, 0xc2, 0xb0, 0x99, 0x8b, 0xfe, 0xfe, 0x81, 0xbb, 0x65, 0x2e, 0xaa, 0x59,
    0x70, 0x46, 0x81, 0xdd, 0x49, 0x76, 0xaa, 0xeb, 0xd0, 0x4c, 0x0b, 0xb7, 0xbd,
    0x4f, 0xa5, 0x4c, 0xec, 0xfc, 0x49, 0x49, 0xe5, 0x03, 0xb3, 0xe1, 0xc9, 0x25,
    0x59, 0x1c, 0x7f, 0xd1, 0xcc, 0x52, 0xd6, 0xed, 0x6b, 0x04, 0x5c, 0x40, 0x0c,
    0xf1, 0x00, 0x00, 0x00, 0x40, 0x85, 0xed, 0x0c, 0xdf, 0x13, 0x39, 0xdd, 0xd4,
    0x21, 0xc4, 0x6b, 0x8b, 0xa1, 0xb2, 0x6b, 0x96, 0xbf, 0xe7, 0x73, 0x43, 0xca,
    0x9e, 0x27, 0x47, 0xd6, 0x8f, 0x85, 0x38, 0x7d, 0x30, 0x85, 0xda, 0x43, 0x6b,
    0xd2, 0x6c, 0x2b, 0x70, 0xd6, 0x85, 0xf1, 0x57, 0x4c, 0x6d, 0xb9, 0xb5, 0xdb,
    0x6c, 0x79, 0x69, 0xcf, 0x4f, 0xae, 0xf2, 0x3c, 0x10, 0x8d, 0x23, 0x86, 0xa7,
    0x56, 0x3e, 0x9b, 0xef};

#endif

/*------------------------------------------------------------------*/


#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) || defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__))
/* Trust Points for the SSL Client to verify SSL server certificates.*/

/* root certs */
typedef struct exampleRootCertInfo
{
    const char* fileName;
    ubyte* certData;
    ubyte4 certLength;
} exampleRootCertInfo;


static exampleRootCertInfo gExampleRootCerts[] =
{
    {"rootCert.der", 0, 0 },
    {"ca.der", 0, 0 },
};

#endif

/*------------------------------------------------------------------*/

#if 0  /* functions are not referenced */
#ifndef __ENABLE_DIGICERT_EXTRACT_CERT_BLOB__
static sbyte4
findCertificateInStore(sbyte4 connectionInstance, certDistinguishedName *pLookupCertDN,
                       certDescriptor* pReturnCert)
{
    MOC_UNUSED(connectionInstance);  /* param not used in this function */
    sbyte4 status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
    certDistinguishedName   *issuer;
    ubyte4 i;

    if (NULL == pCertificates && numCerts <= 0)
        goto exit;

    for (i = 0; i < numCerts; i++)
    {
        issuer = MALLOC(sizeof(certDistinguishedName));
        memset(issuer, 0x00, sizeof(certDistinguishedName));

        if (OK == (CA_MGMT_extractCertDistinguishedName(pCertificates[i].pCertificate, pCertificates[i].certLength, 0, issuer)))
        {
            if (TRUE == CA_MGMT_compareCertDistinguishedName(pLookupCertDN, issuer))
            {
                pReturnCert->pCertificate = pCertificates[i].pCertificate;
                pReturnCert->certLength   = pCertificates[i].certLength;
                status = OK;
                pReturnCert->cookie         = 0;
                CA_MGMT_freeCertDistinguishedName(&issuer);
                break;
            }
        }
        CA_MGMT_freeCertDistinguishedName(&issuer);
    }
#else
#if 0
    /* normally locate certificate in store... */
    certDistinguishedName   issuer;
    sbyte4                     status;

    status = CA_MGMT_extractCertDistinguishedName(pCertificate, certificateLength, 0, &issuer);

    if (0 > status)
        return status;
#endif

    MOC_UNUSED(pLookupCertDN);

    /* for this example implementation, we only recognize one certificate authority */

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    pReturnCert->pCertificate   = m_rootCertificate;
    pReturnCert->certLength     = m_rootCertificateLen;
#else
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
    if (m_rootCertificate)
    {
        pReturnCert->pCertificate = m_rootCertificate;
        pReturnCert->certLength = m_rootCertificateLen;
    }
    else
#endif
#ifdef __TEST_FEDORA_SERVER__
    {
        pReturnCert->pCertificate = fedoraRootCert;
        pReturnCert->certLength = sizeof(fedoraRootCert);
    }
#else
    {
        if (0 > (status = DIGICERT_readFile((char *)CERTIFICATE_DER_FILE,
                                    &m_mocanaServerCert, &pReturnCert->certLength)))

            goto exit;
        pReturnCert->pCertificate = m_mocanaServerCert;
    }
#endif

#endif
    pReturnCert->cookie         = 0;

    status = OK;
#endif
exit:
    return status;
}

#else /* __ENABLE_DIGICERT_EXTRACT_CERT_BLOB__ is defined */

/*------------------------------------------------------------------*/

static sbyte4
findCertificateInStore(sbyte4 connectionInstance,
                       ubyte* pDistinguishedName, ubyte4 distinguishedNameLen,
                       certDescriptor* pReturnCert)
{
    sbyte4 status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
    ubyte*  distinguishName = NULL;
    ubyte4  distinguishNameLen = 0;
    ubyte4 i;

    if (NULL == pCertificates && numCerts <= 0)
        goto exit;

    for (i = 0; i < numCerts; i++)
    {
        if (OK <= CA_MGMT_findCertDistinguishedName(pCertificates[i].pCertificate, pCertificates[i].certLength, FALSE, &distinguishName, &distinguishNameLen))
        {
            if ( 0 == memcmp(pDistinguishedName, distinguishName, distinguishNameLen))
            {
                pReturnCert->pCertificate = pCertificates[i].pCertificate;
                pReturnCert->certLength   = pCertificates[i].certLength;
                status = OK;
                break;
            }
        }
    }
    free(distinguishName);
#else
#if 0
    /* normally locate certificate in store... */
    certDistinguishedName   issuer;
    sbyte4                     status;

    status = CA_MGMT_extractCertDistinguishedName(pCertificate, certificateLength, 0, &issuer);

    if (0 > status)
        return status;
#endif

    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(pDistinguishedName);
    MOC_UNUSED(distinguishedNameLen);

    /* for this example implementation, we only recognize one certificate authority */

    pReturnCert->pCertificate = fedoraRootCert;
    pReturnCert->certLength   = sizeof(fedoraRootCert);
    pReturnCert->cookie       = 0;
#endif

exit:
    return status;
}
#endif
#endif /* ifdef 0  functions are not referenced */

#if 0  /* functions are not referenced */
/*------------------------------------------------------------------*/

static sbyte4
releaseStoreCertificate(sbyte4 connectionInstance, certDescriptor* pFreeCert)
{
    MOC_UNUSED(connectionInstance);

    /* just need to release the certificate, not the key blob */
    if (0 != pFreeCert->pCertificate)
    {
        if (0 != pFreeCert->cookie)
        {
            free(pFreeCert->pCertificate);
        }

        pFreeCert->pCertificate = 0;
    }

    return 0;
}


/*------------------------------------------------------------------*/

static sbyte4
verifyCertificateInStore(sbyte4 connectionInstance,
                         ubyte *pCertificate, ubyte4 certificateLength,
                         sbyte4 isSelfSigned)
{
    /* lookup to verify certificate is in store */
    sbyte4 status = -1;

    MOC_UNUSED(connectionInstance);

#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
    ubyte4 i = 0;

    if (NULL != pCertificates && numCerts > 0)
    {
        for (i = 0; i < numCerts; i++)
        {
            if (certificateLength == pCertificates[i].certLength)
            {
                if ( 0 == memcmp(pCertificate, pCertificates[i].pCertificate, certificateLength))
                {
                    status = OK;
                    break;
                }
            }
        }
    }

    if (i == numCerts && 1 == isSelfSigned)
        status = OK;  /* do you accept self-signed certificates? if so, return 0 else error */
#else
    /* every app, should always check a length before a memcmp */
#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    if ((certificateLength == (m_rootCertificateLen)) &&
        (0 == memcmp(pCertificate, m_rootCertificate, certificateLength)) )
    {
        status = 0;             /* we recognize this certificate authority */
    }
#else
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
    if (m_rootCertificate &&
        (certificateLength == m_rootCertificateLen) &&
        (0 == memcmp(pCertificate, m_rootCertificate, certificateLength)))
    {
        status = 0;
    }
    else
#endif

    if ((certificateLength == sizeof(fedoraRootCert)) &&
        (0 == memcmp(pCertificate, fedoraRootCert, certificateLength)) )
    {
        status = 0;             /* we recognize this certificate authority */
    }
    else
    {
        if (1 == isSelfSigned)
            status = 0;         /* do you accept self-signed certificates? if so, return 0 else error */
    }
#endif
#endif
    return status;
}
#endif /* functions are not referenced */

/*------------------------------------------------------------------*/

#if !defined(__DISABLE_CA_MGMT_EXAMPLE_COMPUTE_HOST_KEYS__)

static sbyte4
testHostKeys(certDescriptor *pRetCertificateDescr)
{
    sbyte4 status;
    hwAccelDescr hwAccelCtx = 0;

#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)
    certDescriptor tempCertificateDescr = { NULL };
#endif

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        goto exit;
    }

    (void) DIGI_MEMSET((ubyte *)pRetCertificateDescr, 0x00, sizeof(certDescriptor));

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    /* read CA certificate */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (0 > (status = DPM_readSignedFile((char *)ROOT_DER_FILE,
                                        &m_rootCertificate, &m_rootCertificateLen, TRUE, DPM_CA_CERTS)))
#else
    if (0 > (status = DIGICERT_readFile((char *)ROOT_DER_FILE,
                                    &m_rootCertificate, &m_rootCertificateLen)))
#endif
    {
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        status = DPM_readSignedFile((char *)ROOT_PEM_FILE,
                                    &m_rootCertificate,
                                    &m_rootCertificateLen, TRUE, DPM_CA_CERTS);
#else
        status = DIGICERT_readFile((char *)ROOT_PEM_FILE,
                                    &m_rootCertificate,
                                    &m_rootCertificateLen);
#endif
#endif
    }
    if (OK == status)
    {
        ubyte *pDerCert = NULL;
        ubyte4 derCertLen;
        sbyte4 cmp = -1;

        status = DIGI_MEMCMP(m_rootCertificate, (ubyte *) "-----BEGIN CERTIFICATE-----", 27, &cmp);
        if (OK != status)
            goto exit;

        if ((0 == cmp) && (OK == CA_MGMT_decodeCertificate(m_rootCertificate, m_rootCertificateLen,
            &pDerCert, &derCertLen)))
        {
            DIGI_FREE((void **) &m_rootCertificate);
            m_rootCertificate = pDerCert;
            m_rootCertificateLen = derCertLen;
        }
    }

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    if (0 > status)
    {
        DEBUG_PRINTNL(DEBUG_EAP_EXAMPLE, (sbyte *)"testHostKeys: CA root does not exist.");
        goto exit;
    }
#endif
    status = 0;
#endif

#ifdef __ENABLE_DIGICERT_EXAMPLE_CERT_NOFS__

    pRetCertificateDescr->pCertificate = malloc(737);
    status = DIGI_MEMCPY(pRetCertificateDescr->pCertificate,rsaDerCert,737);
    pRetCertificateDescr->certLength = 737;



#else
    /* read host certificate */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (0 > (status = DPM_readSignedFile((char *)CERTIFICATE_DER_FILE,
                                    &pRetCertificateDescr->pCertificate,
                                    &pRetCertificateDescr->certLength, TRUE, DPM_CA_CERTS)))
#else
    if (0 > (status = DIGICERT_readFile((char *)CERTIFICATE_DER_FILE,
                                    &pRetCertificateDescr->pCertificate,
                                    &pRetCertificateDescr->certLength)))
#endif
    {
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (0 == (status = DPM_readSignedFile((char *)CERTIFICATE_PEM_FILE,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength, TRUE, DPM_CA_CERTS)))
#else
        if (0 == (status = DIGICERT_readFile((char *)CERTIFICATE_PEM_FILE,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength)))
#endif
        {
            /* convert PEM-encoded certificate to DER-encoded certificate */
            status = CA_MGMT_decodeCertificate(
                                    tempCertificateDescr.pCertificate,
                                    tempCertificateDescr.certLength,
                                    &pRetCertificateDescr->pCertificate,
                                    &pRetCertificateDescr->certLength);
        }
        if (0 > status)
#endif
        {
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
            if (m_pCertFile != CERTIFICATE_DER_FILE) /* from command line */
            {
                DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"testHostKeys: Cannot read host certificate, status = ", status);
                (void) CA_MGMT_freeCertificate(pRetCertificateDescr);
                status = 0;
            }
#endif
            goto exit;
        }
    }

#endif /*__ENABLE_DIGICERT_EXAMPLE_CERT_NOFS__*/

    /* read host keys */
#ifdef __ENABLE_DIGICERT_EXAMPLE_CERT_NOFS__
    pRetCertificateDescr->pKeyBlob = malloc(1057);
    status = DIGI_MEMCPY(pRetCertificateDescr->pKeyBlob,rsaKeyDat,1057);
    pRetCertificateDescr->keyBlobLength = 1057;


#else
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (0 > (status = DIGICERT_readFileEx((char *)HOST_KEYS,
                                    &pRetCertificateDescr->pKeyBlob,
                                    &pRetCertificateDescr->keyBlobLength, TRUE)))
#else
    if (0 > (status = DIGICERT_readFile((char *)HOST_KEYS,
                                    &pRetCertificateDescr->pKeyBlob,
                                    &pRetCertificateDescr->keyBlobLength)))
#endif
    {
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (0 == (status = DIGICERT_readFileEx((char *)HOST_KEYS_DER_FILE,
                                    &tempCertificateDescr.pKeyBlob,
                                    &tempCertificateDescr.keyBlobLength, TRUE)))
#else
        if (0 == (status = DIGICERT_readFile((char *)HOST_KEYS_DER_FILE,
                                    &tempCertificateDescr.pKeyBlob,
                                    &tempCertificateDescr.keyBlobLength)))
#endif
        {

            /* pkcs#1 and pkcs#8 decoding has been merged in serialize and deserialize keys
             API's so instead of decoding PKCS1 and PKCS8 seprately call the CRYPTO_deserializeAsymKey to
             get rsa key.*/
            AsymmetricKey   rsaKey;
            if (OK > (status = CRYPTO_initAsymmetricKey (&rsaKey)))
            {
                goto exit;
            }

            if (OK <= (status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) tempCertificateDescr.pKeyBlob, tempCertificateDescr.keyBlobLength, NULL, &rsaKey)))
            {
                if (OK > (status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &rsaKey, mocanaBlobVersion2, &pRetCertificateDescr->pKeyBlob, &pRetCertificateDescr->keyBlobLength)))
                {
                    DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"testHostKeys: Could not serialize key, status = ", status);
                    goto exit;
                }
            }
            CRYPTO_uninitAsymmetricKey(&rsaKey, NULL);
        }
        else
#endif
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
        {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            if (0 == (status = DIGICERT_readFileEx((char *)HOST_KEYS_PEM_FILE,
                                        &tempCertificateDescr.pKeyBlob,
                                        &tempCertificateDescr.keyBlobLength, TRUE)))
#else
            if (0 == (status = DIGICERT_readFile((char *)HOST_KEYS_PEM_FILE,
                                        &tempCertificateDescr.pKeyBlob,
                                        &tempCertificateDescr.keyBlobLength)))
#endif
            {
                /* convert PEM file key information to Digicert key blob */
                status = CA_MGMT_convertKeyPEM(
                                        tempCertificateDescr.pKeyBlob,
                                        tempCertificateDescr.keyBlobLength,
                                        &pRetCertificateDescr->pKeyBlob,
                                        &pRetCertificateDescr->keyBlobLength);
            }
        }
#endif
        {
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
            if ((0 > status) && (m_pHostKeyFile != HOST_KEYS)) /* from command line */
            {
                DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"testHostKeys: Cannot read key blob, status = ", status);
                (void) CA_MGMT_freeCertificate(pRetCertificateDescr);
                status = 0;
            }
#endif
            goto exit;
        }
    }

#endif /* __ENABLE_DIGICERT_EXAMPLE_CERT_NOFS__ */

exit:
    /* check status and free up space, if necessary */
#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)
    (void) CA_MGMT_freeCertificate(&tempCertificateDescr);
#endif
    if (0 > status)
        (void) CA_MGMT_freeCertificate(pRetCertificateDescr);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

/*------------------------------------------------------------------*/

extern sbyte4
computeHostKeysFromGivenFiles(certDescriptor *pRetCertificateDescr, sbyte *CACertPath, sbyte *ClientCertPath, sbyte *ClientKey)
{
    sbyte4 status = 0;

    certDescriptor tempCertificateDescr = { NULL };
    AsymmetricKey key = {0};
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        goto exit;
    }

    (void) DIGI_MEMSET((ubyte *)pRetCertificateDescr, 0x00, sizeof(certDescriptor));

#if (!defined(__ENABLE_DIGICERT_PEM_CONVERSION__) && !defined(__ENABLE_DIGICERT_DER_CONVERSION__))
    MOC_UNUSED(ClientKey); /* parameter only used with PEM and DER conversion */
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    /* read CA certificate */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (0 > (status = DPM_readSignedFile((char *)CACertPath,
                                    &tempCertificateDescr.pCertificate, &tempCertificateDescr.certLength, TRUE, DPM_CA_CERTS)))
#else
    if (0 > (status = DIGICERT_readFile((char *)CACertPath,
                                    &tempCertificateDescr.pCertificate, &tempCertificateDescr.certLength)))
#endif
    {
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (0 == (status = DPM_readSignedFile((char *)ROOT_PEM_FILE,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength, TRUE, DPM_CA_CERTS)))
#else
        if (0 == (status = DIGICERT_readFile((char *)ROOT_PEM_FILE,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength)))
#endif
        {
            status = CA_MGMT_decodeCertificate(
                                    tempCertificateDescr.pCertificate,
                                    tempCertificateDescr.certLength,
                                    &m_rootCertificate, &m_rootCertificateLen);

            (void) CA_MGMT_freeCertificate(&tempCertificateDescr);
        }
#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
        if (0 > status)
#endif
#endif
#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
        {
            DEBUG_PRINTNL(DEBUG_EAP_EXAMPLE, (sbyte *)"testHostKeys: CA root does not exist.");
            goto exit;
        }
#endif
    }
    else
    {
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
        status = CA_MGMT_decodeCertificate(tempCertificateDescr.pCertificate, tempCertificateDescr.certLength,
                                           &(pRetCertificateDescr[1].pCertificate), &(pRetCertificateDescr[1].certLength));
        m_rootCertificate = pRetCertificateDescr[1].pCertificate;
        m_rootCertificateLen = pRetCertificateDescr[1].certLength;

        (void) CA_MGMT_freeCertificate(&tempCertificateDescr);
        if (OK > status)
        {
            DEBUG_PRINTNL(DEBUG_EAP_EXAMPLE, (sbyte *)"unable to load CA files ");
            goto exit;
        }
#endif
    }

#else
    MOC_UNUSED(CACertPath);
#endif

    /* read host certificate */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (0 > (status = DIGICERT_readSignedFile((char *)ClientCertPath,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength, TRUE)))
#else
    if (0 > (status = DIGICERT_readFile((char *)ClientCertPath,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength)))
#endif
    {
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (0 == (status = DIGICERT_readSignedFile((char *)CERTIFICATE_PEM_FILE,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength, TRUE)))
#else
        if (0 == (status = DIGICERT_readFile((char *)CERTIFICATE_PEM_FILE,
                                    &tempCertificateDescr.pCertificate,
                                    &tempCertificateDescr.certLength)))
#endif
        {
            /* convert PEM-encoded certificate to DER-encoded certificate */
            status = CA_MGMT_decodeCertificate(
                                    tempCertificateDescr.pCertificate,
                                    tempCertificateDescr.certLength,
                                    &pRetCertificateDescr->pCertificate,
                                    &pRetCertificateDescr->certLength);
        }
        if (0 > status)
#endif
            goto exit;
    }
    else
    {
#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__
        status = CA_MGMT_decodeCertificate(tempCertificateDescr.pCertificate, tempCertificateDescr.certLength,
                                           &(pRetCertificateDescr[0].pCertificate), &(pRetCertificateDescr[0].certLength));
        (void) CA_MGMT_freeCertificate(&tempCertificateDescr);
        if (OK > status)
        {
            DEBUG_PRINTNL(DEBUG_EAP_EXAMPLE, (sbyte *)"unable to load CA files ");
            goto exit;
        }
#endif
    }

    /* read host keys */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
    if (0 == (status = DIGICERT_readFileEx((char *)ClientKey,
                                &tempCertificateDescr.pKeyBlob,
                                &tempCertificateDescr.keyBlobLength, TRUE)))
#else
    if (0 == (status = DIGICERT_readFile((char *)ClientKey,
                                &tempCertificateDescr.pKeyBlob,
                                &tempCertificateDescr.keyBlobLength)))
#endif
    {
        /* convert file key information to Digicert key blob */

        status = CRYPTO_initAsymmetricKey(&key);
        if (OK != status)
            goto exit;

        status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) tempCertificateDescr.pKeyBlob, tempCertificateDescr.keyBlobLength, NULL, &key);
        if (OK == status)
        {
            status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &key, mocanaBlobVersion2, &pRetCertificateDescr->pKeyBlob, &pRetCertificateDescr->keyBlobLength);
            if (OK != status)
                goto exit;
        }
    }

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);
    /* check status and free up space, if necessary */
    (void) CA_MGMT_freeCertificate(&tempCertificateDescr);
    if (0 > status)
        (void) CA_MGMT_freeCertificate(pRetCertificateDescr);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

#endif /* #if !defined(__DISABLE_CA_MGMT_EXAMPLE_COMPUTE_HOST_KEYS__) */

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_EXAMPLE_releaseHostKeys(certDescriptor *pCertificateDescr)
{
    (void) DIGICERT_freeReadFile(&pCertificateDescr->pCertificate);
    (void) DIGICERT_freeReadFile(&pCertificateDescr->pKeyBlob);

    return 0;
}


/*------------------------------------------------------------------*/

#if !defined(__DISABLE_CA_MGMT_EXAMPLE_COMPUTE_HOST_KEYS__)

extern sbyte4
CA_MGMT_EXAMPLE_computeHostKeys(certDescriptor *pRetCertificateDescr)
{
    sbyte4 status;

#ifndef __ENABLE_DIGICERT_TPM_SSL_SERVER__
#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)
    certDescriptor tempCertificateDescr = { NULL };
#endif
#if defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    certExtensions extensions = { 0 };
    extensions.hasBasicConstraints = TRUE;
    extensions.isCA = TRUE;
    extensions.certPathLen = -1;
    extensions.hasKeyUsage = TRUE;
    extensions.keyUsage = (1 << digitalSignature) + (1 << keyCertSign);
#endif
    /* check for pre-existing set of host keys */
    if (0 > (status = testHostKeys(pRetCertificateDescr)))
    {
#endif
#ifndef __DISABLE_DIGICERT_CA_MGMT_EXAMPLE_CERTS__
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *)"CA_MGMT_EXAMPLE_computeHostKeys: host keys do not exist, computing new key pair.");

#ifdef _MSC_VER
        InitExampleCertDescr();
#endif
        /* if not, compute new host keys */
#ifdef __ENABLE_DIGICERT_TPM_SSL_SERVER__
        if (0 > (status = CA_MGMT_generateCertificateEx2(pRetCertificateDescr, pRetCertificateDescr->pKey,
                &exampleCertificateDescr, ht_sha1)))
#else

#if defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
        if (0 > (status = CA_MGMT_generateCertificateEx(pRetCertificateDescr,
#ifdef ECC_EXAMPLE_KEY_SIZE
                                                        ECC_EXAMPLE_KEY_SIZE,
#else
                                                        RSA_EXAMPLE_KEY_SIZE,
#endif
                                                        &exampleCertificateDescr, ht_sha1,
                                                        &extensions, NULL)))
#elif defined(ECC_EXAMPLE_KEY_SIZE) && defined(__ENABLE_DIGICERT_SSL_SERVER__) && defined(__ENABLE_DIGICERT_CCM_8__)
        if (0 > (status = CA_MGMT_generateCertificateEx(pRetCertificateDescr, ECC_EXAMPLE_KEY_SIZE,
                                                        &exampleCertificateDescr, ht_sha256,
                                                        NULL, NULL)))
#else
        if (0 > (status = CA_MGMT_generateCertificateEx(pRetCertificateDescr, RSA_EXAMPLE_KEY_SIZE,
                                                        &exampleCertificateDescr, ht_sha1,
                                                        NULL, NULL)))
#endif
#endif
        {
            DEBUG_ERROR(DEBUG_CRYPTO, (sbyte *)"CA_MGMT_generateCertificateEx() failed, status = ", status);
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (0 > (status = DIGICERT_writeFileEx((const char *)CERTIFICATE_DER_FILE,
                                           pRetCertificateDescr->pCertificate,
                                           pRetCertificateDescr->certLength, TRUE)))
#else
        if (0 > (status = DIGICERT_writeFile((const char *)CERTIFICATE_DER_FILE,
                                           pRetCertificateDescr->pCertificate,
                                           pRetCertificateDescr->certLength)))
#endif
        {
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"CA_MGMT_EXAMPLE: DIGICERT_writeFile() failed, status = ", status);
            goto exit;
        }

#ifndef __ENABLE_DIGICERT_TPM_SSL_SERVER__
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        if (0 > (status = DIGICERT_writeFileEx((const char *)HOST_KEYS,
                                           pRetCertificateDescr->pKeyBlob,
                                           pRetCertificateDescr->keyBlobLength, TRUE)))
#else
        if (0 > (status = DIGICERT_writeFile((const char *)HOST_KEYS,
                                           pRetCertificateDescr->pKeyBlob,
                                           pRetCertificateDescr->keyBlobLength)))
#endif
        {
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"CA_MGMT_EXAMPLE: DIGICERT_writeFile() failed, status = ", status);
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)
        if (OK ==
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
                  CA_MGMT_keyBlobToDER
#else
                  CA_MGMT_keyBlobToPEM
#endif
                                      (pRetCertificateDescr->pKeyBlob,
                                       pRetCertificateDescr->keyBlobLength,
                                       &tempCertificateDescr.pKeyBlob,
                                       &tempCertificateDescr.keyBlobLength))
        {
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
            (void) DIGICERT_writeFileEx((const char *)
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
                             HOST_KEYS_DER_FILE,
#else
                             HOST_KEYS_PEM_FILE,
#endif
                             tempCertificateDescr.pKeyBlob,
                             tempCertificateDescr.keyBlobLength, TRUE);
#else
            (void) DIGICERT_writeFile((const char *)
#ifdef __ENABLE_DIGICERT_DER_CONVERSION__
                             HOST_KEYS_DER_FILE,
#else
                             HOST_KEYS_PEM_FILE,
#endif
                             tempCertificateDescr.pKeyBlob,
                             tempCertificateDescr.keyBlobLength);
#endif
        }
#endif
#endif
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *)"CA_MGMT_EXAMPLE_computeHostKeys: host key computation completed.");
#else
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *)"CA_MGMT_EXAMPLE_computeHostKeys: failed...");
#endif
#ifndef __ENABLE_DIGICERT_TPM_SSL_SERVER__
    }
#endif

exit:
#if (defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)) && !defined(__ENABLE_DIGICERT_TPM_SSL_SERVER__)
    (void) CA_MGMT_freeCertificate(&tempCertificateDescr);
#endif
    if (0 > status)
    {
        (void) CA_MGMT_freeCertificate(pRetCertificateDescr);
    }
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
    else if (m_rootCertificate && m_rootCertificateLen)
    {
        certDescriptor caDescr = { NULL };
        caDescr.pCertificate = m_rootCertificate;
        caDescr.certLength = m_rootCertificateLen;
        if (OK > (status = IKE_initTrustAnchor(&caDescr, 1)))
        {
            DEBUG_ERROR(DEBUG_IKE_EXAMPLE, (sbyte *)"CA_MGMT_EXAMPLE: IKE_initTrustAnchor() failed, status = ", status);
        }
    }
#endif
    return status;
}

#endif /* #if !defined(__DISABLE_CA_MGMT_EXAMPLE_COMPUTE_HOST_KEYS__) */

/*------------------------------------------------------------------*/

#if 0   /* function not used */
/* Enable if certificate leaf test needs to be performed */
static sbyte4
certificateLeafTest(sbyte4 serverInstance, struct ikesa *pxSa,
                    ubyte *pCertificate, ubyte4 certificateLen)
{
    sbyte4 status = OK;
    MOC_UNUSED(serverInstance);
    MOC_UNUSED(pxSa);
    MOC_UNUSED(pCertificate);
    MOC_UNUSED(certificateLen);

    //const  sbyte4 oid[] = { 0x55, 0x1d, 0x25 };
    //const  sbyte4 oidCheck[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
    //sbyte4 isPresent = 0;

    //status = CA_MGMT_rawVerifyOID(pCertificate, certificateLen, oid, sizeof(oid) / sizeof(sbyte4), oidCheck, sizeof(oidCheck) / sizeof(sbyte4), &isPresent);

    //if (isPresent)
    //    printf("certificateLeafTest: Secure Mail certificate OID is present!\n");

    return status;
}
#endif

/*------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__))
certStorePtr pSslClientCertStore;
#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__))
static sbyte4
setMutualAuthCertStore()
{
    MSTATUS status = OK;
    certDescriptor retCertDescr;
    SizedBuffer certificate[1];

#if 0
    {
        sbyte4 status;
        if (0 > (status = DIGICERT_readFile((char *)"CertChain.dat",
                                          &retCertDescr.pCertificate,
                                          &retCertDescr.certLength)))
            return status;

        status = DIGICERT_readFile((char *)"MyLeafCertKey.dat",
                                 &retCertDescr.pKeyBlob,
                                 &retCertDescr.keyBlobLength);

        return status;
    }
#else
    /* normally, lookup certificate for particular interface */
    /* for this example, we just recycle the host certificate out of the file system */
    CA_MGMT_EXAMPLE_computeHostKeys(&retCertDescr);
#endif


    certificate[0].data = retCertDescr.pCertificate;
    certificate[0].length = retCertDescr.certLength;

    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(pSslClientCertStore, certificate, 1, retCertDescr.pKeyBlob, retCertDescr.keyBlobLength)))
        goto exit;



exit:
    CA_MGMT_EXAMPLE_releaseHostKeys(&retCertDescr);

    return status;
}
#endif /*__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__*/
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__))
static sbyte4
freeMutualAuthCertStore()
{
    return CERT_STORE_releaseStore(&pSslClientCertStore);
}
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
sbyte4 returnZeroPacKey(sbyte4 connectionInstance, ubyte* pPACOpaque, ubyte4 pacOpaqueLen,
                        ubyte pacKey[/*PACKEY_SIZE*/])
{
    /* just return a pacKey full of zero for testing -- a real implementation
    would use the pPacOpaque to retrieve the key */
    (void) DIGI_MEMSET( pacKey, 0, 32);
    return OK;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__))
certStorePtr pSslCertStore;
#ifndef __ENABLE_DIGICERT_TPM_SSL_SERVER__
static sbyte4
setServerCertStore()
{
    SizedBuffer certificates[2];
    ubyte4 numCertificate;
    AsymmetricKey key = { 0 };

    ubyte*  pLeaf = NULL;
    ubyte4  leafLen = 0;
#if 0
    ubyte*  pIssuer = NULL;
    ubyte4  issuerLen = 0;
#endif  /* no longer used here */
    ubyte*  pKey = NULL;
    ubyte4  keyLen;
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLen = 0;
    MSTATUS status;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
    {
        goto exit;
    }

    /* read all of the data in... */
    if (OK > (status = (MSTATUS) DIGICERT_readFile(CERTIFICATE_DER_FILE, &pLeaf, &leafLen)))
        goto exit;

#if 1 /*read in Keys file*/

    if (OK > (status = (MSTATUS) DIGICERT_readFile(HOST_KEYS_DER_FILE, &pKey, &keyLen)))
        goto exit;
    /* convert file key information to Digicert key blob */

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, &key);
    if (OK == status)
    {
        status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &key, mocanaBlobVersion2, &pKeyBlob, &keyBlobLen);
        if (OK != status)
            goto exit;
    }
    else
    {
        goto exit;
    }


#else /*read in Digicert keyBlob*/
    if (OK > (status = DIGICERT_readFile(HOST_KEYS, &pKeyBlob, &keyBlobLen)))
        goto exit;
#endif

    if (OK > (status = CERT_STORE_createStore(&pSslCertStore)))
        goto exit;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    /*Populate cert store with root certificats*/
    ubyte4 j;
    for (j = 0 ; j < COUNTOF(gExampleRootCerts); ++j)
    {

        /*Read root certs*/
        if (OK > (status = DIGICERT_readFile(gExampleRootCerts[j].fileName,
                                           &gExampleRootCerts[j].certData,
                                           &gExampleRootCerts[j].certLength)))
           continue;

        /*Add root certs as trust points*/
        if (OK > (status = CERT_STORE_addTrustPoint(pSslCertStore,
                                                    gExampleRootCerts[j].certData,
                                                    gExampleRootCerts[j].certLength)))
            goto exit;
    }
#endif

    certificates[0].data = pLeaf;
    certificates[0].length = leafLen;
    numCertificate = (ubyte4) 1;

#if 0 /* Code to add issuer and upload certificate chain */
    if (OK > (status = DIGICERT_readFile(ROOT_DER_FILE, &pIssuer, &issuerLen)))
        goto exit;
    certificates[1].data = pIssuer;
    certificates[1].length = issuerLen;
    numCertificate = 2;
#endif

    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(pSslCertStore, certificates, numCertificate, pKeyBlob, keyBlobLen)))
        goto exit;

exit:

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    if(pLeaf)
        (void) DIGICERT_freeReadFile(&pLeaf);

    if(pKey)
        (void) DIGICERT_freeReadFile(&pKey);

    if(pKeyBlob)
        (void) DIGICERT_freeReadFile(&pKeyBlob);

#if 0
    if(pIssuer)
        (void) DIGICERT_freeReadFile(&pIssuer);
#endif
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}
#endif /* __ENABLE_DIGICERT_TPM_SSL_SERVER__ */
#endif


/*------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__))

static sbyte4
setClientCertStore()
{
    ubyte           j;
    MSTATUS         status;

    /*Initialize Cert Store*/
    if (OK > (status = CERT_STORE_createStore(&pSslClientCertStore)))
        goto exit;

    /*Populate cert store with root certificats*/
    for (j = 0 ; j < COUNTOF(gExampleRootCerts); ++j)
    {

        /*Read root certs*/
        if (OK > (status = (MSTATUS) DIGICERT_readFile(gExampleRootCerts[j].fileName,
                                           &gExampleRootCerts[j].certData,
                                           &gExampleRootCerts[j].certLength)))
	    continue;

        /*Add root certs as trust points*/
        if (OK > (status = CERT_STORE_addTrustPoint(pSslClientCertStore,
                                                    gExampleRootCerts[j].certData,
                                                    gExampleRootCerts[j].certLength)))
            goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    setMutualAuthCertStore();
#endif

exit:
    return status;
}
#endif
/*------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__))

static sbyte4
freeClientCertStore()
{
    (void) CERT_STORE_releaseStore(&pSslClientCertStore);
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    freeMutualAuthCertStore();
#endif

    return 0;
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSL_SERVER__))
static sbyte4
freeServerCertStore()
{
    return (sbyte4)CERT_STORE_releaseStore(&pSslCertStore);
}
#endif

/*------------------------------------------------------------------*/

extern void
CA_MGMT_EXAMPLE_initUpcalls(void)
{
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
    if (NULL == CERTIFICATE_DER_FILE) CERTIFICATE_DER_FILE = m_pCertFile;
    if (NULL == HOST_KEYS) HOST_KEYS = m_pHostKeyFile;
#endif
#if defined(__ENABLE_DIGICERT_SSL_SERVER__) && !defined(__ENABLE_DIGICERT_TPM_SSL_SERVER__) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    (void) setServerCertStore();
#endif
#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
    getCaBundle();
#endif
#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) || defined(__ENABLE_DIGICERT_SSL_SERVER__)) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    /* SSL_sslSettings()->funcPtrCertificateStoreVerify    = verifyCertificateInStore; */
    /* SSL_sslSettings()->funcPtrCertificateStoreLookup    = findCertificateInStore; */
    /* SSL_sslSettings()->funcPtrCertificateStoreRelease   = releaseStoreCertificate; */
#if (defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_SERVER__))
    SSL_sslSettings()->funcPtrPACOpaqueCallback         = returnZeroPacKey;
#endif
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    (void) setClientCertStore();
#endif
#endif /* (defined(__ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE__) || defined(__ENABLE_DIGICERT_SSL_SERVER__)) */
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
#if 0
    // Enable if certificate leaf needs to be performed
    IKE_ikeSettings()->funcPtrCertificateLeafTest       = certificateLeafTest;
#endif
#endif
}


/*------------------------------------------------------------------*/

extern void
CA_MGMT_EXAMPLE_uninitUpcalls(void)
{
#if defined(__ENABLE_DIGICERT_SSL_SERVER__) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    (void) freeServerCertStore();
#endif

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && !defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    (void) freeClientCertStore();
#endif
#ifdef __ENABLE_DIGICERT_CA_BUNDLE_SUPPORT__
    releaseCaBundle();
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)
    (void) DIGICERT_freeReadFile(&m_rootCertificate);
    m_rootCertificateLen = 0;
#endif
    if (m_mocanaServerCert != NULL)
        (void) DIGICERT_freeReadFile(&m_mocanaServerCert);
}

#if 0 /* unused & deprecated */
extern sbyte4
CA_MGMT_EXAMPLE_testAPI(ubyte* pFileName)
{

    MSTATUS status      = OK;
    ubyte* pCertificate = NULL;
    ubyte4 certLength   = 0;
    ubyte* pSignature   = NULL;
    ubyte4 sigLength    = 0;
    intBoolean isCritical = FALSE;
    certExtensions certExt;
    ubyte4 hashType     = 0;
    ubyte4 pubKeyType   = 0;
#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__
    ubyte* pSerialNum   = NULL;
    ubyte4 serialNumLength;
#endif
    certDistinguishedName *pMyDNs = NULL;
    certDistinguishedName *pTimeDNs = NULL;
    certDistinguishedName *pSubjectDNs = NULL;

    ubyte* pKeyBlob = NULL;
    ubyte4 keyBlobLen;

    certDescriptor certChain[6];
    ubyte     *file = NULL;
    ubyte4     fileLen = 0;

    ubyte4 i,j;

    ubyte pShaFingerPrint[20];
    ubyte pMD5FingerPrint[16];

#ifdef __ENABLE_DIGICERT_CA_MGMT_UTILS__
    intBoolean dnCompareResult = FALSE;
#endif
    ubyte* pSignedCertificate = NULL;
    ubyte4 signedCertLength;
    sbyte  numReorderedCert = 0;

    (void) DIGI_MEMSET((ubyte *)certChain, 0x00, sizeof(certChain));

    if (OK > DIGICERT_readFile((const char *)pFileName, &pCertificate, &certLength))
        goto exit;

    if (OK > (status = CA_MGMT_returnCertificatePrints(pCertificate, certLength, pShaFingerPrint, pMD5FingerPrint)))
        goto exit;

    if (OK > (status = CA_MGMT_extractPublicKeyInfo(pCertificate, certLength, &pKeyBlob, &keyBlobLen)))
        goto exit;

    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pSubjectDNs)))
        goto exit;

    /* Now verify signature of the certificate */
    if (OK > DIGICERT_readFile((const char *) "requester_cert.der", &pSignedCertificate, &signedCertLength))
        goto exit;

    if (OK > (status = CA_MGMT_verifySignature(pKeyBlob, keyBlobLen, pSignedCertificate, signedCertLength)))
        goto exit;

    if (OK > (status = CA_MGMT_extractSignature(pCertificate, certLength, &pSignature, &sigLength)))
        goto exit;

    if (OK > (status = CA_MGMT_extractBasicConstraint(pCertificate, certLength, &isCritical, &certExt)))
    {
        if (ERR_CERT_BASIC_CONSTRAINT_EXTENSION_NOT_FOUND == status)
        {
            /* No well formed basic constraint extension present; do your stuff here*/
        }
        else
        {
            goto exit;
        }
    }

    if (OK > (status = CA_MGMT_getCertSignAlgoType(pCertificate, certLength, &hashType, &pubKeyType)))
        goto exit;

    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pTimeDNs)))
        goto exit;

    if (OK > (status = CA_MGMT_extractCertTimes(pCertificate, certLength, pTimeDNs)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__
    if (OK > (status = CA_MGMT_extractSerialNum(pCertificate, certLength, &pSerialNum, &serialNumLength)))
        goto exit;
#endif
    /* Create a clone of certDistinguishedName */
    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pMyDNs)))
        goto exit;

    pMyDNs->dnCount = exampleCertificateDescr.dnCount;
    pMyDNs->pDistinguishedName = (relativeDN *)MALLOC(sizeof(relativeDN)*pMyDNs->dnCount);
    if (NULL == pMyDNs->pDistinguishedName)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for (i = 0; i < exampleCertificateDescr.dnCount; i++)
    {
        relativeDN *pSrcDn = &exampleCertificateDescr.pDistinguishedName[i];
        relativeDN *pDstDn = &pMyDNs->pDistinguishedName[i];
        pDstDn->nameAttrCount = pSrcDn->nameAttrCount;
        pDstDn->pNameAttr = (nameAttr *)MALLOC(sizeof(nameAttr)*pSrcDn->nameAttrCount);
        if (NULL == pDstDn->pNameAttr)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        for (j = 0; j < pSrcDn->nameAttrCount; j++)
        {
            nameAttr *pSrcNameAttr = &pSrcDn->pNameAttr[j];
            nameAttr *pDstNameAttr = &pDstDn->pNameAttr[j];
            /* should point to const */
            pDstNameAttr->oid = pSrcNameAttr->oid;
            pDstNameAttr->type = pSrcNameAttr->type;
            pDstNameAttr->valueLen = pSrcNameAttr->valueLen;
            pDstNameAttr->value = (ubyte *)MALLOC(pSrcNameAttr->valueLen);
            if (NULL == pDstNameAttr->value)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(pDstNameAttr->value, pSrcNameAttr->value, pSrcNameAttr->valueLen);

        }
    }

#ifdef __ENABLE_DIGICERT_CA_MGMT_UTILS__
    /* CA_MGMT_certDistinguishedNameCompare example */
    if (OK > (status = CA_MGMT_certDistinguishedNameCompare(&exampleCertificateDescr, pMyDNs, &dnCompareResult)))
        goto exit;

    /* Check result */
    if (TRUE == dnCompareResult)
    {
        /* certDistinguished names are identical and matched */
    }
#endif

    /* CA_MGMT_reorderChain sample */
    if (OK > (status = DIGICERT_readFile((const char *)"ECDHCert521_ECC.der", &file, &fileLen)))
        goto exit;
    certChain[2].pCertificate = file;
    certChain[2].certLength   = fileLen;

    if (OK > (status = DIGICERT_readFile((const char *)"ECDHCert384_ECC.der", &file, &fileLen)))
        goto exit;
    certChain[3].pCertificate = file;
    certChain[3].certLength   = fileLen;

    if (OK > (status = DIGICERT_readFile((const char *)"ECDHCert224_ECC.der", &file, &fileLen)))
        goto exit;
    certChain[1].pCertificate = file;
    certChain[1].certLength   = fileLen;

    if (OK > (status = DIGICERT_readFile((const char *)"ECDHCert192_ECC.der", &file, &fileLen)))
        goto exit;
    certChain[0].pCertificate = file;
    certChain[0].certLength   = fileLen;

    if (OK > (status = DIGICERT_readFile((const char *)"ECDHCert256_ECC.der", &file, &fileLen)))
        goto exit;
    certChain[4].pCertificate = file;
    certChain[4].certLength   = fileLen;

    if (OK > (status = DIGICERT_readFile((const char *)"ECCCertCA.der", &file, &fileLen)))
        goto exit;
    certChain[5].pCertificate = file;
    certChain[5].certLength   = fileLen;

    /* Positive test */
    status = CA_MGMT_reorderChain(certChain, 6, &numReorderedCert);

exit:
    if (pSubjectDNs)
        CA_MGMT_freeCertDistinguishedName(&pSubjectDNs);

    if (pTimeDNs)
        CA_MGMT_freeCertDistinguishedName(&pTimeDNs);

    /* Now free the cloned CertDistinguishedName */
    if (pMyDNs)
        CA_MGMT_freeCertDistinguishedName(&pMyDNs);

    if (pKeyBlob)
        CA_MGMT_freeKeyBlob(&pKeyBlob);

    if (pSignedCertificate)
        FREE(pSignedCertificate);

    if(pCertificate)
        FREE(pCertificate);

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__
    if(pSerialNum)
        FREE(pSerialNum);
#endif

    if (pSignature)
        FREE(pSignature);

    for (i=0; i < 5; i++)
    {
        if (certChain[i].pCertificate)
            FREE (certChain[i].pCertificate);
    }

    /*if (pMD5FingerPrint)
        FREE(pMD5FingerPrint);

    if (pShaFingerPrint)
        FREE(pShaFingerPrint);*/

    return status;

}
#endif /* 0 */

extern sbyte4
CA_MGMT_EXAMPLE_verifyCertWithKeyBlob(const sbyte* certFileName, const sbyte* keyFileName)
{
    MSTATUS status;
    certDescriptor certDescr = { 0 };
    ubyte* buffer = NULL;
    ubyte4 bufferLen;
    ubyte* keyblob = NULL;
    ubyte4 keyblobLen;
    sbyte4 result = 0;

    if (OK > (status = (MSTATUS) DIGICERT_readFile((const char *)certFileName, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (OK > (status = (MSTATUS) DIGICERT_readFile((const char *)keyFileName, &keyblob,
                                                        &keyblobLen)))
    {
        goto exit;
    }

    certDescr.pCertificate  = buffer;
    certDescr.certLength    = bufferLen;
    certDescr.pKeyBlob      = keyblob;
    certDescr.keyBlobLength = keyblobLen;

    if (OK > (status = (MSTATUS) CA_MGMT_verifyCertWithKeyBlob(&certDescr, &result)))
    {
        goto exit;
    }

exit:

    if (NULL != buffer)
        FREE(buffer);

    if (NULL != keyblob)
        FREE(keyblob);

    return status;
}

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__

typedef struct ExpectedCRLValue {
    ubyte4          type;
    const sbyte*    value;
} ExpectedCRLValue;

typedef struct MyEnumCrlCbArg
{
    ubyte4 failures;
    ubyte4 numValues;
    const ExpectedCRLValue* pExpectedValues;
} MyEnumCrlCbArg;

sbyte4
MyEnumCallback(const ubyte* crlValue, ubyte4 crlValueLen, ubyte4 type,
                       ubyte4 index, void* userArg)
{
    MyEnumCrlCbArg* pTestInfo = (MyEnumCrlCbArg*) userArg;
    const ExpectedCRLValue* pEV;
    ubyte4 errors = 0;
    sbyte4 cmpRes;

    if (index < pTestInfo->numValues)
    {
        pEV = pTestInfo->pExpectedValues + index;

        /* Test whether the observed value is same as the expected value */
        if (pEV->type != type)
        {
            /* Not the expected value; do your stuff here  */
            errors ++;
        }

        if (crlValueLen != DIGI_STRLEN(pEV->value))
        {
            /* Not the expected value; do your stuff here  */
            errors ++;
        }

        DIGI_MEMCMP(crlValue, (const ubyte *)pEV->value, crlValueLen, &cmpRes);
        if (0 != cmpRes)
        {
            /* Not the expected value; do your stuff here  */
            errors ++;
        }

    }
    else
    {
        /* Not the expected value; do your stuff here */
        errors ++;
    }

    pTestInfo->failures += errors;
    return 0;
}

/*------------------------------------------------------------------------*/
extern sbyte4
CA_MGMT_EXAMPLE_enumCRL_test(const sbyte* fileName, ubyte2 numCRLs,
                 const ExpectedCRLValue* expectedValues)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MyEnumCrlCbArg testInfo;

    testInfo.failures = 0;
    testInfo.numValues = numCRLs;
    testInfo.pExpectedValues = expectedValues;

    if (OK > (status = DIGICERT_readFile((const char *) fileName, &pCert, &certLen)))
        goto exit;

    if (OK > (status = CA_MGMT_enumCrl(pCert, certLen, MyEnumCallback, &testInfo)))
        goto exit;

exit:

    if (pCert)
    {
        FREE(pCert);
    }

    return status;
}

#endif /* def __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__ */

#endif /* (defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER_EXAMPLE__)) */
#endif /* (defined(__ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE__) || defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__)) */
