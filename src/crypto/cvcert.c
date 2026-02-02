/*
 * cvcert.c
 *
 * Definitions of functions that build and read various CV CERT constructs.
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

#ifdef __ENABLE_DIGICERT_CV_CERT__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../asn1/parseasn1.h"

#include "../crypto/pubcrypto.h"
#include "../crypto/crypto.h"
#include "../crypto/cvcert.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/malgo_id.h"
#include "../crypto/rsa.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/cryptointerface.h"

#ifdef __ENABLE_DIGICERT_PKCS1__
#include "../crypto/pkcs1.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/ecc.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

/* From Table 27 Section D2 
   Technical Guideline TR-03110
   Advanced Security Mechanisms for Machine Readable Travel Documents and eIDAS Token */

#define OID                       0x06   /* Object Identifier */
#define CERT_AUTH_REF             0x42   /* Certification Authority Reference */
#define DISC_DATA                 0x53   /* Octet String Contains arbitrary data. */
#define CERT_HOLDER_REF           0x5F20 /* Character String Associates the public key contained in a certificate with an identifier. */
#define CERT_EXP_DATE             0x5F24 /* The date after which the certificate expires. */
#define CERT_EFFECTIVE_DATE       0x5F25 /* The date of the certificate generation. */
#define CERT_PROFILE_ID           0x5F29 /* Version of the certificate and certificate request format. */
#define SIGNATURE                 0x5F37 /* Digital signature produced by an asymmetric cryptographic algorithm. */
#define CERT_EXTENSIONS           0x65   /* Nests certificate extensions. */
#define AUTHENTICATION            0x67   /* Contains authentication related data objects. */
#define DISC_DATA_TEMPLATE        0x73   /* Nests arbitrary data objects. */
#define CV_CERT_TAG               0x7F21 /* Nests certificate body and signature. */
#define PUBLIC_KEY                0x7F49 /* Nests the public key value and the domain parameters. */
#define CERT_HOLDER_AUTH_TEMPLATE 0x7F4C /* Sequence Encodes the role of the certificate holder (i.e. CVCA, DV, Terminal) */
                                         /* and assigns read/write access rights.*/
#define CERT_BODY                 0x7F4E /* Nests data objects of the certificate body */

#define RSA_MODULUS   0x81
#define RSA_EXP       0x82

#ifdef __ENABLE_DIGICERT_ECC__
#define ECC_MODULUS           0x81
#define ECC_FIRST_COEFF       0x82
#define ECC_SECOND_COEFF      0x83
#define ECC_BASE_POINT        0x84
#define ECC_BASE_POINT_ORDER  0x85
#define ECC_PUB_POINT         0x86
#define ECC_COFACTOR          0x87

/************************* P *****************************/
#ifdef __ENABLE_DIGICERT_ECC_P192__
static const ubyte gpP192_P[24] =
{
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
#endif

static const ubyte gpP224_P[28] =
{
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

static const ubyte gpP256_P[32] =
{
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

static const ubyte gpP384_P[48] =
{
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
};

static const ubyte gpP521_P[66] =
{
    0x01,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
};

static const ubyte *gpEccP[] = 
{
   (ubyte *) gpP224_P, (ubyte *) gpP256_P, (ubyte *) gpP384_P, (ubyte *) gpP521_P
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , (ubyte *) gpP192_P
#endif
};

/************************** A *****************************/

#ifdef __ENABLE_DIGICERT_ECC_P192__
static const ubyte gpP192_A[24] =
{
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
};
#endif

static const ubyte gpP224_A[28] =
{
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe
};

static const ubyte gpP256_A[32] =
{
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc
};

static const ubyte gpP384_A[48] =
{
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xfc,
};

static const ubyte gpP521_A[66] =
{
    0x01,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,
};

static const ubyte *gpEccA[] = 
{
   (ubyte *) gpP224_A, (ubyte *) gpP256_A, (ubyte *) gpP384_A, (ubyte *) gpP521_A
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , (ubyte *) gpP192_A
#endif
};

/************************** B *****************************/

#ifdef __ENABLE_DIGICERT_ECC_P192__
static const ubyte gpP192_B[24] =
{
    0x64,0x21,0x05,0x19,0xe5,0x9c,0x80,0xe7,0x0f,0xa7,0xe9,0xab,0x72,0x24,0x30,0x49,
    0xfe,0xb8,0xde,0xec,0xc1,0x46,0xb9,0xb1
};
#endif

static const ubyte gpP224_B[28] =
{
    0xb4,0x05,0x0a,0x85,0x0c,0x04,0xb3,0xab,0xf5,0x41,0x32,0x56,0x50,0x44,0xb0,0xb7,
    0xd7,0xbf,0xd8,0xba,0x27,0x0b,0x39,0x43,0x23,0x55,0xff,0xb4
};

static const ubyte gpP256_B[32] =
{
    0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
    0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b
};

static const ubyte gpP384_B[48] =
{
    0xb3,0x31,0x2f,0xa7,0xe2,0x3e,0xe7,0xe4,0x98,0x8e,0x05,0x6b,0xe3,0xf8,0x2d,0x19,
    0x18,0x1d,0x9c,0x6e,0xfe,0x81,0x41,0x12,0x03,0x14,0x08,0x8f,0x50,0x13,0x87,0x5a,
    0xc6,0x56,0x39,0x8d,0x8a,0x2e,0xd1,0x9d,0x2a,0x85,0xc8,0xed,0xd3,0xec,0x2a,0xef
};

static const ubyte gpP521_B[65] =
{
    0x51,
    0x95,0x3e,0xb9,0x61,0x8e,0x1c,0x9a,0x1f,0x92,0x9a,0x21,0xa0,0xb6,0x85,0x40,0xee,
    0xa2,0xda,0x72,0x5b,0x99,0xb3,0x15,0xf3,0xb8,0xb4,0x89,0x91,0x8e,0xf1,0x09,0xe1,
    0x56,0x19,0x39,0x51,0xec,0x7e,0x93,0x7b,0x16,0x52,0xc0,0xbd,0x3b,0xb1,0xbf,0x07,
    0x35,0x73,0xdf,0x88,0x3d,0x2c,0x34,0xf1,0xef,0x45,0x1f,0xd4,0x6b,0x50,0x3f,0x00
};

static const ubyte *gpEccB[] = 
{
   (ubyte *) gpP224_B, (ubyte *) gpP256_B, (ubyte *) gpP384_B, (ubyte *) gpP521_B
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , (ubyte *) gpP192_B
#endif
};

/************************** G *****************************/

#ifdef __ENABLE_DIGICERT_ECC_P192__
static const ubyte gpP192_G[49] =
{
    0x04,
    0x18,0x8d,0xa8,0x0e,0xb0,0x30,0x90,0xf6,0x7c,0xbf,0x20,0xeb,0x43,0xa1,0x88,0x00,
    0xf4,0xff,0x0a,0xfd,0x82,0xff,0x10,0x12,
    0x07,0x19,0x2b,0x95,0xff,0xc8,0xda,0x78,0x63,0x10,0x11,0xed,0x6b,0x24,0xcd,0xd5,
    0x73,0xf9,0x77,0xa1,0x1e,0x79,0x48,0x11
};
#endif

static const ubyte gpP224_G[57] =
{
    0x04,
    0xb7,0x0e,0x0c,0xbd,0x6b,0xb4,0xbf,0x7f,0x32,0x13,0x90,0xb9,0x4a,0x03,0xc1,0xd3,
    0x56,0xc2,0x11,0x22,0x34,0x32,0x80,0xd6,0x11,0x5c,0x1d,0x21,
    0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,0xdf,0xe6,0xcd,0x43,0x75,0xa0,
    0x5a,0x07,0x47,0x64,0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34
};

static const ubyte gpP256_G[65] =
{
    0x04,
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};

static const ubyte gpP384_G[97] =
{
    0x04,
    0xaa,0x87,0xca,0x22,0xbe,0x8b,0x05,0x37,0x8e,0xb1,0xc7,0x1e,0xf3,0x20,0xad,0x74,
    0x6e,0x1d,0x3b,0x62,0x8b,0xa7,0x9b,0x98,0x59,0xf7,0x41,0xe0,0x82,0x54,0x2a,0x38,
    0x55,0x02,0xf2,0x5d,0xbf,0x55,0x29,0x6c,0x3a,0x54,0x5e,0x38,0x72,0x76,0x0a,0xb7,
    0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,0x98,0xbf,0x92,0x92,0xdc,0x29,
    0xf8,0xf4,0x1d,0xbd,0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,0x13,0xb5,0xf0,0xb8,0xc0,
    0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f
};

static const ubyte gpP521_G[133] =
{
    0x04,0x00,0xc6,
    0x85,0x8e,0x06,0xb7,0x04,0x04,0xe9,0xcd,0x9e,0x3e,0xcb,0x66,0x23,0x95,0xb4,0x42,
    0x9c,0x64,0x81,0x39,0x05,0x3f,0xb5,0x21,0xf8,0x28,0xaf,0x60,0x6b,0x4d,0x3d,0xba,
    0xa1,0x4b,0x5e,0x77,0xef,0xe7,0x59,0x28,0xfe,0x1d,0xc1,0x27,0xa2,0xff,0xa8,0xde,
    0x33,0x48,0xb3,0xc1,0x85,0x6a,0x42,0x9b,0xf9,0x7e,0x7e,0x31,0xc2,0xe5,0xbd,0x66,
    0x01,0x18,
    0x39,0x29,0x6a,0x78,0x9a,0x3b,0xc0,0x04,0x5c,0x8a,0x5f,0xb4,0x2c,0x7d,0x1b,0xd9,
    0x98,0xf5,0x44,0x49,0x57,0x9b,0x44,0x68,0x17,0xaf,0xbd,0x17,0x27,0x3e,0x66,0x2c,
    0x97,0xee,0x72,0x99,0x5e,0xf4,0x26,0x40,0xc5,0x50,0xb9,0x01,0x3f,0xad,0x07,0x61,
    0x35,0x3c,0x70,0x86,0xa2,0x72,0xc2,0x40,0x88,0xbe,0x94,0x76,0x9f,0xd1,0x66,0x50
};

static const ubyte *gpEccG[] = 
{
   (ubyte *) gpP224_G, (ubyte *) gpP256_G, (ubyte *) gpP384_G, (ubyte *) gpP521_G
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , (ubyte *) gpP192_G
#endif
};

/************************** N *****************************/

#ifdef __ENABLE_DIGICERT_ECC_P192__
static const ubyte gpP192_N[24] =
{
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x99,0xDE,0xF8,0x36,
    0x14,0x6B,0xC9,0xB1,0xB4,0xD2,0x28,0x31
};
#endif

static const ubyte gpP224_N[28] =
{
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x16,0xa2,
    0xe0,0xb8,0xf0,0x3e,0x13,0xdd,0x29,0x45,0x5c,0x5c,0x2a,0x3d
};

static const ubyte gpP256_N[32] =
{
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};

static const ubyte gpP384_N[48] =
{
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc7,0x63,0x4d,0x81,0xf4,0x37,0x2d,0xdf,
    0x58,0x1a,0x0d,0xb2,0x48,0xb0,0xa7,0x7a,0xec,0xec,0x19,0x6a,0xcc,0xc5,0x29,0x73
};

static const ubyte gpP521_N[66] =
{
    0x01,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfa,
    0x51,0x86,0x87,0x83,0xbf,0x2f,0x96,0x6b,0x7f,0xcc,0x01,0x48,0xf7,0x09,0xa5,0xd0,
    0x3b,0xb5,0xc9,0xb8,0x89,0x9c,0x47,0xae,0xbb,0x6f,0xb7,0x1e,0x91,0x38,0x64,0x09
};

static const ubyte *gpEccN[] = 
{
   (ubyte *) gpP224_N, (ubyte *) gpP256_N, (ubyte *) gpP384_N, (ubyte *) gpP521_N
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , (ubyte *) gpP192_N
#endif
};

/************************** lengths *****************************/

static const ubyte4 gEccLens[] =
{
    28, 32, 48, 66
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , 24
#endif
};

/* Cheat sheet, pre-computed ECC Key serialization lens */
static const ubyte4 gEccSerKeyLen[] =
{
    253, 285, 413, 558
#ifdef __ENABLE_DIGICERT_ECC_P192__
   , 221
#endif
};

#endif /* __ENABLE_DIGICERT_ECC__ */

#define FIRST( x) ((x & 0xff00)>>8)
#define LAST( x) (x & 0xff)

#define CERT_AUTH_REF_MAX_LEN 16
#define CERT_HOLDER_REF_MAX_LEN 16
#define OID_LEN 10
#define DATE_LEN 6
#define PROFILE_LEN 1

static MSTATUS validateAndGetDate(ubyte *pBuff, TimeDate *pDate)
{
    sbyte4 i = 0;
    ubyte4 year = 0;
    ubyte4 month = 0;
    ubyte4 day = 0;

    /* Date is YYMMDD format with YY being two decimal digits representing 2000-2099 */
    
    /* validate first that everything is a digit */
    for (i = 0; i < 6; i++)
    {
        if (pBuff[i] > 9)
            return ERR_CERT_INVALID_DATE_FORMAT;
    }

    year = 10 * pBuff[0] + pBuff[1];
    month = 10 * pBuff[2] + pBuff[3];
    day = 10 * pBuff[4] + pBuff[5];

    if ( month < 1 || month > 12 || 0 == day || day > 31 ||
        (2 == month && (day > 29 || (0 != (year % 4) && day > 28)) ) ||   /* Feb, leap years */
        ((4 == month || 6 == month || 9 == month || 11 == month) && day > 30) )  /* Apr, June, Sept, Nov */
        return ERR_CERT_INVALID_DATE_FORMAT;

    /* all is good, copy to the outgoing struct */

    /* our DateTime's begin at 1970, so add 30 years to the year */
    pDate->m_year = (ubyte2) 30 + year;
    pDate->m_month = (ubyte) month;
    pDate->m_day = (ubyte) day;

    /* rest of fields should be zero by default initialization */

    return OK;
}

MOC_EXTERN MSTATUS CV_CERT_getLenAndValue(
    ubyte *pLenAndValue,
    ubyte **ppValue,
    ubyte4 *pLen
    )
{
    MSTATUS status = OK;
    ubyte byteCount = 0, j = 0;

    *pLen = 0;

    /* If the length byte is 0x80 then the encoding is indefinite which will
     * not be supported.
     * 
     * If the length byte is less then 0x80 then the byte itself is the length
     * of the tag.
     * 
     * If the length byte is greater then 0x80 (cannot exceed 0x82) then the
     * next few bytes are the length bytes.
     */
    if (0x80 == *pLenAndValue)
    {
        status = ERR_ASN_INDEFINITE_LEN_UNSUPPORTED;
        goto exit;
    }
    else if (0x80 > *pLenAndValue)
    {
        *pLen = *pLenAndValue;
        *ppValue = pLenAndValue + 1;
    }
    else
    {
        byteCount = *pLenAndValue - 0x80;
        if (2 < byteCount)
        {
            status = ERR_ASN_BAD_LENGTH_FIELD;
            goto exit;
        }

        for (j = 0; j < byteCount; ++j)
            *pLen |= (*(pLenAndValue + byteCount - j) << (j * 8));

        *ppValue = pLenAndValue + byteCount + 1;
    }

exit:

    return status;
}

static MSTATUS CV_CERT_copyDate(ubyte2 tag, ubyte *pBuffer, TimeDate date)
{
    /* make sure the year is in the range 2000-2099 */
    if (date.m_year < 30 || date.m_year > 129)
        return ERR_INVALID_ARG;

    /* rest of date validation should happen before/when the TimeDate is created */
    pBuffer[0] = FIRST(tag);
    pBuffer[1] = LAST(tag);
    pBuffer[2] = (ubyte) DATE_LEN;
    
    pBuffer[3] = (ubyte) (date.m_year - 30) / 10;
    pBuffer[4] = (ubyte) (date.m_year - 30) % 10;

    pBuffer[5] = (ubyte) date.m_month / 10;
    pBuffer[6] = (ubyte) date.m_month % 10;
    
    pBuffer[7] = (ubyte) date.m_day / 10;
    pBuffer[8] = (ubyte) date.m_day % 10;

    return OK;
}

/* Serializes the length and moves *ppPtr to the next buffer position */
static MSTATUS CV_CERT_serializeLen(ubyte **ppPtr, ubyte4 len)
{
    if (len < 0x80)
    {
        **ppPtr = (ubyte) len;
        (*ppPtr)++;
    }
    else if (len < 0x100)
    {
        **ppPtr  = 0x81;
        (*ppPtr)++;
        **ppPtr = (ubyte) len;
        (*ppPtr)++;
    }
    else if (len < 0x00010000)
    {
        **ppPtr = 0x82;
        (*ppPtr)++;
        **ppPtr  = (ubyte) ((len & 0xff00) >> 8);
        (*ppPtr)++;
        **ppPtr = (ubyte) len & 0xff;
        (*ppPtr)++;
    }
    else
    {
        return ERR_BAD_LENGTH;
    }

    return OK;
}

/* If pBuffer is NULL then it just computes the out Len from the valueLen */
static MSTATUS CV_CERT_copyItem(ubyte *pBuffer, ubyte2 tag, ubyte *pValue, ubyte4 valueLen, ubyte4 *pOutLen)
{
    MSTATUS status = OK;

    if (valueLen > 0x0000ffff)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    *pOutLen = valueLen + (FIRST(tag) ? 2 : 1) 
                        + ((valueLen < 0x80) ? 1 : (valueLen < 0x100 ? 2 : 3));

    if (NULL != pBuffer)
    {
        /* TAG */
        if (FIRST(tag))
        {
            pBuffer[0] = FIRST(tag);
            pBuffer[1] = LAST(tag);
            pBuffer += 2;
        }
        else
        {
            pBuffer[0] = LAST(tag);
            pBuffer++;
        }

        /* Length */ 
        status = CV_CERT_serializeLen(&pBuffer, valueLen);
        if (OK != status)
            goto exit;

        /* Value */
        status = DIGI_MEMCPY(pBuffer, pValue, valueLen);
    }

exit:

    return status;
}

static MSTATUS CV_CERT_parseRSAKey(MOC_RSA(hwAccelDescr hwAccelCtx) ubyte *pCvcRsa, sbyte4 cvcRsaLen, AsymmetricKey *pKey)
{
    MSTATUS status = ERR_CERT_INVALID_STRUCT;
    RSAKey *pRSAKey = NULL;
    ubyte *pMod = NULL;
    ubyte4 modLen = 0;
    ubyte *pExp = NULL;
    ubyte4 expLen = 0;

    /* internal method, NULL checks not necc */
    if (cvcRsaLen < 3)
        goto exit;

    /* Correct order is required, must be modulus first */
    if (RSA_MODULUS != pCvcRsa[0])
        goto exit;

    status = CV_CERT_getLenAndValue(pCvcRsa + 1, &pMod, &modLen);
    if (OK != status)
        goto exit;

    /* sanity check we have more left */
    cvcRsaLen -= (sbyte4) (pMod - pCvcRsa);
    cvcRsaLen -= (sbyte4) modLen;

    if (cvcRsaLen < 3)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* exponent is next */
    pExp = pMod + modLen;
    if (RSA_EXP != pExp[0])
        goto exit;

    status = CV_CERT_getLenAndValue(pExp + 1, &pExp, &expLen);
    if (OK != status)
        goto exit;

    /* sanity check we are at the end */
    cvcRsaLen -= (sbyte4) (pExp - pMod - modLen);
    cvcRsaLen -= (sbyte4) expLen;

    if (0 != cvcRsaLen)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CRYPTO_INTERFACE_RSA_createKeyAux(&pRSAKey);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_RSA_setPublicKeyData(MOC_RSA(hwAccelCtx) pRSAKey, pExp, expLen, pMod, modLen, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(pKey, akt_rsa, (void **) &pRSAKey);
    if (OK != status)
        goto exit;

    pRSAKey = NULL;

exit:

    if (NULL != pRSAKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pRSAKey, NULL);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_ECC__
static MSTATUS CV_CERT_parseECCKey(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte *pCvcEcc, sbyte4 cvcEccLen, ubyte4 *pCurveId, AsymmetricKey *pKey)
{
    MSTATUS status = ERR_CERT_INVALID_STRUCT;
    ECCKey *pECCKey = NULL;
    ubyte4 curveId = 0;
    ubyte4 curveIndex = 0;
    sbyte4 cmp = -1;

    ubyte *pPtr = pCvcEcc;
    ubyte4 tempLen = 0;
    ubyte *pNextPtr = NULL;

    /* internal method, NULL checks not necc */
    if (cvcEccLen < 3)
        goto exit;

    /* Correct order is required. modulus and curve params are optional */

    /********************************** P *********************************/
    if (ECC_MODULUS == *pPtr)
    {
        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
        if (OK != status)
            goto exit;

        /* We only support these 5 curves, tempLen is enough to know if we have a candidate */
        switch(tempLen)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case 24:
                curveId = cid_EC_P192;
                curveIndex = 4;
                break;
#endif
            case 28:
                curveId = cid_EC_P224;
                curveIndex = 0;
                break;

            case 32:
                curveId = cid_EC_P256;
                curveIndex = 1;
                break;

            case 48:
                curveId = cid_EC_P384;
                curveIndex = 2;
                break;

            case 66:
                curveId = cid_EC_P521;
                curveIndex = 3;
                break;

            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
        }

        status = DIGI_MEMCMP(pNextPtr, gpEccP[curveIndex], tempLen, &cmp);
        if (OK != status)
            goto exit;

        if (cmp)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }

        /* Rest of params (minus cofactor) are required if P is present. */
        /* sanity check we have more left */
        cvcEccLen -= (sbyte4) (pNextPtr - pPtr);
        cvcEccLen -= (sbyte4) tempLen;

        /********************************** A *********************************/
        if (cvcEccLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        
        pPtr = pNextPtr + tempLen;
        if (ECC_FIRST_COEFF != *pPtr)
            goto exit;

        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
        if (OK != status)
            goto exit;

        if (tempLen != gEccLens[curveIndex])
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;            
        }

        status = DIGI_MEMCMP(pNextPtr, gpEccA[curveIndex], tempLen, &cmp);
        if (OK != status)
            goto exit;

        if (cmp)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }

        cvcEccLen -= (sbyte4) (pNextPtr - pPtr);
        cvcEccLen -= (sbyte4) tempLen;

        /********************************** B *********************************/
        if (cvcEccLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        
        pPtr = pNextPtr + tempLen;
        if (ECC_SECOND_COEFF != *pPtr)
            goto exit;

        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
        if (OK != status)
            goto exit;
        
        /* P521 B has leading 0x00 which should not be included */
        if (tempLen != gEccLens[curveIndex] - (cid_EC_P521 == curveId ? 1 : 0) )
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;            
        }
        
        status = DIGI_MEMCMP(pNextPtr, gpEccB[curveIndex], tempLen, &cmp);
        if (OK != status)
            goto exit;

        if (cmp)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }

        cvcEccLen -= (sbyte4) (pNextPtr - pPtr);
        cvcEccLen -= (sbyte4) tempLen;

        /********************************** G ***********************************/
        if (cvcEccLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        
        pPtr = pNextPtr + tempLen;
        if (ECC_BASE_POINT != *pPtr)
            goto exit;

        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
        if (OK != status)
            goto exit;

        if (tempLen != 2*gEccLens[curveIndex] + 1)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;            
        }
        
        status = DIGI_MEMCMP(pNextPtr, gpEccG[curveIndex], tempLen, &cmp);
        if (OK != status)
            goto exit;

        if (cmp)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }

        cvcEccLen -= (sbyte4) (pNextPtr - pPtr);
        cvcEccLen -= (sbyte4) tempLen;

        /********************************** N ***********************************/
        if (cvcEccLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        
        pPtr = pNextPtr + tempLen;
        if (ECC_BASE_POINT_ORDER != *pPtr)
            goto exit;

        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
        if (OK != status)
            goto exit;

        if (tempLen != gEccLens[curveIndex])
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;            
        }
        
        status = DIGI_MEMCMP(pNextPtr, gpEccN[curveIndex], tempLen, &cmp);
        if (OK != status)
            goto exit;

        if (cmp)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }

        cvcEccLen -= (sbyte4) (pNextPtr - pPtr);
        cvcEccLen -= (sbyte4) tempLen;

        /* make sure still room for a required Q */
        if (cvcEccLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        pPtr = pNextPtr + tempLen;
    }

    /********************************** Q (required) ***********************************/    
    if (ECC_PUB_POINT != *pPtr)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    /* if we did not obtain the curve id yet, we'll have to assumme it based on the Q size */
    if (0 == curveId)
    {
        switch(tempLen)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case 49:
                curveId = cid_EC_P192;
                break;
#endif
            case 57:
                curveId = cid_EC_P224;
                break;
            case 65:
                curveId = cid_EC_P256;
                break;
            case 97:
                curveId = cid_EC_P384;
                break;
            case 133:
                curveId = cid_EC_P521;
                break;
            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
        }
    }

    cvcEccLen -= (sbyte4) (pNextPtr - pPtr);
    cvcEccLen -= (sbyte4) tempLen;

    /* cofactor is optional, if not 1 though we have invalid curve */
    /********************************** h ***********************************/
    if (0 != cvcEccLen)
    {
        /* new vars so we can save the previous ones pointing to Q */
        ubyte4 tempLen2;
        ubyte *pNextPtr2;

        if (cvcEccLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        
        pPtr = pNextPtr + tempLen;
        if (ECC_COFACTOR != *pPtr)
            goto exit;

        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr2, &tempLen2);
        if (OK != status)
            goto exit;

        if (1 != tempLen2 || 0x01 != *pNextPtr2)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;           
        }

        cvcEccLen -= (sbyte4) (pNextPtr2 - pPtr);
        cvcEccLen -= (sbyte4) tempLen2;
    }

    /* sanity check we are at the end now */    
    if (0 != cvcEccLen)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;            
    }

    status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &pECCKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pECCKey, pNextPtr, tempLen, NULL, 0);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(pKey, akt_ecc, (void **) &pECCKey);
    if (OK != status)
        goto exit;

    pECCKey = NULL;

    if (NULL != pCurveId)
    {
        *pCurveId = curveId;
    }

exit:

    if (NULL != pECCKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pECCKey);
    }

    return status;
}
#endif

MOC_EXTERN MSTATUS CV_CERT_isRootCert(CV_CERT *pCert)
{
    sbyte4 cmp = 1;
    MSTATUS status;

    if (NULL == pCert)
        return ERR_NULL_POINTER;

    if (pCert->certAuthRefLen != pCert->certHolderRefLen)
        return ERR_FALSE;

    status = DIGI_MEMCMP(pCert->pCertAuthRef, pCert->pCertHolderRef, pCert->certAuthRefLen, &cmp);
    if (OK != status)
        return status;

    if (0 != cmp)
        return ERR_FALSE;

    return OK;
}

MOC_EXTERN MSTATUS CV_CERT_parseKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pCvcKey, ubyte4 cvcKeyLen, AsymmetricKey *pKey, ubyte4 *pHashAlgo, byteBoolean *pIsPss)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pPtr = NULL;
    ubyte4 tempLen = 0;
    sbyte4 cmp = -1;
    MAlgoId *pAlgoId = NULL;
    ubyte hashAlg = ht_sha256;
#ifdef __ENABLE_DIGICERT_ECC__
    EcPublicKeyAlgIdParams *pEcParam = NULL;
#endif

    if (NULL == pCvcKey)
        goto exit;

    if (NULL != pIsPss)
        *pIsPss = FALSE;

    status = ERR_CERT_INVALID_STRUCT;
    if (cvcKeyLen < 3)
        goto exit;

    if (OID != pCvcKey[0])
        goto exit;

    /* starts with the oid */
    status = CV_CERT_getLenAndValue(pCvcKey + 1, &pPtr, &tempLen);
    if (OK != status)
        goto exit;
    
    if (OID_LEN != tempLen)
    {
        status = ERR_CERT_UNRECOGNIZED_OID;
        goto exit;
    }

    /* all 9 supported oid's begin with the same 8 bytes */
    status = DIGI_MEMCMP(pPtr, (ubyte *) cvc_rsaWithSha1_OID + 1 , OID_LEN - 2, &cmp);
    if (OK != status)
        goto exit;

    if (cmp)
    {
        status = ERR_CERT_UNRECOGNIZED_OID;
        goto exit;
    }

    /* RSA has next byte 0x01 */
    if (0x01 == pPtr[OID_LEN - 2])
    {
        /* Next byte determines hash alg and pss */
        switch (pPtr[OID_LEN - 1])
        {
            /* hashAlg = ht_sha256 by default */
            case 0x01:

                hashAlg = ht_sha1;
                /* fall through */

            case 0x02:

                if (NULL != pKey)
                {           
                    status = DIGI_CALLOC((void **) &pAlgoId, 1, sizeof(MAlgoId));
                    if (OK != status)
                        goto exit;

                    pAlgoId->oidFlag = ALG_ID_RSA_ENC_OID;
                }
                break;

            case 0x03:

                hashAlg = ht_sha1;
                /* fall through */

            case 0x04:
                
                if (NULL != pKey)
                {
                    status = ALG_ID_createRsaPssParams(hashAlg, hashAlg, hashAlg, ht_sha1 == hashAlg ? 20 : 32, 0xBC, &pAlgoId);
                    if (OK != status)
                        goto exit;
                }

                if (NULL != pIsPss)
                    *pIsPss = TRUE;
                
                break;

            default:
                status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
                goto exit;
        }

        if (NULL != pKey)
        {
            status = CV_CERT_parseRSAKey(MOC_RSA(hwAccelCtx) pPtr + tempLen, (sbyte4) cvcKeyLen - (sbyte4) tempLen - (sbyte4) (pPtr - pCvcKey), pKey);
            if (OK != status)
                goto exit;
        }
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (0x02 == pPtr[OID_LEN - 2])  /* 0x02 for ECC */
    {
        switch (pPtr[OID_LEN - 1])
        {
            /* hashAlg = ht_sha256 by default */
            case 0x01:
                hashAlg = ht_sha1;
                break;

            case 0x02:
                hashAlg = ht_sha224;
                break;

            case 0x03:
                break;

            case 0x04:
                hashAlg = ht_sha384;
                break;

            case 0x05:
                hashAlg = ht_sha512;
                break;

            default:
                status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
                goto exit;
        }

        if (NULL != pKey)
        {
            status = DIGI_CALLOC((void **) &pAlgoId, 1, sizeof(MAlgoId));
            if (OK != status)
                goto exit;

            status = DIGI_CALLOC((void **) &pEcParam, 1, sizeof(EcPublicKeyAlgIdParams));
            if (OK != status)
                goto exit;

            status = CV_CERT_parseECCKey(MOC_ECC(hwAccelCtx) pPtr + tempLen, (sbyte4) cvcKeyLen - (sbyte4) tempLen - (sbyte4) (pPtr - pCvcKey), &pEcParam->curveId, pKey);
            if (OK != status)
                goto exit;

            pAlgoId->oidFlag = ALG_ID_EC_PUBLIC_KEY_OID;
            pAlgoId->pParams = (void *) pEcParam; pEcParam = NULL;
        }        
    }
#endif
    else
    {
        status = ERR_CERT_UNRECOGNIZED_OID;
        goto exit;
    }

    if (NULL != pKey)
    {
        status = CRYPTO_loadAlgoId (pKey, (void **) &pAlgoId);
        if (OK != status)
            goto exit;

        pAlgoId = NULL;
    }

    if (NULL != pHashAlgo)
    {
        *pHashAlgo = (ubyte4) hashAlg;
    }

exit:

#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEcParam)
    {
        (void) DIGI_FREE((void **) &pEcParam);
    }
#endif

    if (NULL != pAlgoId)
    {
        (void) ALG_ID_free(&pAlgoId);
    }

    return status;
}

MOC_EXTERN MSTATUS CV_CERT_parseCert(ubyte *pCert, ubyte4 certLen, CV_CERT **ppNewCvcCert)
{
    MSTATUS status = ERR_NULL_POINTER;
    CV_CERT *pNewCert = NULL;
    ubyte *pBodyPtr = NULL;
    ubyte *pPtr = NULL;
    ubyte *pNextPtr = NULL;
    ubyte4 tempLen = 0;
    sbyte4 bodyParseLen = 0;
    
    if (NULL == pCert || NULL == ppNewCvcCert)
        goto exit;

    status = ERR_CERT_INVALID_STRUCT;
    if (certLen < 6)
        goto exit;

    if (FIRST(CV_CERT_TAG) != pCert[0] || LAST(CV_CERT_TAG) != pCert[1])
        goto exit;

    /* first tag should be the cert Body */
    status = CV_CERT_getLenAndValue(pCert + 2, &pBodyPtr, &tempLen);
    if (OK != status)
        goto exit;

    /* sanity check that our original buffer is the correct length */
    status = ERR_CERT_INVALID_STRUCT;
    if (certLen != tempLen + (ubyte4) (pBodyPtr - pCert))
        goto exit;

    /* Now parse the rest of the cert body and the signature */
    status = DIGI_CALLOC((void **) &pNewCert, 1, sizeof(CV_CERT));
    if (OK != status)
        goto exit;

    /******************************* CERT BODY *********************************/
    if (FIRST(CERT_BODY) != pBodyPtr[0] || LAST(CERT_BODY) != pBodyPtr[1])
        goto exit;

    /* get the length of the cert body */
    status = CV_CERT_getLenAndValue(pBodyPtr + 2, &pPtr, &tempLen);
    if (OK != status)
        goto exit;

    /* Set our first set of output params. Length inlcludes the cert body tag */
    pNewCert->pCertBody = pBodyPtr;
    pNewCert->certBodyLen = tempLen + (ubyte4) (pPtr - pBodyPtr);

    bodyParseLen = (sbyte4) tempLen;

    /******************************* Profile Id *********************************/
    if (bodyParseLen < 4)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (FIRST(CERT_PROFILE_ID) != pPtr[0] || LAST(CERT_PROFILE_ID) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    if (PROFILE_LEN != tempLen)
    {
        status = ERR_CERT_INVALID_PROFILE;
        goto exit;
    }
 
    /* only Version 1, ie profile Id = 0, is supported */
    if (0 != *pNextPtr)
    {
        status = ERR_CERT_INVALID_PROFILE;
        goto exit;
    }

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;

    /********************************* Cert Auth Ref ******************************/
    if (bodyParseLen < 3)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (CERT_AUTH_REF != pPtr[0])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    if (tempLen > CERT_AUTH_REF_MAX_LEN)
    {
        status = ERR_CERT_INVALID_REF_LEN;
        goto exit;
    }
    pNewCert->pCertAuthRef = pNextPtr;
    pNewCert->certAuthRefLen = tempLen;

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;

    /********************************* Public Key ******************************/
    if (bodyParseLen < 4)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (FIRST(PUBLIC_KEY) != pPtr[0] || LAST(PUBLIC_KEY) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    pNewCert->pCvcKey = pNextPtr;
    pNewCert->cvcKeyLen = tempLen;

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;

    /********************************* Holder Reference ******************************/
    if (bodyParseLen < 4)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (FIRST(CERT_HOLDER_REF) != pPtr[0] || LAST(CERT_HOLDER_REF) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    if (tempLen > CERT_HOLDER_REF_MAX_LEN)
    {
        status = ERR_CERT_INVALID_REF_LEN;
        goto exit;
    }  
    pNewCert->pCertHolderRef = pNextPtr;
    pNewCert->certHolderRefLen = tempLen;

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;

    /********************************* Holder Auth Template ******************************/
    if (bodyParseLen < 4)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (FIRST(CERT_HOLDER_AUTH_TEMPLATE) != pPtr[0] || LAST(CERT_HOLDER_AUTH_TEMPLATE) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    pNewCert->pCertHolderAuthTemplate = pNextPtr;
    pNewCert->certHolderAuthTemplateLen = tempLen;

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;

    /********************************* Effecitve Date ******************************/
    if (bodyParseLen < 4)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (FIRST(CERT_EFFECTIVE_DATE) != pPtr[0] || LAST(CERT_EFFECTIVE_DATE) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    if (DATE_LEN != tempLen)
    {
        status = ERR_CERT_INVALID_DATE_FORMAT;
        goto exit;
    }

    status = validateAndGetDate(pNextPtr, &pNewCert->effectiveDate);
    if (OK != status)
        goto exit;

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;


    /********************************* Expiration Date ******************************/
    if (bodyParseLen < 4)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (FIRST(CERT_EXP_DATE) != pPtr[0] || LAST(CERT_EXP_DATE) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pNextPtr, &tempLen);
    if (OK != status)
        goto exit;

    if (DATE_LEN != tempLen)
    {
        status = ERR_CERT_INVALID_DATE_FORMAT;
        goto exit;
    }

    status = validateAndGetDate(pNextPtr, &pNewCert->expDate);
    if (OK != status)
        goto exit;

    /* adjust the remaining length */
    bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
    bodyParseLen -= (sbyte4) tempLen;

    /* and move to the next field */
    pPtr = pNextPtr + tempLen;

    /********************************* Extensions (Optional) ******************************/

    if (bodyParseLen > 0)
    {
        if (bodyParseLen < 3)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        if (CERT_EXTENSIONS != pPtr[0])
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        status = CV_CERT_getLenAndValue(pPtr + 1, &pNextPtr, &tempLen);
        if (OK != status)
            goto exit;

        pNewCert->pExtensions = pNextPtr;
        pNewCert->extLen = tempLen;

        /* adjust the remaining length */
        bodyParseLen -= (sbyte4)(pNextPtr - pPtr);
        bodyParseLen -= (sbyte4) tempLen;

        /* and move to the next field */
        pPtr = pNextPtr + tempLen;
    }

    /* bodyParseLen should end cleanly at 0 */
    if (0 != bodyParseLen)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /************************************ Signature *********************************/
    if (FIRST(SIGNATURE) != pPtr[0] || LAST(SIGNATURE) != pPtr[1])
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = CV_CERT_getLenAndValue(pPtr + 2, &pPtr, &tempLen);
    if (OK != status)
        goto exit;

    pNewCert->pSig = pPtr;
    pNewCert->sigLen = tempLen;

    *ppNewCvcCert = pNewCert; pNewCert = NULL;   

exit:

    if (NULL != pNewCert)
    {
        (void) DIGI_FREE((void **) &pNewCert);
    }

    return status;
}

static MSTATUS CV_CERT_serializeRsaKey(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte4 hashAlgo, byteBoolean isPss, ubyte *pBuffer, ubyte4 *pOutLen)
{
    MSTATUS status = OK;
    MRsaKeyTemplate template = {0};
    ubyte4 outLen = 0;
    RSAKey *pPubKey = NULL;

    if (akt_tap_rsa == pKey->type)
    {
        status = CRYPTO_INTERFACE_getRSAPublicKey(pKey, &pPubKey);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(MOC_RSA(hwAccelCtx) pPubKey, &template, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(MOC_RSA(hwAccelCtx) pKey->key.pRSA, &template, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;
    }

    *pOutLen = OID_LEN + 2;
    if (NULL == pBuffer)
    {
        /* get the length of the encoded modulus and exponent */
        status = CV_CERT_copyItem(NULL, RSA_MODULUS, NULL, template.nLen, &outLen);
        if (OK != status)
            goto exit;

        *pOutLen += outLen;
        status = CV_CERT_copyItem(NULL, RSA_EXP, NULL, template.eLen, &outLen);
        if (OK != status)
            goto exit;
        
        *pOutLen += outLen;
        goto exit;
    }

    /* oid begins on second byte, index 1, we'll manually change the last byte */
    status = CV_CERT_copyItem(pBuffer, OID, (ubyte *) cvc_rsaWithSha1_OID + 1, OID_LEN, &outLen);
    if (OK != status)
        goto exit;

    if (ht_sha256 == (ubyte) hashAlgo)
    {
        if (isPss)
        {
            pBuffer[outLen - 1] = 0x04;
        }
        else
        {
            pBuffer[outLen - 1] = 0x02;
        }
    }
    else if (isPss)
    {
        pBuffer[outLen - 1] = 0x03;
    }

    pBuffer += outLen;

    /*********************************** N **********************************/

    status = CV_CERT_copyItem(pBuffer, RSA_MODULUS, template.pN, template.nLen, &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;
    *pOutLen += outLen;

    /*********************************** E **********************************/
    
    status = CV_CERT_copyItem(pBuffer, RSA_EXP, template.pE, template.eLen, &outLen);
    if (OK != status)
        goto exit;

    *pOutLen += outLen;

exit:
    if (NULL != pPubKey)
    {
        CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    }
    
    (void) CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pKey->key.pRSA, &template);
    
    return status;
}

#ifdef __ENABLE_DIGICERT_ECC__
static MSTATUS CV_CERT_serializeEccKey(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte4 hashAlgo, ubyte *pBuffer, ubyte4 *pOutLen)
{
    MSTATUS status = OK;
    ubyte4 curveId = 0;
    ubyte4 curveIdx = 0;
    ubyte4 outLen = 0;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    /* internal method, NULL checks not necc */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux (pKey->key.pECC, &curveId);
    if (OK != status)
        goto exit;

    switch (curveId)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case cid_EC_P192:
            curveIdx = 4;
            break;
#endif
        case cid_EC_P224:
            curveIdx = 0;
            break;

        case cid_EC_P256:
            curveIdx = 1;
            break;

        case cid_EC_P384:
            curveIdx = 2;
            break;

        case cid_EC_P521:
            curveIdx = 3;
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;        
    }

    /* We have a lookup table since all keys are the same length per curve */
    *pOutLen = gEccSerKeyLen[curveIdx];
    if (NULL == pBuffer)
    {
        goto exit; /* status OK */
    }

    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(MOC_ECC(hwAccelCtx) pKey->key.pECC, &pPub, &pubLen);
    if (OK != status)
        goto exit;

    /*********************************** OID **********************************/

    /* oid begins on second byte, index 1, we'll manually change the last byte */
    status = CV_CERT_copyItem(pBuffer, OID, (ubyte *) cvc_ecdsaWithSha1_OID + 1, OID_LEN, &outLen);
    if (OK != status)
        goto exit;

    switch(hashAlgo)
    {
        case ht_sha1: /* already correct oid */
            break;
        case ht_sha224:
            pBuffer[outLen - 1] = 0x02;
            break;
        case ht_sha256:
            pBuffer[outLen - 1] = 0x03;
            break;
        case ht_sha384:
            pBuffer[outLen - 1] = 0x04;
            break;
        case ht_sha512:
            pBuffer[outLen - 1] = 0x05;
            break;
        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    pBuffer += outLen;

    /*********************************** P **********************************/

    status = CV_CERT_copyItem(pBuffer, ECC_MODULUS, (ubyte *) gpEccP[curveIdx], gEccLens[curveIdx], &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;

    /*********************************** A **********************************/
    
    status = CV_CERT_copyItem(pBuffer, ECC_FIRST_COEFF, (ubyte *) gpEccA[curveIdx], gEccLens[curveIdx], &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;

    /*********************************** B **********************************/
    
    /* P521 has one less byte for B */
    status = CV_CERT_copyItem(pBuffer, ECC_SECOND_COEFF, (ubyte *) gpEccB[curveIdx], gEccLens[curveIdx] - (cid_EC_P521 == curveId ? 1 : 0), &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;

    /*********************************** G ***********************************/
    
    status = CV_CERT_copyItem(pBuffer, ECC_BASE_POINT, (ubyte *) gpEccG[curveIdx], 2 * gEccLens[curveIdx] + 1, &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;

    /*********************************** N **********************************/
    
    status = CV_CERT_copyItem(pBuffer, ECC_BASE_POINT_ORDER, (ubyte *) gpEccN[curveIdx], gEccLens[curveIdx], &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;

    /*********************************** Q **********************************/
    
    status = CV_CERT_copyItem(pBuffer, ECC_PUB_POINT, pPub, pubLen, &outLen);
    if (OK != status)
        goto exit;

    pBuffer += outLen;

    /*********************************** H **********************************/

    pBuffer[0] = ECC_COFACTOR;
    pBuffer[1]  = 0x01;
    pBuffer[2] = 0x01;

exit:

    if (NULL != pPub)
    {
        (void) DIGI_MEMSET_FREE(&pPub, pubLen);
    }

    return status;
}
#endif

MOC_EXTERN MSTATUS CV_CERT_generateCert(MOC_ASYM(hwAccelDescr hwAccelCtx) CV_CERT_GEN_DATA *pCertGenData, ubyte **ppCert, ubyte4 *pCertLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pCert = NULL;
    ubyte *pCertBody = NULL;
    ubyte4 certBodyLen = 0;
    ubyte4 certBodyValueLen = 0;
    ubyte4 sigLen = 0;
    ubyte4 sigValueLen = 0;
    ubyte4 certLen = 0;
    ubyte4 pubKeyValueLen = 0;
    ubyte4 tempLen = 0;
    ubyte *pPtr = 0;
    ubyte profile = 0x00;

    AsymmetricKey *pSignerKey = NULL;
    ubyte4 signHashAlgo = 0;
    byteBoolean signIsPss = FALSE;
    ubyte *pAuthRef = NULL;
    ubyte4 authRefLen = 0;
    ubyte pHoldRefCopy[CERT_HOLDER_REF_MAX_LEN] = {0};
    ubyte4 holdRefLen = 0;

    if (NULL == pCertGenData || NULL == ppCert || NULL == pCertLen)
        goto exit;

    if (NULL == pCertGenData->pCertKey || NULL == pCertGenData->pCertHolderAuthTemplate || (NULL == pCertGenData->pExtensions && pCertGenData->extLen))
        goto exit;

    if (NULL == pCertGenData->pSignerKey) /* Then self signed, get the signing params */
    {
        pSignerKey = pCertGenData->pCertKey;
        signHashAlgo = pCertGenData->hashAlgo;
        signIsPss = pCertGenData->isPss;
        pAuthRef = (ubyte *) pHoldRefCopy;   /* will be copied in later */
        authRefLen = 2 + pCertGenData->mnemonicLen + 5;
    }
    else
    {
        pSignerKey = pCertGenData->pSignerKey;
        signHashAlgo = pCertGenData->signHashAlgo;
        signIsPss = pCertGenData->signIsPss;
        pAuthRef = pCertGenData->pSignerAuthRef;
        authRefLen = pCertGenData->signerAuthRefLen;

        if (NULL == pAuthRef)
            goto exit;  /* Still ERR_NULL_POINTER */
    }

    /* copy the holder Reference */
    status = DIGI_MEMCPY(pHoldRefCopy, pCertGenData->countryCode, 2);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pHoldRefCopy + 2, pCertGenData->mnemonic, pCertGenData->mnemonicLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pHoldRefCopy + 2 + pCertGenData->mnemonicLen, pCertGenData->seqNum, 5);
    if (OK != status)
        goto exit;

    holdRefLen = 2 + pCertGenData->mnemonicLen + 5;

    /* First we need to compute the length of the serialized cert */

    /* first get the sig Len */
    if (akt_rsa == pSignerKey->type || akt_rsa_pss == pSignerKey->type
#ifdef __ENABLE_DIGICERT_TAP__
    || akt_tap_rsa == pSignerKey->type
#endif
    )
    {
        status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pSignerKey->key.pRSA, (sbyte4 *) &sigValueLen);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == pSignerKey->type
#ifdef __ENABLE_DIGICERT_TAP__
         || akt_tap_ecc == pSignerKey->type
#endif
    )
    {
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux (pSignerKey->key.pECC, &sigValueLen);
        if (OK != status)
            goto exit;

        sigValueLen *= 2;
    }
#endif
    else 
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    /* account for the signature tag and length */
    status = CV_CERT_copyItem(NULL, SIGNATURE, NULL, sigValueLen, &sigLen);
    if (OK != status)
        goto exit;

    /* Next get the serialized cert key Len */
    if (akt_rsa == pCertGenData->pCertKey->type || akt_rsa_pss == pCertGenData->pCertKey->type
#ifdef __ENABLE_DIGICERT_TAP__
      || akt_tap_rsa == pCertGenData->pCertKey->type
#endif
    )
    {
        status = CV_CERT_serializeRsaKey(MOC_RSA(hwAccelCtx) pCertGenData->pCertKey, pCertGenData->hashAlgo, pCertGenData->isPss, NULL, &pubKeyValueLen);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == pCertGenData->pCertKey->type
#ifdef __ENABLE_DIGICERT_TAP__
        || akt_tap_ecc == pCertGenData->pCertKey->type
#endif
    )
    {
        status = CV_CERT_serializeEccKey(MOC_ECC(hwAccelCtx) pCertGenData->pCertKey, pCertGenData->hashAlgo, NULL, &pubKeyValueLen);
        if (OK != status)
            goto exit;
    }
#endif
    else 
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    /* account for the public key tag and length to the public key len */
    status = CV_CERT_copyItem(NULL, PUBLIC_KEY, NULL, pubKeyValueLen, &tempLen);
    if (OK != status)
        goto exit;

    /* get the body len, easy to compute profile + pub key + two dates + holdRef + authRef */
    certBodyValueLen = 4 + tempLen + 2 * (DATE_LEN + 3) + (holdRefLen + 3) + (authRefLen + 2);
    
    status = CV_CERT_copyItem(NULL, CERT_HOLDER_AUTH_TEMPLATE, NULL, pCertGenData->certHolderAuthTemplateLen, &tempLen);
    if (OK != status)
        goto exit;

    certBodyValueLen += tempLen;

    if (NULL != pCertGenData->pExtensions)
    {
        status = CV_CERT_copyItem(NULL, CERT_EXTENSIONS, NULL, pCertGenData->extLen, &tempLen);
        if (OK != status)
            goto exit;

        certBodyValueLen += tempLen;
    }

    /* account for the tag and length */
    status = CV_CERT_copyItem(NULL, CERT_BODY, NULL, certBodyValueLen, &certBodyLen);
    if (OK != status)
        goto exit;

    /* Now get the full cert Len */
    tempLen = certBodyLen + sigLen;

    /* account for the CERT tag */
    status = CV_CERT_copyItem(NULL, CV_CERT_TAG, NULL, tempLen, &certLen);
    if (OK != status)
        goto exit;

    /* OK, ready to allocate and serialize! */
    status = DIGI_MALLOC((void **) &pCert, certLen);
    if (OK != status)
        goto exit;

    /***************************** CV CERT ***************************/
    pCert[0] = FIRST(CV_CERT_TAG);
    pCert[1] = LAST(CV_CERT_TAG);

    /* tempLen is still the length of the body + sig */
    pPtr = pCert + 2;
    status = CV_CERT_serializeLen(&pPtr, tempLen);
    if (OK != status)
        goto exit;

    /***************************** BODY ***************************/

    pCertBody = pPtr;
    pPtr[0] = FIRST(CERT_BODY);
    pPtr[1] = LAST(CERT_BODY);
   
    pPtr += 2;
    status = CV_CERT_serializeLen(&pPtr, certBodyValueLen);
    if (OK != status)
        goto exit;

    /***************************** PROFILE ***************************/

    status = CV_CERT_copyItem(pPtr, CERT_PROFILE_ID, &profile, PROFILE_LEN, &tempLen);
    if (OK != status)
        goto exit;

    pPtr += tempLen;

    /***************************** CERT AUTH REF ***************************/

    status = CV_CERT_copyItem(pPtr, CERT_AUTH_REF, pAuthRef, authRefLen, &tempLen);
    if (OK != status)
        goto exit;

    pPtr += tempLen;

    /****************************** PUB KEY *******************************/

    pPtr[0] = FIRST(PUBLIC_KEY);
    pPtr[1] = LAST(PUBLIC_KEY);

    pPtr += 2;
    status = CV_CERT_serializeLen(&pPtr, pubKeyValueLen);
    if (OK != status)
        goto exit;

    if (akt_rsa == pCertGenData->pCertKey->type || akt_rsa_pss == pCertGenData->pCertKey->type
#ifdef __ENABLE_DIGICERT_TAP__
    || akt_tap_rsa == pCertGenData->pCertKey->type
#endif
    )
    {
        status = CV_CERT_serializeRsaKey(MOC_RSA(hwAccelCtx) pCertGenData->pCertKey, pCertGenData->hashAlgo, pCertGenData->isPss, pPtr, &tempLen);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == pCertGenData->pCertKey->type
#ifdef __ENABLE_DIGICERT_TAP__
         || akt_tap_ecc == pCertGenData->pCertKey->type
#endif
    )
    {
        status = CV_CERT_serializeEccKey(MOC_ECC(hwAccelCtx) pCertGenData->pCertKey, pCertGenData->hashAlgo, pPtr, &tempLen);
        if (OK != status)
            goto exit;
    }
#endif
  
    pPtr += tempLen;

    /********************************* CERT HOLD REF ***********************/

    status = CV_CERT_copyItem(pPtr, CERT_HOLDER_REF, (ubyte *) pHoldRefCopy, holdRefLen, &tempLen);
    if (OK != status)
        goto exit;

    pPtr += tempLen;

    /********************************* HOLD AUTH TEMPLATE ***********************/

    status = CV_CERT_copyItem(pPtr, CERT_HOLDER_AUTH_TEMPLATE, pCertGenData->pCertHolderAuthTemplate, pCertGenData->certHolderAuthTemplateLen, &tempLen);
    if (OK != status)
        goto exit;

    pPtr += tempLen;

    /********************************* EFF DATE *******************************/
    
    status = CV_CERT_copyDate(CERT_EFFECTIVE_DATE, pPtr, pCertGenData->effectiveDate);
    if (OK != status)
        goto exit;

    pPtr += (DATE_LEN + 3);

    /********************************* EXP DATE *******************************/
    
    status = CV_CERT_copyDate(CERT_EXP_DATE, pPtr, pCertGenData->expDate);
    if (OK != status)
        goto exit;

    pPtr += (DATE_LEN + 3);

    /********************************* EXTENSIONS *******************************/

    if (NULL != pCertGenData->pExtensions)
    {
        status = CV_CERT_copyItem(pPtr, CERT_EXTENSIONS, pCertGenData->pExtensions, pCertGenData->extLen, &tempLen);
        if (OK != status)
            goto exit;

        pPtr += tempLen;
    }

    /********************************* SIGNATURE *******************************/
    
    pPtr[0] = FIRST(SIGNATURE);
    pPtr[1] = LAST(SIGNATURE);

    pPtr += 2;
    status = CV_CERT_serializeLen(&pPtr, sigValueLen);
    if (OK != status)
        goto exit;

    if ((akt_rsa == pSignerKey->type || akt_tap_rsa == pSignerKey->type) && !signIsPss)
    {
        ubyte pHash[SHA256_RESULT_SIZE] = {0}; /* big enough for either sha */
        ubyte4 hashLen = SHA256_RESULT_SIZE;
        ubyte *pDigestInfo = NULL;
        ubyte4 digestInfoLen = 0;

        /* Hash the Cert Body */
        if (ht_sha1 == (ubyte) signHashAlgo)
        {
            hashLen = SHA1_RESULT_SIZE;
            status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(hwAccelCtx) pCertBody, certBodyLen, pHash);
            if (OK != status)
                goto exit;
        }
        else if (ht_sha256 == (ubyte) signHashAlgo)
        {
            status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(hwAccelCtx) pCertBody, certBodyLen, pHash);
            if (OK != status)
                goto exit;

        }

        status = ASN1_buildDigestInfoAlloc (pHash, hashLen, signHashAlgo, &pDigestInfo, &digestInfoLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_RSA_signMessageAux(MOC_RSA(hwAccelCtx) pSignerKey->key.pRSA, pDigestInfo, digestInfoLen, pPtr, NULL);
        (void) DIGI_MEMSET_FREE(&pDigestInfo, digestInfoLen);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_PKCS1__
    else if ((akt_rsa_pss == pSignerKey->type || akt_rsa == pSignerKey->type || akt_tap_rsa == pSignerKey->type) && signIsPss)
    {
        ubyte *pSig = NULL;
        ubyte4 sigLen = 0;
        
        status = CRYPTO_INTERFACE_PKCS1_rsaPssSign(MOC_RSA(hwAccelCtx) g_pRandomContext, pSignerKey->key.pRSA, (ubyte) signHashAlgo, 
                                                    MOC_PKCS1_ALG_MGF1, (ubyte) signHashAlgo, pCertBody, certBodyLen, 
                                                    ht_sha256 == (ubyte) signHashAlgo ? SHA256_RESULT_SIZE : SHA1_RESULT_SIZE, &pSig, &sigLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pPtr, pSig, sigLen);
        
        /* free local pSig in any case */
        if (NULL != pSig)
        {
            (void) DIGI_MEMSET_FREE(&pSig, sigLen);
        }

        if (OK != status)
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == pSignerKey->type || akt_tap_ecc == pSignerKey->type)
    {
        status = CRYPTO_INTERFACE_ECDSA_signMessageExt(MOC_ECC(hwAccelCtx) pSignerKey->key.pECC, RANDOM_rngFun, g_pRandomContext,
                                                       (ubyte) signHashAlgo, pCertBody, certBodyLen, pPtr, sigLen, &tempLen, NULL);
        if (OK != status)
            goto exit;
    }
#endif

    *ppCert = pCert; pCert = NULL;
    *pCertLen = certLen;

exit:
   
    if (NULL != pCert)
    {
        (void) DIGI_MEMSET_FREE(&pCert, certLen);
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_CV_CERT__ */
