/*
 * moccms_util.c
 *
 * CMS Utility API
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

/**
 * The functions in this file create a shim between the MOC CMS API and the
 * crypto algorithms, ASN1 utility parsing, and callback calls.
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/datetime.h"
#include "../common/debug_console.h"

#include "../asn1/mocasn1.h"

#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../crypto/pkcs_common.h"

#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/dsa2.h"
#include "../crypto/pkcs1.h"
#include "../crypto/three_des.h"
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#include "../crypto/crypto.h"
#include "../crypto/ansix9_63_kdf.h"
#include "../crypto/aes_keywrap.h"

#include "../harness/harness.h"

#include "../crypto/moccms.h"
#include "../crypto/moccms_util.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"

#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_composite.h"
#endif

#endif
#if defined(__ENABLE_DIGICERT_CMS__)

#ifndef MOCANA_MAX_MODULUS_SIZE
#define MOCANA_MAX_MODULUS_SIZE     (1024)
#endif

#define VERBOSE_DEBUG (0)

#define DEFAULT_CMS_RSA_OAEP_MSG_DIGEST  ht_sha1
#define DEFAULT_CMS_RSA_OAEP_MGF         MOC_PKCS1_ALG_MGF1
#define DEFAULT_CMS_RSA_OAEP_MGF_DIGEST  ht_sha1

/*****************************************************************/

/* ASN representation of NIL */
static ubyte ASN1_NIL[] =
{ 0x05, 0x00 };
static ubyte4 ASN1_NILLen = 2;

/* OID: 1.2.840.113549.1.1.1 */
static ubyte RSA_ENCRYPTION_OID[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static ubyte4 RSA_ENCRYPTION_OID_LEN = 11;

/* OID: 1.2.840.113549.1.1.7 */
static ubyte RSAES_OAEP_OID[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07 };
static ubyte4 RSAES_OAEP_OID_LEN = 11;

/* OID: 1.2.840.113549.1.1.8 */
static ubyte PKCS1MGF_OID[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08 };
static ubyte4 PKCS1MGF_OID_LEN = 11;

/* OID: 1.2.840.113549.1.1.9 */
static ubyte PSPECIFIED_OID[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x09 };
static ubyte4 PSPECIFIED_OID_LEN = 11;

/* OID: 1.2.840.113549.1.1.(sigAlgs) */
static ubyte RSAWithSHA_OID[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0 };
static ubyte4 RSAWithSHA_OID_LEN = 11;

/* OID: 1.2.840.113549.1.9.4 */
static ubyte ASN1_PKCS9_MESSAGE_DIGEST[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
static ubyte4 ASN1_PKCS9_MESSAGE_DIGEST_LEN = 11;

/* OID: 1.2.840.113549.1.9.5 */
static ubyte ASN1_PKCS9_SIGNING_TIME[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05 };
static ubyte4 ASN1_PKCS9_SIGNING_TIME_LEN = 11;

/* OID: 1.2.840.113549.2.5 */
static ubyte ASN1_md5_OID[] =
{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05 };
static ubyte4 ASN1_md5_OID_LEN = 10;

#ifndef __DISABLE_3DES_CIPHERS__
/* OID: 1.2.840.113549.3.7 */
static ubyte ALGO_desEDE3CBC_OID[] =
{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07 };
static ubyte4 ALGO_desEDE3CBC_OID_LEN = 10;
#endif

#ifdef __ENABLE_DIGICERT_DSA__
/* OID: 1.2.840.10040.4.3 */
static ubyte DSAWithSHA1_OID[] =
{  0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03};
static ubyte4 DSAWithSHA1_OID_LEN = 9;

/* OID: 2.16.840.1.101.3.4.3.(sigAlgs) */
static ubyte DSAWithSHA2_OID[] =
{  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0};
static ubyte4 DSAWithSHA2_OID_LEN = 11;
#endif  /* __ENABLE_DIGICERT_DSA__ */

#ifdef __ENABLE_DIGICERT_ECC__
/* OID: 1.2.840.10045.2.1 */
static ubyte ASN1_ecPublicKey_OID[] =
{ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static ubyte4 ASN1_ecPublicKey_OID_LEN = 9;

/* OID: 1.2.840.10045.2.1 */
static ubyte ECC_PUBLICKEY_DATA[] =
{ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static ubyte4 ECC_PUBLICKEY_DATA_LEN = 9;

/* OID: 1.2.840.10045.3.1.(curveId) */
static ubyte ASN1_X962CurvesPrime_OID[] =
{  0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x0 };
static ubyte4 ASN1_X962CurvesPrime_OID_LEN = 10;

/* OID: 1.2.840.10045.4.1 */
static ubyte ECDSAWithSHA1_OID[] =
{  0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};
static ubyte4 ECDSAWithSHA1_OID_LEN = 9;

/* OID: 1.2.840.10045.4.3.(sigAlgs) */
static ubyte ECDSAWithSHA2_OID[] =
{  0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x0 };
static ubyte4 ECDSAWithSHA2_OID_LEN = 10;

/* OID: 1.3.132.0.(curveId) */
static ubyte ASN1_certicomCurve_OID[] =
{  0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x00 };
static ubyte ASN1_certicomCurve_OID_LEN = 7;
#endif  /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
/* OID  2.16.840.1.101.3.4.3.x where x is 17, 18, or 19 */
MOC_EXTERN_DATA_DEF ubyte ASN1_mldsa_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x00};
static ubyte4 MLDSA_OID_LEN = 11;
#define MLDSA_OID_MIN 17
#define MLDSA_OID_MAX 19

/* OID: 2.16.840.1.114027.80.8.1.x where x = 60 to 75 */
static ubyte ASN1_mldsa_composite_OID[] =
{ 0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x00};
static ubyte4 MLDSA_COMPOSITE_OID_LEN = 13;
#define MLDSA_COMPOSITE_OID_MIN 60
#define MLDSA_COMPOSITE_OID_MAX 75
#endif /* __ENABLE_DIGICERT_PQC__ */

/* OID: 1.2.840.113549.3.(subtype) */
static ubyte RSA_EncrAlgoRoot_OID[] =
{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x0 };
static ubyte4 RSA_EncrAlgoRoot_OID_LEN = 10;

/* OID: 1.2.840.113549.2.5 */
static ubyte HASH_md5_OID[] =
{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05 };
/* HASH_md5_OID_LEN = 10 */

#ifdef __ENABLE_DES_CIPHER__
/* OID: 1.3.14.3.2.7 */
static ubyte ALGO_desCBC_OID[] =
{ 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x07 };
static ubyte4 ALGO_desCBC_OID_LEN = 7;
#endif

/* OID: 1.3.14.3.2.26 */
static ubyte HASH_sha1_OID[] =
{ 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A };
/* HASH_sha1_OID_LEN = 7 */

/* OID: 1.3.133.16.840.63.0.2 */
static ubyte ASN1_dhSinglePassStdDHSha1KDF_OID[] =
{ 0x06, 0x09, 0x2b, 0x81, 0x05, 0x10, 0x86, 0x48, 0x3f, 0x00, 0x02 };
static ubyte4 ASN1_dhSinglePassStdDHSha1KDF_OID_LEN = 11;

#ifndef __DISABLE_DIGICERT_ECC_P224__
/* OID: 1.3.132.1.11.0 */
static ubyte ASN1_dhSinglePassStdDHSha224KDF_OID[] =
{ 0x06, 0x06, 0x2B, 0x81, 0x04, 0x01, 0x0B, 0x00 };
static ubyte4 ASN1_dhSinglePassStdDHSha224KDF_OID_LEN = 8;
#endif

/* OID: 1.3.132.1.11.1 */
static ubyte ASN1_dhSinglePassStdDHSha256KDF_OID[] =
{ 0x06, 0x06, 0x2B, 0x81, 0x04, 0x01, 0x0B, 0x01 };
static ubyte4 ASN1_dhSinglePassStdDHSha256KDF_OID_LEN = 8;

/* OID: 1.3.132.1.11.2 */
static ubyte ASN1_dhSinglePassStdDHSha384KDF_OID[] =
{ 0x06, 0x06, 0x2B, 0x81, 0x04, 0x01, 0x0B, 0x02 };
static ubyte4 ASN1_dhSinglePassStdDHSha384KDF_OID_LEN = 8;

/* OID: 1.3.132.1.11.3 */
static ubyte ASN1_dhSinglePassStdDHSha512KDF_OID[] =
{ 0x06, 0x06, 0x2B, 0x81, 0x04, 0x01, 0x0B, 0x03 };
static ubyte4 ASN1_dhSinglePassStdDHSha512KDF_OID_LEN = 8;

/* OID: 2.5.29.14 */
static ubyte ASN1_subjectKeyIdentifier_OID[] = { 0x06, 0x03, 0x55, 0x1D, 0x0E };
static ubyte4 ASN1_subjectKeyIdentifier_OID_LEN = 5;

/* OID: 2.5.29.35 */
static ubyte ASN1_authorityKeyIdentifier_OID[] = { 0x06, 0x03, 0x55, 0x1D, 0x23 };
static ubyte4 ASN1_authorityKeyIdentifier_OID_LEN = 5;

/* OID: 2.16.840.1.101.3.4.1.5 */
static ubyte ASN1_aes128Wrap_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05 };
static ubyte4 ASN1_aes128Wrap_OID_LEN = 11;

/* OID: 2.16.840.1.101.3.4.1.25 */
static ubyte ASN1_aes192Wrap_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x19 };
static ubyte4 ASN1_aes192Wrap_OID_LEN = 11;

/* OID: 2.16.840.1.101.3.4.1.45 */
static ubyte ASN1_aes256Wrap_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D };
static ubyte ASN1_aes256Wrap_OID_LEN = 11;

/* OID: 2.16.840.1.101.3.4.2.1 */
static ubyte HASH_sha256_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
/* HASH_sha256_OID_LEN = 11 */

/* OID: 2.16.840.1.101.3.4.2.2 */
static ubyte HASH_sha384_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
/* HASH_sha384_OID_LEN = 11 */

/* OID: 2.16.840.1.101.3.4.2.3 */
static ubyte HASH_sha512_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
/* HASH_sha512_OID_LEN = 11 */

/* OID: 2.16.840.1.101.3.4.2.4 */
static ubyte HASH_sha224_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
/* HASH_sha224_OID_LEN = 11 */

/* OID: 2.16.840.1.101.3.4.1.2 */
static ubyte AES_128CBC_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
static ubyte4 AES_128CBC_OID_LEN = 11;

/* OID: 2.16.840.1.101.3.4.1.22 */
static ubyte AES_192CBC_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16 };
static ubyte4 AES_192CBC_OID_LEN = 11;

/* OID: 2.16.840.1.101.3.4.1.42 */
static ubyte AES_256CBC_OID[] =
{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a };
static ubyte4 AES_256CBC_OID_LEN = 11;

/************************************************************************/

/** Function to parse an X509 ASN1 encoded certificate.
 *  <p>The parsing of the certificate is 'limited' to the parts other
 *     utility functions in this file are interested in.
 *  <p>The returned 'MAsn1Element' pointers reference the memory in 'pCert'
 *     which holds the ASN1 string. Once this string is freed, these
 *     references are no longer valid.
 *  <p>The 'pRoot' object describes the 'outer-most' sequence of the 'Certificate'.
 *  <p>The 'pTBS' object describes the 'To Be Signed' certificate data.
 *
 *  @param pCert   The ASN1 encoded certificate data.
 *  @param certLen The length of the ASN1 string.
 *  @param ppRoot  The pointer to a variable where an 'MAsn1Element*' instance
 *                 should be stored.
 *  @param ppTBS   The pointer to a variable where an 'MAsn1Element*' instance
 *                 should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_parseX509(const ubyte  *pCert,
                    ubyte4       certLen,
                    MAsn1Element **ppRoot,
                    MAsn1Element **ppTBS);

/** Function to compute the hash of a certificate, encoded in the X509 format.
 *  <p>This function parses the X509 data to obtain the signature algorithm and the
 *   'To-Be-Signed' section of the certificate.
 *  <p>This function returns the hash value as a byte array.
 *  <p>It also returns the hash type ID (e.g. \c ht_sha1) and the key type ID (e.g. \c akt_rsa) of
 *   the key used when signing the certificate.
 *
 *  @param pCert      The X509 data as a byte array.
 *  @param certLen    The length of the X509 data in bytes.
 *  @param pHash      A pointer to the memory where the hash value should be stored.
 *  @param hashLen    A pointer to a \c ubyte4 variable, where the length of the hash (in bytes) will be stored.
 *  @param hashType   A pointer to a \c ubyte4 variable, where the hash ID value will be stored.
 *  @param pubkeyType A pointer to a \c ubyte4 variable, where the type of the key used for signing will be
 *                    stored.
 */
static MSTATUS
DIGI_CMS_U_computeCertificateHash(ubyte  *pCert,
                                 ubyte4 certLen,
                                 ubyte  *pHash,
                                 ubyte4 *hashLen,
                                 ubyte4 *hashType,
                                 ubyte4 *pubkeyType);

/** Function to locate an extension ASN.1 data section by
 *  finding a matching OID.
 * <p>Returns 'OK' when the OID was found, otherwise an error is
 *  returned.
 * <p>The returned ASN1 data value array points to the memory of the input data and
 *  stays valid until that memory is released.
 * <p>Per RFC5280, a value in an extension is stored as an OCTET STRING, and the
 *  returned data is still inside that 'container'.
 *
 * @param pExtension   The ASN1 data containing the 'extension' objects as defined by
 *                     RFC-5280.
 * @param extensionLen The length of the ASN1 data array in bytes.
 * @param pOID         The ASN1 encoded OID the function should look for.
 * @param OIDLen       The length of the ASN1 OID data array.
 * @param pIsCritical  A pointer to an 'intBoolean' value, where the function will store the
 *                     'critical' Boolean value taken from the ASN1 data section, if it is found.
 * @param ppValue      A pointer to a 'ubyte*' memory variable, where the function will store
 *                     the memory address of the ASN1 'data value' of the located extension.
 * @param pValueLen    A pointer to a 'ubyte4' variable, where the function will store the length
 *                     of the ASN1 data value memory in bytes.
 */
static MSTATUS
DIGI_CMS_U_locateExtensionByOID(ubyte      *pExtension,
                               ubyte4     extensionLen,
                               ubyte      *pOID,
                               ubyte4     OIDLen,
                               intBoolean *pIsCritical,
                               ubyte      **ppValue,
                               ubyte4     *pValueLen);

/** A function to locate an 'attribute' entry in an array of 'attributes' that has
 *  been filled by reading a SETOF from a CMS message. This means each 'attribute' is (still)
 *  encoded as an ASN1 structure with definite length.
 *  <p>The returned data represents the 'value' section of the ASN1 encoding of an 'attribute'.
 *  <p>An 'attribute' is uniquely identified by an OID 'string'.
 *  <p>An error is returned in case the OID is not matched with any 'attribute' in the array.
 *
 *  @param pAllAttr    A pointer to the byte array containing the attribute data.
 *  @param allAttrLen  The length of the attribute data array in bytes.
 *  @param tagVal      The expected 'TAG' value with which the SETOF must be tagged.
 *  @param pOID        The OID value 'string' that is requested.
 *  @param oidLen      The length of the OID value in bytes.
 *  @param ppVal       A pointer to a memory variable, where this function will store the start
 *                     of the found attribute data.
 *  @param pValLen     A pointer to a \c ubyte4 variable where this function will store the length
 *                     of the found attribute data.
 *
 */
static MSTATUS
DIGI_CMS_U_getAttribute(ubyte  *pAllAttr,
                       ubyte4 allAttrLen,
                       ubyte  tagVal,
                       ubyte  *pOID,
                       ubyte4 oidLen,
                       ubyte  **ppVal,
                       ubyte4 *pValLen);

/** Function to decode an 'attribute's value data.
 *
 *  @param pValAttr   The byte array containing the ASN encoded value (e.g. returned
 *                    by the \c DIGI_CMS_U_getAttribute() function)
 *  @param valAttrLen The length of the value array.
 *  @param typeId     The ASN1 type id the value is expected to represent (e.g. \c MASN1_TYPE_INTEGER). These
 *                    type id values are found in 'mocasn1.h'.
 *  @param pVal       A pointer to a memory variable, which will be overwritten by this function with the value
 *                    memory.
 *  @param pValLen    A pointer to a \c ubyte4 variable, which will be used to store the length of the value memory.
 *
 */
static MSTATUS
DIGI_CMS_U_decodeAttribute(ubyte  *pValAttr,
                          ubyte4 valAttrLen,
                          ubyte4 typeId,
                          ubyte  **pVal,
                          ubyte4 *pValLen);

/** Function to create the digest/hash value authenticating a set of attributes
 *
 *  @param pAttr        Pointer to the ASN1 encoded attribute list.
 *  @param attrLen      The length in bytes of the attribute data.
 *  @param pHash        A pointer to the hash digest algorithm instance (\c MOC_CMS_SignedDataHash) used
 *                      by the signature containing these attributes.
 *  @param ppHashResult A pointer to where the allocated memory with the hash value should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_hashAuthAttributes(const ubyte            *pAttr,
                             ubyte4                 attrLen,
                             MOC_CMS_SignedDataHash *pHash,
                             ubyte                  **ppHashResult);

/** Function to extract the public key from an RSA certificate.
 *
 *  @param pSubj   The ASN1 encoded certificate data.
 *  @param subjLen The length of the ASN1 string.
 *  @param pKey    The pointer to a variable, where the public 'AsymmtricKey' instance
 *                 should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_extractRSAKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                        ubyte* pSubj, ubyte4 subjLen,
                        AsymmetricKey* pKey);

#if (defined(__ENABLE_DIGICERT_DSA__))
/** Function to extract the public key from a DSA certificate.
 *
 *  @param pSubj   The ASN1 encoded certificate data.
 *  @param subjLen The length of the ASN1 string.
 *  @param pKey    The pointer to a variable, where the public 'AsymmtricKey' instance
 *                 should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_extractDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx)
                        ubyte* pSubj, ubyte4 subjLen,
                        AsymmetricKey* pKey);
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
/** Function to extract the public key from an ECC certificate.
 *
 *  @param pSubj   The ASN1 encoded certificate data.
 *  @param subjLen The length of the ASN1 string.
 *  @param pKey    The pointer to a variable, where the public 'AsymmtricKey' instance
 *                 should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_extractECCKey(MOC_ECC(hwAccelDescr hwAccelCtx) ubyte* pSubj, ubyte4 subjLen,
                        AsymmetricKey* pKey);
#endif

#if (defined(__ENABLE_DIGICERT_PQC__))
/** Function to extract the public key from an HYBRID certificate.
 *
 *  @param pSubj   The ASN1 encoded certificate data.
 *  @param subjLen The length of the ASN1 string.
 *  @param pKey    The pointer to a variable, where the public 'AsymmtricKey' instance
 *                 should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_extractHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte* pSubj, ubyte4 subjLen,
                           AsymmetricKey* pKey);


/** Function to extract the public key from a QS certificate.
 *
 *  @param pSubj   The ASN1 encoded certificate data.
 *  @param subjLen The length of the ASN1 string.
 *  @param pKey    The pointer to a variable, where the public 'AsymmtricKey' instance
 *                 should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_extractQsKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pSubj, ubyte4 subjLen, AsymmetricKey *pKey);
#endif

/** Function to verify a signature using an RSA key for the digest.
 *  <p>The verification result is the combination of the return error code (any failure),
 *     and the returned integer value, with the value '0' signaling a successful
 *     verification.
 *
 *  @param pRSAKey       Pointer to the RSA key instance.
 *  @param pHashResult   The hash value created from the payload.
 *  @param hashResultLen The length of the hash value.
 *  @param pSignature    The ASN1 encoded DSA signature string.
 *  @param signatureLen  The length of the signature string.
 *  @param sigFail       Pointer the variable where the verification result should
 *                       be stored.
 *  @param keyType       Specifies the type of key (akt_rsa, akt_ecc, akt_tap_rsa, akt_tap_ecc ...)
 *
 */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
DIGI_CMS_U_verifyRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                             RSAKey* pRSAKey,
                             const ubyte* pHashResult,
                             ubyte4  hashResultLen,
                             ubyte*  pSignature,
                             ubyte4  signatureLen,
                             ubyte4* sigFail,
                             ubyte4  keyType);
#else

static MSTATUS
DIGI_CMS_U_verifyRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                             RSAKey* pRSAKey,
                             const ubyte* pHashResult,
                             ubyte4  hashResultLen,
                             ubyte*  pSignature,
                             ubyte4  signatureLen,
                             ubyte4* sigFail);
#endif

/** Function to create a signature using an RSA key for the digest encryption.
 *
 */
static MSTATUS
DIGI_CMS_U_setRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                          RSAKey      *pRSAKey,
                          const ubyte *pHashResult,
                          ubyte4      hashResultLen,
                          ubyte4      hashAlgo,
                          ubyte4      keyType,
                          ubyte       **ppSignature,
                          ubyte4      *pSignatureLen);

#if (defined(__ENABLE_DIGICERT_DSA__))

/** Function to verify a signature using a DSA key for the digest.
 *  <p>The verification result is the combination of the return error code (any failure),
 *     and the returned integer value, with the value '0' signaling a successful
 *     verification.
 *
 *  @param pDSAKey       Pointer to the DSA key instance.
 *  @param pHashResult   The hash value created from the payload.
 *  @param hashResultLen The length of the hash value.
 *  @param pSignature    The ASN1 encoded DSA signature string.
 *  @param signatureLen  The length of the signature string.
 *  @param sigFail       Pointer the variable where the verification result should
 *                       be stored.
 */
static MSTATUS
DIGI_CMS_U_verifyDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                             DSAKey* pDSAKey,
                             const ubyte* pHashResult,
                             ubyte4  hashResultLen,
                             ubyte*  pSignature,
                             ubyte4  signatureLen,
                             ubyte4* sigFail);

/** Function to create a signature using a DSA key for the digest encryption.
 *
 */
static MSTATUS
DIGI_CMS_U_setDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey* pDSAKey,
                          RNGFun rngFun, void* rngArg,
                          const ubyte* pHashResult,
                          ubyte4  hashResultLen,
                          ubyte   **ppSignature,
                          ubyte4  *pSignatureLen);
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))

/** Function to verify a signature using an ECC key for the digest.
 *  <p>The verification result is the combination of the return error code (any failure),
 *     and the returned integer value, with the value '0' signaling a successful
 *     verification.
 *
 *  @param pECCKey       The pointer to the ECC key instance
 *  @param pHashResult   The hash value created from the payload.
 *  @param hashResultLen The length of the hash value.
 *  @param pSignature    The ASN1 encoded ECC signature string.
 *  @param signatureLen  The length of the signature string.
 *  @param sigFail       Pointer the variable where the verification result should
 *                       be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_verifyECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx)
                               ECCKey* pECCKey,
                               const ubyte* pHashResult,
                               ubyte4  hashResultLen,
                               ubyte*  pSignature,
                               ubyte4  signatureLen,
                               ubyte4* sigFail);

/** Function to create a signature using an ECC key for the digest encryption.
 *
 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
DIGI_CMS_U_setECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                            const ubyte *plainData,
                            ubyte4      plainDataLen,
                            RNGFun      rngFun,
                            void        *rngArg,
                            const ubyte *pHashResult,
                            ubyte4      hashResultLen,
                            ubyte       **ppSignature,
                            ubyte4      *pSignatureLen);
#else
static MSTATUS
DIGI_CMS_U_setECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey* pECCKey,
                            RNGFun rngFun, void* rngArg,
                            const ubyte* pHashResult,
                            ubyte4  hashResultLen,
                            ubyte   **ppSignature,
                            ubyte4  *pSignatureLen);
#endif
#endif


#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS
DIGI_CMS_U_setHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                             RNGFun      rngFun,
                             void        *rngArg,
                             const ubyte *pHashResult,
                             ubyte4      hashResultLen,
                             ubyte       **ppSignature,
                             ubyte4      *pSignatureLen);

static MSTATUS
DIGI_CMS_U_verifyHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                AsymmetricKey *pKey,
                                const ubyte *pHashResult,
                                ubyte4  hashResultLen,
                                ubyte   *pSignature,
                                ubyte4  signatureLen,
                                ubyte4  *sigFail);

static MSTATUS
DIGI_CMS_U_setQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                         RNGFun      rngFun,
                         void        *rngArg,
                         const ubyte *pHashResult,
                         ubyte4      hashResultLen,
                         ubyte       **ppSignature,
                         ubyte4      *pSignatureLen);

static MSTATUS
DIGI_CMS_U_verifyQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx)
                            AsymmetricKey *pKey,
                            const ubyte *pHashResult,
                            ubyte4  hashResultLen,
                            ubyte   *pSignature,
                            ubyte4  signatureLen,
                            ubyte4  *sigFail);
#endif

/** Function to decode the ASN1 string with the (generic) CBC IV data.
 *  <p>The output array should have enough memory for the largest IV expected for this
 *     algorithm.
 *
 *  @param pIV       The pointer to the ASN1 string with the data.
 *  @param IVlen     The length of the ASN1 string.
 *  @param blocksize The expected blocksize of the CBC logic.
 *  @param iv        The memory array to which the decoded IV value should be copied.
 *
 */
static MSTATUS
DIGI_CMS_U_getCBCParams(ubyte* pIV,
                       ubyte4 IVLen,
                       ubyte blockSize,
                       ubyte iv[16]);

#ifdef __ENABLE_ARC2_CIPHERS__
/** Function to decode the ASN1 string with the RC2-CBC IV data.
 *  <p>The output array should have enough memory for the largest IV expected for this
 *     algorithm.
 *
 *  @param pIV               The pointer to the ASN1 string with the data.
 *  @paran IVLen             The length of the ASN1 string.
 *  @param pEffectiveKeyBits
 *  @param iv                The memory array to which the decoded IV value should be copied.
 *
 */
static MSTATUS
DIGI_CMS_U_getRC2CBCParams(ubyte* pIV,
                          ubyte4 IVLen,
                          sbyte4* pEffectiveKeyBits,
                          ubyte iv[/*RC2_BLOCK_SIZE*/]);
#endif

/** Function to set the OID of a signer using RSA, matching the given digest ID value.
 *
 *  @param pMem        The ASN1 memory cache for the allocated memory.
 *  @param digestAlg   The ID value for the digest algorithm, e.g. \c ht_sha1.
 *  @param pSignerOID  A pointer to an \c MAsn1Element that will contain the created OID value.
 *
 */
static MSTATUS
DIGI_CMS_U_setSignerSignatureRSA(MOC_CMS_ASN1_Memory* pMem,
                                ubyte4        digestAlg,
                                MAsn1Element* pSignerOID);

static MSTATUS
DIGI_CMS_U_writeRSARecipientID(MOC_RSA(hwAccelDescr hwAccelCtx)
                              MOC_CMS_ASN1_Memory *pMem,
                              RSAKey* pRSA,
                              RNGFun rngFun,
                              void* rngFunArg,
                              ubyte  *pKey,
                              ubyte4 keyLen,
                              ubyte  *pCert,
                              ubyte4 certLen,
                              ubyte  **ppASN1,
                              ubyte4 *pASN1Len);

#if (defined(__ENABLE_DIGICERT_DSA__))
/** Function to set the OID of a signer using DSA, matching the given digest ID value.
 *
 *  @param pMem        The ASN1 memory cache for the allocated memory.
 *  @param digestAlg   The ID value for the digest algorithm, e.g. \c ht_sha1.
 *  @param pSignerOID  A pointer to an \c MAsn1Element that will contain the created OID value.
 *
 */
static MSTATUS
DIGI_CMS_U_setSignerSignatureDSA(MOC_CMS_ASN1_Memory* pMem,
                                ubyte4        digestAlg,
                                MAsn1Element* pSignerOID);
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))

static MSTATUS
DIGI_CMS_U_writeECDHRecipientID(MOC_HW(hwAccelDescr hwAccelCtx)
                               ECCKey *pECCKey,
                               RNGFun rngFun,
                               void* rngFunArg,
                               const BulkEncryptionAlgo* pBulkEncryptionAlgo,
                               ubyte  *pKey,
                               ubyte4 keyLen,
                               ubyte  *pCert,
                               ubyte4 certLen,
                               ubyte  **ppASN1,
                               ubyte4 *pASN1Len);

/** Function to encrypt a key value with an ECC private key instance.
 *
 *  @param pHashAlgo        The pointer to a bulk hash algorithm context.
 *  @param pPublicECCKey    The pointer to a ECC public key instance.
 *  @param pPrivateECCKey   The pointer to a ECC private key instance.
 *  @param keyWrapOID       The OID data describing the wrap algorithm.
 *  @param keyWrapOIDLen    The length of the OID data.
 *  @param ukmData          The byte array that contains the User Key Material string.
 *  @param ukmDataLen       The length of the User Key Material string.
 *  @param cek              The pointer to the unencrypted key data.
 *  @param cekLen           The length of the unencrypted key data.
 *  @param encryptedKey     A pointer to memory variable, where this function will store the encrypted key
 *                          data.
 *  @param encryptedKeyLen  A pointer to a \c ubyte4 variable, where this function will store the length
 *                          of the encrypted key data.
 */
static MSTATUS
DIGI_CMS_U_encryptECCKey(MOC_HW(hwAccelDescr hwAccelCtx)
                        const BulkHashAlgo* pHashAlgo,
                        ECCKey *pPublicECCKey, ECCKey *pPrivateECCKey,
                        const ubyte* keyWrapOID, ubyte4 keyWrapOIDLen,
                        const ubyte* ukmData, ubyte4 ukmDataLen,
                        const ubyte* cek, ubyte4 cekLen,
                        ubyte** encryptedKey, ubyte4* encryptedKeyLen);

/** Function to set the OID of a signer using ECDSA, matching the given digest ID value.
 *
 *  @param pMem        The ASN1 memory cache for the allocated memory.
 *  @param digestAlg   The ID value for the digest algorithm, e.g. \c ht_sha1.
 *  @param pSignerOID  A pointer to an \c MAsn1Element that will contain the created OID value.
 *
 */
static MSTATUS
DIGI_CMS_U_setSignerSignatureECDSA(MOC_CMS_ASN1_Memory* pMem,
                                  ubyte4        digestAlg,
                                  MAsn1Element* pSignerOID);


#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS
DIGI_CMS_U_setSignerSignatureHybrid(MOC_CMS_ASN1_Memory* pMem,
                                   ubyte4 digestAlg,
                                   AsymmetricKey *pKey,
                                   MAsn1Element* pSignerOID);

static MSTATUS
DIGI_CMS_U_setSignerSignatureQs(MOC_CMS_ASN1_Memory* pMem,
                               ubyte4 digestAlg,
                               AsymmetricKey *pKey,
                               MAsn1Element* pSignerOID);
#endif

/** Function to decrypt the key for an ECC algorithm instance.
 *
 *  @param pHashAlgo       The pointer to a bulk hash algorithm context.
 *  @param pPublicECCKey   The pointer to a public ECC key instance.
 *  @param pPrivateECCKey  The pointer to the private ECC key instance.
 *  @param keyWrapOID      The OID data describing the wrap algorithm.
 *  @param keyWrapOIDLen   The length of the OID data.
 *  @param hasECDHData     The input DER of the CMS has data in its 'AlgorithmIdentifier'.
 *  @param ukmData         The byte array that contains the User Key Material string.
 *  @param ukmDataLen      The length of the User Key Material string.
 *  @param encryptedKey    The encrypted key data from CMS.
 *  @param encryptedKeyLen The length of the encrypted key data.
 *  @param cek             The pointer to the variable, where the memory pointer to the
 *                         decrypted key should be stored.
 *  @param cekLen          The pointer to the variable, where the length of the decrypted
 *                         key should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_decryptECCKey(MOC_HW(hwAccelDescr hwAccelCtx)
                        const BulkHashAlgo* pHashAlgo,
                        ECCKey* pPublicECCKey, ECCKey* pPrivateECCKey,
                        const ubyte* keyWrapOID, ubyte4 keyWrapOIDLen,
                        intBoolean hasECDHData,
                        ubyte* ukmData, ubyte4 ukmDataLen,
                        const ubyte* encryptedKey, ubyte4 encryptedKeyLen,
                        ubyte** cek, ubyte4* cekLen);

/** Function to generate the 'KEK' for a given ECC key.
 *  <p>The key encryption key is used to decrypt the key from CMS data.
 *
 *  @param pHashAlgo      The pointer to a bulk hash algorithm context.
 *  @param pPublicECCKey  The pointer to a ECC public key instance.
 *  @param pPrivateECCKey The pointer to a ECC private key instance.
 *  @param keyWrapOID     The OID data describing the wrap algorithm.
 *  @param keyWrapOIDLen  The length of OID data.
 *  @param hasECDHData    The input DER of the CMS has data in its 'AlgorithmIdentifier'.
 *  @param ukmData        The byte array that contains the User Key Material string.
 *  @param ukmDataLen     The length of the User Key Material string.
 *  @param kekLen         The length of the ECC crypto key (in bytes).
 *  @param pkek           The pointer to the array variable, where the address to the
 *                        KEK string should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_generateECCKeyEncryptionKey(MOC_ECC(hwAccelDescr hwAccelCtx)
                                      const BulkHashAlgo* pHashAlgo,
                                      ECCKey *pPublicECCKey, ECCKey *pPrivateECCKey,
                                      const ubyte* keyWrapOID, ubyte4 keyWrapOIDLen,
                                      intBoolean hasECDHData,
                                      const ubyte* ukmData, ubyte4 ukmDataLen,
                                      ubyte4 kekLen, ubyte** pkek);

/** Function to create the ECC-CMS shared data for initializing ECCDH crypto
 *  algorithm for key management.
 *  <p>The shared info is a DER encoding of the passed in data, per RFC-5753.
 *
 *  @param keyInfoOID    The OID data describing the wrap algorithm
 *  @param keyInfoOIDLen The length of the OID data
 *  @param hasECDHData   The input DER of the CMS has data in its 'AlgorithmIdentifier'.
 *  @param ukmData       The byte array that contains the User Key Material string
 *  @param ukmDataLen    The length of the User Key Material string.
 *  @param kekLen        The length of the ECC crypto key (in bytes).
 *  @param sharedInfo    The pointer to the variable, where the array pointer of the
 *                       created DER string should be stored.
 *  @param sharedInfoLen The pointer to the variable, where the length of the created
 *                       DER string should be stored.
 *
 */
static MSTATUS
DIGI_CMS_U_generateECCCMSSharedInfo(const ubyte* keyInfoOID,
                                   ubyte4       keyInfoOIDLen,
                                   intBoolean   hasECDHData,
                                   const ubyte* ukmData,
                                   ubyte4       ukmDataLen,
                                   ubyte4       kekLen,
                                   ubyte**      sharedInfo,
                                   ubyte4       *sharedInfoLen);
#endif  /* defined(__ENABLE_DIGICERT_ECC__) */

/************************************************************************/

extern MSTATUS
DIGI_CMS_U_createAsn1MemoryCache(MOC_CMS_ASN1_Memory **ppMem)
{
    return DIGI_CALLOC ((void**)ppMem, 1, sizeof(MOC_CMS_ASN1_Memory));
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_deleteAsn1MemoryCache(MOC_CMS_ASN1_Memory **ppMem)
{
    if ((NULL != ppMem) &&
        (NULL != *ppMem))
    {
        DIGI_CMS_U_cleanAsn1MemoryCache (*ppMem);
        DIGI_FREE ((void**)ppMem);
    }
    return OK;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_addToAsn1MemoryCache(MOC_CMS_ASN1_Memory* pMem,
                               void* pASN1)
{
    MSTATUS             status;
    MOC_CMS_ASN1_Memory *pNew;

    status = DIGI_MALLOC ((void**)&pNew, sizeof(MOC_CMS_ASN1_Memory));
    if (OK != status)
        goto exit;

    pNew->asn1Entry = pASN1;
    pNew->pNext = pMem->pNext;
    pMem->pNext = pNew;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_cleanAsn1MemoryCache(MOC_CMS_ASN1_Memory* pMem)
{
    MOC_CMS_ASN1_Memory *pOld = pMem->pNext;

    while (NULL != pOld)
    {
        MOC_CMS_ASN1_Memory *pNext = pOld->pNext;

        DIGI_FREE ((void**)&(pOld->asn1Entry));
        DIGI_FREE ((void**)&pOld);

        pOld = pNext;
    }

    pMem->pNext = NULL;
    return OK;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_constructHashes(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 hashes,
                          ubyte4 *numHashes,
                          MOC_CMS_SignedDataHash **ppHashes)
{
    MSTATUS status = OK;

    ubyte4 i,j;
    MOC_CMS_SignedDataHash* pHashes = 0;

    /* compute the hashes here */
    *numHashes = DIGI_BITCOUNT (hashes);
    if (0 == *numHashes)
    {
        *ppHashes = NULL;
        goto exit;
    }

    status = DIGI_MALLOC ((void**)&pHashes,
                         (*numHashes) * sizeof (MOC_CMS_SignedDataHash));
    if (OK != status)
        goto exit;

    DIGI_MEMSET ((ubyte*)pHashes, 0, (*numHashes) * sizeof (MOC_CMS_SignedDataHash));

    i = j = 0;
    while ((0 != hashes) &&
           (j < *numHashes))
    {
        if (0 != (1 & hashes))
        {
            pHashes[j].hashType = (ubyte) i;
            status = CRYPTO_getHashAlgoOID ((ubyte) i, &pHashes[j].algoOID);
            if (OK != status)
                goto exit;

            status = CRYPTO_getRSAHashAlgo ((ubyte) i, &pHashes[j].hashAlgo);
            if (OK != status)
               goto exit;

            pHashes[j].hashDataLen = pHashes[j].hashAlgo->digestSize;
            status = CRYPTO_ALLOC (hwAccelCtx,
                                   pHashes[j].hashAlgo->digestSize,
                                   TRUE, &(pHashes[j].hashData));
            if (OK != status)
               goto exit;

            status = pHashes[j].hashAlgo->allocFunc (MOC_HASH(hwAccelCtx)
                                                     &pHashes[j].bulkCtx);
            if (OK != status)
                goto exit;

            status = pHashes[j].hashAlgo->initFunc (MOC_HASH(hwAccelCtx)
                                                    pHashes[j].bulkCtx);
            if (OK != status)
                goto exit;
            
            ++j;
        }
        hashes >>= 1;
        i++;
    }

    *ppHashes = pHashes;
    pHashes = NULL;

exit:
    if (NULL != pHashes)
    {
        DIGI_CMS_U_destructHashes (MOC_HASH(hwAccelCtx) *numHashes, &pHashes);
    }

    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_destructHashes(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 numHashes,
                         MOC_CMS_SignedDataHash  **ppHashes)
{
    MSTATUS status = OK;
    ubyte4  i;

    MOC_CMS_SignedDataHash *pHashes;

    if ((NULL == ppHashes) ||
        (NULL == *ppHashes))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pHashes = *ppHashes;

    for (i = 0; i < numHashes; ++i)
    {
        if (NULL != pHashes[i].bulkCtx)
        {
            pHashes[i].hashAlgo->freeFunc (MOC_HASH(hwAccelCtx)
                                           &pHashes[i].bulkCtx);
        }
        if (NULL != pHashes[i].hashData)
        {
            CRYPTO_FREE (hwAccelCtx, TRUE, &pHashes[i].hashData);
        }
    }

    DIGI_FREE ((void**)&pHashes);
    *ppHashes = NULL;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getHashAlgoIdFromHashAlgoOID(MAsn1Element* pDigestAlgoOID,
                                       ubyte4* pDigestAlg)
{
    return DIGI_CMS_U_getHashAlgoIdFromHashAlgoOIDData(pDigestAlgoOID[0].encoding.pEncoding,
                                                      pDigestAlgoOID[0].encodingLen,
                                                      pDigestAlg);
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getHashAlgoIdFromHashAlgoOIDData(const ubyte *pDigestAlgoOID,
                                           ubyte4 digestAlgoOIDLen,
                                           ubyte4 *pDigestAlg)
{
    MSTATUS status;
    sbyte4  cmpResult;

    /* Add MD5 to recognized digests */
    status = ASN1_compareOID(ASN1_md5_OID, ASN1_md5_OID_LEN,
                             pDigestAlgoOID,
                             digestAlgoOIDLen,
                             NULL, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        *pDigestAlg = ht_md5;
    }
    else
    {
        status = ASN1_getDigestFlagFromOid (pDigestAlgoOID,
                                            digestAlgoOIDLen, pDigestAlg);
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getDigestAlgorithmHash(MAsn1Element *pDigestAlgorithm,
                                 ubyte4       *pHashes)
{
    MSTATUS status = OK;
    ubyte4  hashType = 0;

    status = DIGI_CMS_U_getHashAlgoIdFromHashAlgoOID(pDigestAlgorithm,
                                                    &hashType);
    if (OK == status)
    {
        (*pHashes) |= (1 << hashType);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setDigestAlgorithmHash(MOC_CMS_ASN1_Memory *pMem,
                                 const ubyte         *pDigestAlgoOID,
                                 ubyte4              digestAlgoOIDLen,
                                 MAsn1Element        *pDigestAlgorithm)
{
    MSTATUS status = OK;
    ubyte   *pData = NULL;
    ubyte4  dataLen;

    MAsn1Element *pRoot = NULL;

    MAsn1TypeAndCount defHash[3] =
    {
      {   MASN1_TYPE_SEQUENCE, 2},
        /* Hash OID */
        {   MASN1_TYPE_OID, 0},
        /* parameters:              ANY DEFINED BY algorithm OPTIONAL */
        { MASN1_TYPE_ENCODED, 0},
    };

    status = MAsn1CreateElementArray (defHash, 3, MASN1_FNCT_ENCODE,
                                      NULL, &pRoot);
    if (OK != status)
        goto exit;

    /* Set OID */
    status = MAsn1SetValue (pRoot + 1,
                            pDigestAlgoOID, digestAlgoOIDLen);
    if (OK != status)
        goto exit;

    /* Set parameters to NULL */
    status = MAsn1SetEncoded (pRoot + 2,
                              ASN1_NIL, ASN1_NILLen);
    if (OK != status)
        goto exit;

    /* Try encoding */
    status = MAsn1EncodeAlloc (pRoot, &pData, &dataLen);
    if (OK != status)
        goto exit;

    /* Set value when success */
    status = MAsn1SetEncoded (pDigestAlgorithm,
                              pData, dataLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pData);
    if (OK != status)
        goto exit;

    /* Output MAsn1Element instance owns data when success */
    pData = NULL;

exit:
    /* Error clean up */
    if (NULL != pData)
    {
        DIGI_FREE ((void**)&pData);
    }
    MAsn1FreeElementArray (&pRoot);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setEncodedNIL(MAsn1Element *pEnc)
{
    return MAsn1SetEncoded (pEnc, ASN1_NIL, ASN1_NILLen);
}

/*----------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__)

static MSTATUS
DIGI_CMS_U_setEncodedRsaOaep(MOC_CMS_ASN1_Memory *pMem,
                            MAsn1Element *pElement,
                            ubyte hashAlgo,
                            ubyte mgfAlgo,
                            ubyte mgfHashAlgo,
                            ubyte *pLabel,
                            ubyte4 labelLen)
{
    MSTATUS status;
    ubyte *pDigestOid;
    ubyte4 digestOidLen;
    ubyte *pEnc = NULL;
    ubyte4 encLen = 0;

    MAsn1Element *pOaepParams = NULL;

    MAsn1TypeAndCount oaepParams[] = {
        { MASN1_TYPE_SEQUENCE, 3 },
            {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL | MASN1_EXPLICIT, 1 },
                /* AlgorithmIdentifier - hashAlgorithm */
                {  MASN1_TYPE_OID, 0 },
            {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL | MASN1_EXPLICIT | 1, 2 },
                /* AlgorithmIdentifier - maskGenAlgorithm */
                {  MASN1_TYPE_OID, 0 },
                {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL, 1 },
                    /* AlgorithmIdentifier - hashAlgorithm */
                    {  MASN1_TYPE_OID, 0 },
            {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL | MASN1_EXPLICIT | 2, 2 },
                /* AlgorithmIdentifier - pSourceAlgorithm */
                {  MASN1_TYPE_OID, 0 },
                {  MASN1_TYPE_OCTET_STRING, 0 }
    };

    status = MAsn1CreateElementArray (oaepParams, 10, MASN1_FNCT_ENCODE,
                                        &MAsn1OfFunction, &pOaepParams);
    if (OK != status)
        goto exit;

    if (hashAlgo != DEFAULT_CMS_RSA_OAEP_MSG_DIGEST)
    {
        switch(hashAlgo)
        {
            case ht_sha224:
                pDigestOid = HASH_sha224_OID;
                digestOidLen = sizeof(HASH_sha224_OID);
                break;

            case ht_sha256:
                pDigestOid = HASH_sha256_OID;
                digestOidLen = sizeof(HASH_sha256_OID);
                break;

            case ht_sha384:
                pDigestOid = HASH_sha384_OID;
                digestOidLen = sizeof(HASH_sha384_OID);
                break;

            case ht_sha512:
                pDigestOid = HASH_sha512_OID;
                digestOidLen = sizeof(HASH_sha512_OID);
                break;

            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }

        status = MAsn1SetValue (
            pOaepParams + 2, pDigestOid + 2, digestOidLen - 2);
        if (OK != status)
            goto exit;
    }
    else
    {
        pOaepParams[1].type |= MASN1_NO_VALUE;
    }

    if (mgfAlgo != DEFAULT_CMS_RSA_OAEP_MGF)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (mgfHashAlgo != DEFAULT_CMS_RSA_OAEP_MGF_DIGEST)
    {
        status = MAsn1SetValue (
            pOaepParams + 4, PKCS1MGF_OID + 2, PKCS1MGF_OID_LEN - 2);
        if (OK != status)
            goto exit;

        switch(mgfHashAlgo)
        {
            case ht_sha224:
                pDigestOid = HASH_sha224_OID;
                digestOidLen = sizeof(HASH_sha224_OID);
                break;

            case ht_sha256:
                pDigestOid = HASH_sha256_OID;
                digestOidLen = sizeof(HASH_sha256_OID);
                break;

            case ht_sha384:
                pDigestOid = HASH_sha384_OID;
                digestOidLen = sizeof(HASH_sha384_OID);
                break;

            case ht_sha512:
                pDigestOid = HASH_sha512_OID;
                digestOidLen = sizeof(HASH_sha512_OID);
                break;

            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }

        status = MAsn1SetValue (
            pOaepParams + 6, pDigestOid + 2, digestOidLen - 2);
        if (OK != status)
            goto exit;
    }
    else
    {
        pOaepParams[3].type |= MASN1_NO_VALUE;
    }

    if (NULL != pLabel)
    {
        status = MAsn1SetValue (
            pOaepParams + 8, PSPECIFIED_OID + 2, PSPECIFIED_OID_LEN - 2);
        if (OK != status)
            goto exit;

        status = MAsn1SetValue (pOaepParams + 9, pLabel, labelLen);
        if (OK != status)
            goto exit;
    }
    else
    {
        pOaepParams[7].type |= MASN1_NO_VALUE;
    }

    status = MAsn1EncodeAlloc (pOaepParams, &pEnc, &encLen);
    if (OK != status)
        goto exit;

    status = MAsn1SetEncoded (pElement, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                            (void*)pEnc);
    if (OK != status)
        goto exit;

    pEnc = NULL;

exit:
    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }
    MAsn1FreeElementArray (&pOaepParams);
    return status;
}

#endif

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setAttributesImpl(MOC_CMS_ASN1_Memory *pMem,
                            MOC_CMS_Attribute **pAttributes,
                            ubyte4            numAttributes,
                            ubyte             tagVal,
                            MAsn1Element      *pEnc)
{
    MSTATUS status;
    sbyte4  idx;
    ubyte   *pData = NULL;
    ubyte4  dataLen;

    MAsn1Element *pSet = NULL;
    MAsn1Element *pCur;

    /* Attributes are in a SET with IMPLICT tag */
    MAsn1TypeAndCount defSet[5] = {
       { MASN1_TYPE_SET_OF | MASN1_IMPLICIT, 1 },
         { MASN1_TYPE_SEQUENCE, 2 },
           { MASN1_TYPE_OID, 0 },
           { MASN1_TYPE_SET_OF, 1},
             { MASN1_TYPE_ENCODED, 0 },
    };

    /* Set tag value */
    defSet[0].tagSpecial += tagVal;

    status = MAsn1CreateElementArray (defSet, 5, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pSet);
    if (OK != status)
        goto exit;

    /* Initial SET entry (a sequence) */
    pCur = pSet + 1;

    for (idx = 0; idx < (sbyte4)numAttributes; ++idx)
    {
        /* A new SET entry? */
        if (idx > 0)
        {
            /* Next SETOF Element */
            status = MAsn1CopyAddOfEntry (pSet, &pCur);
            if (OK != status)
                goto exit;
        }

        status = MAsn1SetValue (pCur + 1, pAttributes[idx]->pOID, pAttributes[idx]->oidLen);
        if (OK != status)
            goto exit;

        status = MAsn1SetValue (pCur + 3, pAttributes[idx]->pASN1, pAttributes[idx]->asn1Len);
        if (OK != status)
            goto exit;
    }

    /* Try encoding */
    status = MAsn1EncodeAlloc (pSet, &pData, &dataLen);
    if (OK != status)
        goto exit;

    /* Set value when success */
    status = MAsn1SetEncoded (pEnc,
                              pData, dataLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pData);
    if (OK != status)
        goto exit;

    /* Output MAsn1Element instance owns data when success */
    pData = NULL;

exit:
    if (NULL != pData)
    {
        DIGI_FREE ((void**)&pData);
    }
    MAsn1FreeElementArray (&pSet);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_parseX509(const ubyte  *pCert,
                    ubyte4       certLen,
                    MAsn1Element **ppRoot,
                    MAsn1Element **ppTBS)
{
    MSTATUS  status = OK;
    ubyte4   bytesRead;

    /* Generic structure expected from external X509 cert data [rfc5280 - Section 4.1, page 16] */
    MAsn1TypeAndCount defCert[4] =
    {
      {   MASN1_TYPE_SEQUENCE, 3},
        /* tbsCertificate:       TBSCertificate */
        {   MASN1_TYPE_ENCODED, 0},
        /* signatureAlgorithm:   AlgorithmIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* signatureValue:       BIT STRING */
        {   MASN1_TYPE_ENCODED, 0},
    };

    /* TBSCertificate structure from X509 cert data [rfc5280 - Appendix, page 116] */
    MAsn1TypeAndCount defTBS[12] =
    {
      {   MASN1_TYPE_SEQUENCE, 10},
         /* version:      INTEGER */
         {   MASN1_TYPE_INTEGER | MASN1_EXPLICIT | MASN1_DEFAULT, 0},
         /* serialNumber: CertificateSerialNumber */
         {   MASN1_TYPE_INTEGER, 0},
         /* signature:    AlgorithmIdentifier */
         {   MASN1_TYPE_ENCODED, 0},
         /* issuer:       Name */
         {   MASN1_TYPE_ENCODED, 0},
         /* validity:     Validity */
         {   MASN1_TYPE_ENCODED, 0},
         /* subject:      Name */
         {   MASN1_TYPE_ENCODED, 0},
         /* subjectPublicKeyInfo: SubjectPublicKeyInfo */
         {   MASN1_TYPE_ENCODED, 0},
         /* issuerUniqueID  [1]:  IMPLICIT UniqueIdentifier OPTIONAL */
         {   MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 1, 0},
         /* subjectUniqueID [2]:  IMPLICIT UniqueIdentifier OPTIONAL */
         {   MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 2, 0},
         /* extensions      [3]  Extensions OPTIONAL */
         {   MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | MASN1_OPTIONAL | 3, 1},
            /* SEQUENCE SIZE (1..MAX) OF Extension */
            { MASN1_TYPE_ENCODED , 0 }
    };

    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;

    status = MAsn1CreateElementArray (defCert, 4, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRoot);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defTBS, 12, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pTBS);
    if (OK != status)
        goto exit;

    /* Decode root cert from memory array */
    status = MAsn1Decode (pCert, certLen,
                          pRoot, &bytesRead);
    if (OK != status)
        goto exit;

    if ((NULL == pRoot[1].value.pValue) ||
         (0 == pRoot[1].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Decode TBS structure */
    status = MAsn1Decode (pRoot[1].value.pValue,
                          pRoot[1].valueLen,
                          pTBS, &bytesRead);
    if (OK != status)
        goto exit;

    *ppRoot = pRoot;
    *ppTBS = pTBS;

exit:
    if (OK != status)
    {
        /* Failure cleanup */
        MAsn1FreeElementArray (&pTBS);
        MAsn1FreeElementArray (&pRoot);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_getCertificateExtensions(ubyte  *pCert,
                                   ubyte4 certLen,
                                   ubyte  **ppExtension,
                                   ubyte4 *pExtensionLen)
{
    MSTATUS      status;
    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte2       idxVersion = 1;
    ubyte2       idxExtens = 10;
    ubyte4       idx;
    ubyte4       val;

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    if ((NULL == pTBS[idxVersion].value.pValue) ||
            (0 == pTBS[idxVersion].valueLen))
    {
        /* No version - Default is 0 */
        *ppExtension = NULL;
        *pExtensionLen = 0;
        goto exit;
    }

    /* Extract integer value */
    val = 0;
    idx = 0;
    while (idx < pTBS[idxVersion].valueLen)
    {
        val <<= 8;
        val += pTBS[idxVersion].value.pValue[idx++];
    }

    /* X509v3 -> Version 2 */
    if (val == 2)
    {
        *ppExtension = pTBS[idxExtens+1].value.pValue;
        *pExtensionLen = pTBS[idxExtens+1].valueLen;
    }
    else
    {
        *ppExtension = NULL;
        *pExtensionLen = 0;
    }

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_locateExtensionByOID(ubyte      *pExtension,
                               ubyte4     extensionLen,
                               ubyte      *pOID,
                               ubyte4     OIDLen,
                               intBoolean *pIsCritical,
                               ubyte      **ppValue,
                               ubyte4     *pValueLen)
{
    MSTATUS      status = OK;
    ubyte4       bytesRead;
    MAsn1Element *pElement = NULL;
    ubyte4       index = 0;

    /* Extension X509 cert data [rfc5280 - Section 4.1, page 17] */
    MAsn1TypeAndCount defExt[5] =
    {
       /* SEQUENCE SIZE (1..MAX) OF Extension */
       { MASN1_TYPE_SEQUENCE_OF, 1},
         /* Extension: SEQUENCE */
         { MASN1_TYPE_SEQUENCE, 3 },
            /* extnID      OBJECT IDENTIFIER */
            { MASN1_TYPE_OID, 0 },
            /* critical    BOOLEAN DEFAULT FALSE */
            { MASN1_TYPE_BOOLEAN | MASN1_OPTIONAL | MASN1_DEFAULT, 0 },
            /* extnValue   OCTET STRING */
            { MASN1_TYPE_OCTET_STRING, 0},
    };
    MAsn1Element *pExt = NULL;
    ubyte2       idxOID = 1;
    ubyte2       idxCrit = 2;
    ubyte2       idxVal = 3;

    status = MAsn1CreateElementArray (defExt, 5, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pExt);
    if (OK != status)
        goto exit;

    /* Decode extension set from memory array */
    status = MAsn1Decode (pExtension, extensionLen,
                          pExt, &bytesRead);
    if (OK != status)
        goto exit;

    status = MAsn1GetOfElementAtIndex (pExt, index, &pElement);
    if (OK != status)
        goto exit;

    /* Loop over the whole set */
    while (NULL != pElement)
    {
        sbyte4 cmpResult = -1;
        status = ASN1_compareOID (pOID, OIDLen,
                                  pElement[idxOID].encoding.pEncoding,
                                  pElement[idxOID].encodingLen, NULL, &cmpResult);
        if (OK != status)
            goto exit;

        /* Found it? */
        if (0 == cmpResult)
        {
            /* Check Boolean */
            if (0 < pElement[idxCrit].valueLen)
            {
                *pIsCritical = pElement[idxCrit].value.pValue[0];
            }
            else
            {
                /* Default */
                *pIsCritical = 0;
            }
            *ppValue = pElement[idxVal].value.pValue;
            *pValueLen = pElement[idxVal].valueLen;
            break;
        }

        /* Next? */
        status = MAsn1GetOfElementAtIndex (pExt, ++index, &pElement);
        if (OK != status)
            goto exit;
    }

    /* Did we find the OID? */
    if (NULL == pElement)
    {
        status = ERR_NOT_FOUND;
    }

exit:
    MAsn1FreeElementArray (&pExt);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_checkCertificateIssuer(const ubyte *pParent,
                                 ubyte4      parentLen,
                                 const ubyte *pCert,
                                 ubyte4      certLen)
{
    MSTATUS status;
    sbyte4  cmpResult = -1;
    ubyte   *pSubj, *pIssuer;
    ubyte4  subjLen, issuerLen;

    if ((NULL == pParent) || (NULL == pCert))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Get subject name from parent certificate */
    status = DIGI_CMS_U_parseX509CertForSubject (pParent, parentLen,
                                                &pSubj, &subjLen);
    if (OK != status)
        goto exit;

    /* Get issuer name from certificate */
    status = DIGI_CMS_U_parseX509CertForIssuerName (pCert, certLen,
                                                   &pIssuer, &issuerLen);
    if (OK != status)
        goto exit;

    /* Compare */
    if (subjLen != issuerLen)
    {
        status = ERR_FALSE;
        goto exit;
    }

    status = DIGI_MEMCMP (pSubj, pIssuer, issuerLen, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 != cmpResult)
    {
        status = ERR_FALSE;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_verifyCertificateSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                     ubyte         *pCert,
                                     ubyte4        certLen,
                                     AsymmetricKey *parentCertKey,
                                     intBoolean    *pFails)
{
    MSTATUS       status;
    ubyte4        sigFails = 1;
    ubyte4        bytesRead;

    MAsn1Element  *pRoot = NULL;
    MAsn1Element  *pTBS = NULL;
    MAsn1Element  *pSign = NULL;

    ubyte         *pSignature;
    ubyte4        signatureLen;
    ubyte         hash[CERT_MAXDIGESTSIZE];
    ubyte4        hashLen = 0;
    ubyte4        hashType;
    ubyte4        pubkeyType = 0;
    ubyte4        signerType;

    /* BIT STRING value  [RFC-5280, section 4.1] */
    MAsn1TypeAndCount defSig[1] =
    {
       /* signatureValue       BIT STRING */
       { MASN1_TYPE_BIT_STRING, 0},
    };

    if ((NULL == pCert) ||
        (NULL == parentCertKey) ||
        (NULL == pFails))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MAsn1CreateElementArray (defSig, 1,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pSign);

    /* Create Hash for Signature */
    status = DIGI_CMS_U_computeCertificateHash (pCert, certLen,
                                               hash, &hashLen,
                                               &hashType, &pubkeyType);

    if (parentCertKey->type != pubkeyType)
    {
        status = ERR_CERT_KEY_SIGNATURE_OID_MISMATCH;
        goto exit;
    }

    /* Locate signature value */
    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    /* Decode BIT STRING from memory array */
    status = MAsn1Decode (pRoot[3].value.pValue,
                          pRoot[3].valueLen,
                          pSign, &bytesRead);
    if (OK != status)
        goto exit;

    pSignature = pSign[0].value.pValue;
    signatureLen = pSign[0].valueLen;

    /* Values must be positive in ASN1, so drop any extra 0 at front if you find
     * that it was added.
     */
    if ((0 == pSignature[0]) &&
        (0 != pSignature[1]))
    {
        ++pSignature;
        --signatureLen;
    }

    /* Switch on key type */
    signerType = parentCertKey->type;
    switch (signerType)
    {
        case akt_rsa:
        {
#ifndef __DISABLE_DIGICERT_RSA__
            status = DIGI_CMS_U_verifyRSASignature (MOC_RSA(hwAccelCtx) parentCertKey->key.pRSA,
                                                   hash, hashLen, /* Hash data */
                                                   pSignature, signatureLen, /* Signature data */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                                                   (ubyte4 *) &sigFails, signerType);
#else
                                                   &sigFails);
#endif
            if (OK != status)
                goto exit;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
            break;
        }
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        case akt_tap_rsa:
        {
#ifndef __DISABLE_DIGICERT_RSA__
            status = DIGI_CMS_U_verifyRSASignature (MOC_RSA(hwAccelCtx) parentCertKey->key.pRSA,
                                                   hash, hashLen, /* Hash data */
                                                   pSignature, signatureLen, /* Signature data */
                                                   &sigFails, signerType);
            if (OK != status)
                goto exit;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
            break;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#ifdef __ENABLE_DIGICERT_DSA__
        case akt_dsa:
        {
            status = DIGI_CMS_U_verifyDSASignature (MOC_DSA(hwAccelCtx) parentCertKey->key.pDSA,
                                                   hash, hashLen, /* Hash data */
                                                   pSignature, signatureLen, /* Signature data */
                                                   &sigFails);
            if (OK != status)
                goto exit;

            break;
        }
#endif  /* __ENABLE_DIGICERT_DSA__ */
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
        {
            status = DIGI_CMS_U_verifyECDSASignature (MOC_ECC(hwAccelCtx) parentCertKey->key.pECC,
                                                     hash, hashLen, /* Hash data */
                                                     pSignature, signatureLen, /* Signature data */
                                                     &sigFails);
            if (OK != status)
                goto exit;

            break;
        }
#endif  /* __ENABLE_DIGICERT_ECC__ */

        default:
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
    }

exit:
    if (NULL != pFails)
    {
        *pFails = (intBoolean) sigFails;
    }

    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    MAsn1FreeElementArray (&pSign);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setSignatureValue(MOC_ASYM(hwAccelDescr hwAccelCtx)
                            MOC_CMS_ASN1_Memory *pMem,
                            RNGFun              rngFun,
                            void                *rngArg,
                            const AsymmetricKey *pKey,
                            ubyte               *pHash,
                            ubyte4              hashLen,
                            ubyte4              hashAlgo,
                            MAsn1Element        *pSig)
{
    MSTATUS status;
    ubyte   *pSignValue = NULL;
    ubyte4  signValueLen = 0;

    /* Switch on key type */
    switch (pKey->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        case akt_tap_rsa:
#endif
        case akt_rsa:
        {
            status = DIGI_CMS_U_setRSASignature (MOC_RSA(hwAccelCtx) pKey->key.pRSA,
                                                pHash, hashLen, hashAlgo, pKey->type,
                                                &pSignValue, &signValueLen);
        }
        break;
#endif /* !__DISABLE_DIGICERT_RSA__ */
#ifdef __ENABLE_DIGICERT_DSA__
        case akt_dsa:
        {
            status = DIGI_CMS_U_setDSASignature (MOC_DSA(hwAccelCtx) pKey->key.pDSA,
                                                rngFun, rngArg,
                                                pHash, hashLen,
                                                &pSignValue, &signValueLen);
        }
        break;
#endif /* __ENABLE_DIGICERT_DSA__ */

#ifdef __ENABLE_DIGICERT_ECC__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        case akt_tap_ecc:
#endif
        case akt_ecc:
        {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            status = DIGI_CMS_U_setECDSASignature (MOC_ECC(hwAccelCtx) (AsymmetricKey *) pKey,
                                                  NULL, 0,
                                                  rngFun, rngArg,
                                                  pHash, hashLen,
                                                  &pSignValue, &signValueLen);
#else
            status = DIGI_CMS_U_setECDSASignature (MOC_ECC(hwAccelCtx) pKey->key.pECC,
                                                  rngFun, rngArg,
                                                  pHash, hashLen,
                                                  &pSignValue, &signValueLen);
#endif
        }
        break;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_PQC__)
        case akt_hybrid:
        {
            status = DIGI_CMS_U_setHybridSignature(MOC_ASYM(hwAccelCtx) (AsymmetricKey *) pKey,
                                                  rngFun, rngArg,
                                                  pHash, hashLen,
                                                  &pSignValue, &signValueLen);
        }
        break;

        case akt_qs:
        {
            status = DIGI_CMS_U_setQsSignature(MOC_HASH(hwAccelCtx) (AsymmetricKey *) pKey,
                                              rngFun, rngArg,
                                              pHash, hashLen,
                                              &pSignValue, &signValueLen);
        }
        break;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ && __ENABLE_DIGICERT_PQC__ */
#endif /* __ENABLE_DIGICERT_ECC__ */

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }
    if (OK != status)
        goto exit;

    status = MAsn1SetEncoded (pSig, pSignValue, signValueLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pSignValue);
    if (OK != status)
        goto exit;

    /* Memory is now owned by ASN1 */
    pSignValue = NULL;

exit:
    /* Error clean up */
    if (NULL != pSignValue)
    {
        DIGI_FREE ((void**)&pSignValue);
    }
    return status;
}


/*----------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
DIGI_CMS_U_setRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                          RSAKey      *pRSAKey,
                          const ubyte *pHashResult,
                          ubyte4      hashResultLen,
                          ubyte4      hashAlgo,
                          ubyte4      keyType,
                          ubyte       **ppSignature,
                          ubyte4      *pSignatureLen)
{
    MSTATUS status;
    ubyte   *pSigBuf = NULL, *pDigest = NULL;
    ubyte4  sigBufLen = 0, digestLen = 0;

    MAsn1Element *pSign = NULL;

    /* BIT STRING value  [RFC-5280, section 4.1] */
    MAsn1TypeAndCount defSig[1] =
    {
       /* signatureValue       BIT STRING */
       { MASN1_TYPE_OCTET_STRING, 0},
    };

    status = MAsn1CreateElementArray (defSig, 1,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pSign);
    if (OK != status)
        goto exit;

    /* Create signature buffer and value */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux (MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &sigBufLen);
#else
    status = RSA_getCipherTextLength (MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &sigBufLen);
#endif
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pSigBuf, 1, sigBufLen);
    if (OK != status)
        goto exit;

    status = ASN1_buildDigestInfoAlloc (pHashResult, hashResultLen,
                                        hashAlgo,
                                        &pDigest, &digestLen);
    if (OK != status)
        goto exit;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_RSA_signMessageAux (MOC_RSA(hwAccelCtx) pRSAKey,
                                                  pDigest, digestLen,
                                                  pSigBuf, NULL);
#else
    status = RSA_signMessage (MOC_RSA(hwAccelCtx) pRSAKey,
                              pDigest, digestLen,
                              pSigBuf, NULL);
#endif
    if (OK != status)
        goto exit;

    /* Store in ASN1 */
    status = MAsn1SetValue (pSign, pSigBuf, sigBufLen);
    if (OK != status)
        goto exit;

    /* Encode as ASN1 */
    status = MAsn1EncodeAlloc (pSign, ppSignature, pSignatureLen);

exit:
    DIGI_FREE ((void**)&pDigest);
    DIGI_FREE ((void**)&pSigBuf);
    MAsn1FreeElementArray (&pSign);
    return OK;
}
#endif

/*----------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_DSA__

static MSTATUS
DIGI_CMS_U_setDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                          DSAKey      *pDSAKey,
                          RNGFun      rngFun,
                          void        *rngArg,
                          const ubyte *pHashResult,
                          ubyte4      hashResultLen,
                          ubyte       **ppSignature,
                          ubyte4      *pSignatureLen)
{
    MSTATUS status;
    vlong  *r = NULL, *s = NULL;
    ubyte  *pEncoded = NULL;
    ubyte4 encodedLen;

    MAsn1Element *pDSA = NULL;
    MAsn1Element *pDSASign = NULL;

    MAsn1TypeAndCount defDSA[1] =
    {
       {  MASN1_TYPE_OCTET_STRING, 0},
    };

    MAsn1TypeAndCount defDSAPar[3] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_INTEGER, 0},
           {  MASN1_TYPE_INTEGER, 0},
    };

    status = MAsn1CreateElementArray (defDSA, 1,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pDSA);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defDSAPar, 3,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pDSASign);
    if (OK != status)
        goto exit;

    status = DSA_computeSignature2 (MOC_DSA(hwAccelCtx) rngFun, rngArg,
                                    pDSAKey, pHashResult, hashResultLen, &r, &s, NULL);
    if (OK != status)
        goto exit;

    /* Set the values */
    status = MAsn1SetIntegerFromVlong (pDSASign + 1, r, TRUE);
    if (OK != status)
        goto exit;

    status = MAsn1SetIntegerFromVlong (pDSASign + 2, s, TRUE);
    if (OK != status)
        goto exit;

    /* Encode parameters as ASN1 */
    status = MAsn1EncodeAlloc (pDSASign, &pEncoded, &encodedLen);
    if (OK != status)
        goto exit;

    /* Set as octet string */
    status = MAsn1SetValue (pDSA, pEncoded, encodedLen);
    if (OK != status)
        goto exit;

    /* Create full signature */
    status = MAsn1EncodeAlloc (pDSA, ppSignature, pSignatureLen);

exit:
    VLONG_freeVlong (&r, NULL);
    VLONG_freeVlong (&s, NULL);
    DIGI_FREE ((void**)&pEncoded);
    MAsn1FreeElementArray (&pDSASign);
    MAsn1FreeElementArray (&pDSA);
    return status;
}
#endif /* __ENABLE_DIGICERT_DSA__ */


/*----------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_ECC__

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
DIGI_CMS_U_setECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                            const ubyte *plainData,
                            ubyte4      plainDataLen,
                            RNGFun      rngFun,
                            void        *rngArg,
                            const ubyte *pHashResult,
                            ubyte4      hashResultLen,
                            ubyte       **ppSignature,
                            ubyte4      *pSignatureLen)
#else
static MSTATUS
DIGI_CMS_U_setECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey      *pECCKey,
                            RNGFun      rngFun,
                            void        *rngArg,
                            const ubyte *pHashResult,
                            ubyte4      hashResultLen,
                            ubyte       **ppSignature,
                            ubyte4      *pSignatureLen)
#endif
{
    MSTATUS status;
    ubyte4        elementLen;
    ubyte         *pSignature = NULL;
    ubyte         *pEncoded = NULL;
    ubyte4        signatureLen = 0;
    ubyte4        encodedLen;

    MAsn1Element *pECDSA = NULL;
    MAsn1Element *pECDSASign = NULL;

    MAsn1TypeAndCount defECDSA[1] =
    {
       {  MASN1_TYPE_OCTET_STRING, 0},
    };

    MAsn1TypeAndCount defECDSAPar[3] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_INTEGER, 0},
           {  MASN1_TYPE_INTEGER, 0},
    };

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_TAP__
    ubyte             keyUsage = 0;
#endif
    ECCKey            *pECCKey = pAsymKey->key.pECC;
#endif

    status = MAsn1CreateElementArray (defECDSA, 1,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pECDSA);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defECDSAPar, 3,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pECDSASign);
    if (OK != status)
        goto exit;

    /* Get the element length so we know how much to allocate for
     * the signature buffer */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux (
        (void *)pECCKey, &elementLen);
#else
    status = EC_getElementByteStringLen (
        pECCKey, &elementLen);
#endif
    if (OK != status)
        goto exit;

    /* Allocate the buffer for the signature value */
    status = DIGI_MALLOC((void **)&pSignature, elementLen * 2);
    if (OK != status)
        goto exit;

    /* If this is a TAP key, check to see if we need to pass the plaintext directly */
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_getKeyUsage ((void *)pECCKey, pAsymKey->type, &keyUsage);
    if (OK != status)
        goto exit;

    if (TAP_KEY_USAGE_ATTESTATION == keyUsage)
    {
        /* Sign the plaintext */
        status = CRYPTO_INTERFACE_ECDSA_signMessage (
            (void *)pECCKey, rngFun, rngArg, (ubyte *) plainData, plainDataLen,
            pSignature, elementLen * 2, &signatureLen, pAsymKey->type);
        if (OK != status)
            goto exit;
    }
    else
    {
#endif
        /* Sign the digest */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDSA_signDigestAux ( MOC_ECC(hwAccelCtx)
            (void *)pECCKey, rngFun, rngArg, (ubyte *) pHashResult, hashResultLen,
            pSignature, elementLen * 2, &signatureLen);
#else
        status = ECDSA_signDigest ( MOC_ECC(hwAccelCtx)
            (void *)pECCKey, rngFun, rngArg, (ubyte *) pHashResult, hashResultLen,
            pSignature, elementLen * 2, &signatureLen);
#endif
        if (OK != status)
            goto exit;

#if defined(__ENABLE_DIGICERT_TAP__)
    }
#endif

    /* Set the values */
    status = MAsn1SetInteger (pECDSASign + 1, pSignature, elementLen, TRUE, 0);
    if (OK != status)
        goto exit;

    status = MAsn1SetInteger (pECDSASign + 2, pSignature + elementLen, elementLen, TRUE, 0);
    if (OK != status)
        goto exit;

    /* Encode parameters as ASN1 */
    status = MAsn1EncodeAlloc (pECDSASign, &pEncoded, &encodedLen);
    if (OK != status)
        goto exit;

    /* Set as octet string */
    status = MAsn1SetValue (pECDSA, pEncoded, encodedLen);
    if (OK != status)
        goto exit;

    /* Create full signature */
    status = MAsn1EncodeAlloc (pECDSA, ppSignature, pSignatureLen);

exit:

    if (NULL != pSignature)
    {
        DIGI_FREE((void **)&pSignature);
    }

    DIGI_FREE ((void**)&pEncoded);
    MAsn1FreeElementArray (&pECDSASign);
    MAsn1FreeElementArray (&pECDSA);
    return status;
}

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_PQC__)
static MSTATUS
DIGI_CMS_U_setHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                             RNGFun      rngFun,
                             void        *rngArg,
                             const ubyte *pHashResult,
                             ubyte4      hashResultLen,
                             ubyte       **ppSignature,
                             ubyte4      *pSignatureLen)
{
    MSTATUS status;
    ubyte4        totalSigLen = 0;
    ubyte         *pSignature = NULL;
    ubyte         *pEncoded = NULL;
    ubyte4        encodedLen;
    ubyte         *pDomain = NULL;
    ubyte4        domainLen = 0;
    ubyte4        qsAlg = 0;

    MAsn1Element *pHybrid = NULL;
    MAsn1Element *pHybridSign = NULL;

    MAsn1TypeAndCount defHybrid[1] =
    {
       {  MASN1_TYPE_OCTET_STRING, 0},
    };

    MAsn1TypeAndCount defHybridPar[2] =
    {
       {  MASN1_TYPE_SEQUENCE, 1},
           {  MASN1_TYPE_BIT_STRING, 0},
    };

    status = MAsn1CreateElementArray (defHybrid, 1,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pHybrid);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defHybridPar, 2,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pHybridSign);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pAsymKey, TRUE, &totalSigLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pSignature, totalSigLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getAlg(pAsymKey->pQsCtx, &qsAlg);
    if (OK != status)
        goto exit;

    status = CRYPTO_getAlgoOIDAlloc(pAsymKey->clAlg, qsAlg, &pDomain, &domainLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeSign(MOC_ASYM(hwAccelCtx) pAsymKey, TRUE, rngFun, rngArg, pDomain, domainLen,
                                               (ubyte *) pHashResult, hashResultLen, pSignature, totalSigLen, &totalSigLen);
    if (OK != status)
        goto exit;

    /* Set the values */
    status = MAsn1SetBitString (pHybridSign + 1, FALSE, pSignature, totalSigLen, totalSigLen * 8);
    if (OK != status)
        goto exit;

    /* Encode parameters as ASN1 */
    status = MAsn1EncodeAlloc (pHybridSign, &pEncoded, &encodedLen);
    if (OK != status)
        goto exit;

    /* Set as octet string */
    status = MAsn1SetValue (pHybrid, pEncoded, encodedLen);
    if (OK != status)
        goto exit;

    /* Create full signature */
    status = MAsn1EncodeAlloc (pHybrid, ppSignature, pSignatureLen);

exit:

    if (NULL != pSignature)
    {
        (void) DIGI_MEMSET_FREE(&pSignature, totalSigLen);
    }

    DIGI_FREE ((void**)&pEncoded);
    MAsn1FreeElementArray (&pHybridSign);
    MAsn1FreeElementArray (&pHybrid);

    if (NULL != pDomain)
    {
        (void) DIGI_MEMSET_FREE(&pDomain, domainLen);
    }

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_PQC__) */
#endif /* __ENABLE_DIGICERT_ECC__ */

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_PQC__)
static MSTATUS
DIGI_CMS_U_setQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey,
                         RNGFun      rngFun,
                         void        *rngArg,
                         const ubyte *pHashResult,
                         ubyte4      hashResultLen,
                         ubyte       **ppSignature,
                         ubyte4      *pSignatureLen)
{
    MSTATUS status;
    ubyte4        sigLen = 0;
    ubyte         *pSignature = NULL;
    ubyte         *pEncoded = NULL;
    ubyte4        encodedLen;

    MAsn1Element *pQs = NULL;
    MAsn1Element *pQsSign = NULL;

    MAsn1TypeAndCount defQs[1] =
    {
       {  MASN1_TYPE_OCTET_STRING, 0},
    };

    MAsn1TypeAndCount defQsPar[2] =
    {
       {  MASN1_TYPE_SEQUENCE, 1},
           {  MASN1_TYPE_BIT_STRING, 0},
    };

    status = MAsn1CreateElementArray (defQs, 1,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pQs);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defQsPar, 2,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pQsSign);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(hwAccelCtx) pAsymKey->pQsCtx, rngFun, rngArg,
                                               (ubyte *) pHashResult, hashResultLen, &pSignature, &sigLen);
    if (OK != status)
        goto exit;

    /* Set the values */
    status = MAsn1SetBitString (pQsSign + 1, FALSE, pSignature, sigLen, sigLen * 8);
    if (OK != status)
        goto exit;

    /* Encode parameters as ASN1 */
    status = MAsn1EncodeAlloc (pQsSign, &pEncoded, &encodedLen);
    if (OK != status)
        goto exit;

    /* Set as octet string */
    status = MAsn1SetValue (pQs, pEncoded, encodedLen);
    if (OK != status)
        goto exit;

    /* Create full signature */
    status = MAsn1EncodeAlloc (pQs, ppSignature, pSignatureLen);

exit:

    if (NULL != pSignature)
    {
        DIGI_MEMSET_FREE(&pSignature, sigLen);
    }

    DIGI_FREE ((void**)&pEncoded);
    MAsn1FreeElementArray (&pQsSign);
    MAsn1FreeElementArray (&pQs);

    return status;
}





#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_PQC__) */


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_writeRecipientID(MOC_HW(hwAccelDescr hwAccelCtx)
                           MOC_CMS_ASN1_Memory *pMem,
                           RNGFun              rngFun,
                           void                *rngFunArg,
                           const BulkEncryptionAlgo* pBulkEncryptionAlgo,
                           ubyte               *pEncrKey,
                           ubyte4              encrKeyLen,
                           ubyte               *pCert,
                           ubyte4              certLen,
                           MAsn1Element        *pID,
                           ubyte4              *pVersion)
{
    MSTATUS       status;
    AsymmetricKey key = { 0 };
    ubyte*        pASN1 = NULL;
    ubyte4        asn1Len;

    /* Extract public key */
    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (MOC_ASYM(hwAccelCtx) pCert, certLen,
                                                       &key);
    if (OK != status)
        goto exit;

    /* Switch on type */
    switch (key.type)
    {
    case akt_rsa:
#ifndef __DISABLE_DIGICERT_RSA__
        status = DIGI_CMS_U_writeRSARecipientID (MOC_RSA(hwAccelCtx)
                                                pMem,
                                                key.key.pRSA,
                                                rngFun, rngFunArg,
                                                pEncrKey, encrKeyLen,
                                                pCert, certLen,
                                                &pASN1, &asn1Len);
#else
        status = ERR_RSA_DISABLED;
#endif
        break;

#ifdef __ENABLE_DIGICERT_ECC__
    case akt_ecc:
        /* Adjust version if needed */
        if (0 == *pVersion)
            *pVersion = 2;

        status = DIGI_CMS_U_writeECDHRecipientID (MOC_HW(hwAccelCtx)
                                                 key.key.pECC,
                                                 rngFun, rngFunArg,
                                                 pBulkEncryptionAlgo,
                                                 pEncrKey, encrKeyLen,
                                                 pCert, certLen,
                                                 &pASN1, &asn1Len);
        break;
#endif

    default:
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
    }

    if (OK != status)
        goto exit;

    /* Set ID data */
    status = MAsn1SetValue (pID, pASN1, asn1Len);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pASN1);
    if (OK != status)
        goto exit;

    /* Memory is now owned by ASN1 */
    pASN1 = NULL;

exit:
    /* Error clean up */
    if (NULL != pASN1)
    {
        DIGI_FREE ((void**)&pASN1);
    }
    CRYPTO_uninitAsymmetricKey (&key, NULL);
    return status;
}


/*----------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
DIGI_CMS_U_writeRSARecipientID(MOC_RSA(hwAccelDescr hwAccelCtx)
                              MOC_CMS_ASN1_Memory *pMem,
                              RSAKey *pRSA,
                              RNGFun rngFun,
                              void   *rngFunArg,
                              ubyte  *pKey,
                              ubyte4 keyLen,
                              ubyte  *pCert,
                              ubyte4 certLen,
                              ubyte  **ppASN1,
                              ubyte4 *pASN1Len)
{
    MSTATUS status;

    ubyte*       pVal;
    ubyte4       valLen;
    ubyte*       encryptedKey = NULL;
    ubyte4       encryptedKeyLen;
    MAsn1Element *pRootRec = NULL;
#if defined(__ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__)
    /* Use default digest algorithm as SHA-256 instead of CMS default of
     * SHA-1 */
    ubyte        hashAlgo = ht_sha256;
    ubyte        mgfAlgo = MOC_PKCS1_ALG_MGF1;
    ubyte        mgfHashAlgo = ht_sha256;
    ubyte        *pLabel = NULL;
    ubyte4       labelLen = 0;
#endif

    /* KeyTransRecipientInfo [rfc5652 - Section 6.2.1, page 21]*/
    MAsn1TypeAndCount defRec[10] =
    {
      /* No CHOICE [x] */
      { MASN1_TYPE_SEQUENCE, 5 },
        /* version:                   CMSVersion,  -- always set to 0 or 2 */
        { MASN1_TYPE_INTEGER, 0 },

        /* rid:                       RecipientIdentifier */
        /** CHOICE -
         * IssuerAndSerialNumber
         * [0]: SubjectKeyIdentifier **/

        /* IssuerAndSerialNumber  (Used)*/
        {  MASN1_TYPE_SEQUENCE, 2 },
          { MASN1_TYPE_ENCODED, 0 },
          { MASN1_TYPE_INTEGER, 0 },
        /* SubjectKeyIdentifier (Not used) */
        {  MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_OPTIONAL , 0 },
        /* keyEncryptionAlgorithm:    KeyEncryptionAlgorithmIdentifier */
        {  MASN1_TYPE_SEQUENCE, 2 },
          /* AlgorithmIdentifier */
          {  MASN1_TYPE_OID, 0 },
          {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
        /* encryptedKey:              EncryptedKey */
        {  MASN1_TYPE_OCTET_STRING, 0 },
    };

    status = MAsn1CreateElementArray (defRec, 10, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pRootRec);
    if (OK != status)
        goto exit;

    /* Set Integer: Always '0' */
    status = MAsn1SetInteger (pRootRec + 1, NULL, 0, TRUE, 0);
    if (OK != status)
        goto exit;

    /* Set issuer name */
    status = DIGI_CMS_U_parseX509CertForIssuerName (pCert, certLen,
                                                   &pVal, &valLen);
    if (OK != status)
        goto exit;

    status = MAsn1SetValue (pRootRec + 3, pVal, valLen);
    if (OK != status)
        goto exit;

    /* Set serial number */
    status = DIGI_CMS_U_parseX509CertForSerialNumber (pCert, certLen,
                                                     &pVal, &valLen);
    if (OK != status)
        goto exit;

    status = MAsn1SetValue (pRootRec + 4, pVal, valLen);
    if (OK != status)
        goto exit;

    /* DO not use SubjectKeyIdentifier */
    status = MAsn1SetValueLenSpecial (pRootRec + 5, MASN1_NO_VALUE);
    if (OK != status)
        goto exit;

    /* Set OID */
#if defined(__ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__)
    status = MAsn1SetValue (pRootRec + 7, RSAES_OAEP_OID + 2,
                            RSAES_OAEP_OID_LEN - 2);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_setEncodedRsaOaep (pMem, pRootRec + 8,
                                          hashAlgo, mgfAlgo, mgfHashAlgo,
                                          pLabel, labelLen);
    if (OK != status)
        goto exit;
#else
    status = MAsn1SetValue (pRootRec + 7, RSA_ENCRYPTION_OID + 2,
                            RSA_ENCRYPTION_OID_LEN - 2);
    if (OK != status)
        goto exit;

    /* Algo params are always NULL */
    status = DIGI_CMS_U_setEncodedNIL (pRootRec + 8);
    if (OK != status)
        goto exit;
#endif

    /* Encrypt key */

#if defined(__ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__)
    /* TODO: CMS provided RNGFun and RNGFun callback argument but PKCS1 OAEP
     * API takes in randomContext - How should this be handled? Okay to use
     * g_pRandomContext? */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt (MOC_RSA(hwAccelCtx) g_pRandomContext,
                          pRSA, hashAlgo,
                          mgfAlgo, mgfHashAlgo,
                          pKey, keyLen, pLabel, labelLen, &encryptedKey,
                          &encryptedKeyLen);
#else
    status = PKCS1_rsaOaepEncrypt (MOC_RSA(hwAccelCtx) g_pRandomContext,
                          pRSA, hashAlgo,
                          mgfAlgo, mgfHashAlgo,
                          pKey, keyLen, pLabel, labelLen, &encryptedKey,
                          &encryptedKeyLen);
#endif
#else
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx)
        pRSA, (sbyte4 *)(&encryptedKeyLen));
#else
    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSA, (sbyte4 *)(&encryptedKeyLen));
#endif
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC ((void**)&encryptedKey, encryptedKeyLen);
    if ( OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_encryptAux (MOC_RSA(hwAccelCtx) pRSA,
                          pKey, keyLen,
                          encryptedKey,
                          rngFun, rngFunArg, NULL);
#else
    status = RSA_encrypt (MOC_RSA(hwAccelCtx) pRSA,
                          pKey, keyLen,
                          encryptedKey,
                          rngFun, rngFunArg, NULL);
#endif
#endif /* __ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__ */
    if (OK != status)
        goto exit;

    /* Add the encrypted key as an OCTET string */
    status = MAsn1SetValue (pRootRec + 9, encryptedKey, encryptedKeyLen);
    if (OK != status)
        goto exit;

    /* Create ASN1 data */
    status = MAsn1EncodeAlloc (pRootRec, ppASN1, pASN1Len);

exit:
    DIGI_FREE ((void**)&encryptedKey);
    MAsn1FreeElementArray (&pRootRec);
    return status;
}
#endif

/*----------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_ECC__

static MSTATUS
DIGI_CMS_U_writeECDHRecipientID(MOC_HW(hwAccelDescr hwAccelCtx)
                               ECCKey                   *pECCKey,
                               RNGFun                   rngFun,
                               void                     *rngFunArg,
                               const BulkEncryptionAlgo *pBulkEncryptionAlgo,
                               ubyte                    *pKey,
                               ubyte4                   keyLen,
                               ubyte                    *pCert,
                               ubyte4                   certLen,
                               ubyte                    **ppASN1,
                               ubyte4                   *pASN1Len)
{
    MSTATUS status;

    ECCKey*      pOurECCKey = NULL;
    ubyte4       curveId = 0;
    ubyte4       pointLen = 0;
    ubyte*       pVal;
    ubyte4       valLen;
    ubyte*       pOrig = NULL;
    ubyte4       origLen;
    ubyte*       ephKey = NULL;
    ubyte4       ephKeyLen;
    ubyte*       encryptedKey = NULL;
    ubyte4       encryptedKeyLen;
    ubyte*       ukmData = NULL;

    const BulkHashAlgo* pHashAlgo;
    ubyte        hashType; /* for X9.63 key derivation */
    const ubyte* keyDerivationOID;
    const ubyte* keyWrapOID;

    MAsn1Element *pRootRec = NULL;
    MAsn1Element *pOrigRec = NULL;

    /* KeyAgreeRecipientInfo sequence [rfc5652 - Section 6.2.2, page 22] */
    MAsn1TypeAndCount defRec[15] =
    {
       /** CHOICE[1] **/
       {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | 1 , 5},
         /* version:                 CMSVersion,  -- always set to 3 */
         {  MASN1_TYPE_INTEGER, 0},
         /* originator [0] EXPLICIT: OriginatorIdentifierOrKey */
         {  MASN1_TYPE_ENCODED | MASN1_EXPLICIT , 0},
         /* ukm [1] EXPLICIT:  UserKeyingMaterial OPTIONAL */
         {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT | 1 , 0},
         /* keyEncryptionAlgorithm:  KeyEncryptionAlgorithmIdentifier*/
         {  MASN1_TYPE_SEQUENCE, 2},
            {  MASN1_TYPE_OID, 0}, /* KDF OID */
            {  MASN1_TYPE_SEQUENCE, 2},
              {  MASN1_TYPE_OID, 0}, /* Crypto Algo */
              {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
         /* recipientEncryptedKeys:  RecipientEncryptedKeys */
         {  MASN1_TYPE_SEQUENCE, 1},
            {  MASN1_TYPE_SEQUENCE, 2},
              /* rid:          KeyAgreeRecipientIdentifier */
              /** CHOICE -
               * IssuerAndSerialNumber
               * [0]: SubjectKeyIdentifier **/

              /* IssuerAndSerialNumber Used */
              {  MASN1_TYPE_SEQUENCE, 2 },
                { MASN1_TYPE_ENCODED, 0 },
                { MASN1_TYPE_INTEGER, 0 },
              /* encryptedKey: EncryptedKey */
              {  MASN1_TYPE_OCTET_STRING, 0},
    };

    /* OriginatorIdentifierOrKey sequence [rfc5652 - Section 6.2.2, page 22] */
    MAsn1TypeAndCount defOrig[5] =
    {
        /* [1]: OriginatorPublicKey */
        {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | 1 , 2},
          /* AlgorithmIdentifier */
          {  MASN1_TYPE_SEQUENCE, 2},
            {  MASN1_TYPE_OID, 0}, /* Should be EC-public key OID */
            {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
          /* BIT STRING */
          {  MASN1_TYPE_BIT_STRING, 0},
    };

    status = MAsn1CreateElementArray (defRec, 15, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pRootRec);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defOrig, 5, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pOrigRec);
    if (OK != status)
        goto exit;

    /* Set Integer: Always '3' */
    status = MAsn1SetInteger (pRootRec + 1, NULL, 0, TRUE, 3);
    if (OK != status)
        goto exit;

    /* set 'public EC' OID in AlgorithmIdentifier */
    status = MAsn1SetValue (pOrigRec + 2,
                            ASN1_ecPublicKey_OID + 2, ASN1_ecPublicKey_OID_LEN - 2);
    if (OK != status)
        goto exit;

    /* Algo params are always NULL */
    status = DIGI_CMS_U_setEncodedNIL (pOrigRec + 3);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
#else
    status = EC_getCurveIdFromKey(pECCKey, &curveId);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux (MOC_ECC(hwAccelCtx)
        curveId, &pOurECCKey, rngFun, rngFunArg);
    if (OK != status)
        goto exit;
#else
    status = EC_generateKeyPairAlloc ( MOC_ECC(hwAccelCtx)
        curveId, &pOurECCKey, rngFun, rngFunArg);
    if (OK != status)
        goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux (
        pOurECCKey, &pointLen);
#else
    status = EC_getPointByteStringLenEx (
        pOurECCKey, &pointLen);
#endif
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&ephKey, pointLen + 1);
    if (OK != status)
        goto exit;

    ephKey[0] = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux ( MOC_ECC(hwAccelCtx)
        pOurECCKey, ephKey + 1, pointLen);
#else
    status = EC_writePublicKeyToBuffer ( MOC_ECC(hwAccelCtx)
        pOurECCKey, ephKey + 1, pointLen);
#endif
    if (OK != status)
        goto exit;

    ephKeyLen = pointLen + 1;

    status = MAsn1SetValue (pOrigRec + 4, ephKey, ephKeyLen);
    if (OK != status)
        goto exit;

    /* Create Originator data */
    status = MAsn1EncodeAlloc (pOrigRec, &pOrig, &origLen);
    if (OK != status)
        goto exit;

    status = MAsn1SetValue (pRootRec + 2, pOrig, origLen);
    if (OK != status)
        goto exit;

    /* Create UKM IV */
    status = DIGI_MALLOC ((void**)&ukmData, keyLen);
    rngFun (rngFunArg, keyLen, ukmData);

    status = MAsn1SetValue (pRootRec + 3, ukmData, keyLen);
    if (OK != status)
        goto exit;

    /* We pick up the key derivation function that makes
     *  sense for the strength of the ECC key --
     *  also compatible with RFC 5008
     */
#ifdef __ENABLE_DIGICERT_ECC_P192__
    if (curveId == cid_EC_P192)
    {
        keyDerivationOID = ASN1_dhSinglePassStdDHSha1KDF_OID;
        hashType = ht_sha1;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    if (curveId == cid_EC_P224)
    {
        keyDerivationOID = ASN1_dhSinglePassStdDHSha224KDF_OID;
        hashType = ht_sha224;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    if (curveId == cid_EC_P256)
    {
        keyDerivationOID = ASN1_dhSinglePassStdDHSha256KDF_OID;
        hashType = ht_sha256;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    if (curveId == cid_EC_P384)
    {
        keyDerivationOID = ASN1_dhSinglePassStdDHSha384KDF_OID;
        hashType = ht_sha384;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    if (curveId == cid_EC_P521)
    {
        keyDerivationOID = ASN1_dhSinglePassStdDHSha512KDF_OID;
        hashType = ht_sha512;
    }
    else
#endif
    {
        status = ERR_EC_UNSUPPORTED_CURVE;
        goto exit;
    }

    /* Obtain hash algo */
    status = CRYPTO_getRSAHashAlgo (hashType, &pHashAlgo);
    if (OK != status)
        goto exit;

    /* Set KDF OID in AlgorithmIdentifier */
    status = MAsn1SetValue (pRootRec + 5,
                            keyDerivationOID + 2,
                            keyDerivationOID[1]);
    if (OK != status)
        goto exit;

#ifndef __DISABLE_AES_CIPHERS__
    if (pBulkEncryptionAlgo == &CRYPTO_AESSuite)
    {
        switch (keyLen)
        {
        case 16: /* AES 128 */
            keyWrapOID = ASN1_aes128Wrap_OID;
            break;
        case 24:
            keyWrapOID = ASN1_aes192Wrap_OID;
            break;
        case 32:
            keyWrapOID = ASN1_aes256Wrap_OID;
            break;
        default:
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;  /* Should this be a fatal error? */
        }
    }
    else
#endif
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    /* Set crypto OID AlgorithmIdentifier */
    status = MAsn1SetValue (pRootRec + 7,
                            keyWrapOID + 2,
                            keyWrapOID[1]);
    if (OK != status)
        goto exit;

    /* Crypto algo params are always NULL */
    status = DIGI_CMS_U_setEncodedNIL (pRootRec + 8);
    if (OK != status)
        goto exit;

    /* Get the encrypted (wrapped) key */
    status = DIGI_CMS_U_encryptECCKey (MOC_HW(hwAccelCtx)
                                      pHashAlgo,
                                      pECCKey, pOurECCKey,
                                      keyWrapOID,
                                      keyWrapOID[1] + 2,
                                      ukmData, keyLen,
                                      pKey, keyLen,
                                      &encryptedKey,
                                      &encryptedKeyLen);
    if (OK != status)
        goto exit;

    /* Set issuer name */
    status = DIGI_CMS_U_parseX509CertForIssuerName (pCert, certLen,
                                                   &pVal, &valLen);
    if (OK != status)
        goto exit;

    status = MAsn1SetValue (pRootRec + 12, pVal, valLen);
    if (OK != status)
        goto exit;

    /* Set serial number */
    status = DIGI_CMS_U_parseX509CertForSerialNumber (pCert, certLen,
                                                     &pVal, &valLen);
    if (OK != status)
        goto exit;

    status = MAsn1SetValue (pRootRec + 13, pVal, valLen);
    if (OK != status)
        goto exit;

    /* Set encrypted key */
    status = MAsn1SetValue (pRootRec + 14, encryptedKey, encryptedKeyLen);
    if (OK != status)
        goto exit;

    /* Create ASN1 data */
    status = MAsn1EncodeAlloc (pRootRec, ppASN1, pASN1Len);

exit:
    DIGI_FREE ((void**)&encryptedKey);
    DIGI_FREE ((void**)&ukmData);
    DIGI_FREE ((void**)&ephKey);
    DIGI_FREE ((void**)&pOrig);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_EC_deleteKeyAux(&pOurECCKey);
#else
    EC_deleteKey(&pOurECCKey);
#endif
    MAsn1FreeElementArray (&pOrigRec);
    MAsn1FreeElementArray (&pRootRec);
    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_computeCertificateHash(ubyte  *pCert,
                                 ubyte4 certLen,
                                 ubyte  *pHash,
                                 ubyte4 *hashLen,
                                 ubyte4 *hashType,
                                 ubyte4 *pubkeyType)
{
    MSTATUS      status;
    ubyte4       bytesRead;
    sbyte4       cmpResult = -1;

    ubyte4                  hashes = 0, hashId;
    ubyte4                  numAlgos;
    MOC_CMS_SignedDataHash* pHashes = NULL;
    ubyte4                  keyType;

    MAsn1Element            *pRoot = NULL;
    MAsn1Element            *pTBS = NULL;
    ubyte2                  idxTBSSignAlgo = 3;
    ubyte2                  idxSignAlgo = 2;

    MAsn1Element *pRootAlgo = NULL;

    /* AlgorithmIdentifier sequence [rfc5280 - Section 4.1.1.2, page 17] */
    MAsn1TypeAndCount defAlgo[3] =
    {
      {   MASN1_TYPE_SEQUENCE, 2},
        /* algorithm:               OBJECT IDENTIFIER */
        {   MASN1_TYPE_OID, 0},
        /* parameters:              ANY DEFINED BY algorithm OPTIONAL */
        {   MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0},
    };

    status = MAsn1CreateElementArray (defAlgo, 3,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootAlgo);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    /* Access signature algorithm OID */
    if ((NULL == pTBS[idxTBSSignAlgo].value.pValue) ||
        (0 == pTBS[idxTBSSignAlgo].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if ((NULL == pRoot[idxSignAlgo].value.pValue) ||
        (0 == pRoot[idxSignAlgo].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Make sure they are the same!! */
    if (pTBS[idxTBSSignAlgo].valueLen != pRoot[idxSignAlgo].valueLen)
    {
        status = ERR_PKCS7_MISMATCH_SIG_HASH_ALGO;
        goto exit;
    }

    status = DIGI_MEMCMP (pTBS[idxTBSSignAlgo].value.pValue,
                         pRoot[idxSignAlgo].value.pValue,
                         pRoot[idxSignAlgo].valueLen,
                         &cmpResult);
    if (OK != status)
        goto exit;

    if (0 != cmpResult)
    {
        status = ERR_PKCS7_MISMATCH_SIG_HASH_ALGO;
        goto exit;
    }

    /* Decode Algorithm ID from memory array */
    status = MAsn1Decode (pTBS[idxTBSSignAlgo].value.pValue,
                          pTBS[idxTBSSignAlgo].valueLen,
                          pRootAlgo, &bytesRead);

    status = DIGI_CMS_U_getSignerSignatureAlgo (pRootAlgo,
                                               &keyType);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_getSignerAlgorithmHash (pRootAlgo,
                                               &hashId);
    if (OK != status)
        goto exit;

    /* Construct hash table - Should be just one */
    hashes |= (1 << hashId);

    status = DIGI_CMS_U_constructHashes (MOC_HASH(0) hashes,
                                        &numAlgos,
                                        &pHashes);
    if (OK != status)
        goto exit;

    /* Hash data from full TBS encoded data */
    pHashes[0].hashAlgo->updateFunc (MOC_HASH(0)
                                     pHashes[0].bulkCtx,
                                     pRoot[1].value.pValue,
                                     pRoot[1].valueLen);

    pHashes[0].hashAlgo->finalFunc (MOC_HASH(0)
                                    pHashes[0].bulkCtx,
                                    pHashes[0].hashData);


    status = DIGI_MEMCPY(pHash, pHashes[0].hashData, pHashes[0].hashDataLen);
    if (OK != status)
        goto exit;

    *hashLen = pHashes[0].hashDataLen;
    *hashType = hashId;
    *pubkeyType = keyType;

exit:
    /* clean up */
    DIGI_CMS_U_destructHashes (MOC_HASH(0) numAlgos, &pHashes);
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    MAsn1FreeElementArray (&pRootAlgo);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_parseX509CertForPublicKey(const ubyte *pCert,
                                    ubyte4      certLen,
                                    ubyte       **ppSubjPubKey,
                                    ubyte4      *pSubjPubKeyLen)
{
    MSTATUS status;
    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte2       idxSubjPub = 7;

    if ((NULL == ppSubjPubKey) ||
        (NULL == pSubjPubKeyLen) ||
        (NULL == pCert))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    /* Valid entry for 'SubjectPublicKeyInfo' */
    if ((NULL == pTBS[idxSubjPub].value.pValue) ||
        (0 == pTBS[idxSubjPub].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* This is a pointer into 'pCert' and is valid as long as 'pCert' is valid */
    *ppSubjPubKey = pTBS[idxSubjPub].value.pValue;
    *pSubjPubKeyLen = pTBS[idxSubjPub].valueLen;

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_parseX509CertForSubject(const ubyte *pCert,
                                  ubyte4      certLen,
                                  ubyte       **ppSubj,
                                  ubyte4      *pSubjLen)
{
    MSTATUS status;
    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte2       idxSubj = 6;

    if ((NULL == pCert) ||
        (NULL == ppSubj) ||
        (NULL == pSubjLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    /* Valid entry for 'Subject' */
    if ((NULL == pTBS[idxSubj].value.pValue) ||
        (0 == pTBS[idxSubj].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* This is a pointer into 'pCert' and is valid as long as 'pCert' is valid */
    *ppSubj = pTBS[idxSubj].value.pValue;
    *pSubjLen = pTBS[idxSubj].valueLen;

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_parseX509CertForSerialNumber(const ubyte *pCert,
                                       ubyte4      certLen,
                                       ubyte       **ppSerial,
                                       ubyte4      *pSerialLen)
{
    MSTATUS status;
    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte2       idxSerial = 2;

    if ((NULL == pCert) ||
        (NULL == ppSerial) ||
        (NULL == pSerialLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    /* Valid entry for 'CertificateSerialNumber' */
    if ((NULL == pTBS[idxSerial].value.pValue) ||
        (0 == pTBS[idxSerial].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* This is a pointer into 'pCert' and is valid as long as 'pCert' is valid */
    *ppSerial = pTBS[idxSerial].value.pValue;
    *pSerialLen = pTBS[idxSerial].valueLen;

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_parseX509CertForIssuerName(const ubyte *pCert,
                                     ubyte4      certLen,
                                     ubyte       **ppIssuerName,
                                     ubyte4      *pIssuerNameLen)
{
    MSTATUS status;
    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte2       idxName = 4;

    if ((NULL == pCert) ||
        (NULL == ppIssuerName) ||
        (NULL == pIssuerNameLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    if (OK != status)
        goto exit;

    /* Valid entry for 'IssuerName' */
    if ((NULL == pTBS[idxName].value.pValue) ||
        (0 == pTBS[idxName].valueLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* This is a pointer into 'pCert' and is valid as long as 'pCert' is valid */
    *ppIssuerName = pTBS[idxName].value.pValue;
    *pIssuerNameLen = pTBS[idxName].valueLen;

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    return status;
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_parseX509CertForSubjectKeyIdentifier(const ubyte *pCert,
                                               ubyte4      certLen,
                                               ubyte       **ppExt,
                                               ubyte4      *pExtLen)
{
    MSTATUS    status;
    ubyte4     bytesRead;

    ubyte      *pExtensions = NULL;
    ubyte4     extensionsLen = 0;
    intBoolean isCritical = FALSE;
    ubyte      *pSKIExt = NULL;
    ubyte4     SKIExtLen;

    /* extnValue OCTET STRING container [RFC-5280, Section 4.1, page 17] */
    MAsn1TypeAndCount defCont[1] =
    {
       { MASN1_TYPE_OCTET_STRING , 0 },
    };
    MAsn1Element *pContRoot = NULL;

    status = DIGI_CMS_U_getCertificateExtensions ((ubyte*)pCert,
                                                 certLen,
                                                 &pExtensions,
                                                 &extensionsLen);
    if (OK != status)
        goto exit;

    if ((NULL != pExtensions) &&
        (0 < extensionsLen))
    {
        /* Look for the Extension by OID */
        status = DIGI_CMS_U_locateExtensionByOID (pExtensions, extensionsLen,
                                                 ASN1_subjectKeyIdentifier_OID,
                                                 ASN1_subjectKeyIdentifier_OID_LEN,
                                                 &isCritical,
                                                 &pSKIExt, &SKIExtLen);
        if (OK != status)
            goto exit;

        /* Parse container */
        status = MAsn1CreateElementArray (defCont, 1, MASN1_FNCT_DECODE,
                                          NULL, &pContRoot);
        if (OK != status)
            goto exit;

        status = MAsn1Decode (pSKIExt, SKIExtLen,
                              pContRoot, &bytesRead);
        if (OK != status)
            goto exit;

        /* Get value inside */
        *ppExt = pContRoot[0].value.pValue;
        *pExtLen = pContRoot[0].valueLen;
    }
    else
    {
        status = ERR_NOT_FOUND;
    }

exit:
    MAsn1FreeElementArray (&pContRoot);
    return status;
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                         const ubyte   *pCert,
                                         ubyte4        certLen,
                                         AsymmetricKey *pCertKey)
{
    MSTATUS status;
    ubyte *pSubjPubKey;
    ubyte4 subjPubKeyLen;

    if ((NULL == pCert) ||
        (NULL == pCertKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CMS_U_parseX509CertForPublicKey(pCert, certLen,
                                                 &pSubjPubKey, &subjPubKeyLen);
    if (OK != status)
        goto exit;

#ifndef __DISABLE_DIGICERT_RSA__
    status = DIGI_CMS_U_extractRSAKey (MOC_RSA(hwAccelCtx) pSubjPubKey,
                                      subjPubKeyLen,
                                      pCertKey);
#else
    status = ERR_CERT_NOT_EXPECTED_OID;
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
    if (OK != status)
    {
        status = DIGI_CMS_U_extractDSAKey (MOC_DSA(hwAccelCtx) pSubjPubKey,
                                          subjPubKeyLen,
                                          pCertKey);
    }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    if (OK != status)
    {
        /* not a RSA or DSA key -> try a ECC key */
        status = DIGI_CMS_U_extractECCKey (MOC_ECC(hwAccelCtx) pSubjPubKey,
                                          subjPubKeyLen,
                                          pCertKey);
    }
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
    if (OK != status)
    {
        /* not a RSA, DSA or ECC key -> try a hybrid key */
        status = DIGI_CMS_U_extractHybridKey (MOC_ASYM(hwAccelCtx) pSubjPubKey,
                                             subjPubKeyLen,
                                             pCertKey);
    }    
    
    if (OK != status)
    {
        /* not a RSA, DSA or ECC key -> try a hybrid key */
        status = DIGI_CMS_U_extractQsKey (MOC_ASYM(hwAccelCtx) pSubjPubKey,
                                         subjPubKeyLen,
                                         pCertKey);
    }
#endif

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getSignerAlgorithmHashType(const ubyte  *pOID,
                                     ubyte4       oidLen,
                                     ubyte4       *pHashAlg)
{
    MSTATUS status = OK;
    sbyte4  cmpResult;

    /* Skip? */
    status = DIGI_MEMCMP (HASH_md5_OID + 2, pOID, oidLen, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 == cmpResult)
    {
        *pHashAlg = ht_md5;
        goto exit;
    }

    status = DIGI_MEMCMP (HASH_sha1_OID + 2, pOID, oidLen, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 == cmpResult)
    {
        *pHashAlg = ht_sha1;
        goto exit;
    }

    status = DIGI_MEMCMP (HASH_sha224_OID + 2, pOID, oidLen, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 == cmpResult)
    {
        *pHashAlg = ht_sha224;
        goto exit;
    }

    status = DIGI_MEMCMP (HASH_sha256_OID + 2, pOID, oidLen, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 == cmpResult)
    {
        *pHashAlg = ht_sha256;
        goto exit;
    }

    status = DIGI_MEMCMP (HASH_sha384_OID + 2, pOID, oidLen, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 == cmpResult)
    {
        *pHashAlg = ht_sha384;
        goto exit;
    }

    status = DIGI_MEMCMP (HASH_sha512_OID + 2, pOID, oidLen, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 == cmpResult)
    {
        *pHashAlg = ht_sha512;
        goto exit;
    }

    /* Not found */
    status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getSignerAlgorithmHash(MAsn1Element *pSignerInfo,
                                 ubyte4       *pDigestAlg)
{
    return DIGI_CMS_U_getSignerAlgorithmHashEncoded (pSignerInfo[1].encoding.pEncoding,
                                                    pSignerInfo[1].encodingLen,
                                                    pDigestAlg);
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getSignerAlgorithmHashEncoded(ubyte  *pEnc,
                                        ubyte4 encLen,
                                        ubyte4 *pDigestAlg)
{
    MSTATUS status = OK;
    sbyte4  cmpResult;
    ubyte4  encryptionSubType;

    /* Check RSA OID */
    status = ASN1_compareOID (RSAWithSHA_OID, RSAWithSHA_OID_LEN,
                              pEnc, encLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        switch(encryptionSubType)
        {
        case 4:
            *pDigestAlg = ht_md5;
            break;

        case 5:
            *pDigestAlg = ht_sha1;
            break;

        case 11:
            *pDigestAlg = ht_sha256;
            break;

        case 12:
            *pDigestAlg = ht_sha384;
            break;

        case 13:
            *pDigestAlg = ht_sha512;
            break;

        case 14:
            *pDigestAlg = ht_sha224;
            break;

        default:
            status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
            goto exit;
        }
        goto exit;
    }

 #ifdef __ENABLE_DIGICERT_DSA__
    /* Check DSA OID */
    status = ASN1_compareOID (DSAWithSHA1_OID, DSAWithSHA1_OID_LEN,
                              pEnc, encLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        *pDigestAlg = ht_sha1;
        goto exit;
    }

    status = ASN1_compareOID (DSAWithSHA2_OID, DSAWithSHA2_OID_LEN,
                              pEnc, encLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        /* DSA with SHA384 or SHA512 is unspecified per [RFC-5754, section 3.1] */
        switch(encryptionSubType)
        {
        case 1:
            *pDigestAlg = ht_sha224;
            break;

        case 2:
           *pDigestAlg = ht_sha256;
            break;

        default:
            status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
            goto exit;
        }
        goto exit;
    }
 #endif
 #ifdef __ENABLE_DIGICERT_ECC__
    /* Check ECDSA OID */
    status = ASN1_compareOID (ECDSAWithSHA1_OID, ECDSAWithSHA1_OID_LEN,
                              pEnc, encLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        *pDigestAlg = ht_sha1;
        goto exit;
    }

    status = ASN1_compareOID (ECDSAWithSHA2_OID, ECDSAWithSHA2_OID_LEN,
                              pEnc, encLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        /* ECC with any allowed SHA2, only */
        switch(encryptionSubType)
        {
        case 1:
            *pDigestAlg = ht_sha224;
            break;

        case 2:
            *pDigestAlg = ht_sha256;
            break;

        case 3:
            *pDigestAlg = ht_sha384;
            break;

        case 4:
            *pDigestAlg = ht_sha512;
            break;

        default:
            status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
            goto exit;
        }
        goto exit;
    }
 #endif
 #ifdef __ENABLE_DIGICERT_PQC__

    /* Check MLDSA OID, use encryptionSubType as dummy var */
    status = ASN1_compareOID (ASN1_mldsa_OID, MLDSA_OID_LEN, pEnc, encLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        *pDigestAlg = ht_none;
        goto exit;
    }

    /* Check Hybrid OID, use encryptionSubType as dummy var */
    status = ASN1_compareOID (ASN1_mldsa_composite_OID, MLDSA_COMPOSITE_OID_LEN, pEnc, encLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult)
    {
        *pDigestAlg = ht_none;
        goto exit;
    }

 #endif

    status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getSignerSignatureAlgo(MAsn1Element *pSignerInfo,
                                 ubyte4       *pubKeyType)
{
    MSTATUS status = OK;
    sbyte4  cmpResult;
    sbyte4  cmpResult2;
    ubyte4  encryptionSubType;

    /* Check RSA OID */
    status = ASN1_compareOID (RSA_ENCRYPTION_OID, RSA_ENCRYPTION_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;

    status = ASN1_compareOID (RSAWithSHA_OID, RSAWithSHA_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              &encryptionSubType, &cmpResult2);
    if (OK != status)
        goto exit;

    if ((0 == cmpResult) ||
        (0 == cmpResult2))
    {
        *pubKeyType = akt_rsa;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DSA__
    /* Check DSA OID */
    status = ASN1_compareOID (DSAWithSHA1_OID, DSAWithSHA1_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;

    status = ASN1_compareOID (DSAWithSHA2_OID, DSAWithSHA2_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              &encryptionSubType, &cmpResult2);
    if ((0 == cmpResult) ||
        (0 == cmpResult2))
    {
#ifdef __ENABLE_DIGICERT_PQC__
        /* DSA has same prefix as pure QS (ending in 17, 18 or 19), hence pass through in that case  */
        if (encryptionSubType < 17 || encryptionSubType > 19)
#endif
        {        
            /* DSA with SHA384 or SHA512 is unspecified per [RFC-5754, section 3.1] */
            if ((0 == cmpResult2) &&
                    ((0 == encryptionSubType) ||
                    (2 < encryptionSubType)))
            {
                status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                goto exit;
            }
            *pubKeyType = akt_dsa;
            goto exit;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    /* Check ECDSA OID */
    status = ASN1_compareOID (ECDSAWithSHA1_OID, ECDSAWithSHA1_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;

    status = ASN1_compareOID (ECDSAWithSHA2_OID, ECDSAWithSHA2_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              &encryptionSubType, &cmpResult2);
    if ((0 == cmpResult) ||
        (0 == cmpResult2))
    {
        /* ECC with any allowed SHA2, only */
        if ((0 == cmpResult2) &&
                ((0 == encryptionSubType) ||
                 (4 < encryptionSubType)))
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;
        }
        *pubKeyType = akt_ecc;
        goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__

    /* Check pure PQC OID */
    status = ASN1_compareOID (ASN1_mldsa_OID, MLDSA_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult && encryptionSubType >= MLDSA_OID_MIN && encryptionSubType <= MLDSA_OID_MAX)
    {
        *pubKeyType = akt_qs;
        goto exit;
    }

    /* Check Hybrid OID*/
    status = ASN1_compareOID (ASN1_mldsa_composite_OID, MLDSA_COMPOSITE_OID_LEN,
                              pSignerInfo[1].encoding.pEncoding,
                              pSignerInfo[1].encodingLen,
                              &encryptionSubType, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 == cmpResult && encryptionSubType >= MLDSA_COMPOSITE_OID_MIN && encryptionSubType <= MLDSA_COMPOSITE_OID_MAX)
    {
        *pubKeyType = akt_hybrid;
        goto exit;
    }
#endif

    status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;

exit:
    return status;
}

/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_setSignerSignatureAlgoInternal(MOC_CMS_ASN1_Memory *pMem,
                                         ubyte4 pubKeyType,
                                         AsymmetricKey *pKey,
                                         ubyte4 digestAlg,
                                         MAsn1Element *pSignerInfo)
{
    MSTATUS status;
    ubyte   *pEnc = NULL;
    ubyte4  encLen;

    MAsn1Element *pAlgo = NULL;

    MAsn1TypeAndCount defAlgo[3] = {
      { MASN1_TYPE_SEQUENCE, 2},
        /* algorithm:               OBJECT IDENTIFIER */
        { MASN1_TYPE_ENCODED, 0},
        /* parameters:              ANY DEFINED BY algorithm OPTIONAL */
        { MASN1_TYPE_ENCODED, 0},
    };

    status = MAsn1CreateElementArray (defAlgo, 3,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pAlgo);
    if (OK != status)
        goto exit;

    switch ((0xFFFF & pubKeyType))
    {
    case akt_rsa:
        status = DIGI_CMS_U_setSignerSignatureRSA (pMem, digestAlg, pAlgo+1);
        break;

#if (defined(__ENABLE_DIGICERT_DSA__))
    case akt_dsa:
        status = DIGI_CMS_U_setSignerSignatureDSA (pMem, digestAlg, pAlgo+1);
        break;
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
        status = DIGI_CMS_U_setSignerSignatureECDSA (pMem, digestAlg, pAlgo+1);
        break;

#if (defined(__ENABLE_DIGICERT_PQC__))
    case akt_hybrid:
        status = DIGI_CMS_U_setSignerSignatureHybrid( pMem, digestAlg, pKey, pAlgo+1);
        break;
    
    case akt_qs:
        status = DIGI_CMS_U_setSignerSignatureQs( pMem, digestAlg, pKey, pAlgo+1);
        break;
#endif
#endif

    default:
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }
    if (OK != status)
        goto exit;
    
    /* Set parameters to NULL */
    status = MAsn1SetEncoded (pAlgo+2, ASN1_NIL, ASN1_NILLen);
    if (OK != status)
        goto exit;

    /* Encode to memory */
    status = MAsn1EncodeAlloc (pAlgo, &pEnc, &encLen);
    if (OK != status)
        goto exit;

    /* Save off in returned instance */
    status = MAsn1SetEncoded (pSignerInfo, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pEnc);
    if (OK != status)
        goto exit;

    /* Memory is now owned by MAsn1Element */
    pEnc = NULL;

exit:
    /* Error clean up */
    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }
    MAsn1FreeElementArray (&pAlgo);
    return status;
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setSignerSignatureAlgo(MOC_CMS_ASN1_Memory *pMem,
                                 ubyte pubKeyType,
                                 ubyte4 digestAlg,
                                 MAsn1Element *pSignerInfo)
{
    return DIGI_CMS_U_setSignerSignatureAlgoInternal(pMem, (ubyte4) pubKeyType, NULL, digestAlg, pSignerInfo);
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setSignerSignatureAlgoKey(MOC_CMS_ASN1_Memory *pMem,
                                    AsymmetricKey *pKey,
                                    ubyte4 digestAlg,
                                    MAsn1Element *pSignerInfo)
{
    if (NULL == pKey)
        return ERR_NULL_POINTER;

    return DIGI_CMS_U_setSignerSignatureAlgoInternal(pMem, pKey->type, pKey, digestAlg, pSignerInfo);
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_processSignerInfoWithCert(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                    MAsn1Element           *pSigner,
                                    MAsn1Element           *pCertificate,
                                    MAsn1Element           *pSignData,
                                    ubyte4                 numHashes,
                                    MOC_CMS_SignedDataHash *pSignedDataHash,
                                    MOC_CMS_MsgSignInfo    *pSigInfos)
{
    MSTATUS status = OK;
    ubyte4  sigFails = 1;
    ubyte   cmsVersion;
    ubyte4  bytesRead;
    ubyte4  hashType = 0;
    ubyte4  signerType;
    sbyte4  i;

    const ubyte *pHashResult = NULL;
    ubyte4      hashResultLen = 0;
    ubyte       *pAttrSign = NULL;

    MAsn1Element *pDigestAlgo = NULL;
    MAsn1Element *pAuthenticatedAttributes = NULL;
    MAsn1Element *pDigestEncryptionAlgo = NULL;
    MAsn1Element *pOID = NULL;
    MAsn1Element *pSignTime = NULL;

    MOC_CMS_SignedDataHash *pHashInfo = NULL;

    MAsn1TypeAndCount oidSet[2] =
    {
        {   MASN1_TYPE_SEQUENCE, 1},
        {   MASN1_TYPE_OID, 0},
    };

    AsymmetricKey certKey = {0};

    ubyte  *pSignature;
    ubyte4 signatureLen;

    status = ERR_PKCS7_INVALID_STRUCT;
    if (NULL == pSigner[1].value.pValue)
    {
        goto exit;
    }

    /* Read version 1 -> Issuer and Serial Number
     *              3 -> Subject key identifier
     *              [rfc-5652 - Section 5.3, page 14] */
    cmsVersion = pSigner[1].value.pValue[0];
    if ( (1 != cmsVersion) &&
         (3 != cmsVersion))
    {
        goto exit;
    }

    /* Access DigestAlgo OID */
    pDigestAlgo = pSigner + 3;
    if (NULL == pDigestAlgo[0].value.pValue)
    {
        goto exit;
    }

    /* OPTIONAL: Authenticated Attributes */
    pAuthenticatedAttributes = pSigner + 4;

    pDigestEncryptionAlgo = pSigner + 6;
    if (NULL == pDigestEncryptionAlgo[0].value.pValue)
    {
        goto exit;
    }

    status = MAsn1CreateElementArray (oidSet, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pOID);
    if (OK != status)
        goto exit;

    /* Decode digest OID from memory array */
    status = MAsn1Decode (pDigestAlgo[0].value.pValue, pDigestAlgo[0].valueLen,
                          pOID, &bytesRead);
    if (OK != status)
        goto exit;

    /* Read hash OID */
    status = DIGI_CMS_U_getHashAlgoIdFromHashAlgoOID (pOID, &hashType);
    if (OK != status)
        goto exit;

    /* Match with hashes list */
    for (i = 0; i < (sbyte4)numHashes; ++i)
    {
        if (pSignedDataHash[i].hashType == hashType)
        {
            /* Keep pointer to array member */
            pHashInfo = pSignedDataHash+i;
            break;
        }
    }
    if (NULL == pHashInfo)
    {
        status = ERR_PKCS7_INVALID_STRUCT; /* ERR_PKCS7_UNEXPECTED_SIGNER_INFO_HASH */
        goto exit;
    }

    pHashResult = pHashInfo->hashData;
    hashResultLen = pHashInfo->hashDataLen;

    if ((0 < pAuthenticatedAttributes[0].encodingLen) &&
        (NULL != pAuthenticatedAttributes[0].encoding.pEncoding))
    {
        ubyte  *pAttrVal = NULL;
        ubyte  *pAttrHash = NULL;
        ubyte4 attrValLen;
        ubyte4 attrHashLen;
        ubyte  *pSigningTime = NULL;
        ubyte4 signingTimeLen;
        MAsn1TypeAndCount signTime[] = {
            { MASN1_TYPE_UTC_TIME, 0 }
        };

        /* Extract optional signing time */
        status = DIGI_CMS_U_getAttribute (pAuthenticatedAttributes[0].encoding.pEncoding,
                                         pAuthenticatedAttributes[0].encodingLen,
                                         0,
                                         ASN1_PKCS9_SIGNING_TIME, ASN1_PKCS9_SIGNING_TIME_LEN,
                                         &pSigningTime, &signingTimeLen);
        if (OK != status)
            goto exit;

        /* Signing time is encoded in a UTCTime tag. If there is a signing time
         * found then parse the UTCTime. */
        if (NULL != pSigningTime)
        {
            status = MAsn1CreateElementArray(
                signTime, 1, MASN1_FNCT_DECODE, &MAsn1OfFunction, &pSignTime);
            if (OK != status)
                goto exit;

            status = MAsn1Decode(
                pSigningTime, signingTimeLen, pSignTime, &bytesRead);
            if (OK != status)
                goto exit;
        }

        /* Extract mandatory digest data and match with the found hash */
        status = DIGI_CMS_U_getAttribute (pAuthenticatedAttributes[0].encoding.pEncoding,
                                         pAuthenticatedAttributes[0].encodingLen,
                                         0,
                                         ASN1_PKCS9_MESSAGE_DIGEST, ASN1_PKCS9_MESSAGE_DIGEST_LEN,
                                         &pAttrVal, &attrValLen);
        if (OK != status)
            goto exit;

        status = DIGI_CMS_U_decodeAttribute (pAttrVal, attrValLen,
                                            MASN1_TYPE_OCTET_STRING,
                                            &pAttrHash, &attrHashLen);
        if (OK != status)
            goto exit;

        /* Compare with found hash */
        status = ERR_PKCS7_INVALID_SIGNATURE;
        if (attrHashLen == hashResultLen)
        {
            sbyte4 cmpResult = -1;

            status = DIGI_MEMCMP (pAttrHash, pHashResult, attrHashLen, &cmpResult);
            if (OK == status)
            {
                if (0 != cmpResult)
                    status = ERR_PKCS7_INVALID_SIGNATURE;
            }
        }
        if (OK != status)
            goto exit;

        /* Replace hash data from encoded payload with data from this ASN1 section.
         * [RFC-5652, Section 5.4, page 16]
         */
        status = DIGI_CMS_U_hashAuthAttributes (pAuthenticatedAttributes[0].encoding.pEncoding,
                                                 pAuthenticatedAttributes[0].encodingLen,
                                                 pHashInfo,
                                                 &pAttrSign);
        if (OK != status)
            goto exit;

        /* Re-direct the hash reference */
        pHashResult = pAttrSign;
    }

    MAsn1FreeElementArray (&pOID);
    status = MAsn1CreateElementArray (oidSet, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pOID);
    if (OK != status)
        goto exit;

    /* Decode digest encryption OID from memory array */
    status = MAsn1Decode (pDigestEncryptionAlgo[0].value.pValue,
                          pDigestEncryptionAlgo[0].valueLen,
                          pOID,
                          &bytesRead);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_getSignerSignatureAlgo (pOID,
                                               &signerType);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (MOC_ASYM(hwAccelCtx) pCertificate[0].encoding.pEncoding,
                                                       pCertificate[0].encodingLen,
                                                       &certKey);
    if (OK != status)
        goto exit;

    pSignature = pSignData[0].value.pValue;
    signatureLen = pSignData[0].valueLen;

    if (akt_rsa == signerType)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        status = DIGI_CMS_U_verifyRSASignature (MOC_RSA(hwAccelCtx) certKey.key.pRSA,
                                               pHashResult, hashResultLen, /* Hash data */
                                               pSignature, signatureLen, /* Signature data */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
                                               &sigFails, signerType);
#else
                                               &sigFails);
#endif
        if (OK != status)
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    else if (akt_tap_rsa == signerType)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        status = DIGI_CMS_U_verifyRSASignature (MOC_RSA(hwAccelCtx) certKey.key.pRSA,
                                               pHashResult, hashResultLen, /* Hash data */
                                               pSignature, signatureLen, /* Signature data */
                                               &sigFails, signerType);
        if (OK != status)
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifdef __ENABLE_DIGICERT_DSA__
    else if (akt_dsa == signerType)
    {
        status = DIGI_CMS_U_verifyDSASignature (MOC_DSA(hwAccelCtx) certKey.key.pDSA,
                                               pHashResult, hashResultLen, /* Hash data */
                                               pSignature, signatureLen, /* Signature data */
                                               &sigFails);
        if (OK != status)
            goto exit;
    }
#endif  /* __ENABLE_DIGICERT_DSA__ */

#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == signerType)
    {
        status = DIGI_CMS_U_verifyECDSASignature (MOC_ECC(hwAccelCtx) certKey.key.pECC,
                                                 pHashResult, hashResultLen, /* Hash data */
                                                 pSignature, signatureLen, /* Signature data */
                                                 &sigFails);
        if (OK != status)
            goto exit;
    }
#endif  /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_hybrid == signerType)
    {
        status = DIGI_CMS_U_verifyHybridSignature (MOC_ASYM(hwAccelCtx) 
                                                 &certKey,
                                                 pHashResult, hashResultLen, /* Hash data */
                                                 pSignature, signatureLen, /* Signature data */
                                                 &sigFails);
        if (OK != status)
            goto exit;
    }
    else if (akt_qs == signerType)
    {
        status = DIGI_CMS_U_verifyQsSignature (MOC_HASH(hwAccelCtx) 
                                              &certKey,
                                              pHashResult, hashResultLen, /* Hash data */
                                              pSignature, signatureLen, /* Signature data */
                                              &sigFails);
        if (OK != status)
            goto exit;
    }
#endif  /* __ENABLE_DIGICERT_PQC__ */

    if (0 != sigFails)
    {
        status = ERR_PKCS7_INVALID_SIGNATURE;
    }

    /* Return signer data, if requested. Do not change return code while copying. */
    if (NULL != pSigInfos)
    {
        MSTATUS status2;

        pSigInfos->ASN1Len = pSigner[0].encodingLen;
        status2 = DIGI_MALLOC ((void**)&(pSigInfos->pASN1),
                             pSigInfos->ASN1Len);
        if (OK != status2)
            goto exit;

        status2 = DIGI_MEMCPY (pSigInfos->pASN1,
                              pSigner[0].encoding.pEncoding, pSigInfos->ASN1Len);
        if (OK != status2)
            goto exit;

        pSigInfos->msgSigDigestLen = hashResultLen;
        status2 = DIGI_MALLOC ((void**)&(pSigInfos->pMsgSigDigest),
                              pSigInfos->msgSigDigestLen);
        if (OK != status2)
            goto exit;

        status2 = DIGI_MEMCPY (pSigInfos->pMsgSigDigest,
                             pHashResult, pSigInfos->msgSigDigestLen);
        if (OK != status2)
            goto exit;

        /* Make Boolean from integer value */
        pSigInfos->verifies = (0 == sigFails);

        /* Store the signature time in the signer information if one was
         * provided. */
        if (NULL != pSignTime)
        {
            status2 = DIGI_MALLOC(
                (void **) &(pSigInfos->pSigningTime), sizeof(TimeDate));
            if (OK != status2)
                goto exit;

            status2 = DATETIME_convertFromValidityString2(
                pSignTime[0].value.pValue, pSignTime[0].valueLen,
                pSigInfos->pSigningTime);
            if (OK != status2)
                goto exit;
        }
    }

exit:
    DIGI_FREE ((void**)&pAttrSign);
    CRYPTO_uninitAsymmetricKey (&certKey, NULL);
    MAsn1FreeElementArray (&pOID);
    MAsn1FreeElementArray (&pSignTime);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_getAttribute(ubyte  *pAllAttr,
                       ubyte4 allAttrLen,
                       ubyte  tagVal,
                       ubyte  *pOID,
                       ubyte4 oidLen,
                       ubyte  **ppVal,
                       ubyte4 *pValLen)
{
    MSTATUS      status = OK;
    ubyte4       bytesRead;
    MAsn1Element *pSet = NULL;
    sbyte4       cmpResult;
    ubyte4       counter = 0;
    MAsn1Element *pElement = NULL;

    /* Attributes are in a SET with IMPLICT tag */
    MAsn1TypeAndCount defSet[5] = {
       { MASN1_TYPE_SET_OF | MASN1_IMPLICIT, 1 },
         { MASN1_TYPE_SEQUENCE, 2 },
           { MASN1_TYPE_OID, 0 },
           { MASN1_TYPE_SET_OF, 1},
             { MASN1_TYPE_ENCODED, 0 },
    };

    /* Set tag value */
    defSet[0].tagSpecial += tagVal;

    status = MAsn1CreateElementArray (defSet, 5, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pSet);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pAllAttr, allAttrLen, pSet, &bytesRead);
    if (OK != status)
        goto exit;

    status = MAsn1GetOfElementAtIndex (pSet, counter, &pElement);
    if (OK != status)
        goto exit;

    while (NULL != pElement)
    {
        /* Found the correct OID? */
        status = ASN1_compareOID (pOID, oidLen,
                                  pElement[1].encoding.pEncoding,
                                  pElement[1].encodingLen, NULL, &cmpResult);
        if (OK != status)
            goto exit;

        if (0 == cmpResult)
        {
            *ppVal = pElement[3].value.pValue;
            *pValLen = pElement[3].valueLen;
            break;
        }

        ++counter;
        status = MAsn1GetOfElementAtIndex (pSet, counter, &pElement);
        if (OK != status)
            goto exit;
    }

exit:
    MAsn1FreeElementArray (&pSet);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_decodeAttribute(ubyte  *pValAttr,
                          ubyte4 valAttrLen,
                          ubyte4 typeId,
                          ubyte  **ppVal,
                          ubyte4 *pValLen)
{
    MSTATUS      status = OK;
    ubyte4       bytesRead;
    MAsn1Element *pData = NULL;

    MAsn1TypeAndCount defVal[1] = {
       { MASN1_TYPE_ENCODED, 0 },
    };

    /* Set to requested type */
    defVal[0].tagSpecial = typeId;

    status = MAsn1CreateElementArray (defVal, 1, MASN1_FNCT_DECODE,
                                      NULL, &pData);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pValAttr, valAttrLen, pData, &bytesRead);
    if (OK != status)
        goto exit;

    *ppVal = pData[0].value.pValue;
    *pValLen = pData[0].valueLen;

exit:
    MAsn1FreeElementArray (&pData);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_hashAuthAttributes(const ubyte            *pAttr,
                             ubyte4                 attrLen,
                             MOC_CMS_SignedDataHash *pHash,
                             ubyte                  **ppHashResult)
{
    MSTATUS status;
    ubyte   *pData = NULL;
    ubyte4  dataLen;

    BulkCtx bulkCtx = NULL;

    /* Copy attribute data */
    status = DIGI_MALLOC ((void**)&pData, attrLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pData, pAttr, attrLen);
    if (OK != status)
        goto exit;

    dataLen = attrLen;

    /* We use the SETOF DER encoding (not the TAG '[0]') for the digest.
     * [RFC-5652, Section 5.4, page 16]
     */
    pData[0] = 0x31;

    /* Create hash algo instance and create digest value of all attributes */
    pHash->hashAlgo->allocFunc (MOC_HASH(0)
                                &bulkCtx);
    pHash->hashAlgo->initFunc (MOC_HASH(0)
                               bulkCtx);
    pHash->hashAlgo->updateFunc (MOC_HASH(0)
                                 bulkCtx,
                                 pData, dataLen);

    /* Create final data and return the hash value
     */
    status = DIGI_CALLOC ((void**)ppHashResult, 1, pHash->hashDataLen);
    if (OK != status)
        goto exit;

    pHash->hashAlgo->finalFunc (MOC_HASH(0)
                                bulkCtx,
                                *ppHashResult);

    /* Free context */
    pHash->hashAlgo->freeFunc (MOC_HASH(0)
                               &bulkCtx);

exit:
    DIGI_FREE ((void**)&pData);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                       ubyte       *pCert,
                       ubyte4      certLen,
                       const ubyte *pParent,
                       ubyte4      parentLen)
{
    MSTATUS       status;

    AsymmetricKey parentCertKey = {0};
    intBoolean        sigFails = 1;

    /* Correct parent? */
    status = DIGI_CMS_U_checkCertificateIssuer (pParent, parentLen,
                                               pCert, certLen);
    if (OK != status)
        goto exit;

    /* Get public key from parent */
    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (MOC_ASYM(hwAccelCtx) pParent, parentLen,
                                                       &parentCertKey);
    if (OK != status)
        goto exit;

    /* Check that the signature verifies with the parent public key */
    status = DIGI_CMS_U_verifyCertificateSignature (MOC_ASYM(hwAccelCtx) pCert,
                                                   certLen,
                                                   &parentCertKey,
                                                   &sigFails);
    if (OK != status)
        goto exit;

    /* Check signature result */
    if (0 != sigFails)
    {
        status = ERR_PKCS7_INVALID_SIGNATURE;
    }

exit:
    CRYPTO_uninitAsymmetricKey (&parentCertKey, NULL);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_isRootCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                            ubyte  *pCert,
                            ubyte4 certLen)
{
    MSTATUS status;
    ubyte4  bytesRead;
    sbyte4  cmpResult = -1;

    AsymmetricKey parentCertKey = {0};
    intBoolean    sigFails = 1;
    ubyte         *pExtensions = NULL;
    ubyte4        extensionsLen = 0;

    intBoolean    isCritical = FALSE;
    ubyte         *pSKIExt = NULL, *pAKIExt = NULL;
    ubyte4        SKIExtLen, AKIExtLen;

    /* extnValue OCTET STRING container [RFC-5280, Section 4.1, page 17] */
    MAsn1TypeAndCount defCont[1] =
    {
       { MASN1_TYPE_OCTET_STRING , 0 },
    };
    MAsn1Element *pContRoot = NULL;

    /* Authority Key Identifier form [RFC-5280, Section 4.2.1.1, page 27] */
    MAsn1TypeAndCount defAKI[4] =
    {
      /* AuthorityKeyIdentifier ::= SEQUENCE */
      { MASN1_TYPE_SEQUENCE, 3},
        /* keyIdentifier [0] KeyIdentifier OPTIONAL */
        { MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 0, 0 },
        /* authorityCertIssuer [1] GeneralNames OPTIONAL */
        { MASN1_TYPE_ENCODED | MASN1_OPTIONAL | 1, 0 },
        /* authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL */
        { MASN1_TYPE_ENCODED | MASN1_OPTIONAL | 2, 0 },
    };
    MAsn1Element *pAKIRoot = NULL;
    ubyte2       idxKeyID = 1;

    /* Self-signed? */
    status = DIGI_CMS_U_checkCertificateIssuer (pCert, certLen,
                                               pCert, certLen);
    if (OK != status)
    {
        return (ERR_CERT_INVALID_PARENT_CERTIFICATE == status) ?
                ERR_FALSE: status;
    }

    /* Get public key from own data */
    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (MOC_ASYM(hwAccelCtx) pCert, certLen,
                                                       &parentCertKey);
    if (OK != status)
        goto exit;

    /* Check that the signature verifies with the my own public key */
    status = DIGI_CMS_U_verifyCertificateSignature (MOC_ASYM(hwAccelCtx) pCert,
                                                   certLen,
                                                   &parentCertKey,
                                                   &sigFails);
    if (OK != status)
        goto exit;

    /* Check signature result */
    if (0 != sigFails)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* Validate attributes in certificate */
    status = DIGI_CMS_U_getCertificateExtensions (pCert,
                                                 certLen,
                                                 &pExtensions,
                                                 &extensionsLen);
    if (OK != status)
        goto exit;

    if ((NULL != pExtensions) &&
        (0 < extensionsLen))
    {
        /* look for the Subject Key Extension */
        status = DIGI_CMS_U_locateExtensionByOID (pExtensions,
                                                 extensionsLen,
                                                 ASN1_subjectKeyIdentifier_OID,
                                                 ASN1_subjectKeyIdentifier_OID_LEN,
                                                 &isCritical,
                                                 &pSKIExt, &SKIExtLen);
        if (OK != status)
        {
            /* None found, we're OK */
            if (ERR_NOT_FOUND == status)
            {
                status = OK;
            }
            goto exit;
        }

        /* look for the Authority Key Identifier */
        status = DIGI_CMS_U_locateExtensionByOID (pExtensions,
                                                 extensionsLen,
                                                 ASN1_authorityKeyIdentifier_OID,
                                                 ASN1_authorityKeyIdentifier_OID_LEN,
                                                 &isCritical,
                                                 &pAKIExt, &AKIExtLen);
        if (OK != status)
        {
            /* None found, we're OK */
            if (ERR_NOT_FOUND == status)
            {
                status = OK;
            }
            goto exit;
        }

        /* Parse container */
        status = MAsn1CreateElementArray (defCont, 1, MASN1_FNCT_DECODE,
                                          NULL, &pContRoot);
        if (OK != status)
            goto exit;

        status = MAsn1Decode (pSKIExt, SKIExtLen,
                              pContRoot, &bytesRead);
        if (OK != status)
            goto exit;

        /* Parse Identifier */
        status = MAsn1CreateElementArray (defAKI, 4, MASN1_FNCT_DECODE,
                                          NULL, &pAKIRoot);
        if (OK != status)
            goto exit;

        status = MAsn1Decode (pAKIExt, AKIExtLen,
                              pAKIRoot, &bytesRead);
        if (OK != status)
            goto exit;

        /* The entry 'KeyIdentifier' must exist */
        if ((NULL == pAKIRoot[idxKeyID].value.pValue) ||
            (0 == pAKIRoot[idxKeyID].valueLen))
        {
            status = ERR_FALSE;
            goto exit;
        }

        /* Both MUST match the same 'Identifier' value */
        if (pContRoot[0].valueLen != pAKIRoot[idxKeyID].valueLen)
        {
            status = ERR_FALSE;
            goto exit;
        }

        status = DIGI_MEMCMP (pAKIRoot[idxKeyID].value.pValue,
                             pContRoot[0].value.pValue,
                             pContRoot[0].valueLen,
                             &cmpResult);
        if (OK != status)
            goto exit;

        if (0 != cmpResult)
        {
            status = ERR_FALSE;
            goto exit;
        }
    }

exit:
    CRYPTO_uninitAsymmetricKey (&parentCertKey, NULL);
    MAsn1FreeElementArray (&pAKIRoot);
    MAsn1FreeElementArray (&pContRoot);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getBulkAlgo(MOC_SYM(hwAccelDescr hwAccelCtx)
                      ubyte   *pEncryptOID,
                      ubyte4  encryptOIDLen,
                      ubyte*  pEncryptIV,
                      ubyte4  encryptIVLen,
                      ubyte*  pSymmetricKey,
                      ubyte4  symmetricKeyLen,
                      ubyte*  iv,
                      BulkCtx *pBulkCtx,
                      const BulkEncryptionAlgo **ppBulkAlgo)
{
    MSTATUS status = OK;
    ubyte4  encryptionSubType;
    BulkCtx ctx = NULL;

#ifdef __ENABLE_ARC2_CIPHERS__
    sbyte4 effectiveKeyBits;
#endif

    /* Check RSA OID */
    sbyte4 cmpResult;
    status = ASN1_compareOID (RSA_EncrAlgoRoot_OID, RSA_EncrAlgoRoot_OID_LEN,
                              pEncryptOID, encryptOIDLen,
                              &encryptionSubType,
                              &cmpResult);
    if (0 == cmpResult)
    {
        switch (encryptionSubType)
        {
#ifdef __ENABLE_ARC2_CIPHERS__
        case 2: /* RC2CBC*/
            status = DIGI_CMS_U_getRC2CBCParams (pEncryptIV,
                                                encryptIVLen,
                                                &effectiveKeyBits, iv);
            if (OK != status)
                goto exit;
            *ppBulkAlgo = &CRYPTO_RC2EffectiveBitsSuite;
            /* special createFunc for RC2 that allows effective keyBits */
            ctx = CreateRC2Ctx2 (MOC_SYM(hwAccelCtx) pSymmetricKey,
                                 symmetricKeyLen, effectiveKeyBits);
            if (NULL == ctx)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
            *pBulkCtx = ctx;
            ctx = NULL;
            break;
#endif  /* __ENABLE_ARC2_CIPHERS__ */

#ifndef __DISABLE_ARC4_CIPHERS__
        case 4: /* RC4 */
            /* no parameter */
            *ppBulkAlgo = &CRYPTO_RC4Suite;
            ctx = CreateRC4Ctx (MOC_SYM(hwAccelCtx) pSymmetricKey,
                                symmetricKeyLen, 0);
            if (NULL == ctx)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
            *pBulkCtx = ctx;
            ctx = NULL;
            break;
#endif  /* __DISABLE_ARC4_CIPHERS__ */

#ifndef __DISABLE_3DES_CIPHERS__
        case 7: /* desEDE3CBC */
            /* iv OCTET STRING (SIZE(8)) */
            status = DIGI_CMS_U_getCBCParams (pEncryptIV,
                                             encryptIVLen,
                                             DES_BLOCK_SIZE, iv);
            if (OK != status)
                goto exit;
            *ppBulkAlgo = &CRYPTO_TripleDESSuite;
            ctx = Create3DESCtx (MOC_SYM(hwAccelCtx) pSymmetricKey,
                                 symmetricKeyLen, 0);
            if (NULL == ctx)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
            *pBulkCtx = ctx;
            ctx = NULL;
            break;
#endif  /* __DISABLE_3DES_CIPHERS__ */

        default:
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;
        }
    }
    else
    {
#ifndef __DISABLE_AES_CIPHERS__
        /* Check AES OID */
        status = ASN1_compareOID (AES_128CBC_OID, AES_128CBC_OID_LEN,
                                  pEncryptOID, encryptOIDLen,
                                  NULL, &cmpResult);
        if (OK != status)
            goto exit;

        if (0 != cmpResult)
        {
            status = ASN1_compareOID (AES_192CBC_OID, AES_192CBC_OID_LEN,
                                      pEncryptOID, encryptOIDLen,
                                      NULL, &cmpResult);
            if (OK != status)
                goto exit;
        }
        if (0 != cmpResult)
        {
            status = ASN1_compareOID (AES_256CBC_OID, AES_256CBC_OID_LEN,
                                      pEncryptOID, encryptOIDLen,
                                      NULL, &cmpResult);
            if (OK != status)
                goto exit;                            
        }

        if (0 == cmpResult)
        {
            /* iv OCTET STRING (SIZE(16)) */
            status = DIGI_CMS_U_getCBCParams (pEncryptIV,
                                             encryptIVLen,
                                             AES_BLOCK_SIZE, iv);
            if (OK != status)
                goto exit;
            *ppBulkAlgo = &CRYPTO_AESSuite;
            ctx = CreateAESCtx (MOC_SYM(hwAccelCtx) pSymmetricKey,
                                symmetricKeyLen, 0);
            if (NULL == ctx)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
            *pBulkCtx = ctx;
            ctx = NULL;
        }
        else
#endif  /* __DISABLE_AES_CIPHERS__ */
        /* add others here if necessary */
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;
        }
    }

exit:
    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getCryptoAlgoParams (const ubyte *encryptAlgoOID,
                               ubyte4      encryptAlgoOIDLen,
                               const BulkEncryptionAlgo** ppBulkAlgo,
                               sbyte4      *keyLength)
{
    MSTATUS status;
    sbyte4 cmpResult;

    ubyte        *pAlgo = NULL;
    ubyte4       algoLen;
    MAsn1Element *pOID = NULL;

    MAsn1TypeAndCount defAlgo[1] =
    {
        { MASN1_TYPE_OID, 0},
    };

    status = MAsn1CreateElementArray (defAlgo, 1,
                                      MASN1_FNCT_ENCODE,
                                      NULL, &pOID);
    if (OK != status)
        goto exit;

    status = MAsn1SetValue (pOID, encryptAlgoOID, encryptAlgoOIDLen);
    if (OK != status)
        goto exit;

    status = MAsn1EncodeAlloc (pOID, &pAlgo, &algoLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DES_CIPHER__
    status = ASN1_compareOID (ALGO_desCBC_OID, ALGO_desCBC_OID_LEN,
                              pAlgo, algoLen,
                              NULL, &cmpResult);
    if (0 == cmpResult)
    {
        *keyLength = DES_KEY_LENGTH;
        *ppBulkAlgo = &CRYPTO_DESSuite;
        goto exit;
    }
#endif
#ifndef __DISABLE_3DES_CIPHERS__
    status = ASN1_compareOID (ALGO_desEDE3CBC_OID, ALGO_desEDE3CBC_OID_LEN,
                              pAlgo, algoLen,
                              NULL, &cmpResult);

    if (0 == cmpResult)
    {
        *keyLength = THREE_DES_KEY_LENGTH;
        *ppBulkAlgo = &CRYPTO_TripleDESSuite;
        goto exit;
    }
#endif
#ifndef __DISABLE_AES_CIPHERS__
    status = ASN1_compareOID (AES_128CBC_OID, AES_128CBC_OID_LEN,
                              pAlgo, algoLen,
                              NULL, &cmpResult);
    if (0 == cmpResult)
    {
        *keyLength = 16;
        *ppBulkAlgo = &CRYPTO_AESSuite;
        goto exit;
    }

    status = ASN1_compareOID (AES_192CBC_OID, AES_192CBC_OID_LEN,
                              pAlgo, algoLen,
                              NULL, &cmpResult);
    if (0 == cmpResult)
    {
        *keyLength = 24;
        *ppBulkAlgo = &CRYPTO_AESSuite;
        goto exit;
    }

    status = ASN1_compareOID (AES_256CBC_OID, AES_256CBC_OID_LEN,
                              pAlgo, algoLen,
                              NULL, &cmpResult);
    if (0 == cmpResult)
    {
        *keyLength = 32;
        *ppBulkAlgo = &CRYPTO_AESSuite;
        goto exit;
    }

    /* add others here if necessary */
#endif
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
    }

exit:
    DIGI_FREE ((void**)&pAlgo);
    MAsn1FreeElementArray (&pOID);
    return OK;
}

/*-------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_processKeyAgreeRecipientInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                       MAsn1Element            *root,
                                       const void              *callbackArg,
                                       MOC_CMS_GetPrivateKey   getPrivateKeyFun,
                                       MOC_CMS_GetPrivateKeyEx getPrivateKeyFunEx,
                                       ubyte                   **ppSymmetricKey,
                                       ubyte4                  *pSymmetricKeyLen,
                                       MOC_CMS_RecipientId     ** pRec)
{
#if (defined(__ENABLE_DIGICERT_ECC__))
   MSTATUS status = OK;
   ubyte4  bytesRead;
   sbyte4  cmpResult;
   ubyte   val;

   intBoolean   hasECDHData = TRUE;

   MAsn1Element *pRootRec = NULL;
   MAsn1Element *pIssueRec = NULL;
   MAsn1Element *pSubjRec = NULL;
   MAsn1Element *pOrigRec = NULL;
   MAsn1Element *pAlgoIdRec = NULL;
   MAsn1Element *pEncrAlgo = NULL;
   MAsn1Element *pEncrKey = NULL;
   MAsn1Element *pKeyAgreeId = NULL;
   MAsn1Element *pKeyAgreeKey = NULL;
   MAsn1Element *pEncrUKM = NULL;

   MOC_CMS_IssuerSerialNumber issuerAndSerialNumber;
   AsymmetricKey       privateKey = {0};
   AsymmetricKey       ephemeralKey = {0};
   MOC_CMS_RecipientId recipientId;
   MAsn1Element        *pEncryptedKey;
   ubyte4              curveId;

   const BulkHashAlgo  *pHashAlgo = NULL;
   const ubyte         *keyWrapOID = NULL;
   ubyte4              keyWrapOIDLen;

   /* KeyAgreeRecipientInfo sequence [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount defRec[6] =
   {
      /** CHOICE[1] **/
      {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | 1 , 5},
        /* version:                 CMSVersion,  -- always set to 3 */
        {  MASN1_TYPE_INTEGER, 0},
        /* originator [0] EXPLICIT: OriginatorIdentifierOrKey */
        {  MASN1_TYPE_ENCODED | MASN1_EXPLICIT , 0},
        /* ukm [1] EXPLICIT:  UserKeyingMaterial OPTIONAL */
        {  MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_OPTIONAL | 1 , 0},
        /* keyEncryptionAlgorithm:  KeyEncryptionAlgorithmIdentifier*/
        {  MASN1_TYPE_ENCODED, 0},
        /* recipientEncryptedKeys:  RecipientEncryptedKeys */
        {  MASN1_TYPE_ENCODED, 0},
   };

   /* IssuerAndSerialNumber sequence [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount issueRec[1] =
   {
       /* IssuerAndSerialNumber */
       {  MASN1_TYPE_ENCODED , 0},
   };

   /* SubjectKeyIdentifier sequence [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount subjRec[1] =
   {
       /* [0]: SubjectKeyIdentifier */
       {  MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT , 0},
   };

   /* OriginatorIdentifierOrKey sequence [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount origRec[3] =
   {
       /* [1]: OriginatorPublicKey */
       {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | 1 , 2},
         /* AlgorithmIdentifier */
         {  MASN1_TYPE_ENCODED, 0},
         /* BIT STRING */
         {  MASN1_TYPE_BIT_STRING, 0},
   };

   /* AlgorithmIdentifier  [rfc5280 - Section 4.1.1.2, page 17] */
   MAsn1TypeAndCount defAlgoId[3] =
   {
        {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_OID, 0}, /* Should be EC-public key OID */
           {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
   };

   /* KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    * [rfc5652 - Section 10.1.3, page 34] */
   MAsn1TypeAndCount defEncrAlgo[5] =
   {
      {  MASN1_TYPE_SEQUENCE, 2},
        {  MASN1_TYPE_OID, 0}, /* curveId OID */
        {  MASN1_TYPE_SEQUENCE, 2},
          {  MASN1_TYPE_OID, 0}, /* Wrap crypto OID */
          {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0},
   };

   /* RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey */
   /* RecipientEncryptedKey sequence [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount defEncrKey[4] =
   {
      {  MASN1_TYPE_SEQUENCE, 1},
        {  MASN1_TYPE_SEQUENCE, 2},
          /* rid:          KeyAgreeRecipientIdentifier */
          {  MASN1_TYPE_ENCODED, 0},
          /* encryptedKey: EncryptedKey */
          {  MASN1_TYPE_OCTET_STRING, 0},
   };

   /* rid = CHOICE IssuerAndSerialNumber SEQ [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount defKeyAgreeId[3] =
   {
     /* SEQ: IssuerAndSerialNumber */
     {  MASN1_TYPE_SEQUENCE , 2 },
         { MASN1_TYPE_ENCODED, 0 },
         { MASN1_TYPE_INTEGER, 0 },
   };

   /* rid = CHOICE RecipientKeyIdentifier SEQ [rfc5652 - Section 6.2.2, page 22] */
   MAsn1TypeAndCount defKeyAgreeKey[4] =
   {
       /* [0]: RecipientKeyIdentifier */
       {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | 0, 3 },
         /* subjectKeyIdentifier: SubjectKeyIdentifier */
         { MASN1_TYPE_OCTET_STRING, 0 },
         /* date: GeneralizedTime */
         { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
         /* other: OtherKeyAttribute */
         { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 }
   };

   /*  UserKeyingMaterial ::= OCTET STRING */
   MAsn1TypeAndCount defUKM[1] =
   {
      {  MASN1_TYPE_OCTET_STRING, 0},
   };

   status = CRYPTO_initAsymmetricKey (&privateKey);
   if (OK != status)
       goto exit;

   status = CRYPTO_initAsymmetricKey (&ephemeralKey);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defRec, 6, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pRootRec);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (issueRec, 1, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pIssueRec);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (subjRec, 1, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pSubjRec);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (origRec, 3, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pOrigRec);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defAlgoId, 3, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pAlgoIdRec);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defEncrAlgo, 5, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pEncrAlgo);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defEncrKey, 4, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pEncrKey);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defKeyAgreeId, 3, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pKeyAgreeId);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defKeyAgreeKey, 4, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pKeyAgreeKey);
   if (OK != status)
       goto exit;

   status = MAsn1CreateElementArray (defUKM, 1, MASN1_FNCT_DECODE,
                                     &MAsn1OfFunction, &pEncrUKM);
   if (OK != status)
       goto exit;

   status = MAsn1Decode (root->encoding.pEncoding,
                         root->encodingLen,
                         pRootRec,
                         &bytesRead);
   if (OK != status)
       goto exit;

   status = ERR_PKCS7_INVALID_STRUCT;
   /* Check INTEGER: Per RFC it must have the value '3' */
   if (1 != pRootRec[1].valueLen)
   {
      goto exit;
   }

   val = pRootRec[1].value.pValue[0];
   if (3 != val)
   {
      goto exit;
   }

   /* Check OriginatorIdentifierOrKey: Per RFC it must be available */
   if ( (NULL == pRootRec[2].value.pValue) ||
           (0 == pRootRec[2].valueLen) )
   {
       goto exit;
   }

   /* Set type := MOC_CMS_KeyAgreeRecipientId */
   recipientId.type = 1;

   /* Default sub-type */
   recipientId.ri.karid.type = NO_TAG;

   /* Try 'OriginatorPublicKey' sequence (CHOICE 1), first */
   status = MAsn1Decode (pRootRec[2].value.pValue,
                         pRootRec[2].valueLen,
                         pOrigRec,
                         &bytesRead);
   if (OK == status)
   {
       /* Disable parsing of other data in this section */
       recipientId.ri.karid.type = pOrigRec[0].encoding.pEncoding[0] & 0x0f;

       status = MAsn1Decode (pOrigRec[1].value.pValue,
                             pOrigRec[1].valueLen,
                             pAlgoIdRec,
                             &bytesRead);
       if (OK != status)
           goto exit;

       /* OID data available? */
       if (0 == pAlgoIdRec[1].encodingLen)
       {
           status = ERR_PKCS7_INVALID_STRUCT;
           goto exit;
       }

       /* BIT_STRING data available? */
       if (NULL == pOrigRec[2].value.pValue)
       {
           status = ERR_PKCS7_INVALID_STRUCT;
           goto exit;
       }

       /* Check OID */
       status = ASN1_compareOID (ECC_PUBLICKEY_DATA, ECC_PUBLICKEY_DATA_LEN,
                                 pAlgoIdRec[1].encoding.pEncoding,
                                 pAlgoIdRec[1].encodingLen,
                                 NULL, &cmpResult);
       if (OK != status)
           goto exit;

       if (0 != cmpResult)
       {
           status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
           goto exit;
       }

       status = DIGI_CMS_U_getOriginatorPublicKey (pOrigRec,
                                                  &recipientId.ri.karid.u.originatorKey);
       if (OK != status)
           goto exit;
   }

   /* Try 'IssuerAndSerialNumber' SEQ, if not yet parsed */
   if (NO_TAG == recipientId.ri.karid.type)
   {
       status = MAsn1Decode (pRootRec[2].value.pValue,
                             pRootRec[2].valueLen,
                             pIssueRec,
                             &bytesRead);
       if (OK == status)
       {
           recipientId.ri.karid.type = pIssueRec[0].encoding.pEncoding[0] & 0x0f;

           status = DIGI_CMS_U_getIssuerSerialNumber (pIssueRec,
                                                     &issuerAndSerialNumber);
           if (OK != status)
               goto exit;
       }
   }

   /* Try 'SubjectKeyIdentifier' choice [0], if not yet parsed*/
   if (NO_TAG == recipientId.ri.karid.type)
   {
       status = MAsn1Decode (pRootRec[2].value.pValue,
                             pRootRec[2].valueLen,
                             pSubjRec,
                             &bytesRead);
       if (OK == status)
       {
           status = DIGI_CMS_U_getIssuerSerialNumber (pSubjRec,
                                                     &issuerAndSerialNumber);
           if (OK != status)
           {
               status = ERR_PKCS7_INVALID_STRUCT;
               goto exit;
           }
       }
   }


   /* Read 'KeyEncryptionAlgorithmIdentifier' */
   if (0 >= pRootRec[4].encodingLen)
   {
      status = ERR_PKCS7_INVALID_STRUCT;
      goto exit;
   }

   status = MAsn1Decode (pRootRec[4].value.pValue,
                         pRootRec[4].valueLen,
                         pEncrAlgo,
                         &bytesRead);
   if (OK != status)
       goto exit;

   /* Read 'RecipientEncryptedKeys' */
   if (0 >= pRootRec[5].encodingLen)
   {
      status = ERR_PKCS7_INVALID_STRUCT;
      goto exit;
   }

   status = MAsn1Decode (pRootRec[5].value.pValue,
                         pRootRec[5].valueLen,
                         pEncrKey,
                         &bytesRead);
   if (OK != status)
       goto exit;

   pEncryptedKey = pEncrKey+3;

   /* Set type := MOC_CMS_KeyAgreeRecipientId */
   recipientId.type = 1;

   if ((NULL != getPrivateKeyFun) &&
       (NO_TAG == recipientId.ri.karid.type))
   {
       status = (*getPrivateKeyFun) (callbackArg,
                                     issuerAndSerialNumber.pSerialNumber,
                                     issuerAndSerialNumber.serialNumberLen,
                                     issuerAndSerialNumber.pIssuer,
                                     issuerAndSerialNumber.issuerLen,
                                     &privateKey);
      if (OK != status)
         goto exit;
   }
   else if (NULL != getPrivateKeyFunEx)
   {
       /* Try CHOICE SEQ as 'IssuerAndSerialNumber' */
       status = MAsn1Decode (pEncrKey[2].value.pValue,
                             pEncrKey[2].valueLen,
                             pKeyAgreeId,
                             &bytesRead);
       if (OK == status)
       {
           /* Found use of 'issuer' as 'KeyAgreeRecipientIdentifier' */
           if (NULL != getPrivateKeyFun)
           {
               issuerAndSerialNumber.pIssuer = pKeyAgreeId[1].value.pValue;
               issuerAndSerialNumber.issuerLen = pKeyAgreeId[1].valueLen;
               issuerAndSerialNumber.pSerialNumber = pKeyAgreeId[2].value.pValue;
               issuerAndSerialNumber.serialNumberLen = pKeyAgreeId[2].valueLen;

               status = (*getPrivateKeyFun) (callbackArg,
                                             issuerAndSerialNumber.pSerialNumber,
                                             issuerAndSerialNumber.serialNumberLen,
                                             issuerAndSerialNumber.pIssuer,
                                             issuerAndSerialNumber.issuerLen,
                                             &privateKey);
           }
           else
           {
               status = ERR_FALSE;
           }
       }

       if (OK != status)
       {
           /* Try CHOICE SEQ as 'RecipientKeyIdentifier' */
           status = MAsn1Decode (pEncrKey[2].value.pValue,
                                 pEncrKey[2].valueLen,
                                 pKeyAgreeKey,
                                 &bytesRead);
           if (OK == status)
           {
               recipientId.ri.karid.type = pKeyAgreeKey[0].encoding.pEncoding[0] & 0x0f;

               recipientId.ri.karid.u.subjectKeyIdentifier.pIdentifier = pKeyAgreeKey[1].value.pValue;
               recipientId.ri.karid.u.subjectKeyIdentifier.identifierLen = pKeyAgreeKey[1].valueLen;

               /* Use recipient id to obtain private key */
               status = (*getPrivateKeyFunEx) (callbackArg,
                                               &recipientId,
                                               &privateKey);
           }

           if (OK != status)
           {
               status = ERR_FALSE;
               goto exit;
           }
       }
   }
   else
   {
       status = ERR_PKCS7_WRONG_CALLBACK;
       goto exit;
   }

   if (((akt_ecc != privateKey.type) && (akt_tap_ecc != privateKey.type)) ||
       (FALSE == privateKey.key.pECC->privateKey))
   {
      status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
      goto exit;
   }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(
        privateKey.key.pECC, &curveId);
#else
    status = EC_getCurveIdFromKey(privateKey.key.pECC, &curveId);
#endif
    if (OK != status)
        goto exit;

   status = CRYPTO_setECCParameters (MOC_ECC(hwAccelCtx) &ephemeralKey,
                                     curveId,
                                     pOrigRec[2].value.pValue+1,
                                     pOrigRec[2].valueLen-1,
                                     NULL,
                                     0);
   if (OK != status)
      goto exit;

   /* Select hash algorithm from OID */
   status = ASN1_compareOID (ASN1_dhSinglePassStdDHSha1KDF_OID,
                             ASN1_dhSinglePassStdDHSha1KDF_OID_LEN,
                             pEncrAlgo[1].encoding.pEncoding,
                             pEncrAlgo[1].encodingLen,
                             NULL,
                             &cmpResult);

   if ((OK == status) &&
       (0 == cmpResult))
   {
       status = CRYPTO_getRSAHashAlgo (ht_sha1, &pHashAlgo);
       if (OK != status)
          goto exit;
   }

#ifndef __DISABLE_DIGICERT_ECC_P224__
   if (NULL == pHashAlgo)
   {
       /* Select hash algorithm from OID */
       status = ASN1_compareOID (ASN1_dhSinglePassStdDHSha224KDF_OID,
                                 ASN1_dhSinglePassStdDHSha224KDF_OID_LEN,
                                 pEncrAlgo[1].encoding.pEncoding,
                                 pEncrAlgo[1].encodingLen,
                                 NULL,
                                 &cmpResult);

       if ((OK == status) &&
           (0 == cmpResult))
       {
           status = CRYPTO_getRSAHashAlgo (ht_sha224, &pHashAlgo);
           if (OK != status)
              goto exit;
       }
   }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
   if (NULL == pHashAlgo)
   {
       /* Select hash algorithm from OID */
       status = ASN1_compareOID (ASN1_dhSinglePassStdDHSha256KDF_OID,
                                 ASN1_dhSinglePassStdDHSha256KDF_OID_LEN,
                                 pEncrAlgo[1].encoding.pEncoding,
                                 pEncrAlgo[1].encodingLen,
                                 NULL,
                                 &cmpResult);

       if ((OK == status) &&
           (0 == cmpResult))
       {
           status = CRYPTO_getRSAHashAlgo (ht_sha256, &pHashAlgo);
           if (OK != status)
              goto exit;
       }
   }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
   if (NULL == pHashAlgo)
   {
       /* Select hash algorithm from OID */
       status = ASN1_compareOID (ASN1_dhSinglePassStdDHSha384KDF_OID,
                                 ASN1_dhSinglePassStdDHSha384KDF_OID_LEN,
                                 pEncrAlgo[1].encoding.pEncoding,
                                 pEncrAlgo[1].encodingLen,
                                 NULL,
                                 &cmpResult);

       if ((OK == status) &&
           (0 == cmpResult))
       {
           status = CRYPTO_getRSAHashAlgo (ht_sha384, &pHashAlgo);
           if (OK != status)
              goto exit;
       }
   }
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
   if (NULL == pHashAlgo)
   {
       /* Select hash algorithm from OID */
       status = ASN1_compareOID (ASN1_dhSinglePassStdDHSha512KDF_OID,
                                 ASN1_dhSinglePassStdDHSha512KDF_OID_LEN,
                                 pEncrAlgo[1].encoding.pEncoding,
                                 pEncrAlgo[1].encodingLen,
                                 NULL,
                                 &cmpResult);

       if ((OK == status) &&
           (0 == cmpResult))
       {
           status = CRYPTO_getRSAHashAlgo (ht_sha512, &pHashAlgo);
           if (OK != status)
              goto exit;
       }
   }
#endif

   if (NULL == pHashAlgo)
   {
       status = ERR_PKCS7_UNSUPPORTED_KDF;
       goto exit;
   }

#ifndef __DISABLE_AES_CIPHERS__
   /* Select AES key wrap size from OID */
   status = ASN1_compareOID (ASN1_aes128Wrap_OID,
                             ASN1_aes128Wrap_OID_LEN,
                             pEncrAlgo[3].encoding.pEncoding,
                             pEncrAlgo[3].encodingLen,
                             NULL,
                             &cmpResult);

   if ((OK == status) &&
       (0 == cmpResult))
   {
       keyWrapOID = ASN1_aes128Wrap_OID;
       keyWrapOIDLen = ASN1_aes128Wrap_OID_LEN;
   }

   if (NULL == keyWrapOID)
   {
       status = ASN1_compareOID (ASN1_aes192Wrap_OID,
                                 ASN1_aes192Wrap_OID_LEN,
                                 pEncrAlgo[3].encoding.pEncoding,
                                 pEncrAlgo[3].encodingLen,
                                 NULL,
                                 &cmpResult);

       if ((OK == status) &&
           (0 == cmpResult))
       {
           keyWrapOID = ASN1_aes192Wrap_OID;
           keyWrapOIDLen = ASN1_aes192Wrap_OID_LEN;
       }
   }

   if (NULL == keyWrapOID)
   {
       status = ASN1_compareOID (ASN1_aes256Wrap_OID,
                                 ASN1_aes256Wrap_OID_LEN,
                                 pEncrAlgo[3].encoding.pEncoding,
                                 pEncrAlgo[3].encodingLen,
                                 NULL,
                                 &cmpResult);

       if ((OK == status) &&
           (0 == cmpResult))
       {
           keyWrapOID = ASN1_aes256Wrap_OID;
           keyWrapOIDLen = ASN1_aes256Wrap_OID_LEN;
       }
   }
#endif  /* __DISABLE_AES_CIPHERS__ */

   if (NULL == keyWrapOID)
   {
       status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
       goto  exit;
   }

   /* Get UKM data if available */
   if ( (NULL != pRootRec[3].value.pValue) &&
        (0 != pRootRec[3].valueLen) )
   {
       status = MAsn1Decode (pRootRec[3].value.pValue,
                             pRootRec[3].valueLen,
                             pEncrUKM,
                             &bytesRead);
       if (OK != status)
          goto exit;
   }

   /* Check if ECDH info's AlgorithmIdentifier should have data after OID */
   if (0 == pEncrAlgo[4].encodingLen)
   {
       hasECDHData = FALSE;
   }

   status = DIGI_CMS_U_decryptECCKey (MOC_HW(hwAccelCtx)
                                     pHashAlgo,
                                     ephemeralKey.key.pECC,
                                     privateKey.key.pECC,
                                     keyWrapOID, keyWrapOIDLen,
                                     hasECDHData,
                                     pEncrUKM[0].value.pValue,
                                     pEncrUKM[0].valueLen,
                                     pEncryptedKey->value.pValue,
                                     pEncryptedKey->valueLen,
                                     ppSymmetricKey, pSymmetricKeyLen);
   if (OK != status)
      goto exit;

   /* Return recipient data, if requested */
   if (pRec != NULL)
   {
       status = DIGI_MALLOC ((void**)pRec,
                            sizeof (MOC_CMS_RecipientId));
       if (OK != status)
          goto exit;

       status = DIGI_MEMCPY (*pRec, &recipientId,
                            sizeof (MOC_CMS_RecipientId));
       if (OK != status)
          goto exit;
   }

exit:
   CRYPTO_uninitAsymmetricKey (&privateKey, (vlong**)NULL);
   CRYPTO_uninitAsymmetricKey (&ephemeralKey, (vlong**)NULL);

   MAsn1FreeElementArray (&pEncrUKM);
   MAsn1FreeElementArray (&pKeyAgreeId);
   MAsn1FreeElementArray (&pKeyAgreeKey);
   MAsn1FreeElementArray (&pEncrAlgo);
   MAsn1FreeElementArray (&pEncrKey);
   MAsn1FreeElementArray (&pAlgoIdRec);
   MAsn1FreeElementArray (&pOrigRec);
   MAsn1FreeElementArray (&pSubjRec);
   MAsn1FreeElementArray (&pIssueRec);
   MAsn1FreeElementArray (&pRootRec);
   return status;

#else  /* __ENABLE_DIGICERT_ECC__ */

   return ERR_UNSUPPORTED_OPERATION;

#endif
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_processKeyTransRecipientInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                       MAsn1Element            *pRoot,
                                       const void              *callbackArg,
                                       MOC_CMS_GetPrivateKey   getPrivateKeyFun,
                                       MOC_CMS_GetPrivateKeyEx getPrivateKeyFunEx,
                                       ubyte                   **ppSymmetricKey,
                                       ubyte4                  *pSymmetricKeyLen,
                                       MOC_CMS_RecipientId     **pRec)
{
    MSTATUS status;

#if (!defined(__DISABLE_DIGICERT_RSA__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)) && \
      defined(__ENABLE_DIGICERT_PKCS1__)
    MAsn1Element *pOaepParams = NULL;
#endif
    MAsn1Element    *pRootRec = NULL;
    ubyte           *pSymmetricKey = NULL;

    AsymmetricKey   asymmetricKey;
    MOC_CMS_RecipientId  recipientId;
    MOC_CMS_IssuerSerialNumber issuerAndSerialNumber = {0};
    ubyte4          bytesRead;
    ubyte           val;
    ubyte           *pCipherText;
    sbyte4          cipherMaxLen;
    sbyte4          cmp;
    RSAKey          *pRSAKey = NULL;

    /* KeyTransRecipientInfo [rfc5652 - Section 6.2.1, page 21]*/
    MAsn1TypeAndCount defRec[10] =
    {
      /* No CHOICE [x] */
      { MASN1_TYPE_SEQUENCE, 5 },
        /* version:                   CMSVersion,  -- always set to 0 or 2 */
        { MASN1_TYPE_INTEGER, 0 },

        /* rid:                       RecipientIdentifier */
        /** CHOICE -
         * IssuerAndSerialNumber
         * [0]: SubjectKeyIdentifier **/

        /* IssuerAndSerialNumber */
        {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL , 2 },
          { MASN1_TYPE_ENCODED, 0 },
          { MASN1_TYPE_INTEGER, 0 },
        /* SubjectKeyIdentifier */
        {  MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 0 , 0 },

        /* keyEncryptionAlgorithm:    KeyEncryptionAlgorithmIdentifier */
        {  MASN1_TYPE_SEQUENCE, 2 },
          /* AlgorithmIdentifier */
          {  MASN1_TYPE_OID, 0 },
          {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },

        /* encryptedKey:              EncryptedKey */
        {  MASN1_TYPE_OCTET_STRING, 0 }
    };
    ubyte2  idxVersion = 1;
    ubyte2  idxIssuer = 3;
    ubyte2  idxSerial = 4;
    ubyte2  idxSKI = 5;
    ubyte2  idxOID = 7;
    ubyte2  idxEK = 9;

    status = CRYPTO_initAsymmetricKey (&asymmetricKey);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defRec, 10, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootRec);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pRoot->encoding.pEncoding, pRoot->encodingLen,
                          pRootRec, &bytesRead);
    if (OK != status)
        goto exit;

    /* Check INTEGER */
    status = ERR_PKCS7_INVALID_STRUCT;
    /* Per RFC the integer value must be '0' or '2' (length is 1) */
    if (1 != pRootRec[idxVersion].valueLen)
    {
       goto exit;
    }

    val = pRootRec[idxVersion].value.pValue[0];
    if ((0 != val) &&
        (2 != val))
    {
       goto exit;
    }

    /* Set type := MOC_CMS_KeyTransRecipientId */
    recipientId.type = NO_TAG;

    status = OK;
    if (0 == val)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        if (VERBOSE_DEBUG)
        {
            DEBUG_CONSOLE_printf("DIGI_CMS_U_processKeyTransRecipientInfo: Using issuer name/serial\n");
        }
#endif
        /* IssuerAndSerialNumber in 'rid' */
        issuerAndSerialNumber.pIssuer = pRootRec[idxIssuer].value.pValue;
        issuerAndSerialNumber.issuerLen = pRootRec[idxIssuer].valueLen;
        issuerAndSerialNumber.pSerialNumber = pRootRec[idxSerial].value.pValue;
        issuerAndSerialNumber.serialNumberLen = pRootRec[idxSerial].valueLen;

        recipientId.ri.ktrid.u.issuerAndSerialNumber = issuerAndSerialNumber;
        recipientId.ri.ktrid.type = NO_TAG;
    }
    else if (2 == val)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        if (VERBOSE_DEBUG)
        {
            DEBUG_CONSOLE_printf("DIGI_CMS_U_processKeyTransRecipientInfo: Using subjectKey\n");
        }
#endif
        /* SubjectKeyIdentifier in 'rid' */
        recipientId.ri.ktrid.u.subjectKeyIdentifier.pIdentifier = pRootRec[idxSKI].value.pValue;
        recipientId.ri.ktrid.u.subjectKeyIdentifier.identifierLen = pRootRec[idxSKI].valueLen;
        recipientId.ri.ktrid.type = 0;
    }

    if ((NULL != getPrivateKeyFun) &&
        (NO_TAG == recipientId.ri.karid.type))
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        if (VERBOSE_DEBUG)
        {
            DEBUG_CONSOLE_printf("DIGI_CMS_U_processKeyTransRecipientInfo: Calling 'privateKeyFun'\n");
        }
#endif
        status = (*getPrivateKeyFun) (callbackArg,
                                      issuerAndSerialNumber.pSerialNumber,
                                      issuerAndSerialNumber.serialNumberLen,
                                      issuerAndSerialNumber.pIssuer,
                                      issuerAndSerialNumber.issuerLen,
                                      &asymmetricKey);
       if (OK != status)
          goto exit;
    }
    else if (NULL != getPrivateKeyFunEx)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        if (VERBOSE_DEBUG)
        {
            DEBUG_CONSOLE_printf("DIGI_CMS_U_processKeyTransRecipientInfo: Calling 'privateKeyFunEx'\n");
        }
#endif
        status = (*getPrivateKeyFunEx) (callbackArg,
                                        &recipientId,
                                        &asymmetricKey);
        if (OK != status)
        {
            status = ERR_FALSE;
            goto exit;
        }
    }
    else
    {
        status = ERR_PKCS7_WRONG_CALLBACK;
        goto exit;
    }

    /* We need an RSA key */
    if ( (akt_rsa != asymmetricKey.type) && (akt_tap_rsa != asymmetricKey.type) )
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    pRSAKey = asymmetricKey.key.pRSA;

    pCipherText  = pRootRec[idxEK].value.pValue;
    cipherMaxLen = pRootRec[idxEK].valueLen;

    if (NULL != pRSAKey)
    {
        /* Check which encryption algorithm is used */
#if (!defined(__DISABLE_DIGICERT_RSA__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))
#if !defined(__DISABLE_DIGICERT_CMS_RSA_PKCS15_DECRYPT__)
        if ((RSA_ENCRYPTION_OID_LEN - 2 == pRootRec[idxOID].valueLen) &&
            (OK == DIGI_MEMCMP(RSA_ENCRYPTION_OID + 2, pRootRec[idxOID].value.pValue, RSA_ENCRYPTION_OID_LEN - 2, &cmp)) &&
            (0 == cmp))
        {
            status = DIGI_MALLOC ((void **)&pSymmetricKey, cipherMaxLen);
            if (OK != status)
                goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_decryptAux (MOC_RSA (0)
                                                    pRSAKey,
                                                    pCipherText,
                                                    pSymmetricKey,
                                                    pSymmetricKeyLen,
                                                    NULL, 0, NULL);
#else
            status = RSA_decrypt (MOC_RSA (0)
                                pRSAKey,
                                pCipherText,
                                pSymmetricKey,
                                pSymmetricKeyLen,
                                NULL, 0, NULL);
#endif
        }
        else
#endif
#if defined(__ENABLE_DIGICERT_PKCS1__)
        if ((RSAES_OAEP_OID_LEN - 2 == pRootRec[idxOID].valueLen) &&
                (OK == DIGI_MEMCMP(RSAES_OAEP_OID + 2, pRootRec[idxOID].value.pValue, RSAES_OAEP_OID_LEN - 2, &cmp)) &&
                (0 == cmp))
        {
            /* Set defaults for OAEP - based on RFC 3560 section 3 */
            ubyte hashAlgo = ht_sha1;
            ubyte mgfType = MOC_PKCS1_ALG_MGF1;
            ubyte mgfHashAlgo = ht_sha1;
            ubyte *pLabel = NULL;
            ubyte4 labelLen = 0;
            ubyte4 hashArg;

            MAsn1TypeAndCount oaepParams[] = {
                { MASN1_TYPE_SEQUENCE, 3 },
                    {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL | MASN1_EXPLICIT, 1 },
                        /* AlgorithmIdentifier - hashAlgorithm */
                        {  MASN1_TYPE_OID, 0 },
                    {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL | MASN1_EXPLICIT | 1, 2 },
                        /* AlgorithmIdentifier - maskGenAlgorithm */
                        {  MASN1_TYPE_OID, 0 },
                        {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL, 1 },
                            /* AlgorithmIdentifier - hashAlgorithm */
                            {  MASN1_TYPE_OID, 0 },
                    {  MASN1_TYPE_SEQUENCE | MASN1_OPTIONAL | MASN1_EXPLICIT | 2, 2 },
                        /* AlgorithmIdentifier - pSourceAlgorithm */
                        {  MASN1_TYPE_OID, 0 },
                        {  MASN1_TYPE_OCTET_STRING, 0 }
            };

            status = MAsn1CreateElementArray(oaepParams, 10,
                                             MASN1_FNCT_DECODE,
                                             &MAsn1OfFunction, &pOaepParams);
            if (OK != status)
            {
                goto exit;
            }

            status = MAsn1Decode(pRootRec[idxOID+1].value.pValue,
                                 pRootRec[idxOID+1].valueLen,
                                 pOaepParams, &bytesRead);
            if (OK != status)
            {
                goto exit;
            }

            /* Check for hashAlgorithm */
            if (NULL != pOaepParams[2].value.pValue)
            {
                status = DIGI_CMS_U_getSignerAlgorithmHashType(pOaepParams[2].value.pValue,
                                                              pOaepParams[2].valueLen,
                                                              &hashArg);
                if (OK != status)
                {
                    goto exit;
                }

                hashAlgo = (ubyte) hashArg;
            }

            /* Check for maskGenAlgorithm */
            if (NULL != pOaepParams[4].value.pValue)
            {
                /* Only MGF1 is supported */
                if ((pOaepParams[4].valueLen == PKCS1MGF_OID_LEN - 2) &&
                    (OK == DIGI_MEMCMP(pOaepParams[4].value.pValue, PKCS1MGF_OID + 2, PKCS1MGF_OID_LEN - 2, &cmp)) &&
                    (0 == cmp))
                {
                    if (NULL != pOaepParams[6].value.pValue)
                    {
                        status = DIGI_CMS_U_getSignerAlgorithmHashType(pOaepParams[6].value.pValue,
                                                                      pOaepParams[6].valueLen,
                                                                      &hashArg);
                        if (OK != status)
                        {
                            goto exit;
                        }

                        mgfHashAlgo = (ubyte) hashArg;
                    }
                }
                else
                {
                    status = ERR_ASN_UNSUPPORTED_ALG_ID;
                    goto exit;
                }
            }

            /* Check for pSourceAlgorithm */
            if (NULL != pOaepParams[8].value.pValue)
            {
                if ((pOaepParams[8].valueLen == PSPECIFIED_OID_LEN - 2) &&
                    (OK == DIGI_MEMCMP(pOaepParams[8].value.pValue, PSPECIFIED_OID + 2, PSPECIFIED_OID_LEN - 2, &cmp)) &&
                    (0 == cmp))
                {
                    pLabel = pOaepParams[9].value.pValue;
                    labelLen = pOaepParams[9].valueLen;
                }
                else
                {
                    status = ERR_ASN_UNSUPPORTED_ALG_ID;
                    goto exit;
                }
            }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(MOC_RSA(hwAccelCtx) pRSAKey,
                                                           hashAlgo,
                                                           mgfType,
                                                           mgfHashAlgo,
                                                           pCipherText,
                                                           cipherMaxLen,
                                                           pLabel, labelLen,
                                                           &pSymmetricKey,
                                                           pSymmetricKeyLen);
#else
            status = PKCS1_rsaOaepDecrypt(MOC_RSA(hwAccelCtx) pRSAKey,
                                          hashAlgo,
                                          mgfType,
                                          mgfHashAlgo,
                                          pCipherText,
                                          cipherMaxLen,
                                          pLabel, labelLen,
                                          &pSymmetricKey, pSymmetricKeyLen);
#endif
        }
        else
#endif
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        }
        if (OK != status)
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }

    /* copy result */
    *ppSymmetricKey = pSymmetricKey;
    pSymmetricKey = NULL;

    /* Return recipient data, if requested */
    if (NULL != pRec)
    {
        status = DIGI_MALLOC ((void**)pRec,
                             sizeof (MOC_CMS_RecipientId));
        if (OK != status)
           goto exit;

        status = DIGI_MEMCPY (*pRec, &recipientId,
                             sizeof (MOC_CMS_RecipientId));
        if (OK != status)
           goto exit;
    }

exit:
    if (NULL != pSymmetricKey)
    {
        DIGI_FREE ((void **)&pSymmetricKey);
    }
#if (!defined(__DISABLE_DIGICERT_RSA__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)) && \
      defined(__ENABLE_DIGICERT_PKCS1__)
    if (NULL != pOaepParams)
    {
        MAsn1FreeElementArray (&pOaepParams);
    }
#endif
    CRYPTO_uninitAsymmetricKey (&asymmetricKey, (vlong**)NULL);
    MAsn1FreeElementArray (&pRootRec);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getIssuerSerialNumber(MAsn1Element               *pIssuerSerialNumber,
                                MOC_CMS_IssuerSerialNumber *pISN)
{
    MSTATUS status = OK;
    ubyte4  bytesRead;

    MAsn1Element *pRootSerialNo = NULL;

    MAsn1TypeAndCount defSerialNo[4] =
    {
        {   MASN1_TYPE_SEQUENCE, 1}, /** SEQUENCE **/
          {   MASN1_TYPE_SEQUENCE, 2}, /** IssuerAndSerialNumber **/
            {   MASN1_TYPE_ENCODED, 0}, /* Name */
            {   MASN1_TYPE_ENCODED, 0}, /* CertificateSerialNumber */
    };

    status = MAsn1CreateElementArray (defSerialNo, 4, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootSerialNo);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pIssuerSerialNumber->encoding.pEncoding,
                          pIssuerSerialNumber->encodingLen,
                          pRootSerialNo,
                          &bytesRead);
    if (OK != status)
        goto exit;

    if (NULL == pRootSerialNo[1].encoding.pEncoding)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }
    if (NULL == pRootSerialNo[2].encoding.pEncoding)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    pISN->pIssuer = pRootSerialNo[1].value.pValue;
    pISN->issuerLen = pRootSerialNo[1].valueLen;
    pISN->pSerialNumber = pRootSerialNo[2].value.pValue;
    pISN->serialNumberLen = pRootSerialNo[2].valueLen;

exit:
    MAsn1FreeElementArray (&pRootSerialNo);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_getOriginatorPublicKey(MAsn1Element                *pRoot,
                                 MOC_CMS_OriginatorPublicKey *pOriginatorKey)
{
    MSTATUS status = OK;
    ubyte4  bytesRead;

    MAsn1Element *pAlgoIdRec = NULL;

    /* AlgorithmIdentifier  [rfc5280 - Section 4.1.1.2, page 17] */
    MAsn1TypeAndCount defAlgoId[3] =
    {
         {  MASN1_TYPE_SEQUENCE, 2},
            {  MASN1_TYPE_OID, 0},
            {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
    };

    status = MAsn1CreateElementArray (defAlgoId, 3, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pAlgoIdRec);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pRoot[1].value.pValue,
                          pRoot[1].valueLen,
                          pAlgoIdRec,
                          &bytesRead);
    if (OK != status)
        goto exit;

    pOriginatorKey->pAlgoOID = pAlgoIdRec[1].value.pValue;
    pOriginatorKey->algoOIDLen = pAlgoIdRec[1].valueLen;
    pOriginatorKey->pAlgoParameters = pAlgoIdRec[2].value.pValue;
    pOriginatorKey->algoParametersLen = pAlgoIdRec[2].valueLen;
    pOriginatorKey->pPublicKey = pRoot[2].value.pValue;
    pOriginatorKey->publicKeyLen = pRoot[2].valueLen;

exit:
    MAsn1FreeElementArray(&pAlgoIdRec);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setIssuerSerialNumber(MOC_CMS_ASN1_Memory        *pMem,
                                MOC_CMS_IssuerSerialNumber *pISN,
                                MAsn1Element               *pIssuerSerialNumber)
{
    MSTATUS status;
    ubyte*  pData = NULL;
    ubyte4  dataLen;

    MAsn1Element *pRootSerialNo = NULL;

    MAsn1TypeAndCount defSerialNo[3] =
    {
       {   MASN1_TYPE_SEQUENCE, 2}, /** IssuerAndSerialNumber **/
          {   MASN1_TYPE_ENCODED, 0}, /* Name */
          {   MASN1_TYPE_INTEGER, 0}, /* CertificateSerialNumber */
    };

    status = MAsn1CreateElementArray (defSerialNo, 3, MASN1_FNCT_ENCODE,
                                      NULL, &pRootSerialNo);
    if (OK != status)
        goto exit;

    /* Set Name */
    status = MAsn1SetEncoded (pRootSerialNo + 1,
                              pISN->pIssuer, pISN->issuerLen);
    if (OK != status)
        goto exit;

    /* Set Serial number */
    status = MAsn1SetInteger (pRootSerialNo + 2,
                              pISN->pSerialNumber, pISN->serialNumberLen,
                              TRUE, 0);
    if (OK != status)
        goto exit;

    /* Try encoding */
    status = MAsn1EncodeAlloc (pRootSerialNo, &pData, &dataLen);
    if (OK != status)
        goto exit;

    /* Set value when success */
    status = MAsn1SetEncoded (pIssuerSerialNumber,
                              pData, dataLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pData);
    if (OK != status)
        goto exit;

    /* Output MAsn1Element instance owns data when success */
    pData = NULL;

exit:
    /* Error clean up */
    if (NULL != pData)
    {
        DIGI_FREE ((void**)&pData);
    }
    MAsn1FreeElementArray (&pRootSerialNo);
    return status;
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_U_setSubjectKeyIdentifier(MOC_CMS_ASN1_Memory *pMem,
                                  ubyte *pSKI,
                                  ubyte4 skiLen,
                                  MAsn1Element *pSKIelement)
{
    MSTATUS status;
    ubyte*  pData = NULL;
    ubyte4  dataLen;

    MAsn1Element *pRootSKI = NULL;

    MAsn1TypeAndCount defSKI[1] =
    {
       { MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT , 0}, /** subjectKeyIdentifier **/
    };

    status = MAsn1CreateElementArray (defSKI, 1, MASN1_FNCT_ENCODE,
                                      NULL, &pRootSKI);
    if (OK != status)
        goto exit;

    /* Set SKI */
    status = MAsn1SetValue (pRootSKI, pSKI, skiLen);
    if (OK != status)
        goto exit;

    /* Try encoding */
    status = MAsn1EncodeAlloc (pRootSKI, &pData, &dataLen);
    if (OK != status)
        goto exit;

    /* Set value when success */
    status = MAsn1SetEncoded (pSKIelement,
                              pData, dataLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pData);
    if (OK != status)
        goto exit;

    /* Output MAsn1Element instance owns data when success */
    pData = NULL;

exit:
    /* Error clean up */
    if (NULL != pData)
    {
        DIGI_FREE ((void**)&pData);
    }
    MAsn1FreeElementArray (&pRootSKI);
    return status;
}

/*----------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_ECC__))

static MSTATUS
DIGI_CMS_U_decryptECCKey(MOC_HW(hwAccelDescr hwAccelCtx)
                        const BulkHashAlgo *pHashAlgo,
                        ECCKey             *pPublicECCKey,
                        ECCKey             *pPrivateECCKey,
                        const ubyte        *keyWrapOID,
                        ubyte4             keyWrapOIDLen,
                        intBoolean         hasECDHData,
                        ubyte              *ukmData,
                        ubyte4             ukmDataLen,
                        const ubyte        *encryptedKey,
                        ubyte4             encryptedKeyLen,
                        ubyte              **cek,
                        ubyte4             *cekLen)
{
    MSTATUS status = OK;
    sbyte4  cmpResult;
    ubyte   *kek = 0;
    ubyte   *unwrappedKey = 0;
    ubyte4  wrapKeyLength = MAX_ENC_KEY_LENGTH; /* 32 <- aes256 wrap algo */

    status = ASN1_compareOID (keyWrapOID, keyWrapOIDLen,
                              ASN1_aes192Wrap_OID, ASN1_aes192Wrap_OID_LEN,
                              NULL, &cmpResult);
    if (0 == cmpResult)
    {
        wrapKeyLength = 24;
    }
    else
    {
        status = ASN1_compareOID (keyWrapOID, keyWrapOIDLen,
                                  ASN1_aes128Wrap_OID, ASN1_aes128Wrap_OID_LEN,
                                  NULL, &cmpResult);
        if (0 == cmpResult)
        {
            wrapKeyLength = 16;
        }
    }

    *cekLen = encryptedKeyLen - 8;
    status = DIGI_CMS_U_generateECCKeyEncryptionKey (MOC_ECC(hwAccelCtx)
                                                    pHashAlgo,
                                                    pPublicECCKey, pPrivateECCKey,
                                                    keyWrapOID, keyWrapOIDLen,
                                                    hasECDHData,
                                                    ukmData, ukmDataLen,
                                                    wrapKeyLength, &kek);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC ((void**)&unwrappedKey, *cekLen);
    if (OK != status)
        goto exit;

    status = AESKWRAP_decrypt (MOC_SYM(hwAccelCtx) kek,
                               wrapKeyLength,
                               encryptedKey, encryptedKeyLen,
                               unwrappedKey);
    if (OK != status)
        goto exit;

    *cek = unwrappedKey;
    unwrappedKey = 0;

exit:
    if (NULL != unwrappedKey)
    {
        DIGI_FREE ((void**)&unwrappedKey);
    }
    if (NULL != kek)
    {
        DIGI_FREE ((void**)&kek);
    }

    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_encryptECCKey(MOC_HW(hwAccelDescr hwAccelCtx)
                        const BulkHashAlgo *pHashAlgo,
                        ECCKey             *pPublicECCKey,
                        ECCKey             *pPrivateECCKey,
                        const ubyte        *keyWrapOID,
                        ubyte4             keyWrapOIDLen,
                        const ubyte        *ukmData,
                        ubyte4             ukmDataLen,
                        const ubyte        *cek,
                        ubyte4             cekLen,
                        ubyte              **encryptedKey,
                        ubyte4             *encryptedKeyLen)
{
    MSTATUS status;

    ubyte *kek = NULL;
    ubyte *wrappedKey = NULL;

    status = DIGI_CMS_U_generateECCKeyEncryptionKey (MOC_ECC(hwAccelCtx)
                                                    pHashAlgo,
                                                    pPublicECCKey, pPrivateECCKey,
                                                    keyWrapOID, keyWrapOIDLen,
                                                    TRUE,
                                                    ukmData, ukmDataLen,
                                                    cekLen, &kek);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC ((void**)&wrappedKey, cekLen + 8);
    if (OK != status)
        goto exit;

    status = AESKWRAP_encrypt (MOC_SYM(hwAccelCtx) kek, cekLen,
                               cek, cekLen, wrappedKey);
    if (OK != status)
        goto exit;

    /* Success */
    *encryptedKey = wrappedKey;
    *encryptedKeyLen = cekLen + 8;
    wrappedKey = NULL;

exit:
    /* Error clean up */
    if (NULL != wrappedKey)
    {
        DIGI_FREE((void**)&wrappedKey);
    }
    DIGI_FREE ((void**)&kek);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_generateECCKeyEncryptionKey(MOC_ECC(hwAccelDescr hwAccelCtx)
                                      const BulkHashAlgo *pHashAlgo,
                                      ECCKey             *pPublicECCKey,
                                      ECCKey             *pPrivateECCKey,
                                      const ubyte        *keyWrapOID,
                                      ubyte4             keyWrapOIDLen,
                                      intBoolean         hasECDHData,
                                      const ubyte        *ukmData,
                                      ubyte4             ukmDataLen,
                                      ubyte4             kekLen,
                                      ubyte              **p_kek)
{
    MSTATUS status;

    ubyte  *sharedInfo = NULL;
    ubyte4 sharedInfoLen;
    ubyte  *z = NULL;
    ubyte4 zLen;
    ubyte  *kek = NULL;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux ( MOC_ECC(hwAccelCtx)
        pPrivateECCKey, pPublicECCKey, &z, &zLen, ECDH_X_CORD_ONLY, NULL);
#else
    status = ECDH_generateSharedSecretFromKeys ( MOC_ECC(hwAccelCtx)
        pPrivateECCKey, pPublicECCKey, &z, &zLen, ECDH_X_CORD_ONLY, NULL);
#endif
    if (OK != status)
        goto exit;

    /* generate the sharedInfo -> DER encoding of ECC-CMS-SharedInfo --
     the kekLen is identical to cekLen -- compatible with RFC 5008 */
    status = DIGI_CMS_U_generateECCCMSSharedInfo (keyWrapOID, keyWrapOIDLen,
                                                 hasECDHData,
                                                 ukmData, ukmDataLen,
                                                 kekLen,
                                                 &sharedInfo, &sharedInfoLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC ((void**)&kek, kekLen);
    if (OK != status)
        goto exit;

    status = ANSIX963KDF_generate (MOC_HASH(hwAccelCtx)
                                   pHashAlgo, z, zLen,
                                   sharedInfo, sharedInfoLen,
                                   kekLen, kek);
    if (OK != status)
        goto exit;

    *p_kek = kek;
    kek = NULL;

exit:
    if (NULL != z)
    {
        DIGI_FREE ((void**)&z);
    }
    if (NULL != sharedInfo)
    {
        DIGI_FREE ((void**)&sharedInfo);
    }
    if (NULL != kek)
    {
        DIGI_FREE ((void**)&kek);
    }

    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_generateECCCMSSharedInfo(const ubyte *keyInfoOID,
                                   ubyte4      keyInfoOIDLen,
                                   intBoolean  hasECDHData,
                                   const ubyte *ukmData,
                                   ubyte4      ukmDataLen,
                                   ubyte4      kekLen,
                                   ubyte       **sharedInfo,
                                   ubyte4      *sharedInfoLen)
{
    MSTATUS status;
    ubyte   copyData[MAX_DER_STORAGE];

    MAsn1Element *pSharedRec = NULL;

    /* ECC-CMS-SharedInfo sequence [rfc5753 - Section 7.2, page 24] */
    MAsn1TypeAndCount defShared[6] =
    {
       { MASN1_TYPE_SEQUENCE, 3},
         /* keyInfo         AlgorithmIdentifier */
         { MASN1_TYPE_SEQUENCE, 2},
           /* algorithm:               OBJECT IDENTIFIER */
           { MASN1_TYPE_OID, 0},
           /* parameters:              ANY DEFINED BY algorithm OPTIONAL */
           { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0},
         /* entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL */
         { MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT | MASN1_OPTIONAL, 0},
         /* suppPubInfo [2] EXPLICIT OCTET STRING */
         { MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT | 2, 0},
    };

    status = MAsn1CreateElementArray (defShared, 6, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pSharedRec);
    if (OK != status)
        goto exit;

    /* Set Value (from internal OID format) */
    status = MAsn1SetValue (pSharedRec+2,
                            keyInfoOID + 2,
                            keyInfoOIDLen - 2);
    if (OK != status)
        goto exit;
    
    if (hasECDHData)
    {
        /* Setting 'NULL' */
        status = MAsn1SetEncoded (pSharedRec+3,
                                  ASN1_NIL,
                                  ASN1_NILLen);
    }
    else
    {
        status = MAsn1SetValueLenSpecial (pSharedRec+3, MASN1_NO_VALUE);
    }
    if (OK != status)
        goto exit;

    /* Any 'User Key Material'? */
    if (NULL != ukmData)
    {
        status = MAsn1SetValue (pSharedRec+4,
                                ukmData,
                                ukmDataLen);
    }
    else
    {
        status = MAsn1SetValueLenSpecial (pSharedRec+4, MASN1_NO_VALUE);
    }
    if (OK != status)
        goto exit;

    /* Encode KEK bit length as 4 byte integer */
    kekLen = kekLen * 8;
    BIGEND32 (copyData, kekLen);
    status = MAsn1SetValue (pSharedRec+5,
                            copyData,
                            4);
    if (OK != status)
        goto exit;
    
    /* Create DER encoding in allocated memory */
    status = MAsn1EncodeAlloc (pSharedRec,
                               sharedInfo,
                               sharedInfoLen);

exit:
    MAsn1FreeElementArray(&pSharedRec);
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_ECC__) */


/*----------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
DIGI_CMS_U_extractRSAKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                        ubyte         *pSubj,
                        ubyte4        subjLen,
                        AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte4  bytesRead;
    sbyte4  cmpResult;
    int     i;

    sbyte4          startModulus;
    ubyte4          exponent, modulusLen;
    const ubyte     *modulus = 0;

    MAsn1Element    *pRootPar = NULL;
    MAsn1Element    *pRSAPar = NULL;

    MAsn1TypeAndCount defEncrPar[5] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
         {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_OID, 0},
           {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
         {  MASN1_TYPE_BIT_STRING, 0 },
    };

    MAsn1TypeAndCount defRSAPar[3] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_INTEGER, 0},
           {  MASN1_TYPE_INTEGER, 0},
    };

    status = MAsn1CreateElementArray (defEncrPar, 5,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootPar);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defRSAPar, 3,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRSAPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSubj,
                          subjLen,
                          pRootPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pRootPar[4].value.pValue+1,
                          pRootPar[4].valueLen-1,
                          pRSAPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    /* Check OID */
    status = ASN1_compareOID (RSA_ENCRYPTION_OID, RSA_ENCRYPTION_OID_LEN,
                              pRootPar[2].encoding.pEncoding,
                              pRootPar[2].encodingLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 != cmpResult)
    {
        status = ERR_CERT_NOT_EXPECTED_OID;
        goto exit;
    }

    /* First INTEGER is the modulus */
    modulusLen = pRSAPar[1].valueLen;
    modulus = pRSAPar[1].value.pValue;

    /* ASN1 INTEGERs are signed so it's possible 0x00 are added to make sure the
     value is represented as positive so check for that */
    startModulus = 0;
    while ((startModulus < ((sbyte4)modulusLen)) && (0 == modulus[startModulus]))
    {
        ++startModulus;
    }

    /* we support only modulus up to 1024 (8192 bits) bytes long */
    if (MOCANA_MAX_MODULUS_SIZE < (modulusLen - startModulus) )
    {
        /* prevent parasitic public key attack */
        status = ERR_CERT_RSA_MODULUS_TOO_BIG;
        goto exit;
    }

    /* Second INTEGER is the exponent */
    /* we support only exponent up to 4 bytes long */
    if (pRSAPar[2].valueLen > (ubyte4)sizeof(exponent))
    {
        status = ERR_CERT_RSA_EXPONENT_TOO_BIG;
        goto exit;
    }

    /* Create value from ASN string */
    exponent = 0;
    for (i = 0; i < (int)pRSAPar[2].valueLen; ++i)
    {
        ubyte digit = pRSAPar[2].value.pValue[i];
        exponent = ((exponent << 8) | digit);
    }

    status = CRYPTO_setRSAParameters (MOC_RSA(hwAccelCtx) pKey,
                                      exponent,
                                      (ubyte*) (modulus + startModulus),
                                      modulusLen - startModulus,
                                      NULL, 0, NULL, 0,
                                      NULL);

exit:
    MAsn1FreeElementArray(&pRSAPar);
    MAsn1FreeElementArray(&pRootPar);
    return status;
}
#endif

/*----------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
static MSTATUS
DIGI_CMS_U_extractDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx)
                        ubyte         *pSubj,
                        ubyte4        subjLen,
                        AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte4  bytesRead;

    const ubyte *p = NULL,
                *q = NULL,
                *g = NULL,
                *bitStr = NULL;
    ubyte4      len, pLen, qLen, gLen;

    MAsn1Element *pRootPar = NULL;
    MAsn1Element *pDSAPar = NULL;

    MAsn1TypeAndCount defEncrPar[8] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
         {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_OID, 0},
           {  MASN1_TYPE_SEQUENCE, 3},
             {  MASN1_TYPE_INTEGER, 0},
             {  MASN1_TYPE_INTEGER, 0},
             {  MASN1_TYPE_INTEGER, 0},
         {  MASN1_TYPE_BIT_STRING, 0 },
    };

    MAsn1TypeAndCount defDSAPar[1] =
    {
        {  MASN1_TYPE_INTEGER, 0},
    };

    status = MAsn1CreateElementArray (defEncrPar, 8,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootPar);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defDSAPar, 1,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pDSAPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSubj,
                          subjLen,
                          pRootPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    p = pRootPar[4].value.pValue;
    pLen = pRootPar[4].valueLen;

    q = pRootPar[5].value.pValue;
    qLen = pRootPar[5].valueLen;

    g = pRootPar[6].value.pValue;
    gLen = pRootPar[6].valueLen;

    status = MAsn1Decode (pRootPar[7].value.pValue+1,
                          pRootPar[7].valueLen-1,
                          pDSAPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    bitStr = pDSAPar[0].value.pValue;
    len = pDSAPar[0].valueLen;

    status = CRYPTO_setDSAParameters (MOC_DSA(hwAccelCtx)
                                      pKey, p, pLen, q, qLen,
                                      g, gLen,
                                      bitStr,
                                      len, NULL, 0, NULL);

exit:
    MAsn1FreeElementArray(&pDSAPar);
    MAsn1FreeElementArray(&pRootPar);
    return status;
}
#endif  /* defined(__ENABLE_DIGICERT_DSA__) */


/*----------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
static MSTATUS
DIGI_CMS_U_extractECCKey(MOC_ECC(hwAccelDescr hwAccelCtx)
                        ubyte         *pSubj,
                        ubyte4        subjLen,
                        AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte4  bytesRead;
    sbyte4  cmpResult;

    ubyte4      curveId;
    const ubyte *point = 0;
    ubyte4      len;

    MAsn1Element *pRootPar = NULL;

    MAsn1TypeAndCount defEncrPar[5] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
         {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_OID, 0},
           {  MASN1_TYPE_OID, 0},
         {  MASN1_TYPE_BIT_STRING, 0 },
    };

    if ((NULL == pSubj) ||
        (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MAsn1CreateElementArray (defEncrPar, 5,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSubj,
                          subjLen,
                          pRootPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    /* Check OID */
    status = ASN1_compareOID (ASN1_ecPublicKey_OID, ASN1_ecPublicKey_OID_LEN,
                              pRootPar[2].encoding.pEncoding,
                              pRootPar[2].encodingLen,
                              NULL, &cmpResult);
    if (OK != status)
        goto exit;
    if (0 != cmpResult)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = ASN1_compareOID (ASN1_X962CurvesPrime_OID, ASN1_X962CurvesPrime_OID_LEN,
                              pRootPar[3].encoding.pEncoding,
                              pRootPar[3].encodingLen,
                              &curveId, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 != cmpResult)
    {
        status = ASN1_compareOID (ASN1_certicomCurve_OID, ASN1_certicomCurve_OID_LEN,
                                  pRootPar[3].encoding.pEncoding,
                                  pRootPar[3].encodingLen,
                                  &curveId, &cmpResult);
        if (OK != status)
            goto exit;
        if (0 != cmpResult)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
    }

    point = pRootPar[4].value.pValue;
    len = pRootPar[4].valueLen;

    /* ASN1 INTEGERs are signed so it's possible 0x00 is added to make sure the
     value is represented as positive so check for that */
    if (0 == point[0])
    {
        point++;
        len--;
    }

    status = CRYPTO_setECCParameters (MOC_ECC(hwAccelCtx) pKey, curveId, point,
                                      len, NULL, 0);

exit:
    MAsn1FreeElementArray(&pRootPar);
    return status;
}
#endif  /* defined(__ENABLE_DIGICERT_ECC__) */


/*----------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PQC__))
static MSTATUS
DIGI_CMS_U_extractHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx)
                           ubyte         *pSubj,
                           ubyte4        subjLen,
                           AsymmetricKey *pKey)
{
    MSTATUS status;

    ubyte4  bytesRead;
    sbyte4  cmpResult;

    ubyte4      compositeAlg;
    ubyte4      clAlg;
    ubyte4      qsAlg;
    const ubyte *pPubKey = 0;
    ubyte4      pubKeyLen;

    MAsn1Element *pRootPar = NULL;

    MAsn1TypeAndCount defEncrPar[4] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
         {  MASN1_TYPE_SEQUENCE, 1},
           {  MASN1_TYPE_OID, 0},
         {  MASN1_TYPE_BIT_STRING, 0 },
    };

    if ((NULL == pSubj) ||
        (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MAsn1CreateElementArray (defEncrPar, 4,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSubj,
                          subjLen,
                          pRootPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    /* Check OID */
    status = ASN1_compareOID (ASN1_mldsa_composite_OID, MLDSA_COMPOSITE_OID_LEN,
                              pRootPar[2].encoding.pEncoding,
                              pRootPar[2].encodingLen,
                              &compositeAlg, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 != cmpResult)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pPubKey = pRootPar[3].value.pValue;
    pubKeyLen = pRootPar[3].valueLen;

    /* ASN1 INTEGERs are signed so it's possible 0x00 is added to make sure the
     value is represented as positive so check for that */
    if (0 == pPubKey[0])
    {
        pPubKey++;
        pubKeyLen--;
    }

    status = CRYPTO_getCompositeAlgs(compositeAlg, &clAlg, &qsAlg);
    if (OK != status)
        goto exit;

    /* Set the public key in the pKey */
    status = CRYPTO_setHybridParameters( MOC_ASYM(hwAccelCtx) pKey, clAlg, qsAlg, (ubyte *) pPubKey, pubKeyLen);

exit:

    (void) MAsn1FreeElementArray(&pRootPar);

    return status;
}

/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_extractQsKey(MOC_ASYM(hwAccelDescr hwAccelCtx) 
                       ubyte         *pSubj,
                       ubyte4        subjLen,
                       AsymmetricKey *pKey)
{
    MSTATUS status;
    QS_CTX *pCtx = NULL;

    ubyte4  alg;
    ubyte4  bytesRead;
    sbyte4  cmpResult;

    const ubyte *pPubKey = 0;
    ubyte4      pubKeyLen;

    MAsn1Element *pRootPar = NULL;

    MAsn1TypeAndCount defEncrPar[4] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
         {  MASN1_TYPE_SEQUENCE, 1},
           {  MASN1_TYPE_OID, 0},
         {  MASN1_TYPE_BIT_STRING, 0 },
    };

    if ((NULL == pSubj) ||
        (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MAsn1CreateElementArray (defEncrPar, 4,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSubj,
                          subjLen,
                          pRootPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    /* Check OID */
    status = ASN1_compareOID (ASN1_mldsa_OID, MLDSA_OID_LEN,
                              pRootPar[2].encoding.pEncoding,
                              pRootPar[2].encodingLen,
                              &alg, &cmpResult);
    if (OK != status)
        goto exit;

    if (0 != cmpResult)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pPubKey = pRootPar[3].value.pValue;
    pubKeyLen = pRootPar[3].valueLen;

    /* ASN1 INTEGERs are signed so it's possible 0x00 is added to make sure the
     value is represented as positive so check for that */
    if (0 == pPubKey[0])
    {
        pPubKey++;
        pubKeyLen--;
    }

    /* convert the OID alg byte to the algorithm identifier */
    switch (alg)
    {
        case 17:
            alg = cid_PQC_MLDSA_44;
            break;
        case 18:
            alg = cid_PQC_MLDSA_65;
            break;
        case 19:
            alg = cid_PQC_MLDSA_87;
            break;
        default:
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
    }
         
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pCtx, alg);
    if (OK != status)
        goto exit;

    /* Set the public key in the pKey */
    status = CRYPTO_INTERFACE_QS_setPublicKey(pCtx, (ubyte *) pPubKey, pubKeyLen);
    if (OK != status)
        goto exit;
    
    /* delete any previously existing key */
    status = CRYPTO_uninitAsymmetricKey(pKey, NULL);
    if (OK != status)
        goto exit;

    pKey->type = akt_qs;
    pKey->pQsCtx = pCtx; pCtx = NULL;

exit:

    (void) MAsn1FreeElementArray(&pRootPar);

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }
    return status;
}
#endif  /* defined(__ENABLE_DIGICERT_PQC__) */

/*----------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
DIGI_CMS_U_verifyRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                             RSAKey  *pRSAKey,
                             const ubyte *pHashResult,
                             ubyte4  hashResultLen,
                             ubyte*  pSignature,
                             ubyte4  signatureLen,
                             ubyte4  *sigFail,
                             ubyte4  keyType)
#else
static MSTATUS
DIGI_CMS_U_verifyRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                             RSAKey  *pRSAKey,
                             const ubyte *pHashResult,
                             ubyte4  hashResultLen,
                             ubyte*  pSignature,
                             ubyte4  signatureLen,
                             ubyte4  *sigFail)
#endif
{
    MSTATUS status;
    ubyte4  rsaAlgoId;
    ubyte   decryptedSignature[CERT_MAXDIGESTSIZE];
    sbyte4  decryptedSignatureLen;
    sbyte4  resCmp;

    /* Assume it fails, if the logic below does not succeed */
    *sigFail = 1;

    if ((NULL == pSignature) ||
        (NULL == pRSAKey) ||
        (NULL == pHashResult))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = X509_decryptRSASignatureBufferEx(MOC_RSA(hwAccelCtx) pRSAKey,
                                            pSignature,
                                            signatureLen,
                                            decryptedSignature,
                                            &decryptedSignatureLen,
                                            &rsaAlgoId, keyType);
#else
    status = X509_decryptRSASignatureBuffer(MOC_RSA(hwAccelCtx) pRSAKey,
                                            pSignature,
                                            signatureLen,
                                            decryptedSignature,
                                            &decryptedSignatureLen,
                                            &rsaAlgoId);
#endif
    if (decryptedSignatureLen != (sbyte4) hashResultLen)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    status = DIGI_CTIME_MATCH (decryptedSignature,
                              pHashResult, hashResultLen,
                              &resCmp);
    if (OK != status)
        goto exit;

    if (0 != resCmp)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    /* Success, no failure */
    *sigFail = 0;

exit:
    return status;
}
#endif

/*----------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
static MSTATUS
DIGI_CMS_U_verifyDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                             DSAKey  *pDSAKey,
                             const ubyte *pHashResult,
                             ubyte4  hashResultLen,
                             ubyte   *pSignature,
                             ubyte4  signatureLen,
                             ubyte4  *sigFail)
{
    MSTATUS      status;
    ubyte4       bytesRead;
    intBoolean   good;
    vlong        *pR = NULL;
    vlong        *pS = NULL;
    MAsn1Element *pDSAPar = NULL;

    MAsn1TypeAndCount defDSAPar[3] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_INTEGER, 0},
           {  MASN1_TYPE_INTEGER, 0},
    };

    /* Assume it fails, if the logic below does not succeed */
    *sigFail = 1;

    if ((NULL == pSignature) ||
        (NULL == pDSAKey) ||
        (NULL == pHashResult))
    {
        return ERR_NULL_POINTER;
    }

    status = MAsn1CreateElementArray (defDSAPar, 3,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pDSAPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSignature,
                          signatureLen,
                          pDSAPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString (pDSAPar[1].value.pValue,
                                        pDSAPar[1].valueLen, &pR, NULL);
    if (OK != status)
        goto exit;

    status = VLONG_vlongFromByteString (pDSAPar[2].value.pValue,
                                        pDSAPar[2].valueLen, &pS, NULL);
    if (OK != status)
        goto exit;

    status = DSA_verifySignature2 (MOC_DSA(hwAccelCtx) pDSAKey,
                                   pHashResult, hashResultLen,
                                   pR, pS, &good, NULL);
    if (OK != status)
        goto exit;
    if (!good)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    /* Success, no failure */
    *sigFail = 0;

exit:
    VLONG_freeVlong (&pR, NULL);
    VLONG_freeVlong (&pS, NULL);

    MAsn1FreeElementArray (&pDSAPar);
    return status;
}
#endif  /* __ENABLE_DIGICERT_DSA__ */


/*----------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
static MSTATUS
DIGI_CMS_U_verifyECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx)
                               ECCKey  *pECCKey,
                               const ubyte *pHashResult,
                               ubyte4  hashResultLen,
                               ubyte   *pSignature,
                               ubyte4  signatureLen,
                               ubyte4  *sigFail)
{
    MSTATUS         status = ERR_NULL_POINTER;
    ubyte4          bytesRead;
    MAsn1Element    *pECDSAPar = NULL;

    MAsn1TypeAndCount defECDSAPar[3] =
    {
       {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_INTEGER, 0},
           {  MASN1_TYPE_INTEGER, 0},
    };

    if (NULL == sigFail)
        goto exit;
    
    /* Assume it fails, if the logic below does not succeed */
    *sigFail = 1;

    if ((NULL == pSignature) ||
        (NULL == pECCKey) ||
        (NULL == pHashResult))
    {
        goto exit;
    }

    status = MAsn1CreateElementArray (defECDSAPar, 3,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pECDSAPar);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSignature,
                          signatureLen,
                          pECDSAPar,
                          &bytesRead);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux ( MOC_ECC(hwAccelCtx)
        pECCKey, (ubyte *) pHashResult, hashResultLen, pECDSAPar[1].value.pValue, pECDSAPar[1].valueLen,
        pECDSAPar[2].value.pValue, pECDSAPar[2].valueLen, sigFail);
#else
    status = ECDSA_verifySignatureDigest ( MOC_ECC(hwAccelCtx)
        pECCKey, (ubyte *) pHashResult, hashResultLen, pECDSAPar[1].value.pValue, pECDSAPar[1].valueLen,
        pECDSAPar[2].value.pValue, pECDSAPar[2].valueLen, sigFail);
#endif
    if (OK != status)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

exit:

    MAsn1FreeElementArray (&pECDSAPar);
    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

/*----------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PQC__))
static MSTATUS
DIGI_CMS_U_verifyHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                AsymmetricKey *pKey,
                                const ubyte *pHashResult,
                                ubyte4  hashResultLen,
                                ubyte   *pSignature,
                                ubyte4  signatureLen,
                                ubyte4  *pSigFail)
{
    MSTATUS         status = ERR_NULL_POINTER;
    ubyte4          bytesRead = 0;
    
    ubyte *pActualSig = NULL;
    ubyte4 actualSigLen = 0;
    ubyte *pDomain = NULL;
    ubyte4 domainLen = 0;
    ubyte4 qsAlg = 0;

    MAsn1Element    *pHybridSign = NULL;

    MAsn1TypeAndCount defHybridPar[2] =
    {
       {  MASN1_TYPE_SEQUENCE, 1},
           {  MASN1_TYPE_BIT_STRING, 0},
    };

    if (NULL == pSigFail)
        goto exit;
    
    /* Assume it fails, if the logic below does not succeed */
    *pSigFail = 1;

    if ((NULL == pSignature) ||
        (NULL == pKey) ||
        (NULL == pHashResult))
    {
        goto exit;
    }

    status = MAsn1CreateElementArray (defHybridPar, 2,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pHybridSign);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSignature,
                          signatureLen,
                          pHybridSign,
                          &bytesRead);
    if (OK != status)
        goto exit;

    pActualSig = pHybridSign[1].value.pValue;
    actualSigLen = pHybridSign[1].valueLen;

    /* Since it's a bit string there should be a zero byte meaning no unused bits */
    if (0x00 == pActualSig[0])
    {
        pActualSig++;
        actualSigLen--;
    }
    else
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    
    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlg);
    if (OK != status)
        goto exit;

    status = CRYPTO_getAlgoOIDAlloc(pKey->clAlg, qsAlg, &pDomain, &domainLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeVerify( MOC_ASYM(hwAccelCtx) pKey, TRUE, pDomain, domainLen,
                                                  (ubyte *) pHashResult, hashResultLen, pActualSig, actualSigLen, pSigFail);
exit:

    MAsn1FreeElementArray (&pHybridSign);

    if (NULL != pDomain)
    {
        (void) DIGI_MEMSET_FREE(&pDomain, domainLen);
    }
    
    return status;
}

/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_verifyQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx)
                            AsymmetricKey *pKey,
                            const ubyte *pHashResult,
                            ubyte4  hashResultLen,
                            ubyte   *pSignature,
                            ubyte4  signatureLen,
                            ubyte4  *pSigFail)
{
    MSTATUS         status = ERR_NULL_POINTER;
    ubyte4          bytesRead = 0;
    
    ubyte *pActualSig = NULL;
    ubyte4 actualSigLen = 0;

    MAsn1Element    *pQsSign = NULL;

    MAsn1TypeAndCount defQsPar[2] =
    {
       {  MASN1_TYPE_SEQUENCE, 1},
           {  MASN1_TYPE_BIT_STRING, 0},
    };

    if (NULL == pSigFail)
        goto exit;
    
    /* Assume it fails, if the logic below does not succeed */
    *pSigFail = 1;

    if ((NULL == pSignature) ||
        (NULL == pKey) ||
        (NULL == pHashResult))
    {
        goto exit;
    }

    status = MAsn1CreateElementArray (defQsPar, 2,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pQsSign);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pSignature,
                          signatureLen,
                          pQsSign,
                          &bytesRead);
    if (OK != status)
        goto exit;

    pActualSig = pQsSign[1].value.pValue;
    actualSigLen = pQsSign[1].valueLen;

    /* Since it's a bit string there should be a zero byte meaning no unused bits */
    if (0x00 == pActualSig[0])
    {
        pActualSig++;
        actualSigLen--;
    }
    else
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    
    status = CRYPTO_INTERFACE_QS_SIG_verify( MOC_HASH(hwAccelCtx) pKey->pQsCtx, (ubyte *) pHashResult, hashResultLen,
                                             pActualSig, actualSigLen, pSigFail);
exit:

    MAsn1FreeElementArray (&pQsSign);

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_getCBCParams(ubyte  *pIV,
                       ubyte4 IVLen,
                       ubyte  blockSize,
                       ubyte  iv[16])
{
    MSTATUS status;

    if (IVLen != blockSize)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* copy the IV to the arg */
    status = DIGI_MEMCPY (iv, pIV, blockSize);

exit:
    return status;
}


/*----------------------------------------------------------------------*/

#ifdef __ENABLE_ARC2_CIPHERS__
static MSTATUS
DIGI_CMS_U_getRC2CBCParams(ubyte  *pIV,
                          ubyte4 IVLen,
                          sbyte4 *pEffectiveKeyBits,
                          ubyte  iv[RC2_BLOCK_SIZE])
{
    MSTATUS status;
    ubyte4  bytesRead;
    int     i;
    sbyte4  encoding = -1;

    MAsn1Element *pRC2Par = NULL;

    MAsn1TypeAndCount defRC2Par[3] =
    {
      { MASN1_TYPE_SEQUENCE, 2},
        { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
        { MASN1_TYPE_OCTET_STRING, 0 },
    };

    if ((NULL == pIV) ||
        (NULL == pEffectiveKeyBits) ||
        (NULL == iv))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MAsn1CreateElementArray (defRC2Par, 3, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pRC2Par);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pIV,
                          IVLen,
                          pRC2Par,
                          &bytesRead);
    if (OK != status)
        goto exit;

    /* Create value from ASN string */
    encoding = 0;
    for (i = 0; i < pRC2Par[1].valueLen; ++i)
    {
        ubyte digit = pRC2Par[1].value.pValue[i];
        encoding = ((encoding << 8) | digit);
    }

    /* weird encoding by RSA of the effective key bits */
    switch (encoding)
    {
        case 160:
            *pEffectiveKeyBits = 40;
            break;
        case 120:
            *pEffectiveKeyBits = 64;
            break;
        case 58:
            *pEffectiveKeyBits = 128;
            break;
        default:
            if (256 <= encoding)
            {
                *pEffectiveKeyBits = encoding;
            }
            /* else -> error or default ? */
            break;
    }

    if (NULL != pRC2Par[2].value.pValue)
    {
        status = DIGI_MEMCPY (iv, pRC2Par[2].value.pValue, RC2_BLOCK_SIZE);
    }

exit:
    MAsn1FreeElementArray (&pRC2Par);
    return status;
}
#endif


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_U_setSignerSignatureRSA(MOC_CMS_ASN1_Memory *pMem,
                                ubyte4        digestAlg,
                                MAsn1Element  *pSignerOID)
{
    MSTATUS status;
    ubyte   *pEnc = NULL;
    ubyte4  encLen;

    status = DIGI_MALLOC((void**)&pEnc, RSA_ENCRYPTION_OID_LEN);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pEnc, RSA_ENCRYPTION_OID, RSA_ENCRYPTION_OID_LEN);
    if (OK != status)
        goto exit;

    encLen = RSA_ENCRYPTION_OID_LEN;

    status = MAsn1SetEncoded (pSignerOID, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pEnc);
    if (OK != status)
        goto exit;

    /* Memory is now owned by MAsn1Element */
    pEnc = NULL;

exit:
    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }
    return status;
}


/*----------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_DSA__))

static MSTATUS
DIGI_CMS_U_setSignerSignatureDSA(MOC_CMS_ASN1_Memory *pMem,
                                ubyte4        digestAlg,
                                MAsn1Element  *pSignerOID)
{
    MSTATUS status;
    ubyte   *pEnc = NULL;
    ubyte4  encLen;

    if (ht_md5 == digestAlg)
    {
        status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
        goto exit;
    }
    else if (ht_sha1 == digestAlg)
    {
        status = DIGI_MALLOC((void**)&pEnc, DSAWithSHA1_OID_LEN);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (pEnc, DSAWithSHA1_OID, DSAWithSHA1_OID_LEN);
        if (OK != status)
            goto exit;

        encLen = DSAWithSHA1_OID_LEN;
    }
    else
    {
        status = DIGI_MALLOC((void**)&pEnc, DSAWithSHA2_OID_LEN);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (pEnc, DSAWithSHA2_OID, DSAWithSHA2_OID_LEN);
        if (OK != status)
            goto exit;

        encLen = DSAWithSHA2_OID_LEN;
        switch (digestAlg)
        {
        case ht_sha256:
            pEnc[DSAWithSHA2_OID_LEN-1] = 2;
            break;

        case ht_sha224:
            pEnc[DSAWithSHA2_OID_LEN-1] = 1;
            break;

        default:
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            goto exit;
        }
    }

    status = MAsn1SetEncoded (pSignerOID, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pEnc);
    if (OK != status)
        goto exit;

    /* Memory is now owned by MAsn1Element */
    pEnc = NULL;

exit:
    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_DSA__) */

/*----------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_ECC__)

static MSTATUS
DIGI_CMS_U_setSignerSignatureECDSA(MOC_CMS_ASN1_Memory *pMem,
                                  ubyte4        digestAlg,
                                  MAsn1Element  *pSignerOID)
{
    MSTATUS status;
    ubyte   *pEnc = NULL;
    ubyte4  encLen;

    if (ht_md5 == digestAlg)
    {
        status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
        goto exit;
    }
    else if (ht_sha1 == digestAlg)
    {
        status = DIGI_MALLOC((void**)&pEnc, ECDSAWithSHA1_OID_LEN);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (pEnc, ECDSAWithSHA1_OID, ECDSAWithSHA1_OID_LEN);
        if (OK != status)
            goto exit;

        encLen = ECDSAWithSHA1_OID_LEN;
    }
    else
    {
        status = DIGI_MALLOC((void**)&pEnc, ECDSAWithSHA2_OID_LEN);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (pEnc, ECDSAWithSHA2_OID, ECDSAWithSHA2_OID_LEN);
        if (OK != status)
            goto exit;

        encLen = ECDSAWithSHA2_OID_LEN;
        switch (digestAlg)
        {

        case ht_sha224:
            pEnc[ECDSAWithSHA2_OID_LEN-1] = 1;
            break;

        case ht_sha256:
            pEnc[ECDSAWithSHA2_OID_LEN-1] = 2;
            break;

        case ht_sha384:
            pEnc[ECDSAWithSHA2_OID_LEN-1] = 3;
            break;

        case ht_sha512:
            pEnc[ECDSAWithSHA2_OID_LEN-1] = 4;
            break;

        default:
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            goto exit;
        }
    }

    status = MAsn1SetEncoded (pSignerOID, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem,
                                             (void*)pEnc);
    if (OK != status)
        goto exit;

    /* Memory is now owned by MAsn1Element */
    pEnc = NULL;

exit:
    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }
    return status;

}

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS
DIGI_CMS_U_setSignerSignatureHybrid(MOC_CMS_ASN1_Memory *pMem,
                                   ubyte4 digestAlg,
                                   AsymmetricKey *pKey,
                                   MAsn1Element *pSignerOID)
{
    MSTATUS status = OK;
    ubyte *pEnc = NULL;
    ubyte4 encLen = 0;

    ubyte4 qsAlgId = 0;
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;

    /* validate we have a supported hashId, ie hashId matches with respect to the the curve */
    if ( ((cid_EC_P256 == pKey->clAlg || cid_RSA_3072_PKCS15 == pKey->clAlg || cid_RSA_3072_PSS == pKey->clAlg 
                                      || cid_RSA_2048_PKCS15 == pKey->clAlg || cid_RSA_2048_PSS == pKey->clAlg ) && ht_sha256 != digestAlg) || 
         ((cid_EC_P384 == pKey->clAlg || cid_RSA_4096_PKCS15 == pKey->clAlg || cid_RSA_4096_PSS == pKey->clAlg ) && ht_sha384 != digestAlg) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    /* we get it from oiddefs rather than have another copy here */
    status = CRYPTO_getAlgoOIDAlloc(pKey->clAlg, qsAlgId, &pOid, &oidLen);
    if (OK != status)
        goto exit;

    /* we need to inlcude the 0x06 byte and the length byte too */
    encLen = oidLen + 2;

    status = DIGI_MALLOC((void**)&pEnc, encLen);
    if (OK != status)
        goto exit;

    pEnc[0] = 0x06;
    pEnc[1] = (ubyte) oidLen;
 
    status = DIGI_MEMCPY(pEnc + 2, pOid, encLen - 2);
    if (OK != status)
        goto exit;

    status = MAsn1SetEncoded (pSignerOID, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem, (void*)pEnc);
    if (OK != status)
        goto exit;

    /* Memory is now owned by MAsn1Element */
    pEnc = NULL;

exit:

    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }

    if (NULL != pOid)
    {
        DIGI_FREE((void **) &pOid);
    }
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_PQC__) */
#endif /* defined(__ENABLE_DIGICERT_ECC__) */

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS
DIGI_CMS_U_setSignerSignatureQs(MOC_CMS_ASN1_Memory *pMem,
                               ubyte4 digestAlg,
                               AsymmetricKey *pKey,
                               MAsn1Element *pSignerOID)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pEnc = NULL;
    ubyte4 encLen = 0;

    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;

    /* sanity check */
    if (NULL == pKey || NULL == pKey->pQsCtx)
        goto exit;

    /* we get it from oiddefs rather than have another copy here */
    status = CRYPTO_getAlgoOIDAlloc(0, pKey->pQsCtx->alg, &pOid, &oidLen);
    if (OK != status)
        goto exit;

    /* we need to inlcude the 0x06 byte and the length byte too */
    encLen = oidLen + 2;

    status = DIGI_MALLOC((void**)&pEnc, encLen);
    if (OK != status)
        goto exit;

    pEnc[0] = 0x06;
    pEnc[1] = (ubyte) oidLen;
 
    status = DIGI_MEMCPY(pEnc + 2, pOid, encLen - 2);
    if (OK != status)
        goto exit;

    status = MAsn1SetEncoded (pSignerOID, pEnc, encLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem, (void*)pEnc);
    if (OK != status)
        goto exit;

    /* Memory is now owned by MAsn1Element */
    pEnc = NULL;

exit:

    if (NULL != pEnc)
    {
        DIGI_FREE ((void**)&pEnc);
    }

    if (NULL != pOid)
    {
        DIGI_FREE((void **) &pOid);
    }
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_PQC__) */

#endif  /* defined(__ENABLE_DIGICERT_CMS__) */
