/*
 * parsecert.h
 *
 * X.509v3 Certificate Parser
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
/**
@file       parsecert.h

@brief      Header file for Mocana SoT Platform source code for X509v3 Certificate parsing routines.
@details    Header file for Mocana SoT Platform source code for X509v3 Certificate parsing routines.

@filedoc    parsecert.h
*/

/**
@file       parsecert.h
@filedoc    parsecert.h
 */
#ifndef __PARSECERT_HEADER__
#define __PARSECERT_HEADER__

#ifdef __ENABLE_MOCANA_CV_CERT__
#include "../crypto/cvcert.h"
#endif

#ifdef __ENABLE_MOCANA_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

/* bits used for Key Usage extensions */
enum
{
    digitalSignature = 0,
    nonRepudiation = 1,
    keyEncipherment = 2,
    dataEncipherment = 3,
    keyAgreement = 4,
    keyCertSign = 5,
    cRLSign = 6,
    encipherOnly = 7,
    decipherOnly = 8
};

struct RSAKey;
#if (defined(__ENABLE_MOCANA_ECC__))
struct ECCKey;
#endif
#if (defined(__ENABLE_MOCANA_DSA__))
struct DSAKey;
#endif

struct ASN1_ITEM;
struct AsymmetricKey;
struct CNMatchInfo;
struct certDistinguishedName;


/* callback function used for enumeration -- should return !=OK to stop
the enumeration */
typedef MSTATUS (*EnumCallbackFun)( struct ASN1_ITEM* pItem, CStream cs, void* userArg);

/* exported routines */
MOC_EXTERN MSTATUS
X509_parseCertificate(CStream s, ASN1_ITEM** ppRootItem);

MOC_EXTERN MSTATUS
X509_decryptRSASignatureBuffer(MOC_RSA(hwAccelDescr hwAccelCtx)
                               struct RSAKey* pRSAKey,
                               const ubyte* pSignature, ubyte4 signatureLen,
                               ubyte hash[64 /*CERT_MAXDIGESTSIZE*/], sbyte4 *pHashLen,
                               ubyte4* rsaAlgoIdSubType);

#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__))
MOC_EXTERN MSTATUS
X509_decryptRSASignatureBufferEx(MOC_RSA(hwAccelDescr hwAccelCtx)
                               struct RSAKey* pRSAKey,
                               const ubyte* pSignature, ubyte4 signatureLen,
                               ubyte hash[64 /*CERT_MAXDIGESTSIZE*/], sbyte4 *pHashLen,
                               ubyte4* rsaAlgoIdSubType, ubyte4 keyType);
#endif

MOC_EXTERN MSTATUS
X509_extractRSAKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                   struct ASN1_ITEM* pSubjectKeyInfo, CStream s,
                   struct AsymmetricKey* pKey);

#if (defined(__ENABLE_MOCANA_DSA__))
MOC_EXTERN MSTATUS
X509_verifyDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                        struct ASN1_ITEM* pSequenceSignature, CStream s,
                        struct DSAKey* pECCKey,
                        sbyte4 computedHashLen, const ubyte computedHash[/*computedHashLen*/]);
MOC_EXTERN MSTATUS
X509_extractDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx)
                   struct ASN1_ITEM* pSubjectKeyInfo, CStream s,
                   struct AsymmetricKey* pKey);
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__))
MOC_EXTERN MSTATUS
X509_verifyECDSASignatureEx( MOC_ECC(hwAccelDescr hwAccelCtx) struct ASN1_ITEM* pSequenceSignature, CStream s,
                          struct ECCKey* pECCKey,
                          sbyte4 computedHashLen,
                          const ubyte computedHash[/*computedHashLen*/],
                          ubyte4 keyType);
#endif /*__ENABLE_MOCANA_CRYPTO_INTERFACE__*/

MOC_EXTERN MSTATUS
X509_verifyECDSASignature( MOC_ECC(hwAccelDescr hwAccelCtx) struct ASN1_ITEM* pSequenceSignature, CStream s,
                          struct ECCKey* pECCKey,
                          sbyte4 computedHashLen,
                          const ubyte computedHash[/*computedHashLen*/]);

#ifdef __ENABLE_MOCANA_PQC__
MOC_EXTERN MSTATUS
X509_verifyQsSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                       ASN1_ITEMPTR pBitString,
                       CStream cs,
                       QS_CTX *pCtx,
                       sbyte4 computedHashLen,
                       ubyte *pComputedHash);
#endif

MOC_EXTERN MSTATUS
X509_extractECCKey( MOC_ECC(hwAccelDescr hwAccelCtx) struct ASN1_ITEM* pSubjectKeyInfo, CStream s,
                   struct AsymmetricKey* pKey);
    
#if defined(__ENABLE_MOCANA_ECC_EDDSA_25519__) || defined(__ENABLE_MOCANA_ECC_EDDSA_448__)
MOC_EXTERN MSTATUS
X509_extractECCEdKey( MOC_ECC(hwAccelDescr hwAccelCtx) struct ASN1_ITEM* pSubjectKeyInfo, CStream s,
                     struct AsymmetricKey* pKey);
#endif

MOC_EXTERN MSTATUS
X509_extractHybridKey( MOC_ASYM(hwAccelDescr hwAccelCtx) struct ASN1_ITEM* pSubjectKeyInfo, CStream s, struct AsymmetricKey* pKey);
#endif /* __ENABLE_MOCANA_ECC__ */

MOC_EXTERN MSTATUS
X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                    struct ASN1_ITEM* pCertificate, CStream s,
                                    struct AsymmetricKey* pPubKey);


MOC_EXTERN MSTATUS
X509_compSubjectCommonName(struct ASN1_ITEM* pCertificate, CStream s,
                            const sbyte* nameToMatch);

MOC_EXTERN MSTATUS
X509_compSubjectAltNames(struct ASN1_ITEM* pCertificate, CStream s,
                         const sbyte* nameToMatch, ubyte4 tagMask);

MOC_EXTERN MSTATUS
X509_compSubjectAltNamesEx( struct ASN1_ITEM* pCertificate, CStream s,
                            const struct CNMatchInfo* namesToMatch,
                            ubyte4 tagMask);

#if (defined(__ENABLE_MOCANA_MULTIPLE_COMMON_NAMES__))
MOC_EXTERN MSTATUS
X509_compSubjectCommonNameEx(struct ASN1_ITEM* pCertificate, CStream s,
                             const struct CNMatchInfo* namesToMatch);
#endif

MOC_EXTERN MSTATUS
X509_matchName( struct ASN1_ITEM* pCertificate, CStream s,
                const sbyte* nameToMatch);

MOC_EXTERN MSTATUS
X509_verifyValidityTime(struct ASN1_ITEM* pCertificate, CStream s, const TimeDate* td);

MOC_EXTERN MSTATUS
X509_computeBufferHash(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte* buffer,
                       ubyte4 bytesToHash,
                       ubyte hash[64 /*CERT_MAXDIGESTSIZE*/], sbyte4* hashSize,
                       ubyte4 hashType);

MOC_EXTERN MSTATUS
X509_getCertificateKeyUsage(struct ASN1_ITEM* pCertificate, CStream s,
                            struct ASN1_ITEM** ppKeyUsage);

/** Return the value of the Key Usage extension. If there's no such extension, it
 * will return 0xFFFF (All flags set)
 * <p>Pass in the address of a ubyte2 and the function will set it to the result.
 * It will be a bit field.
 * <pre>
 * %keyUsage ::= BIT STRING {
 * &nbsp;&nbsp;digitalSignature(0), nonRepudiation(1), keyEncipherment(2),
 * &nbsp;&nbsp;dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6),
 * &nbsp;&nbsp;encipherOnly(7), decipherOnly(8)}
 * </pre>
 * <p>For example, if the 0x0001 bit is set, then the digitalSignature bit is
 * set. Similarly, if the 0x0020 bit is set, then the keyCertSign bit is set.
 * <p>To decode the certificate (get the certificate as an ASN1_ITEMPTR), do the
 * following.
 * <pre>
 * <code>
 * #include "common/moptions.h"
 * #include "common/mtypes.h"
 * #include "common/mdefs.h"
 * #include "common/merrors.h"
 * #include "common/mocana.h"
 * #include "common/mrtos.h"
 * #include "common/mem_part.h"
 * #include "common/mstdlib.h"
 * #include "common/random.h"
 * #include "crypto/hw_accel.h"
 * #include "common/vlong.h"
 * #include "common/datetime.h"
 * #include "common/tree.h"
 * #include "common/absstream.h"
 * #include "common/memfile.h"
 * #include "asn1/oiddefs.h"
 * #include "asn1/parseasn1.h"
 * #include "asn1/parsecert.h"
 * #include "asn1/derencoder.h"
 *
 * #include "crypto/crypto.h"
 * #include "crypto/pubcrypto.h"
 * #include "crypto/ca_mgmt.h"
 * #include "crypto/asn1cert.h"
 *
 *   MemFile memFile;
 *   CStream cStream;
 *   ASN1_ITEMPTR pCertRoot = NULL;
 *   ASN1_ITEMPTR pCertSeq;
 *
 *   status = (MSTATUS)MF_attach (&memFile, (sbyte4)certLen, pCert);
 *   if (OK != status)
 *   goto exit;
 *
 *   CS_AttachMemFile (&cStream, (void *)&memFile);
 *
 *   status = ASN1_Parse (cStream, &pCertRoot);
 *   if (OK != status)
 *   goto exit;
 *
 *   status = ASN1_GetNthChild (pCertRoot, 1, &pCertSeq);
 *   if (OK != status)
 *     goto exit;
 *
 * exit:
 *   if (NULL != pCertRoot)
 *   {
 *     TREE_DeleteTreeItem ((TreeItem *)pCertRoot);
 *   }
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS
X509_getCertificateKeyUsageValue(struct ASN1_ITEM* pCertificate, CStream s,
                                 ubyte2* pValue);

MOC_EXTERN MSTATUS
X509_canSignChain(struct ASN1_ITEM* pCertificate, CStream s, sbyte4 chainLength);

/* this function will validate the link between the two certificates --
 no time validation is performed, just the fact that parent is authorized to
 sign and that the signature is correct */
MOC_EXTERN MSTATUS
X509_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                  struct ASN1_ITEM* pCertificate, CStream pCertStream,
                  struct ASN1_ITEM* pParentCertificate, CStream pParentCertStream,
                  sbyte4 chainLength);


MOC_EXTERN MSTATUS
X509_extractDistinguishedNames(struct ASN1_ITEM* pCertificate, CStream s,
                                intBoolean isSubject,
                                struct certDistinguishedName *pRetDN);

MOC_EXTERN MSTATUS
X509_extractDistinguishedNamesFromName(struct ASN1_ITEM* pName, CStream s,
                                       struct certDistinguishedName *pRetDN);

/**
 * Extract the distinguished name components as a comma separated buffer.
 * <p>This function takes in an ASN1_ITEMPTR which points to a distinguished
 * name such as the subject or issuer name and extracts the name components.
 * Each of the name components are placed inside a buffer with a comma
 * delimiter. This buffer is allocated by this function and given back to the
 * caller who must free it. Note that the buffer returned is not NULL
 * terminated.
 * <p> For a certificate which contains the following attributes in the subject
 * portion.
 *
 *   CN=TestCert
 *   C=US
 *   L=San Francisco
 *   ST=CA
 *   O=Mocana Corp
 *
 * The buffer will be output as follows without a NULL terminating character.
 *
 *   CN=TestCert,C=US,L=San Francisco,ST=CA,O=Mocana Corp
 *
 * @param pNameItem     Pointer to the distinguished name to parse.
 * @param cs            CStream which holds the distinguished name data.
 * @param ppBuffer      Address where return pointer is placed.
 * @param pBufferLen    Address where length of return pointer is placed.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS
X509_extractDistinguishedNamesBuffer(ASN1_ITEMPTR pNameItem, CStream cs,
                                     ubyte **ppBuffer, ubyte4 *pBufferLen);

MOC_EXTERN MSTATUS
X509_extractVersion(struct ASN1_ITEM* pCertificate, sbyte4 *pRetVersion);

MOC_EXTERN MSTATUS
X509_getSubjectCommonName( struct ASN1_ITEM* pCertificate, CStream s,
                           struct ASN1_ITEM** ppCommonNameItem);


MOC_EXTERN MSTATUS
X509_getSubjectEntryByOID( struct ASN1_ITEM* pCertificate, CStream s,
                          const ubyte* oid, struct ASN1_ITEM** ppEntryItem);

MOC_EXTERN MSTATUS
X509_getEntryByOID( ASN1_ITEMPTR pInputItem, CStream s,
                   const ubyte* oid, ASN1_ITEMPTR *ppEntryItem);

MOC_EXTERN MSTATUS
X509_checkCertificateIssuer(struct ASN1_ITEM* pParentCertificate,
                            CStream pParentCertStream,
                            struct ASN1_ITEM* pCertificate,
                            CStream pCertStream);

MOC_EXTERN MSTATUS
X509_getCertTime( struct ASN1_ITEM* pTime, CStream s, TimeDate* pGMTTime);

MOC_EXTERN MSTATUS
X509_verifySignature( MOC_ASYM(hwAccelDescr hwAccelCtx) struct ASN1_ITEM* pCertOrCRL,
                     CStream cs, struct AsymmetricKey *pIsuerPubKey);

MOC_EXTERN MSTATUS
X509_extractValidityTime(struct ASN1_ITEM* pCertificate, CStream s,
                                             struct certDistinguishedName *pRetDN);
MOC_EXTERN MSTATUS
X509_getValidityTime(struct ASN1_ITEM* pCertificate,
                     struct ASN1_ITEM** pRetStart, struct ASN1_ITEM** pRetEnd);


MOC_EXTERN MSTATUS
X509_rawVerifyOID(struct ASN1_ITEM* pCertificate, CStream s,
                  const ubyte *pOidItem, const ubyte *pOidValue,
                  intBoolean *pIsPresent);

MOC_EXTERN MSTATUS
X509_extractSerialNum(struct ASN1_ITEM* pCertificate, CStream s,
                      ubyte** ppRetSerialNum, ubyte4 *pRetSerialNumLength);

/* use this function to go through all the crlDistributionPoints -- pCurrItem is the current item -- it should be NULL
in the first call or to reset the enumeration; the function will return ERR_FALSE if there not any more items */
MOC_EXTERN MSTATUS
X509_enumerateCRL( struct ASN1_ITEM* pCertificate, CStream s,
                  EnumCallbackFun ecf, void* userArg);

MOC_EXTERN MSTATUS
X509_enumerateAltName( struct ASN1_ITEM* pCertificate, CStream s, sbyte4 isSubject,
                      EnumCallbackFun ecf, void* userArg);

MOC_EXTERN MSTATUS
X509_checkCertificateIssuerSerialNumber(struct ASN1_ITEM* pIssuer,
                                        struct ASN1_ITEM* pSerialNumber,
                                        CStream pIssuerStream,
                                        struct ASN1_ITEM* pCertificate,
                                        CStream pCertStream);

MOC_EXTERN MSTATUS
X509_getCertificateIssuerSerialNumber( struct ASN1_ITEM* pCertificate,
                                      struct ASN1_ITEM** ppIssuer,
                                      struct ASN1_ITEM** ppSerialNumber);

MOC_EXTERN MSTATUS
X509_getCertificateSubject( struct ASN1_ITEM* pCertificate, struct ASN1_ITEM** ppSubject);

MOC_EXTERN MSTATUS
X509_getRSASignatureAlgo( struct ASN1_ITEM* pCertificate, CStream certStream,
                         ubyte* signAlgo);

MOC_EXTERN MSTATUS
X509_isRootCertificate(struct ASN1_ITEM* pCertificate, CStream s);

#ifdef __ENABLE_MOCANA_EXTRACT_CERT_BLOB__
MOC_EXTERN MSTATUS
X509_extractDistinguishedNamesBlob(struct ASN1_ITEM* pCertificate,
                                   CStream s,
                                   intBoolean isSubject,
                                   ubyte **ppRetDistinguishedName,
                                   ubyte4 *pRetDistinguishedNameLen);
#endif

MOC_EXTERN MSTATUS
X509_getCertExtension( struct ASN1_ITEM* pExtensionsSeq, CStream s,
                      const ubyte* whichOID, intBoolean* critical,
                      struct ASN1_ITEM** ppExtension);

/** Get the ASN1_ITEMPTR that contains the extensions. Use it to get individual
 * extensions out (see X509_getCertExtension).
 * <p>If there are no extensions, the function will set *ppExtensions to NULL and
 * retun OK.
 * <p>This will return a reference to the Extensions ASN.1 object. That object
 * belongs to the cert object. Do not free it.
 * <p>To decode the certificate (get the certificate as an ASN1_ITEMPTR), do the
 * following.
 * <pre>
 * <code>
 * #include "common/moptions.h"
 * #include "common/mtypes.h"
 * #include "common/mdefs.h"
 * #include "common/merrors.h"
 * #include "common/mocana.h"
 * #include "common/mrtos.h"
 * #include "common/mem_part.h"
 * #include "common/mstdlib.h"
 * #include "common/random.h"
 * #include "crypto/hw_accel.h"
 * #include "common/vlong.h"
 * #include "common/datetime.h"
 * #include "common/tree.h"
 * #include "common/absstream.h"
 * #include "common/memfile.h"
 * #include "asn1/oiddefs.h"
 * #include "asn1/parseasn1.h"
 * #include "asn1/parsecert.h"
 * #include "asn1/derencoder.h"
 *
 * #include "crypto/crypto.h"
 * #include "crypto/pubcrypto.h"
 * #include "crypto/ca_mgmt.h"
 * #include "crypto/asn1cert.h"
 *
 *   MemFile memFile;
 *   CStream cStream;
 *   ASN1_ITEMPTR pCertRoot = NULL;
 *   ASN1_ITEMPTR pCertSeq, pExtensions;
 *
 *   status = (MSTATUS)MF_attach (&memFile, (sbyte4)certLen, pCert);
 *   if (OK != status)
 *   goto exit;
 *
 *   CS_AttachMemFile (&cStream, (void *)&memFile);
 *
 *   status = ASN1_Parse (cStream, &pCertRoot);
 *   if (OK != status)
 *   goto exit;
 *
 *   status = ASN1_GetNthChild (pCertRoot, 1, &pCertSeq);
 *   if (OK != status)
 *     goto exit;
 *
 *   status = X509_getCertificateExtensions (pCertSeq, &pExtensions);
 *   if (OK != status)
 *     goto exit;
 *
 * exit:
 *   if (NULL != pCertRoot)
 *   {
 *     TREE_DeleteTreeItem ((TreeItem *)pCertRoot);
 *   }
 * </code>
 * </pre>
 */
MOC_EXTERN MSTATUS
X509_getCertificateExtensions(struct ASN1_ITEM* pCertificate,
                              struct ASN1_ITEM** ppExtensions);

MOC_EXTERN MSTATUS
X509_getCertSignAlgoType(struct ASN1_ITEM* pSignAlgoId, CStream s,
                         ubyte4* hashType, ubyte4* pubKeyType);

MOC_EXTERN MSTATUS
X509_getCertSignAlgoTypeEx(struct ASN1_ITEM* pSignAlgoId, CStream s,
                           ubyte4* hashType, ubyte4* pubKeyType, ubyte4* pClType, ubyte4 *pQsAlg);

MOC_EXTERN MSTATUS
X509_getSignatureItem(struct ASN1_ITEM* pCertificate, CStream s,
                      struct ASN1_ITEM** ppSignature);

MOC_EXTERN void
X509_convertTime(TimeDate *pTime, ubyte *pOutputTime);

MOC_EXTERN MSTATUS 
X509_printCertificateOrCsr(ubyte *pCertOrCsr, ubyte4 certOrCsrLen);

MOC_EXTERN MSTATUS
X509_decodeRS(ubyte *pSer, ubyte4 serLen, ubyte *pR, ubyte *pS, ubyte4 elemLen);

#ifdef __ENABLE_MOCANA_CV_CERT__
MOC_EXTERN MSTATUS
PARSE_CV_CERT_checkCertificateIssuer(CV_CERT *pCertificate,
                                     CV_CERT *pParentCertificate);

MOC_EXTERN MSTATUS 
PARSE_CV_CERT_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                           CV_CERT *pCertificate,
                           CV_CERT *pParentCertificate);
MOC_EXTERN MSTATUS
PARSE_CV_CERT_verifySignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              CV_CERT *pCertificate,
                              CV_CERT *pParentCertificate);
                  
MOC_EXTERN MSTATUS
PARSE_CV_CERT_verifyValidityTime(CV_CERT* pCert, const TimeDate* currTime);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __PARSECERT_HEADER__ */
