/*
 * cvcert.h
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

#ifndef __CV_CERT_H__
#define __CV_CERT_H__

#include "../crypto/pubcrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    ubyte *pCertAuthRef;
    ubyte4 certAuthRefLen;

    ubyte *pCvcKey;
    ubyte4 cvcKeyLen;

    ubyte *pCertHolderRef;
    ubyte4 certHolderRefLen;

    ubyte *pCertHolderAuthTemplate;
    ubyte4 certHolderAuthTemplateLen;

    TimeDate effectiveDate;
    TimeDate expDate;

    ubyte *pExtensions;
    ubyte4 extLen;

    ubyte *pCertBody;
    ubyte4 certBodyLen;

    ubyte *pSig;
    ubyte4 sigLen;

} CV_CERT;

typedef struct
{
    /* signer info */
    AsymmetricKey *pSignerKey; /* NULL pSignerKey indicates it will be self signed */

    ubyte *pSignerAuthRef;
    ubyte4 signerAuthRefLen;    

    ubyte4 signHashAlgo;
    byteBoolean signIsPss;

    /* holder info */
    AsymmetricKey *pCertKey;
    ubyte4 hashAlgo;
    byteBoolean isPss;

    ubyte countryCode[2];

    ubyte mnemonic[9];
    ubyte4 mnemonicLen;

    ubyte seqNum[5];

    ubyte *pCertHolderAuthTemplate;
    ubyte4 certHolderAuthTemplateLen;

    TimeDate effectiveDate;
    TimeDate expDate;

    ubyte *pExtensions;
    ubyte4 extLen;

} CV_CERT_GEN_DATA;


/**
 * Computes the length of a CV form element.
 *
 * @param pLenAndValue  Pointer to the length of the (tag length value) triple
 * @param ppValue       Contents will be set to a pointer to the value. May be the
 *                      address of \c pLenAndValue;
 * @param pLen          Contents will be set to the length of the value in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CV_CERT_getLenAndValue(ubyte *pLenAndValue, ubyte **ppValue, ubyte4 *pLen);

/**
 * Parses a serialized key from a \c CV_CERT instance. An instance of an 
 * \c AsymmetricKey containing the key will be created, and the hashAlgo 
 * and whether it's an RSA-PSS key will also be output.
 *
 * @param pCvcKey    Buffer holding the serialized RSA or ECC key.
 * @param cvcKeyLen  The length of the \c pCvcKey buffer in bytes.
 * @param pKey       The output \c AsymmetricKey.
 * @param pHashAlgo  Will be set to the hash algorithm identifier associated with the key.
 * @param pIsPss     Will be set to \c TRUE if the key is an RSA-pSS key and \c FALSE otherwise.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CV_CERT_parseKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pCvcKey, ubyte4 cvcKeyLen, AsymmetricKey *pKey, ubyte4 *pHashAlgo, byteBoolean *pIsPss);

/**
 * Parses a serialized CV form certificate and allocated a new structure
 * to hold the obtained data. The fields within this structure are not
 * allocated. The original buffer \c pCert must still be present in memory
 * until finished with the allocated \c CV_CERT instance.
 *
 * @param pCert        Buffer holding the certificate.
 * @param certLen      The length of the certificate in bytes.
 * @param ppNewCvcCert Contents will point to a newly allocated instance
 *                     of a \c CV_CERT structure with the certificate data
 *                     present. Be sure to free this structure when done with it.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CV_CERT_parseCert(ubyte *pCert, ubyte4 certLen, CV_CERT **ppNewCvcCert);

/**
 * Generates a new CV form certificate from the data within a \c CV_CERT_GEN_DATA instance.
 *
 * @param pCertGenData The data that is to go in the certificate, and the key used to sign it.
 * @param ppCert       Contents will be set to a buffer holding the new Certificate. Be sure
 *                     to free this buffer when done with it.
 * @param pCertLen     Contents will be set to the length of the new certificate in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CV_CERT_generateCert(MOC_ASYM(hwAccelDescr hwAccelCtx) CV_CERT_GEN_DATA *pCertGenData, ubyte **ppCert, ubyte4 *pCertLen);

/**
 * Determines wheter a CV form certificate is a root certificate or a child one.
 *
 * @param pCert   An instance of a \c CV_CERT containing the data of a parsed certificate.
 *
 * @return         \c OK (0) if successful and the certificate is a root certificate, 
 *                 \c ERR_FALSE (-6011) if the certificate is not a root certificate,
 *                 and otherwise a negative number error code from merrors.h
 */
MOC_EXTERN MSTATUS CV_CERT_isRootCert(CV_CERT *pCert);

#ifdef __cplusplus
}
#endif

#endif
