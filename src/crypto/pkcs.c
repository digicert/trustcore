/*
 * pkcs.c
 *
 * PKCS7 Utilities
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
@file       pkcs.c
@brief      High-level wrappers for Mocana SoT Platform PKCS&nbsp;\#7
            convenience API functions.

@details    This file contains the high-level wrappers for Mocana
            SoT Platform PKCS&nbsp;\#7 convenience API functions.

For documentation of lower-level, fundamental SoT Platform PKCS&nbsp;\#7
functions, see the pkcs7.c documentation.

@flags
To enable any of the functions in pkcs.{c,h}, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__

@filedoc    pkcs.c
*/

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_PKCS7__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/derencoder.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs.h"

#if defined(__ENABLE_DIGICERT_HARNESS__)
#include "../harness/harness.h"
#endif


/*--------------------------------------------------------------------------*/

/* This API returns an DER encoded PKCS7 message that contains the
payload enveloped using the provided certificate. This is just a
high level wrapper, with less flexibility of PKCS7_EnvelopData */
/**
@brief      Get a PKCS&nbsp;\#7, DER-encoded, bare ASN.1 \c EnvelopedData object
            containing a given payload.

@details    This function encrypts (DER-encodes) a given payload and envelops
            it in an ASN.1 \c EnvelopedData object.

@note       This function returns a \e bare \c EnvelopedData object&mdash;one
            that is not contained in a PKCS&nbsp;\#7 \c ContentInfo object. To
            get an \c EnvelopedData object that \c is contained in a \c
            ContentInfo object, call the PKCS7_EnvelopData() function.

This function is a wrapper for PKCS7_EnvelopData().

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__

@inc_file filename.h

@param  cert        Pointer to a buffer containing the certificate with the
                      payload to encrypt.
@param  certLen     Length of the DER-encoded certificate buffer, \p cert.
@param  encryptAlgoOID  Pointer to OID array that describes the type of
                          encryption to apply to the \c EnvelopedData object.
                          Use any of the preconfigured OID arrays from
                          src/asn1/oiddefs.h:
                          + \c aes128CBC_OID
                          + \c aes192CBC_OID
                          + \c aes256CBC_OID
@param  pPayLoad    Pointer to a buffer containing the payload data to envelop.
@param  payLoadLen  Length of payload data, \p pPayLoad.
@param  ppEnveloped     On return, pointer to the address of the DER-encoded
                          ASN.1 \c EnvelopedData object.
@param  pEnvelopedLen   On return, pointer to length of the \c EnvelopedData
                          object, \p ppEnveloped.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs.c
*/
extern MSTATUS
PKCS7_EnvelopWithCertificate( const ubyte* cert,
                                ubyte4 certLen,
                                const ubyte* encryptAlgoOID,
                                const ubyte* pPayLoad,
                                ubyte4 payLoadLen,
                                ubyte** ppEnveloped,
                                ubyte4* pEnvelopedLen)
{
    hwAccelDescr    hwAccelCtx;
    ASN1_ITEMPTR    pCertificate = NULL;
    CStream         s;
    MemFile         certMemFile;
    MSTATUS         status;

    if ( !cert || !encryptAlgoOID ||
        !pPayLoad || !ppEnveloped || !pEnvelopedLen)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    MF_attach(&certMemFile, certLen, (ubyte*) cert);
    CS_AttachMemFile(&s, &certMemFile );

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate( s, &pCertificate)))
        goto exit;

    status = PKCS7_EnvelopData( MOC_HW(hwAccelCtx)
                                NULL, NULL, &pCertificate,
                                &s, 1, encryptAlgoOID,
                                RANDOM_rngFun, g_pRandomContext,
                                pPayLoad, payLoadLen,
                                ppEnveloped, pEnvelopedLen);
exit:

    if (pCertificate)
    {
        TREE_DeleteTreeItem( &pCertificate->treeItem);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}


/*--------------------------------------------------------------------------*/

/* This API returns an DER encoded PKCS7 message that contains the
payload enveloped using the provided certificates. This is just a
high level wrapper for PKCS7_EnvelopData */

/**
@brief      Get a PKCS&nbsp;\#7, DER-encoded, bare ASN.1 \c EnvelopedData object
            containing a given payload.

@details    This function encrypts (DER-encodes) a given payload and envelops
            it in an ASN.1 \c EnvelopedData object.

@note       This function returns a \e bare \c EnvelopedData object&mdash;one
            that is not contained in a PKCS&nbsp;\#7 \c ContentInfo object. To
            get an \c EnvelopedData object that \c is contained in a \c
            ContentInfo object, call the PKCS7_EnvelopData() function.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__

@inc_file filename.h

@param  numCerts    Number of certificates in \p cert.
@param  certs       Pointer to array of certificates containing the
                      payload to encrypt.
@param  certLens    Length of the DER-encoded certificates array, \p certs.
@param  encryptAlgoOID  Pointer to OID array that describes the type of
                          encryption to apply to the \c EnvelopedData object.
                          Use any of the preconfigured OID arrays from
                          src/asn1/oiddefs.h:
                          + \c aes128CBC_OID
                          + \c aes192CBC_OID
                          + \c aes256CBC_OID
@param  pPayLoad    Pointer to a buffer containing the payload data to envelop.
@param  payLoadLen  Length of payload data, \p pPayLoad.
@param  ppEnveloped     On return, pointer to the address of the DER-encoded
                          ASN.1 \c EnvelopedData object.
@param  pEnvelopedLen   On return, pointer to length of the \c EnvelopedData
                          object, \p ppEnveloped.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs.c
*/
MSTATUS
PKCS7_EnvelopWithCertificates( ubyte4 numCerts, const ubyte* certs[/*numCerts*/],
                                ubyte4 certLens[/*numCerts*/],
                                const ubyte* encryptAlgoOID,
                                const ubyte* pPayLoad, ubyte4 payLoadLen,
                                ubyte** ppEnveloped, ubyte4* pEnvelopedLen)
{
    hwAccelDescr    hwAccelCtx;
    ASN1_ITEMPTR*   pCertificates = NULL;
    CStream*        streams = NULL;
    MemFile*        certMemFiles = NULL;
    ubyte4          i;
    MSTATUS         status;

    if ( !certs || !encryptAlgoOID ||
        !pPayLoad || !ppEnveloped || !pEnvelopedLen)
    {
        return ERR_NULL_POINTER;
    }

    if ( !numCerts)
        return ERR_INVALID_ARG;

    if (OK > ( status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    /* array allocations */
    pCertificates = MALLOC( numCerts * sizeof( ASN1_ITEMPTR));
    if (pCertificates)
        DIGI_MEMSET((ubyte*)pCertificates, 0, numCerts * sizeof( ASN1_ITEMPTR));

    streams = MALLOC( numCerts * sizeof( CStream));
    if (streams)
        DIGI_MEMSET((ubyte*)streams, 0, numCerts * sizeof( CStream));

    certMemFiles = MALLOC( numCerts * sizeof( MemFile));
    if (certMemFiles)
        DIGI_MEMSET((ubyte*)certMemFiles, 0, numCerts * sizeof( MemFile));

    if ((NULL == pCertificates) || (NULL == streams) || (NULL == certMemFiles))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for ( i = 0; i < numCerts; ++i)
    {
        MF_attach(certMemFiles+i, certLens[i], (ubyte*) certs[i]);
        CS_AttachMemFile(streams+i, certMemFiles+i );

        /* parse the certificate */
        if (OK > (status = X509_parseCertificate( streams[i], pCertificates+i)))
            goto exit;
    }

    status = PKCS7_EnvelopData( MOC_HW(hwAccelCtx)
                                NULL, NULL, pCertificates,
                                streams, numCerts, encryptAlgoOID,
                                RANDOM_rngFun, g_pRandomContext,
                                pPayLoad, payLoadLen,
                                ppEnveloped, pEnvelopedLen);
exit:

    if (pCertificates)
    {
        for ( i = 0; i < numCerts; ++i)
        {
            if ( pCertificates[i])
            {
                TREE_DeleteTreeItem( &(pCertificates[i]->treeItem));
            }
        }
        FREE( pCertificates);
    }

    if ( certMemFiles)
    {
        FREE( certMemFiles);
    }

    if ( streams)
    {
        FREE( streams);
    }


    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

/*--------------------------------------------------------------------------*/

/* This API decrypts the Enveloped Data part of a PKCS7 message
This is a high level wrapper for PKCS7_DecryptEnvelopedData */
/**
@brief      Decrypt the \c EnvelopedData part of a PKCS&nbsp;\#7 message.

@details    This function decrypts the \c EnvelopedData part of a PKCS&nbsp;\#7
            message. The \c EnvelopedData can be a \e bare object&mdash;one
            that is not contained in a PKCS&nbsp;\#7&mdash;or it can be
            contained in a PKCS&nbsp;\#7 \c ContentInfo object.

This function is wrapper for PKCS7_DecryptEnvelopedData().

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__

@inc_file filename.h

@param  pkcs7Msg        Pointer to buffer containing the \c EnvelopedData
                          object to decrypt.
@param  pkcs7MsgLen     Length of the \c EnvelopedData buffer, \p pkcs7Msg.
@param  callbackArg     Pointer to arguments that are required by the function
                          referenced in \p getPrivateKeyFun.
@param  getPrivateKeyFun    Pointer to a callback that gets the private
                              key for the recipient of this \c EnvelopedData
                              object. The recipient is specified by \c
                              EnvelopedData object's \c RecipientInfo, which
                              contains \c SerialNumber and \c IssuerName values
                              that uniquely identify a certificate, and
                              therefore, a subject.
@param  decryptedInfo   On return, pointer to the address of a buffer containing
                          the decrypted content of \c EnvelopedData object's \c
                          encryptedContent child.
@param decryptedInfoLen On return, pointer to length of decrypted information,
                          \p decryptedInfo.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs.c
*/
MSTATUS
PKCS7_DecryptEnvelopedDataPart( const ubyte* pkcs7Msg,
                               ubyte4 pkcs7MsgLen,
                               void* callbackArg,
                               PKCS7_GetPrivateKey getPrivateKeyFun,
                               ubyte** decryptedInfo,
                               sbyte4* decryptedInfoLen)
{
    hwAccelDescr    hwAccelCtx;
    CStream         s;
    MemFile         certMemFile;
    ASN1_ITEMPTR    rootItem = NULL, pItem, pEnvelopedData;
    MSTATUS         status;

    if ( !pkcs7Msg || !decryptedInfo || !decryptedInfoLen)
        return ERR_NULL_POINTER;

    if (OK > ( status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;


    MF_attach(&certMemFile, pkcs7MsgLen, (ubyte*) pkcs7Msg);
    CS_AttachMemFile(&s, &certMemFile );

    /* parse the PKCS7 message */
    if (OK > (status = ASN1_Parse( s, &rootItem)))
        goto exit;

    /* now look for the PKCS7 OID for Enveloped data */
    if ( OK > ( status = ASN1_GetChildWithOID( rootItem, s, pkcs7_envelopedData_OID, &pItem)))
        goto exit;

    if ( pItem) /* found */
    {
        /* pkcs7 enveloped data -> we need to content type: child of tag 0*/
        if ( OK > ( status = ASN1_GetChildWithTag( pItem, 0, &pEnvelopedData)))
            goto exit;
    }
    else /* assume the whole thing is an enveloped msg */
    {
        pEnvelopedData = ASN1_FIRST_CHILD( rootItem);
    }

    if (!pEnvelopedData)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /*  call the middle level routine */
    status = PKCS7_DecryptEnvelopedData( MOC_HW(hwAccelCtx)
                                        pEnvelopedData, s, callbackArg,
                                        getPrivateKeyFun,
                                        decryptedInfo, decryptedInfoLen);

exit:

    if ( rootItem)
    {
        TREE_DeleteTreeItem( &rootItem->treeItem);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}


/*--------------------------------------------------------------------------*/

/**
@brief      Create a bare \c SignedData object that is signed by a given
            certificate and SoT Platform keyblob; optionally include
            certificates in the resultant \c SignedData object.

@details    This function creates a bare \c SignedData object that is signed by
            a given certificate and SoT Platform keyblob. You can include
            certificates in the resultant \c SignedData object, or omit them.

@note       This function returns a \e bare SignedData object&mdash;one that is
            not contained in a \c ContentInfo object. To get a \c SignedData
            object that \e is contained in a \c ContentInfo object, call the
            PKCS7_SignData() function.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__


@inc_file filename.h

@param  cert            Pointer to buffer containig the signing certificate.
@param  certLen         Length of the signing certificate, \p cert.
@param  keyBlob         Pointer to SoT Platform keyblob containing the signing
                          key.
@param  keyBlobLen      Length of the SoT Pltfrom keyblob, \p keyBlob.

@param  pCACertificates To omit certificates, a NULL pointer; to include
                          certificates, pointer to \c ASN1_ITEMPTR array. The
                          array's first element references an \c ASN1_ITEM
                          structure for the first certificate in the CStream
                          (\p pCAStreams) that contains the certificates to
                          include in the \c SignedData object. To obtain this
                          \c ASN1_ITEMPTR structure, submit the CStream object
                          in \p pCAStreams to ASN1_Parse().
@param  pCAStreams      To omit certificates, a NULL pointer; to include
                          certificates, pointer to a \c CStream array that
                          contains the certificates to include in the resultant
                          \c SignedData object.
@param  numCACerts      If \p pCAStreams is a NULL pointer, zero (0); otherwise
                          the number of certificates in \p pCAStreams.
@param  pCrls           To omit CRLs, a NULL pointer; to include CRLs, pointer
                          to an \c ASN1_ITEMPTR array. The array's first
                          element references an \c ASN1_ITEM structure for the
                          first CRL in the CStream (\p pCrlStreams) that
                          contains the CRLs to include in the \c SignedData
                          object. To obtain this \c ASN1_ITEMPTR structurre,
                          submit the CStream object in \p pCrlStreams to
                          ASN1_Parse().
@param  pCrlStreams     To omit CRLs, a NULL pointer; to include CRLs, pointer
                          to a CStream array that contains the CRLs to include
                          in the resultant \c SignedData object.
@param  numCrls         If \p pCrlStreams is a NULL pointer, zero (0);
                          otherwise the number of CRLs in \p pCrlStreams.
@param  digestAlgoOID   Pointer to the OID for the message digest method to
                          use for the signer. Valid values are \c md5_OID or
                          \c sha1_OID, defined in src/asn1/oiddefs.h.
@param  payLoadType     Pointer to an OID describing the payload data, \p
                          pPayLaod. The src/asn1/oiddefs.c file defines the
                          valid constant arrays, typically \c pkcs7_data_OID.
                          You can create a \c SignedData object for other types
                          of payloads, such as \c pkcs7_encryptedData_OID.
                          Refer to src/asn1/oiddefs.c for the arrays of OID
                          types.
@param  pPayLoad        Pointer to the buffer containing payload data for which
                          to create the signature.
@param  payLoadLen      Pointer to length of payload data, \p pPayLaod.
@param  pAuthAttrs      (Optional except if \c ContentInfo type is data) NULL
                          or pointer to signer's authenticated attributes (a
                          single structure or array of structures).
@param  authAttrsLen    Length of signer's authenticated attributes, \p
                          pAuthAttrs.
@param  rngFun      Pointer to a function that generates random numbers
                      suitable for cryptographic use. To be FIPS-compliant,
                      reference RANDOM_rngFun() (defined in random.c), and make
                      sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is defined in
                      moptions.h
@param  rngFunArg   Pointer to arguments that are required by the function
                      referenced in \p rngFun. If you use RANDOM_rngFun(), you
                      must supply a \c randomContext structure, which you can
                      create by calling RANDOM_acquireContext().
@param  ppSigned    On return, pointer to address of resultant DER-encoded,
                      ASN.1 \c SignedData object.
@param  pSignedLen  On return, pointer to length of the resultant \c SignedData
                      object, \p ppSigned.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    pkcs.c
*/
extern MSTATUS
PKCS7_SignWithCertificateAndKeyBlob( const ubyte* cert,
                                    ubyte4 certLen,
                                    const ubyte* keyBlob,
                                    ubyte4 keyBlobLen,
                                    ASN1_ITEMPTR pCACertificates[/*numCACerts*/],
                                    CStream pCAStreams[/*numCACerts*/],
                                    sbyte4 numCACerts,
                                    ASN1_ITEMPTR pCrls[/*numCrls*/],
                                    CStream pCrlStreams[/*numCrls*/],
                                    sbyte4 numCrls,
                                    const ubyte* digestAlgoOID,
                                    const ubyte* payLoadType,
                                    ubyte* pPayLoad, /* removed const to get rid of compiler warning */
                                    ubyte4 payLoadLen,
                                    Attribute* pAuthAttrs,
                                    ubyte4 authAttrsLen,
                                    RNGFun rngFun,
                                    void* rngFunArg,
                                    ubyte** ppSigned,
                                    ubyte4* pSignedLen)
{
    hwAccelDescr    hwAccelCtx;
    ASN1_ITEMPTR    pCertificate = NULL;
    CStream         s;
    MemFile         certMemFile;
    AsymmetricKey   key;
    signerInfo  mySignerInfo;
    signerInfoPtr mySignerInfoPtr[1];
    MSTATUS         status;
    randomContext   *pRandomContext = 0;

    if ( !cert || !keyBlob || !digestAlgoOID || !pPayLoad || !ppSigned || !pSignedLen)
    {
        return ERR_NULL_POINTER;
    }

    DIGI_MEMSET ((ubyte *)&mySignerInfo, 0, sizeof (mySignerInfo));
    DIGI_MEMSET ((ubyte *)&key, 0, sizeof (key));

    if (OK > ( status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    /* if no random function passed in, get one */
    if ( 0 == rngFun)
    {
        rngFun = RANDOM_rngFun;
        if (OK > ( status = RANDOM_acquireContext( &pRandomContext)))
            goto exit;
        rngFunArg = pRandomContext;
    }

    MF_attach(&certMemFile, certLen, (ubyte*) cert);
    CS_AttachMemFile(&s, &certMemFile );

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate( s, &pCertificate)))
        goto exit;

    /* load the key */
    if (OK > (status = CA_MGMT_extractKeyBlobEx(keyBlob, keyBlobLen, &key)))
        goto exit;

    /* need to initialize issuerandserialno */
    mySignerInfo.digestAlgoOID = digestAlgoOID;
    mySignerInfo.pKey = &key;
    mySignerInfo.pAuthAttrs = pAuthAttrs;
    mySignerInfo.authAttrsLen = authAttrsLen;
    mySignerInfo.unauthAttrsLen = 0;
    mySignerInfoPtr[0]=&mySignerInfo;

    status = PKCS7_SignData( MOC_ASYM( hwAccelCtx)
                            0, NULL, NULL, pCACertificates,
                            pCAStreams, numCACerts,
                            pCrls, pCrlStreams, numCrls,
                            mySignerInfoPtr, 1,
                            payLoadType, pPayLoad, payLoadLen,
                            rngFun, rngFunArg, ppSigned, pSignedLen);
exit:

    CRYPTO_uninitAsymmetricKey (&key, (struct vlong **)0);
    if (pCertificate)
    {
        TREE_DeleteTreeItem( &pCertificate->treeItem);
    }
    RANDOM_releaseContext(&pRandomContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;

}

#endif /* __ENABLE_DIGICERT_PKCS__ */
