/*
 * cert_chain.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

/**
 * @file       cert_chain.h
 *
 * @brief      Header file for ASN.1 Certificate Chain Verification.
 * @details    Header file for ASN.1 Certificate Chain Verification.
 *
 * @filedoc    cert_chain.h
 */

#ifndef __CERT_CHAIN_HEADER__
#define __CERT_CHAIN_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

struct certChain;
typedef struct certChain* certChainPtr;

struct certStore;
struct TimeDate;
struct AsymmetricKey;

/**
 * @brief      Validation configuration structure.
 * @details    Validation configuration structure.
 */
typedef struct ValidationConfig
{
    /**
     * @brief      Cert store to use for trust points. May be NULL.
     * @details    Cert store to use for trust points. May be NULL.
     */
    struct certStore* pCertStore;
    
    /**
     * @brief      Found anchor in cert store if any.
     * @details    Found anchor in cert store if any.
     */
    const ubyte* anchorCert;
    
    /**
     * @brief      Found anchor length in certstore if any.
     * @details    Found anchor length in certstore if any.
     */
    ubyte4 anchorCertLen;
    
    /**
     * @brief      Time to use for validation. May be NULL.
     * @details    Time to use for validation. May be NULL.
     */
    const struct TimeDate *td;
    
    /**
     * @brief      Common name. May be NULL.
     * @details    Common name. May be NULL.
     */
    const sbyte* commonName;
    
    /**
     * @brief      Bits (0-8) that must be set if KeyUsage is present.
     * @details    Bits (0-8) that must be set if KeyUsage is present.
     */
    ubyte2 keyUsage;
    
    /**
     * @brief      NULL terminated array of OIDs that must be present in
     *             the certificate extended key usage if present. May be NULL.
     * @details    NULL terminated array of OIDs that must be present in
     *             the certificate extended key usage if present. May be NULL.
     */
    const ubyte** extendedKeyUsage;
    
} ValidationConfig;
    

/* Note (1): param can be null */


/* build a certificate chain from an SSL Certificate message
 pSSLCertificateMsg starts at the CertificateChainLength field
 and the sslCertificateMsgLen is the value of the medium after the
 message type (11) */

MOC_EXTERN MSTATUS
CERTCHAIN_getCertificateExtensions(certChainPtr pCertChain,
                                   ubyte4 index,
                                   ubyte **ppCertExts,
                                   ubyte4 *pCertExtLen);

MOC_EXTERN MSTATUS
CERTCHAIN_getCertificateExtensionsCertStatus(certChainPtr pCertChain,
                                   ubyte4 index,
                                   ubyte **ppOcspExt,
                                   ubyte4 *pOcspExtLen);

/**
 * @brief   Build a certificate chain from an SSL Certificate message.
 *
 * @details Build a certificate chain from an SSL Certificate message.
 *          This method allocates memory so be sure to call
 *          \c CERTCHAIN_delete when done with the new cert chain.
 *
 * @param ppNewCertChain        Pointer to the location of the newly allocated certificate chain.
 * @param pSSLCertificateMsg    The SSL certificate message. This should be a pointer to the
 *                              certificate chain length (medium) field after the message type (11).
 * @param sslCertificateMsgLen  The length of pSSLCertificateMsg buffer in bytes. This should be
 *                              the number of bytes after the message type (11), so 3
 *                              bytes more than the length contained in the medium length.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_createFromSSLRecord(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                                 certChainPtr* ppNewCertChain,
                                                 const ubyte* pSSLCertificateMsg,
                                                 ubyte4 sslCertificateMsgLen);

MOC_EXTERN MSTATUS CERTCHAIN_createFromSSLRecordEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                                 certChainPtr* ppNewCertChain,
                                                 const ubyte* pSSLCertificateMsg,
                                                 ubyte4 sslCertificateMsgLen,
                                                 ubyte sslMinorVersion);

MOC_EXTERN MSTATUS CERTCHAIN_createFromSSLRecordOriginal(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                                 certChainPtr* ppNewCertChain,
                                                 const ubyte* pSSLCertificateMsg,
                                                 ubyte4 sslCertificateMsgLen,
                                                 ubyte sslMinorVersion);
#ifdef __ENABLE_MOCANA_CV_CERT__
/**
 * @brief   Build a certificate chain from an SSL Certificate message.
 *
 * @details Build a certificate chain from an SSL Certificate message.
 *          This method allocates memory so be sure to call
 *          \c CERTCHAIN_delete when done with the new cert chain.
 *
 * @param ppNewCertChain        Pointer to the location of the newly allocated certificate chain.
 * @param pSSLCertificateMsg    The SSL certificate message. This should be a pointer to the
 *                              certificate chain length (medium) field after the message type (11).
 * @param sslCertificateMsgLen  The length of pSSLCertificateMsg buffer in bytes. This should be
 *                              the number of bytes after the message type (11), so 3
 *                              bytes more than the length contained in the medium length.
 * @param pIsCvc                Will be set to TRUE if the cert chain is formed using CV certificates.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_CVC_createFromSSLRecordEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                                       certChainPtr* ppNewCertChain,
                                                       const ubyte* pSSLCertificateMsg,
                                                       ubyte4 sslCertificateMsgLen,
                                                       ubyte sslMinorVersion,
                                                       byteBoolean *pIsCvc);
#endif

#if (defined(__ENABLE_MOCANA_SSH_CLIENT__) || defined(__ENABLE_MOCANA_SSH_SERVER__))

typedef MSTATUS (*funcPtrWalkStr)(const ubyte *, ubyte4, ubyte4 *);

/**
 * @brief   Build a certificate chain from an SSH Certificate chain buffer.
 *
 * @details Build a certificate chain from an SSH Certificate chain buffer.
 *          This method allocates memory so be sure to call
 *          \c CERTCHAIN_delete when done with the new cert chain.
 *
 * @param ppNewCertChain        Pointer to the location of the newly allocated certificate chain.
 * @param pSSHCertChainBuf      The SSH certificate chain buffer.
 * @param sshCertChainBufLen    The length of pSSHCertChainBuf buffer in bytes.
 * @param pBufIndex             Contents should begin at the offset in the pSSHCertChainBuf
 *                              buffer where the certificate chain begins. This is the number of
 *                              certificates in the chain field. Contents will be updated to
 *                              the end of the certificate chain buffer when done.
 * @param walkStrFunc           Function pointer that performs an SSH string walk.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_createFromSSHEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           certChainPtr* ppNewCertChain,
                                           const ubyte* pSSHCertChainBuf,
                                           ubyte4 sshCertChainBufLen,
                                           ubyte4 *pBufIndex,
                                           funcPtrWalkStr walkStrFunc);


#ifndef __DISABLE_MOCANA_CERT_CHAIN_SSH_DEP__
/**
 * @brief   Build a certificate chain from an SSH Certificate chain buffer.
 *
 * @details Build a certificate chain from an SSH Certificate chain buffer.
 *          This method allocates memory so be sure to call
 *          \c CERTCHAIN_delete when done with the new cert chain.
 *
 * @param ppNewCertChain        Pointer to the location of the newly allocated certificate chain.
 * @param pSSHCertChainBuf      The SSH certificate chain buffer.
 * @param sshCertChainBufLen    The length of pSSHCertChainBuf buffer in bytes.
 * @param pBufIndex             Contents should begin at the offset in the pSSHCertChainBuf
 *                              buffer where the certificate chain begins. This is the number of
 *                              certificates in the chain field. Contents will be updated to
 *                              the end of the certificate chain buffer when done.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_createFromSSH(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           certChainPtr* ppNewCertChain,
                                           const ubyte* pSSHCertChainBuf,
                                           ubyte4 sshCertChainBufLen,
                                           ubyte4 *pBufIndex);
#endif /* __DISABLE_MOCANA_CERT_CHAIN_SSH_DEP__ */
#endif /* (defined(__ENABLE_MOCANA_SSH_CLIENT__) || defined(__ENABLE_MOCANA_SSH_SERVER__)) */

struct certDescriptor;

/**
 * @brief   Build a certificate chain from a certificate descriptor.
 *
 * @details Build a certificate chain from a certificate descriptor.
 *          This method allocates memory so be sure to call
 *          \c CERTCHAIN_delete when done with the new cert chain.
 *
 * @param ppNewCertChain  Pointer to the location of the newly allocated certificate chain.
 * @param certiDesc       Array of certificate descriptors. Please see the \c certDescriptor
 *                        type definition in ca_mgmt.h.
 * @param numCertDesc     The number of certificate descriptors in the array certiDesc.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           certChainPtr* ppNewCertChain,
                                           struct certDescriptor certiDesc[],
                                           ubyte4 numCertDesc);

#ifdef __ENABLE_MOCANA_CV_CERT__

/**
 * @brief   Build a certificate chain from a certificate descriptor containing CV certs.
 *
 * @details Build a certificate chain from a certificate descriptor.
 *          This method allocates memory so be sure to call
 *          \c CERTCHAIN_delete when done with the new cert chain.
 *
 * @param ppNewCertChain  Pointer to the location of the newly allocated certificate chain.
 * @param certiDesc       Array of certificate descriptors. Please see the \c certDescriptor
 *                        type definition in ca_mgmt.h.
 * @param numCertDesc     The number of certificate descriptors in the array certiDesc.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_createFromCVC(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           certChainPtr* ppNewCertChain,
                                           struct certDescriptor certiDesc[],
                                           ubyte4 numCertDesc);

#endif

/**
 * @brief   Gets the number of certificates in a chain.
 *
 * @details Gets the number of certificates in a chain.
 *
 * @param pCertChain   Pointer to the input certificate chain.
 * @param numCerts     Contents will be set to the number of certificates in the chain.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_numberOfCertificates(certChainPtr pCertChain,
                                                  ubyte4* numCerts);

/* get certificate in the chain, 0 == leaf, last = chain root */

/**
 * @brief   Gets a certificate from a chain.
 *
 * @details Gets a certificate from a chain. Index 0 is the leaf certificate and the last valid index will
 *          be the root certificate. Memory is not allocated by this method.
 
 * @param pCertChain      Pointer to the input certificate chain.
 * @param indexInChain    The index to retrieve, with 0 being the leaf and the last valid
 *                        index being the root.
 * @param certDerData     Pointer to the location of the requested certificate in DER form.
 * @param certDerDataLen  Contents will be set to the length of the requested certificate in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_getCertificate(certChainPtr pCertChain,
                                            ubyte4 indexInChain,
                                            const ubyte** certDerData,
                                            ubyte4* certDerDataLen);
/**
 * @brief   Gets the public key of a certificate from a chain.
 *
 * @details Gets the public key of a certificate from a chain. Index 0 is the leaf certificate and the last valid index will
 *          be the root certificate. Memory is not allocated by this method.
 *
 * @param pCertChain      Pointer to the input certificate chain.
 * @param indexInChain    The index to retrieve, with 0 being the leaf and the last valid
 *                        index being the root.
 * @param pubKey          Pointer to a previously initialized \c AsymmetricKey. This key will
 *                        be set according to the certificate found via the indexInChain passed in.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_getKey(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                    certChainPtr pCertChain,
                                    ubyte4 indexInChain,
                                    struct AsymmetricKey* pubKey);

#ifdef __ENABLE_MOCANA_CERTIFICATE_SEARCH_SUPPORT__
/**
 * @brief   Gets the RSA hash algorithm in a certificate from a chain.
 *
 * @details Gets the RSA hash algorithm in a certificate from a chain. Index 0 is the leaf certificate and the last valid index will
 *          be the root certificate.
 *
 * @param pCertChain      Pointer to the input certificate chain.
 * @param indexInChain    The index to retrieve, with 0 being the leaf and the last valid
 *                        index being the root.
 * @param sigAlgo         Contents will be set to the hash algorithm identifier found in the
 *                        requested certificate. This is one of the ht_<...> types found in crypto.h.
 *                        Note this is stored in a single byte.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_getRSASigAlgo(certChainPtr pCertChain,
                                           ubyte4 indexInChain,
                                           ubyte *sigAlgo);
#endif

/**
 * @brief   Checks whether the last certificate in the chain is a self-signed certificate.
 *
 * @details Checks whether the last certificate in the chain is a self-signed certificate.
 *
 * @param pCertChain      Pointer to the input certificate chain.
 * @param complete        Contents will be set to TRUE if the last certificate is self-signed.
 *                        and FALSE otherwise.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_isComplete(certChainPtr pCertChain,
                                        intBoolean* complete);

#if !defined(__DISABLE_MOCANA_CERTIFICATE_PARSING__)
/**
 * @brief   Validates a certificate chain with respect to a validation configuration.
 *
 * @details Validates a certificate chain with respect to a validation configuration.
 *          Options in the configuration are to
 *
 *          + validate a certificate in the chain (or its parent) are in a trusted cert store.
 *          + validate the certificate dates (including the possible parent found in a trusted cert store).
 *          + validate the leaf certificate's common name, key usage, or extended key usage.
 *
 *          If the root of trust certificate was not in the cert chain but was
 *          found in the cert store, this method will optionally output it. Please also see the description
 *          of the \c ValidationConfig type.
 *
 * @param pCertChain        Pointer to the input cert chain to be validated.
 * @param validationConfig  Pointer to the input validation config. If the root of trust certificate
 *                          was not in the cert chain but was in the cert store, the anchorCert
 *                          field and anchorCertLen field will be set to it and its length in bytes.
 *
 * @return  \c OK (0) if successful and all validation is valid, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_validate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                      certChainPtr pCertChain,
                                      ValidationConfig* validationConfig);

#ifdef __ENABLE_MOCANA_CV_CERT__

/**
 * @brief   Validates a CV certificate chain with respect to a validation configuration.
 *
 * @details Validates a certificate chain with respect to a validation configuration.
 *          Options in the configuration are to
 *
 *          + validate a certificate in the chain (or its parent) are in a trusted cert store.
 *          + validate the certificate dates (including the possible parent found in a trusted cert store).
 *
 *          If the root of trust certificate was not in the cert chain but was
 *          found in the cert store, this method will optionally output it. Please also see the description
 *          of the \c ValidationConfig type.
 *
 * @param pCertChain        Pointer to the input cert chain to be validated, created using CERTCHAIN_createFromCVC.
 * @param validationConfig  Pointer to the input validation config. If the root of trust certificate
 *                          was not in the cert chain but was in the cert store, the anchorCert
 *                          field and anchorCertLen field will be set to it and its length in bytes.
 *
 * @return  \c OK (0) if successful and all validation is valid, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_CVC_validate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                      certChainPtr pCertChain,
                                      ValidationConfig* validationConfig);

#endif

/**
 * @brief      Validates an array of certificates with respect to a validation configuration.
 *             and upon success will return the certificates in a certificate chain form.
 *
 * @details    Validates an array of certificates with respect to a validation configuration
 *             and upon success will return the certificates in a certificate chain form.
 *             The array of certificates can be in any order. Validation will only be done with
 *             respect to a trusted cert store and with respect to dates of validity.
 *             This function will also allow self-signed certificates. The certificate array
 *             provided to this function must only contain DER encoded certificates. Note also
 *             if validation is successful then memory will be allocated to store the resulting
 *             chain. Please be sure to use \c CERTCHAIN_delete to delete it when done with it.
 *
 * @param pCertArr    Pointer to the array of certificates. All certificates
 *                    within the certificate chain must be DER encoded.
 * @param certArrLen  Length of the certificate array in bytes.
 * @param pConfig     Pointer to the ValidationConfig struct. This struct
 *                    must contain which certificate store to validate against and
 *                    optionally may contain the time to validate against.
 * @param ppRetChain  Pointer to the location of the resulting chain. The certificate
 *                    chain will only be computed if the validation was successful.
 *
 * @return  \c OK (0) if successful and all validation is valid, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_validateAll(MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCertArr, sbyte4 certArrLen, ValidationConfig *pConfig,
    certChainPtr *ppRetChain);
#endif

/**
 * @brief   Deletes a certificate chain and alll memory allocated within it.
 *
 * @details Deletes a certificate chain and alll memory allocated within it.
 *
 * @param ppCertChain  Pointer to the location of the certificate chain to be deleted.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS CERTCHAIN_delete( certChainPtr* ppCertChain);

/**
 * @brief   Takes an SSL certificate message. Returns number of certs in record.
 *
 * @details Takes an SSL certificate message. Returns number of certs in record.
 *
 * @param pSSLCertificateMsg    The SSL certificate message. This should be a pointer to the
 *                              certificate chain length (medium) field after the message type (11).
 * @param sslCertificateMsgLen  The length of pSSLCertificateMsg buffer in bytes. This should be
 *                              the number of bytes after the message type (11), so 3
 *                              bytes more than the length contained in the medium length.
 * @param pCertNum              Pointer to location where cert count is written to.
 *
 * @return  \c OK (0) if successful, otherwise a negative number
 *          error code from merrors.h.
 */
MOC_EXTERN MSTATUS
CERTCHAIN_getSSLRecordCertNum(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    const ubyte* pSSLCertificateMsg,
    ubyte4 sslCertificateMsgLen,
    ubyte sslMinorVersion,
    ubyte4 *pCertNum);

#ifdef __cplusplus
}
#endif

#endif /* __CERT_CHAIN_HEADER__ */
