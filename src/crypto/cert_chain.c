/*
 * cert_chain.c
 *
 * Certificate Chain Verification
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"

#include "../common/tree.h"
#include "../common/sizedbuffer.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/oiddefs.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"

#if (defined(__ENABLE_DIGICERT_SSH_CLIENT__) || defined(__ENABLE_DIGICERT_SSH_SERVER__))
#include "../ssh/ssh_str.h"
#endif

#include "cert_chain.h"

#ifdef __ENABLE_DIGICERT_CV_CERT__
#include "../crypto/cvcert.h"
#endif

#define SSL_MEDIUM_SIZE  (3)
#define SSL_TLS13_MINORVERSION (4)
#define SSL_TLS12_MINORVERSION (3)

#define SSL_DTLS13_MINORVERSION (252)
#define SSL_DTLS12_MINORVERSION (253)

typedef struct certChainEntry
{
    /* raw data */
    ubyte4 certLength;
    const ubyte* cert;
    /* Certificate extensions - points to the first extension type stored in a
     * TLS 1.3 certificate chain CertificateEntry structure. The length is the
     * length of all the extensions. Each extension is composed of the type
     * bytes followed by the extension length bytes followed by the actual
     * extension data itself. */
    const ubyte *pCertExt;
    ubyte4 certExtLen;
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)
    /* OCSP request - points to the OCSP extension stored in a TLS 1.3
     * certificate chain CertificateEntry structure. The extension type and
     * extension length bytes are not included. The length is the length
     * of just the OCSP extension. */
    const ubyte *pOcspExt;
    ubyte4 ocspExtLen;
#endif /* __ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__ */
    /* ASN.1 parsing tree */
    ASN1_ITEMPTR pRoot;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    CV_CERT *pCertData;
#endif
} certChainEntry;

/* This enumeration is for TLS 1.3 certificate extensions
 */
enum tls13CertExtTypes
{
    tlsExt_status_request = 5,
    tlsExt_signed_certificate_timestamp = 18
};

typedef struct certChain
{
    ubyte*              buffer;         /* data from all the certificates */
    sbyte4              numCerts;       /* number of certificates in chain */
    ubyte4              isComplete:1;
    certChainEntry      certs[1];       /* the certs, pointer to the data inside buffer */
} certChain;


typedef struct testAnchorArg
{
    ASN1_ITEMPTR pCertificate;
    CStream rcs;
    sbyte4 chainLength;
    ASN1_ITEMPTR pValidAnchorRoot;
} testAnchorArg;

#ifdef __ENABLE_DIGICERT_CV_CERT__
typedef struct testAnchorArgCvc
{
    CV_CERT *pCertificate;
    CV_CERT *pValidAnchorRoot;
} testAnchorArgCvc;
#endif
/*---------------------------------------------------------------------------*/

static void
CERTCHAIN_deleteCertChainEntry(certChainEntry* pCCE)
{
    if (pCCE->pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pCCE->pRoot);
    }
#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (pCCE->pCertData)
    {
        DIGI_FREE((void **)&pCCE->pCertData);
    }
#endif
}


/*---------------------------------------------------------------------------*/

static ubyte2
getMediumValue(const ubyte* med)
{
    return  (ubyte2)(((ubyte2)med[1] << 8) | (med[2]));
}

/*---------------------------------------------------------------------------*/

static ubyte2
getShortValue(const ubyte* med)
{
    return  (ubyte2)(((ubyte2)med[0] << 8) | (med[1]));
}

/*---------------------------------------------------------------------------*/

static MSTATUS
CERTCHAIN_swapEntries(
                   certChainEntry *pCertA,
                   certChainEntry *pCertB)
{
    certChainEntry tmpCert = {0};

    if (NULL == pCertA || NULL == pCertB)
        return ERR_NULL_POINTER;

    /* swap parent with next */
    tmpCert.cert = pCertA->cert;
    tmpCert.certLength = pCertA->certLength;
    tmpCert.pCertExt = pCertA->pCertExt;
    tmpCert.certExtLen = pCertA->certExtLen;
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)
    tmpCert.pOcspExt = pCertA->pOcspExt;
    tmpCert.ocspExtLen = pCertA->ocspExtLen;
#endif
    tmpCert.pRoot = pCertA->pRoot;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    tmpCert.pCertData = pCertA->pCertData;
#endif

    pCertA->cert = pCertB->cert;
    pCertA->certLength = pCertB->certLength;
    pCertA->pCertExt = pCertB->pCertExt;
    pCertA->certExtLen = pCertB->certExtLen;
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)
    pCertA->pOcspExt = pCertB->pOcspExt;
    pCertA->ocspExtLen = pCertB->ocspExtLen;
#endif
    pCertA->pRoot = pCertB->pRoot;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    pCertA->pCertData = pCertB->pCertData;
#endif

    pCertB->cert = tmpCert.cert;
    pCertB->certLength = tmpCert.certLength;
    pCertB->pCertExt = tmpCert.pCertExt;
    pCertB->certExtLen = tmpCert.certExtLen;
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)
    pCertB->pOcspExt = tmpCert.pOcspExt;
    pCertB->ocspExtLen = tmpCert.ocspExtLen;
#endif
    pCertB->pRoot = tmpCert.pRoot;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    pCertB->pCertData = tmpCert.pCertData;
#endif

    return OK;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

static MSTATUS CERTCHAIN_CVC_finishBuild(MOC_ASYM(hwAccelDescr hwAccelCtx) certChainPtr pCertChain)
{
    sbyte4 i;
    MSTATUS status;
    certChainEntry* pLastEntry;

    /* parse the certs */
    for (i = 0; i < pCertChain->numCerts; ++i)
    {
        certChainEntry* currCert = pCertChain->certs + i;

        status = CV_CERT_parseCert((ubyte *) currCert->cert, currCert->certLength, &currCert->pCertData);
        if (OK != status)
            goto exit;
    }

    /* is this a complete chain (top certificate is self-signed)
     or an open one? Note: cs is still linked to the right buffer */
    pLastEntry = pCertChain->certs + pCertChain->numCerts - 1;

    status = CV_CERT_isRootCert(pLastEntry->pCertData);
    switch (status)
    {
        case OK:
            pCertChain->isComplete = 1;
            break;
        case ERR_FALSE:
            pCertChain->isComplete = 0;
            break;
        default: /*error*/
            goto exit;
    }

    if (pCertChain->isComplete)
    {
        /* validate the root certificate. */
        status = PARSE_CV_CERT_validateLink(MOC_ASYM(hwAccelCtx) pLastEntry->pCertData, pLastEntry->pCertData);
        if (OK != status)
        {
            goto exit;
        }
    }

    /* validate the certificates chain w/o policy, time or external data => */
    /* issuer of cert is subject of next cert, verify signature, check extensions */
    for ( i = pCertChain->numCerts-2; i >=0; --i)
    {
        certChainEntry* currCert = pCertChain->certs + i;
        certChainEntry* parentCert = pCertChain->certs + i + 1;

        /* cert chain length for currCert is i */
        status = PARSE_CV_CERT_validateLink(MOC_ASYM(hwAccelCtx) currCert->pCertData, parentCert->pCertData);
        if (OK > status)
        {
            goto exit;
        }
    }
    status = OK;
exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

static MSTATUS CERTCHAIN_finishBuild(MOC_ASYM(hwAccelDescr hwAccelCtx) certChainPtr pCertChain)
{
    sbyte4 i;
    CStream cs;
    MemFile mf;
    MSTATUS status;
    certChainEntry* pLastEntry;

    /* Init the CStream in case there are no certs.
     */
    status = DIGI_MEMSET ((void *)&cs, 0, sizeof (CStream));
    if (OK != status)
      goto exit;

    /* parse the certs */
    for (i = 0; i < pCertChain->numCerts; ++i)
    {
        certChainEntry* currCert = pCertChain->certs + i;

        MF_attach(&mf, currCert->certLength, (ubyte*) currCert->cert);
        CS_AttachMemFile(&cs, &mf);

        status = X509_parseCertificate(cs, &currCert->pRoot);
        if (OK > status)
        {
            goto exit;
        }
    }

    /* is this a complete chain (top certificate is self-signed)
     or an open one? Note: cs is still linked to the right buffer */
    pLastEntry = pCertChain->certs + pCertChain->numCerts - 1;

    status = X509_isRootCertificate(ASN1_FIRST_CHILD(pLastEntry->pRoot), cs);
    switch (status)
    {
        case OK:
            pCertChain->isComplete = 1;
            break;
        case ERR_FALSE:
            pCertChain->isComplete = 0;
            break;
        default: /*error*/
            goto exit;
    }

    if (pCertChain->isComplete)
    {
        /* validate the root certificate. Again cs is still linked to the
         right buffer */
        status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                                   ASN1_FIRST_CHILD(pLastEntry->pRoot), cs,
                                   ASN1_FIRST_CHILD(pLastEntry->pRoot), cs,
                                   pCertChain->numCerts-1);
        if (OK > status)
        {
            goto exit;
        }
    }

    /* validate the certificates chain w/o policy, time or external data => */
    /* issuer of cert is subject of next cert, verify signature, check extensions */
    for ( i = pCertChain->numCerts-2; i >=0; --i)
    {
        certChainEntry* currCert = pCertChain->certs + i;
        certChainEntry* parentCert = pCertChain->certs + i + 1;
        CStream parentCs;
        MemFile parentMf;

        MF_attach(&mf, currCert->certLength, (ubyte*) currCert->cert);
        CS_AttachMemFile(&cs, &mf);

        MF_attach(&parentMf, parentCert->certLength, (ubyte*) parentCert->cert);
        CS_AttachMemFile(&parentCs, &parentMf);

        /* cert chain length for currCert is i */
        status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                                   ASN1_FIRST_CHILD(currCert->pRoot), cs,
                                   ASN1_FIRST_CHILD(parentCert->pRoot), parentCs, i);
        if (OK > status)
        {
            goto exit;
        }
    }
    status = OK;
exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CERTCHAIN_originalChain(MOC_ASYM(hwAccelDescr hwAccelCtx) certChainPtr pCertChain)
{
    sbyte4 i;
    CStream cs;
    MemFile mf;
    MSTATUS status;

    certChainEntry* currCert;

    /* Init the CStream in case there are no certs.
     */
    status = DIGI_MEMSET ((void *)&cs, 0, sizeof (CStream));
    if (OK != status)
      goto exit;

    /* parse the certs */
    for (i = 0; i < pCertChain->numCerts; ++i)
    {
        currCert = pCertChain->certs + i;

        MF_attach(&mf, currCert->certLength, (ubyte*) currCert->cert);
        CS_AttachMemFile(&cs, &mf);

        status = X509_parseCertificate(cs, &currCert->pRoot);
        if (OK > status)
        {
            goto exit;
        }
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CERTCHAIN_finishBuildEx(MOC_ASYM(hwAccelDescr hwAccelCtx) certChainPtr pCertChain)
{
    sbyte4 i, j, k;
    sbyte4 count;
    sbyte4 tmp;
    CStream cs;
    MemFile mf;
    MSTATUS status;
    sbyte4* pParents = NULL;
    sbyte4* pChildren = NULL;
    certChainEntry* pLastEntry = NULL;
    certChainEntry* currCert;
    sbyte4 kChild = 0;
    sbyte4 kParent = 0;
    sbyte4 jChild = 0;
    sbyte4 jParent = 0;

    /* Init the CStream in case there are no certs.
     */
    status = DIGI_MEMSET ((void *)&cs, 0, sizeof (CStream));
    if (OK != status)
      goto exit;

    /* parse the certs */
    for (i = 0; i < pCertChain->numCerts; ++i)
    {
        currCert = pCertChain->certs + i;

        MF_attach(&mf, currCert->certLength, (ubyte*) currCert->cert);
        CS_AttachMemFile(&cs, &mf);

        status = X509_parseCertificate(cs, &currCert->pRoot);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = DIGI_MALLOC(
        (void **) &pParents, sizeof(sbyte4) * pCertChain->numCerts);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MALLOC(
        (void **) &pChildren, sizeof(sbyte4) * pCertChain->numCerts);
    if (OK > status)
    {
        goto exit;
    }
    for (i = 0; i < pCertChain->numCerts; i++)
    {
        pParents[i] = -1;
        pChildren[i] = -1;
    }

    /* validate the certificates chain w/o policy, time or external data => */
    /* issuer of cert is subject of next cert, verify signature, check extensions */
    for (i = 0; i < pCertChain->numCerts; i++)
    {
        currCert = pCertChain->certs + i;

        MF_attach(&mf, currCert->certLength, (ubyte*) currCert->cert);
        CS_AttachMemFile(&cs, &mf);

        for (j = 0; j < pCertChain->numCerts; j++)
        {
            certChainEntry* parentCert = pCertChain->certs + j;
            CStream parentCs;
            MemFile parentMf;

            MF_attach(&parentMf, parentCert->certLength, (ubyte*) parentCert->cert);
            CS_AttachMemFile(&parentCs, &parentMf);

            /* Cannot determine certificate chain length here since we do not
             * know which certificate we're at in the chain. Pass 0 to ignore
             * the chain length check.
             */
            status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                                    ASN1_FIRST_CHILD(currCert->pRoot), cs,
                                    ASN1_FIRST_CHILD(parentCert->pRoot), parentCs, 0);
            if (OK == status)
            {
                pParents[i] = j;
                if (i != j)
                {
                    pChildren[j] = i;
                }
                break;
            }
        }
    }

    i = 0; /* 1st certificate is the leaf certificate */
    j = 0;

    /* Loop until the top of the certificate chain is found.
     */
    while (NULL == pLastEntry && j < pCertChain->numCerts)
    {
        /* If this certificate has no parent or it is self-signed assume its
         * the last certificate in the chain.
         */
        if (-1 == pParents[i] || pParents[i] == i)
        {
            pLastEntry = pCertChain->certs + i;
        }
        else
        {
            i = pParents[i];
            currCert = pCertChain->certs + i;

            MF_attach(&mf, currCert->certLength, (ubyte*) currCert->cert);
            CS_AttachMemFile(&cs, &mf);

            /* Validate the certificate chain signing depth correctly. Verify
             * parent certificate chain can sign j certificates down.
             */
            status = X509_canSignChain(
                ASN1_FIRST_CHILD(currCert->pRoot), cs, j);
            if (OK != status)
            {
                goto exit;
            }

            j++;
        }
    }

    /* If we have looped through all the certificates and have not found the
     * last entry then something is wrong with the set of certificates.
     */
    if ((j == pCertChain->numCerts) || (NULL == pLastEntry))
    {
        status = ERR_CERT_BUFFER_OVERFLOW;
        goto exit;
    }

    /* Check if the last certificate is a root certificate or not
     */
    MF_attach(&mf, pLastEntry->certLength, (ubyte*) pLastEntry->cert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_isRootCertificate(ASN1_FIRST_CHILD(pLastEntry->pRoot), cs);
    switch (status)
    {
        case OK:
            pCertChain->isComplete = 1;
            break;
        case ERR_FALSE:
            pCertChain->isComplete = 0;
            status = OK;
            break;
        default: /*error*/
            goto exit;
    }

    if (pCertChain->isComplete)
    {
        /* validate the root certificate. Again cs is still linked to the
         right buffer */
        status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                                   ASN1_FIRST_CHILD(pLastEntry->pRoot), cs,
                                   ASN1_FIRST_CHILD(pLastEntry->pRoot), cs,
                                   j);
        if (OK > status)
        {
            goto exit;
        }
    }

    for (i = 0; i < pCertChain->numCerts; i++)
    {
        if (i == pParents[i])
        {
            pParents[i] = -1;
        }
    }

    i = 0; /* 1st certificate is the leaf certificate */
    j = 1; /* the next certificate in chain */
    count = 1; /* number of certs in chain */

    kChild = 0;
    kParent = 0;
    jChild = 0;
    jParent = 0;
    while (j < pCertChain->numCerts)
    {
        certChainEntry* pNextCert = pCertChain->certs + j;
        /* if certificate has no parent, it is end of certificate chain */
        if (-1 == pParents[i])
        {
            break;
        }

        if (j != pParents[i])
        {
            certChainEntry* pParentCert = pCertChain->certs + pParents[i];

            CERTCHAIN_swapEntries(pNextCert, pParentCert);
            k = pParents[i];

            kChild = pChildren[k];
            kParent = pParents[k];

            jChild = pChildren[j];
            jParent = pParents[j];

            if (j == pParents[k])
            {
                pParents[k] = pParents[j];
                pParents[j] = k;

                pChildren[j] = pChildren[k];
                pChildren[k] = j;

                if (kChild >= 0)
                {
                    pParents[kChild] = j;
                }

                if (jParent >= 0)
                {
                    pChildren[jParent] = k;
                }
            }
            else if (k == pParents[j])
            {
                pParents[j] = pParents[k];
                pParents[k] = j;

                pChildren[k] = pChildren[j];
                pChildren[j] = k;

                if (jChild >= 0)
                {
                    pParents[jChild] = k;
                }

                if (kParent >= 0)
                {
                    pChildren[kParent] = j;
                }
            }
            else
            {
                tmp = pParents[k];
                pParents[k] = pParents[j];
                pParents[j] = tmp;

                tmp = pChildren[k];
                pChildren[k] = pChildren[j];
                pChildren[j] = tmp;

                if (kParent >= 0)
                {
                    pChildren[kParent] = j;
                }

                if (kChild >= 0)
                {
                    pParents[kChild] = j;
                }

                if (jParent >= 0)
                {
                    pChildren[jParent] = k;
                }

                if (jChild >= 0)
                {
                    pParents[jChild] = k;
                }
            }

        }
        i++;
        j++;
        count++;
    }

    if (count < pCertChain->numCerts)
    {
        for (i = count; i < pCertChain->numCerts; i++)
        {
            CERTCHAIN_deleteCertChainEntry(pCertChain->certs + i);
        }
        pCertChain->numCerts = count;
    }

exit:

    if (NULL != pParents)
    {
        DIGI_FREE((void **) &pParents);
    }

    if (NULL != pChildren)
    {
        DIGI_FREE((void **) &pChildren);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
CERTCHAIN_getCertificateExtensions(certChainPtr pCertChain,
                                   ubyte4 index,
                                   ubyte **ppCertExts,
                                   ubyte4 *pCertExtLen)
{
    if ( (NULL == pCertChain) || (NULL == ppCertExts) || (NULL == pCertExtLen) )
    {
        return ERR_NULL_POINTER;
    }

    if ((sbyte4)index >= pCertChain->numCerts)
    {
        return ERR_INDEX_OOB;
    }

    *ppCertExts = (ubyte*)pCertChain->certs[index].pCertExt;
    *pCertExtLen = pCertChain->certs[index].certExtLen;

    return OK;
}

/*---------------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)

extern MSTATUS
CERTCHAIN_getCertificateExtensionsCertStatus(certChainPtr pCertChain,
                                   ubyte4 index,
                                   ubyte **ppOcspExt,
                                   ubyte4 *pOcspExtLen)
{
    if ( (NULL == pCertChain) || (NULL == ppOcspExt) || (NULL == pOcspExtLen) )
    {
        return ERR_NULL_POINTER;
    }

    if ((sbyte4) index >= pCertChain->numCerts)
    {
        return ERR_INDEX_OOB;
    }

    *ppOcspExt = (ubyte*)pCertChain->certs[index].pOcspExt;
    *pOcspExtLen = pCertChain->certs[index].ocspExtLen;

    return OK;
}

#endif /* __ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__ */

/*---------------------------------------------------------------------------*/

extern MSTATUS
CERTCHAIN_getSSLRecordCertNum(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    const ubyte* pSSLCertificateMsg,
    ubyte4 sslCertificateMsgLen,
    ubyte sslMinorVersion,
    ubyte4 *pCertNum)
{
    MSTATUS status = OK;
    ubyte2 len;
    ubyte2 extensionsLength = 0;
    ubyte4 remain;
    ubyte4 numCerts;

    const ubyte* p;

    if (NULL == pSSLCertificateMsg || NULL == pCertNum)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == sslCertificateMsgLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (sslCertificateMsgLen < SSL_MEDIUM_SIZE)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE;
        goto exit;
    }
    /* read the medium which is the certificate chain length */
    len = getMediumValue(pSSLCertificateMsg);

    /* Error for empty certificate */
    if (0 == len)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE;
        goto exit;
    }

    /* should always be sslCertificateMsgLen - 3 */
    if (len != (sslCertificateMsgLen - SSL_MEDIUM_SIZE))
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE;
        goto exit;
    }

    /* figure out the total number of certificates */
    p = pSSLCertificateMsg + SSL_MEDIUM_SIZE;
    remain = sslCertificateMsgLen - SSL_MEDIUM_SIZE;
    numCerts = 0;
    while (remain >= SSL_MEDIUM_SIZE)
    {
        /* length of certificate */
        len = getMediumValue(p);
        p += SSL_MEDIUM_SIZE;
        remain -= SSL_MEDIUM_SIZE;

        if (len <= remain)
        {
            /* one more cert */
            ++numCerts;
            /* go over the cert */
            p += len;
            remain -= len;

            if (SSL_TLS13_MINORVERSION == sslMinorVersion || SSL_DTLS13_MINORVERSION == sslMinorVersion)
            {
                if (2 > remain)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                extensionsLength = getShortValue(p);

                remain -= 2;
                p      += 2;

                if(remain >= extensionsLength)
                {
                    remain -= extensionsLength;
                    p      += extensionsLength;
                }
            }
        }
    }
    /* at the end of this, remain should be zero */
    if (remain || 0 == numCerts)
    {
        status = ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE;
        goto exit;
    }

    *pCertNum = numCerts;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
CERTCHAIN_createFromSSLRecordEx2(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              certChainPtr* ppNewCertChain,
                              const ubyte* pSSLCertificateMsg,
                              ubyte4 sslCertificateMsgLen,
                              ubyte sslMinorVersion,
                              byteBoolean *pIsCvc, byteBoolean validateChain)
{
    MSTATUS status = OK;
    ubyte2 len;
    const ubyte* p;
    const ubyte* cert;
    ubyte4 remain;
    ubyte4 numCerts;
    ubyte2 extensionsLength = 0;
    certChain* pNewCertChain = 0;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    ubyte isCvc = FALSE;
#endif

    status = CERTCHAIN_getSSLRecordCertNum(MOC_ASYM(hwAccelCtx) pSSLCertificateMsg,
        sslCertificateMsgLen, sslMinorVersion, &numCerts);
    if (OK != status)
    {
        goto exit;
    }

    /* allocate a buffer to store everything in one block */
    pNewCertChain = (certChain*) MALLOC( sizeof(certChain) +
                                        (numCerts - 1) * sizeof(certChainEntry) +
                                        sslCertificateMsgLen - 2 * SSL_MEDIUM_SIZE);
    if (!pNewCertChain)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    /* initialize the fields to safe values */
    DIGI_MEMSET((ubyte*) pNewCertChain->certs, 0, numCerts * sizeof(certChainEntry));
    pNewCertChain->numCerts = numCerts;
    pNewCertChain->buffer = (ubyte*) (pNewCertChain->certs + numCerts);
    DIGI_MEMCPY(pNewCertChain->buffer,
               pSSLCertificateMsg + 2 * SSL_MEDIUM_SIZE,
               sslCertificateMsgLen - 2 * SSL_MEDIUM_SIZE);

    /* second pass: store the values */
    p = pSSLCertificateMsg + SSL_MEDIUM_SIZE;
    remain = sslCertificateMsgLen - SSL_MEDIUM_SIZE;
    numCerts = 0;
    cert = pNewCertChain->buffer;
    while (remain >= SSL_MEDIUM_SIZE)
    {
        /* length of certificate */
        len = getMediumValue(p);
        p += SSL_MEDIUM_SIZE;
        remain -= SSL_MEDIUM_SIZE;

        if (len <= remain)
        {
            /* one more cert */
            numCerts++;
            pNewCertChain->certs[numCerts - 1].certLength = len;
            pNewCertChain->certs[numCerts - 1].cert = cert;
#ifdef __ENABLE_DIGICERT_CV_CERT__
            if (0x7F == cert[0])
            {
                isCvc = TRUE;
            }
#endif
            /* go over the cert */
            p += len;
            remain -= len;
            cert += len + SSL_MEDIUM_SIZE;
            if (SSL_TLS13_MINORVERSION == sslMinorVersion || SSL_DTLS13_MINORVERSION == sslMinorVersion)
            {
                ubyte4 extensionMask[2] = { 0, 0 };
                ubyte2 extType;
                ubyte2 extLen;

                if (2 > remain)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                extensionsLength = getShortValue(p);

                if (extensionsLength > remain)
                {
                    status = ERR_SSL_EXTENSION_LENGTH;
                    goto exit;
                }

                /* Move past the total extension length - 2 bytes
                 */
                remain -= 2;
                p      += 2;
                cert   += 2;

                pNewCertChain->certs[numCerts - 1].pCertExt = (ubyte *) p;
                pNewCertChain->certs[numCerts - 1].certExtLen = extensionsLength;

                while (0 != extensionsLength)
                {

                    if (4 > extensionsLength)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    /* Get the extension type
                     */
                    extType = getShortValue(p);

                    /* Move past the extension type - 2 bytes
                     */
                    remain -= 2;
                    p      += 2;
                    cert   += 2;
                    extensionsLength -= 2;

                    /* Get the extension length
                     */
                    extLen = getShortValue(p);

                    /* Move past the extension length - 2 bytes
                     */
                    remain -= 2;
                    p      += 2;
                    cert   += 2;
                    extensionsLength -= 2;

                    /* Check for duplicate extensions.
                     */
                    if (64 > extType)
                    {
                        if (extensionMask[extType / 32] & (1 << (extType % 32)))
                        {
                            status = ERR_SSL_EXTENSION_DUPLICATE;
                            goto exit;
                        }

                        extensionMask[extType / 32] |= (1 << (extType % 32));
                    }

                    /* Ensure the extension type is valid.
                     */
                    switch (extType)
                    {
                        case tlsExt_status_request:
#if defined(__ENABLE_DIGICERT_OCSP_CERT_STORE_EXT__)
                            pNewCertChain->certs[numCerts - 1].pOcspExt = (ubyte *) p;
                            pNewCertChain->certs[numCerts - 1].ocspExtLen = extLen;
#endif
                            /* fall-through */

                        case tlsExt_signed_certificate_timestamp:
                            break;

                        default:
                            status = ERR_SSL_EXTENSION_UNRECOGNIZED_NAME;
                            goto exit;
                    }

                    /* Validate against the total extension length.
                     */
                    if (extLen > extensionsLength)
                    {
                        status = ERR_SSL_EXTENSION_LENGTH;
                        goto exit;
                    }

                    /* Move past the extension data.
                     */
                    remain -= extLen;
                    p      += extLen;
                    cert   += extLen;
                    extensionsLength -= extLen;
                }
            }
        }
    }

    if (TRUE == validateChain)
    {
#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (TRUE == isCvc)
        {
            status = CERTCHAIN_CVC_finishBuild(MOC_ASYM(hwAccelCtx) pNewCertChain);
            if (OK == status && NULL != pIsCvc)
            {
                *pIsCvc = TRUE;
            }
        }
        else
#endif
        {
            status = CERTCHAIN_finishBuildEx(MOC_ASYM(hwAccelCtx) pNewCertChain);
        }
    }
    else
    {
        status = CERTCHAIN_originalChain(MOC_ASYM(hwAccelCtx) pNewCertChain);
    }
    if (OK > status) goto exit;

    *ppNewCertChain = pNewCertChain;
    pNewCertChain = 0;

exit:

    CERTCHAIN_delete(&pNewCertChain);

    return status;
}

#ifdef __ENABLE_DIGICERT_CV_CERT__
MOC_EXTERN MSTATUS
CERTCHAIN_CVC_createFromSSLRecordEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              certChainPtr* ppNewCertChain,
                              const ubyte* pSSLCertificateMsg,
                              ubyte4 sslCertificateMsgLen,
                              ubyte sslMinorVersion,
                              byteBoolean *pIsCvc)
{
    return CERTCHAIN_createFromSSLRecordEx2(
        MOC_ASYM(hwAccelCtx) ppNewCertChain,
        pSSLCertificateMsg, sslCertificateMsgLen, sslMinorVersion, pIsCvc, TRUE);
}
#endif

MOC_EXTERN MSTATUS
CERTCHAIN_createFromSSLRecordEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              certChainPtr* ppNewCertChain,
                              const ubyte* pSSLCertificateMsg,
                              ubyte4 sslCertificateMsgLen,
                              ubyte sslMinorVersion)
{
    return CERTCHAIN_createFromSSLRecordEx2(
        MOC_ASYM(hwAccelCtx) ppNewCertChain,
        pSSLCertificateMsg, sslCertificateMsgLen, sslMinorVersion, NULL, TRUE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CERTCHAIN_createFromSSLRecordOriginal(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              certChainPtr* ppNewCertChain,
                              const ubyte* pSSLCertificateMsg,
                              ubyte4 sslCertificateMsgLen,
                              ubyte sslMinorVersion)
{
    return CERTCHAIN_createFromSSLRecordEx2(
        MOC_ASYM(hwAccelCtx) ppNewCertChain,
        pSSLCertificateMsg, sslCertificateMsgLen, sslMinorVersion, NULL, FALSE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CERTCHAIN_createFromSSLRecord(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              certChainPtr* ppNewCertChain,
                              const ubyte* pSSLCertificateMsg,
                              ubyte4 sslCertificateMsgLen)
{
    return CERTCHAIN_createFromSSLRecordEx(
        MOC_ASYM(hwAccelCtx) ppNewCertChain,
        pSSLCertificateMsg, sslCertificateMsgLen, SSL_TLS12_MINORVERSION);
}

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSH_CLIENT__) || defined(__ENABLE_DIGICERT_SSH_SERVER__))
MOC_EXTERN MSTATUS
CERTCHAIN_createFromSSHEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         certChainPtr* ppNewCertChain,
                         const ubyte* pSSHCertChainBuf,
                         ubyte4 sshCertChainBufLen,
                         ubyte4 *pBufIndex,
                         funcPtrWalkStr walkStrFunc)
{
    certChainPtr        pNewCertChain = NULL;
    const ubyte*        pCert;
    ubyte4              certLen;
    ubyte4              startBufIndex;
    ubyte4              certificateCount;
    ubyte4              indexCerts;
    MSTATUS             status = OK;

    if (NULL == walkStrFunc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* NOTE: We expect the SSH cert chain in this format: <numCerts><leaf length: 4 bytes><leaf cert: leaf length>...<trust point cert length: 4><trust point cert: trust point cert length>*/

    if (sshCertChainBufLen <= (4 + (*pBufIndex)))
    {
        /* definitely needs to be more than 4 bytes... */
        status = ERR_SSH_PROTOCOL_PROCESS_CERTIFICATE;       /* gone past the end of the buffer */
        goto exit;
    }

    /* <uint32 certificate-count> */
    certificateCount  = (ubyte4)pSSHCertChainBuf[(*pBufIndex)];   certificateCount <<= 8;
    certificateCount |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+1]; certificateCount <<= 8;
    certificateCount |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+2]; certificateCount <<= 8;
    certificateCount |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+3];
    *pBufIndex += 4;

    /*!!!! should we check for max cert chain length? */

    /* allocate a buffer to store everything in one block */
    pNewCertChain = (certChainPtr) MALLOC(sizeof(certChain) +
                                       (certificateCount - 1) * sizeof(certChainEntry));
    if (NULL == pNewCertChain)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize the fields to safe values */
    DIGI_MEMSET((ubyte*) pNewCertChain->certs, 0x00, certificateCount * sizeof(certChainEntry));
    pNewCertChain->numCerts = certificateCount;
    pNewCertChain->buffer = NULL;

    /* extract location of certifcates upto certificateCount */
    for (indexCerts = 0; indexCerts < certificateCount; indexCerts++)
    {
        startBufIndex = *pBufIndex;

        if (OK > (status = walkStrFunc(pSSHCertChainBuf, sshCertChainBufLen, pBufIndex)))
        {
            /* any string error, we convert to certificate error */
            status = ERR_SSH_PROTOCOL_PROCESS_CERTIFICATE;
            goto exit;
        }

        /* <string certificate[1..certificate-count]> */
        pCert   = pSSHCertChainBuf + (4 + startBufIndex);
        certLen = (*pBufIndex) - (4 + startBufIndex);

        /* add the certificate to array */
        pNewCertChain->certs[indexCerts].cert = pCert;
        pNewCertChain->certs[indexCerts].certLength = certLen;
    }

    if (OK > (status = CERTCHAIN_finishBuild(MOC_ASYM(hwAccelCtx) pNewCertChain)))
        goto exit;

    *ppNewCertChain = pNewCertChain;
    pNewCertChain = NULL;


exit:
    CERTCHAIN_delete(&pNewCertChain);

    return status;

}

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERT_CHAIN_SSH_DEP__
MOC_EXTERN MSTATUS
CERTCHAIN_createFromSSH(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         certChainPtr* ppNewCertChain,
                         const ubyte* pSSHCertChainBuf,
                         ubyte4 sshCertChainBufLen,
                         ubyte4 *pBufIndex)
{
    return CERTCHAIN_createFromSSHEx(MOC_ASYM(hwAccelCtx) ppNewCertChain, pSSHCertChainBuf, sshCertChainBufLen, pBufIndex, &SSH_STR_walkStringInPayload);
} /* CERT_CHAIN_createFromSSH */
#endif /* __DISABLE_DIGICERT_CERT_CHAIN_SSH_DEP__ */
#endif /* (defined(__ENABLE_DIGICERT_SSH_CLIENT__) || defined(__ENABLE_DIGICERT_SSH_SERVER__)) */


/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

MOC_EXTERN MSTATUS
CERTCHAIN_createFromCVC(MOC_ASYM(hwAccelDescr hwAccelCtx)
                        certChainPtr* ppNewCertChain,
                        certDescriptor certiDesc[], ubyte4 numCerts)
{
    MSTATUS status = OK;

    ubyte4 i, len;
    certChain* pNewCertChain = NULL;
    ubyte *buffer;

    if (!ppNewCertChain || !certiDesc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == numCerts)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    for (i=0, len=0; i != numCerts; i++)
    {
        len += certiDesc[i].certLength;
    }

    /* allocate a buffer to store everything in one block */
    pNewCertChain = (certChain*) MALLOC(sizeof(certChain) +
                                        (numCerts - 1) * sizeof(certChainEntry) +
                                        len);
    if (!pNewCertChain)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize the fields */
    DIGI_MEMSET((ubyte*) pNewCertChain->certs, 0, numCerts * sizeof(certChainEntry));
    pNewCertChain->numCerts = numCerts;
    pNewCertChain->buffer = buffer = (ubyte*) (pNewCertChain->certs + numCerts);

    /* store the certificate value */
    for (i=0; i != numCerts; i++)
    {
        pNewCertChain->certs[i].certLength = len = certiDesc[i].certLength;
        DIGI_MEMCPY(buffer, certiDesc[i].pCertificate, len);
        pNewCertChain->certs[i].cert = buffer;
        buffer += len;
    }

    status = CERTCHAIN_CVC_finishBuild(MOC_ASYM(hwAccelCtx) pNewCertChain);
    if (OK > status) goto exit;

    *ppNewCertChain = pNewCertChain;
    pNewCertChain = NULL;

exit:
    CERTCHAIN_delete(&pNewCertChain);
    return status;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelDescr hwAccelCtx)
                        certChainPtr* ppNewCertChain,
                        certDescriptor certiDesc[], ubyte4 numCerts)
{
    MSTATUS status = OK;

    ubyte4 i, len;
    certChain* pNewCertChain = 0;
    ubyte *buffer;

    if (!ppNewCertChain || !certiDesc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == numCerts)
    {
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

    for (i=0, len=0; i != numCerts; i++)
    {
        len += certiDesc[i].certLength;
    }

    /* allocate a buffer to store everything in one block */
    pNewCertChain = (certChain*) MALLOC(sizeof(certChain) +
                                        (numCerts - 1) * sizeof(certChainEntry) +
                                        len);
    if (!pNewCertChain)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize the fields */
    DIGI_MEMSET((ubyte*) pNewCertChain->certs, 0, numCerts * sizeof(certChainEntry));
    pNewCertChain->numCerts = numCerts;
    pNewCertChain->buffer = buffer = (ubyte*) (pNewCertChain->certs + numCerts);

    /* store the certificate value */
    for (i=0; i != numCerts; i++)
    {
        pNewCertChain->certs[i].certLength = len = certiDesc[i].certLength;
        DIGI_MEMCPY(buffer, certiDesc[i].pCertificate, len);
        pNewCertChain->certs[i].cert = buffer;
        buffer += len;
    }

    status = CERTCHAIN_finishBuild(MOC_ASYM(hwAccelCtx) pNewCertChain);
    if (OK > status) goto exit;

    *ppNewCertChain = pNewCertChain;
    pNewCertChain = 0;

exit:
    CERTCHAIN_delete(&pNewCertChain);
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERTCHAIN_numberOfCertificates(certChainPtr pCertChain,
                                                  ubyte4* numCerts)
{
    if (!pCertChain || !numCerts)
        return ERR_NULL_POINTER;

    *numCerts = pCertChain->numCerts;

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERTCHAIN_isComplete( certChainPtr pCertChain,
                                        intBoolean* complete)
{
    if (!pCertChain || !complete)
        return ERR_NULL_POINTER;

    *complete = pCertChain->isComplete;

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERTCHAIN_getCertificate(certChainPtr pCertChain,
                                            ubyte4 indexInChain,
                                            const ubyte** certDerData,
                                            ubyte4* certDerDataLen)
{
    if (!pCertChain || !certDerData || !certDerDataLen)
        return ERR_NULL_POINTER;

     if ((sbyte4)indexInChain >= pCertChain->numCerts)
         return ERR_INDEX_OOB;

    /* return a pointer into our internal buffer */
    *certDerData = pCertChain->certs[indexInChain].cert;
    *certDerDataLen = pCertChain->certs[indexInChain].certLength;

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERTCHAIN_getKey(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                    certChainPtr pCertChain,
                                    ubyte4 indexInChain,  /* 0 - n-1 */
                                    AsymmetricKey* pubKey)
{
    MemFile mf;
    CStream cs;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    MSTATUS status = OK;
    CV_CERT *pCertData = NULL;
#endif

    if (!pCertChain || !pubKey)
        return ERR_NULL_POINTER;

    if ((sbyte4)indexInChain >= pCertChain->numCerts)
        return ERR_INDEX_OOB;

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (0x7F == pCertChain->certs[indexInChain].cert[0])
    {
        status = CV_CERT_parseCert (
            (ubyte*) pCertChain->certs[indexInChain].cert, 
            pCertChain->certs[indexInChain].certLength, &pCertData);
        if (OK != status)
        {
            return status;
        }

        status = CV_CERT_parseKey (MOC_ASYM(hwAccelCtx)
            pCertData->pCvcKey, pCertData->cvcKeyLen, pubKey, NULL, NULL);
        
        /* free whether error or not */
        (void) DIGI_FREE((void **)&pCertData);

        return status;
    }
#endif

    /* return a pointer into our internal buffer */
    MF_attach(&mf, pCertChain->certs[indexInChain].certLength,
              (ubyte*) pCertChain->certs[indexInChain].cert);

    CS_AttachMemFile(&cs, &mf);

    return X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                            ASN1_FIRST_CHILD(pCertChain->certs[indexInChain].pRoot),
                                               cs, pubKey);
}

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__
/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERTCHAIN_getRSASigAlgo(certChainPtr pCertChain,
                                           ubyte4 indexInChain,  /* 0 - n-1 */
                                           ubyte *sigAlgo)
{
    MemFile mf;
    CStream cs;

    if (!pCertChain || !sigAlgo)
        return ERR_NULL_POINTER;

    if ((sbyte4) indexInChain >= pCertChain->numCerts)
        return ERR_INDEX_OOB;

    /* return a pointer into our internal buffer */
    MF_attach(&mf, pCertChain->certs[indexInChain].certLength,
              (ubyte*) pCertChain->certs[indexInChain].cert);

    CS_AttachMemFile(&cs, &mf);

    return X509_getRSASignatureAlgo(
                        ASN1_FIRST_CHILD(pCertChain->certs[indexInChain].pRoot),
                                    cs, sigAlgo);
}
#endif


#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

/*---------------------------------------------------------------------------*/

static MSTATUS
CERTCHAIN_matchCertEntry(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         const void* arg,
                         const ubyte* testCert, ubyte4 testCertLength)
{
    sbyte4 resCmp;

    const certChainEntry* pCert = (certChainEntry*) arg;

    if (pCert->certLength == testCertLength &&
        0 == (DIGI_MEMCMP(pCert->cert, testCert, testCertLength, &resCmp), resCmp) )
    {
        return OK;
    }
    return ERR_FALSE;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

static MSTATUS
CERTCHAIN_CVC_findLastCertificateInStore(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                     const certChainEntry* pLastCert,
                                     certStorePtr pCertStore,
                                     intBoolean* foundLastCertificateInStore)
{
    MSTATUS status;
    const ubyte* foundCert;
    ubyte4 foundCertLen;


    if (OK > (status = CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelCtx)
                                                          pCertStore,
                                                          pLastCert->pCertData->pCertHolderRef,
                                                          pLastCert->pCertData->certHolderRefLen,
                                                          pLastCert,
                                                          CERTCHAIN_matchCertEntry,
                                                          &foundCert,
                                                          &foundCertLen)))
    {
        return status;
    }

    *foundLastCertificateInStore = (foundCertLen && foundCert) ? 1 : 0;
    return OK;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

static MSTATUS
CERTCHAIN_findLastCertificateInStore(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                     const certChainEntry* pLastCert,
                                     certStorePtr pCertStore,
                                     intBoolean* foundLastCertificateInStore)
{
    MSTATUS status;
    ASN1_ITEMPTR pSubject;
    const ubyte* foundCert;
    ubyte4 foundCertLen;

    if (OK  > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pLastCert->pRoot),
                                                   &pSubject)))
    {
        return status;
    }

    if (OK > (status = CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelCtx)
                                                          pCertStore,
                                                          pLastCert->cert + pSubject->dataOffset,
                                                          pSubject->length,
                                                          pLastCert,
                                                          CERTCHAIN_matchCertEntry,
                                                          &foundCert,
                                                          &foundCertLen)))
    {
        return status;
    }

    *foundLastCertificateInStore = (foundCertLen && foundCert) ? 1 : 0;
    return OK;
}


/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

static MSTATUS
CERTCHAIN_CVC_testAnchor(MOC_ASYM(hwAccelDescr hwAccelCtx)
                     const void* arg, const ubyte* anchor, ubyte4 anchorLen)
{
    MSTATUS status;
    CV_CERT *pAnchor = NULL;

    testAnchorArgCvc* pTestArg = (testAnchorArgCvc*) arg;

    status = CV_CERT_parseCert((ubyte *) anchor, anchorLen, &pAnchor);
    if (OK != status)
        goto exit;

    status = PARSE_CV_CERT_validateLink(MOC_ASYM(hwAccelCtx) pTestArg->pCertificate, pAnchor);
    if (OK != status)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* success: saves the result of the parse for further use */
    pTestArg->pValidAnchorRoot = pAnchor;
    pAnchor = 0;

exit:

    if (NULL != pAnchor)
    {
        DIGI_FREE((void **)&pAnchor);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

static MSTATUS
CERTCHAIN_testAnchor(MOC_ASYM(hwAccelDescr hwAccelCtx)
                     const void* arg, const ubyte* anchor, ubyte4 anchorLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pAnchorRoot;

    testAnchorArg* pTestArg = (testAnchorArg*) arg;

    MF_attach(&mf, anchorLen, (ubyte*) anchor);
    CS_AttachMemFile(&cs, &mf);

    /* parse it */
    if (OK > (status = X509_parseCertificate(cs, &pAnchorRoot)))
    {
        goto exit;
    }

    status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                               pTestArg->pCertificate, pTestArg->rcs,
                               ASN1_FIRST_CHILD(pAnchorRoot), cs,
                               pTestArg->chainLength);
    if (OK > status)
    {
        status = ERR_FALSE; /* let's try another one */
        goto exit;
    }

    /* success: saves the result of the parse for further use */
    pTestArg->pValidAnchorRoot = pAnchorRoot;
    pAnchorRoot = 0;

exit:

    if (pAnchorRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pAnchorRoot);
    }

    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
CERTCHAIN_testLeaf( const certChainEntry* pLeafCert,
                   ValidationConfig* config)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    static WalkerStep goToExtendedKeyUsageSequence[] =
    {
        { GoChildWithOID, 0, (ubyte*) extendedKeyUsage_OID},
        { GoNextSibling, 0, 0},
        { VerifyType, OCTETSTRING, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { Complete, 0, 0}
    };

    ASN1_ITEMPTR pCertificate = ASN1_FIRST_CHILD(pLeafCert->pRoot);

    MF_attach(&mf, pLeafCert->certLength, (ubyte*) pLeafCert->cert);
    CS_AttachMemFile(&cs, &mf);

    /* if commonName is provided, see if matches the first certificate in
     the chain */
    /* it either match the common name or the subjectAltNames */
    if (config->commonName)
    {
        if (OK > ( status = X509_matchName(pCertificate, cs,
                                           config->commonName)))
        {
            goto exit;
        }
    }

    /* if key usage is not 0, verify all bits are set */
    if ( config->keyUsage)
    {
        ubyte2 pKeyUsageVal;

        if (OK > (status = X509_getCertificateKeyUsageValue(pCertificate, cs,
                                                            &pKeyUsageVal)))
        {
            /* error in structure of cert */
            goto exit;
        }

        /* all the bits required should be set in the certificate */
        if ( config->keyUsage != (config->keyUsage & pKeyUsageVal))
        {
            status = ERR_CERT_INVALID_KEYUSAGE;
            goto exit;
        }
    }

    /* if extended key usage array is not null, verify all specified OIDs are
     there if extendedKeyUsage is present */
    if (config->extendedKeyUsage)
    {
        ASN1_ITEMPTR pExtensions;

        if (OK > (status = X509_getCertificateExtensions(pCertificate,
                                                         &pExtensions)))
        {
            goto exit;
        }

        if (pExtensions)
        {
            /* is there an extended key usage extension? */
            ASN1_ITEMPTR pExtendedKeyUsageExtension = 0;
            ASN1_WalkTree(pExtensions, cs, goToExtendedKeyUsageSequence,
                          &pExtendedKeyUsageExtension);

            if (pExtendedKeyUsageExtension)
            {
                ASN1_ITEMPTR firstKeyUsage = ASN1_FIRST_CHILD(pExtendedKeyUsageExtension);
                sbyte4 i;
                for (i = 0; config->extendedKeyUsage[i]; ++i)
                {
                    ASN1_ITEMPTR keyUsage = firstKeyUsage;
                    ubyte  extendedOIDFound = 0;

                    while (keyUsage)
                    {
                        if (OK <= ASN1_VerifyOID(keyUsage, cs,
                                                 config->extendedKeyUsage[i]))
                        {
                            extendedOIDFound = 1;
                            break;
                        }
                        /* try next item in sequence */
                        keyUsage = ASN1_NEXT_SIBLING(keyUsage);
                    }
                    /* run out of items before finding the value ? */
                    if (!extendedOIDFound)
                    {
                        status = ERR_CERT_INVALID_EXTENDED_KEYUSAGE;
                        goto exit;
                    }
                }

            }
            else
            {
                status = ERR_CERT_EXTENDED_KEYUSAGE_NOT_FOUND;
                goto exit;
            }
        }
        else
        {
            status = ERR_CERT_NO_EXTENSION_FOUND;
            goto exit;
        }
    }

    status = OK;

exit:

    return status;
}


/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

static MSTATUS
CERTCHAIN_CVC_findParentOfLastCertificateInStore(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                             const certChainEntry* pLastCert,
                                             const certChainPtr pCertChain,
                                             certStorePtr pCertStore,
                                             const ubyte** anchor,
                                             ubyte4* anchorLen,
                                             CV_CERT **ppAnchorRoot)
{
    MSTATUS status;
    testAnchorArgCvc taa;
    MOC_UNUSED(pCertChain);

    taa.pCertificate = pLastCert->pCertData;
    taa.pValidAnchorRoot = NULL;

    if (OK > (status = CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelCtx)
                                                          pCertStore,
                                                          pLastCert->pCertData->pCertAuthRef,
                                                          pLastCert->pCertData->certAuthRefLen,
                                                          &taa,
                                                          CERTCHAIN_CVC_testAnchor,
                                                          anchor,
                                                          anchorLen)))
    {
        goto exit;
    }

    *ppAnchorRoot = taa.pValidAnchorRoot;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

static MSTATUS
CERTCHAIN_findParentOfLastCertificateInStore(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                             const certChainEntry* pLastCert,
                                             const certChainPtr pCertChain,
                                             certStorePtr pCertStore,
                                             const ubyte** anchor,
                                             ubyte4* anchorLen,
                                             ASN1_ITEMPTR* ppAnchorRoot)
{
    ASN1_ITEMPTR pIssuer;
    MSTATUS status;
    testAnchorArg taa;
    MemFile mf;

    if (OK > ( status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pLastCert->pRoot),
                                                              &pIssuer,
                                                              NULL)))
    {
        goto exit;
    }


    MF_attach(&mf, pLastCert->certLength, (ubyte*) pLastCert->cert);
    CS_AttachMemFile(&taa.rcs, &mf);
    taa.pCertificate = ASN1_FIRST_CHILD(pLastCert->pRoot);
    taa.chainLength = pCertChain->numCerts;
    taa.pValidAnchorRoot = 0;

    if (OK > (status = CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelCtx)
                                                          pCertStore,
                                                          pLastCert->cert + pIssuer->dataOffset,
                                                          pIssuer->length,
                                                          &taa,
                                                          CERTCHAIN_testAnchor,
                                                          anchor,
                                                          anchorLen)))
    {
        goto exit;
    }

    *ppAnchorRoot = taa.pValidAnchorRoot;

exit:

    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
CERTCHAIN_fullValidate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                   certChainPtr pCertChain,
                   ValidationConfig* pConfig)
{
    MSTATUS status;
    MemFile parentMF, childMF;
    CStream parentCS, childCS;
    ubyte4 anchorLen = 0;
    sbyte4 i, j;
    const certChainEntry *pCurCert, *pCert;
    intBoolean certInStore;
    const ubyte *pAnchor = NULL;
    ASN1_ITEMPTR pAnchorRoot = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pCertChain) || (NULL == pConfig) )
        goto exit;

    /* Loop through all the certificates in the chain and verify them.
     */
    for (i = 0; i < pCertChain->numCerts; ++i)
    {
        pCurCert = pCertChain->certs + i;

        MF_attach(&childMF, pCurCert->certLength, (ubyte *) pCurCert->cert);
        CS_AttachMemFile(&childCS, &childMF);

        for (j = 0; j < pCertChain->numCerts; ++j)
        {
            pCert = pCertChain->certs + j;

            MF_attach(&parentMF, pCert->certLength, (ubyte *) pCert->cert);
            CS_AttachMemFile(&parentCS, &parentMF);

            /* If a parent is found then break out of the loop. Note that this
             * will also verify self-signed certificates as well.
             */
            status = X509_validateLink( MOC_ASYM(hwAccelCtx)
                ASN1_FIRST_CHILD(pCurCert->pRoot), childCS,
                ASN1_FIRST_CHILD(pCert->pRoot), parentCS,
                pCertChain->numCerts);
            if (OK == status)
                break;
        }

        /* If the certificate does not have a parent in the chain then
         * check if the certificate itself is in the certificate store
         * or if the parent of the certificate is in the certificate
         * store.
         */
        if (j == pCertChain->numCerts)
        {
            /* Check if the certificate is already in the trust store.
             */
            status = CERTCHAIN_findLastCertificateInStore( MOC_ASYM(hwAccelCtx)
                pCurCert, pConfig->pCertStore, &certInStore);
            if (OK != status)
                goto exit;
            
            if (!certInStore)
            {
                /* The certificate was not found in the trust store. Check if
                 * the parent of the certificate is in the trust store.
                 */
                status = CERTCHAIN_findParentOfLastCertificateInStore(
                    MOC_ASYM(hwAccelCtx)
                    pCurCert, pCertChain, pConfig->pCertStore,
                    &pAnchor, &anchorLen, &pAnchorRoot);
                if (OK != status)
                    goto exit;

                /* If no root is found then throw an error indicating
                 * that no root of trust was found.
                 */
                if (NULL == pAnchorRoot)
                {
                    status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                    goto exit;
                }
                else if (NULL != pConfig->td)
                {
                    /* If a trust anchor was found then validate the
                     * certificate time.
                     */
                    MF_attach(&parentMF, anchorLen, (ubyte *) pAnchor);
                    CS_AttachMemFile(&parentCS, &parentMF);

                    status = X509_verifyValidityTime(
                        ASN1_FIRST_CHILD(pAnchorRoot), parentCS,
                        pConfig->td);
                    if (OK != status)
                        goto exit;
                }
            }
        }
    }

    /* If the config specified to verify the timing, loop through all the
     * certificates in the chain and verify the time.
     */
    if (NULL != pConfig->td)
    {
        for (i = 0; i < pCertChain->numCerts; ++i)
        {
            pCurCert = pCertChain->certs + i;

            MF_attach(&childMF, pCurCert->certLength, (ubyte*) pCurCert->cert);
            CS_AttachMemFile(&childCS, &childMF);

            status = X509_verifyValidityTime(
                ASN1_FIRST_CHILD(pCurCert->pRoot), childCS, pConfig->td);
            if (OK != status)
                goto exit;
        }
    }

exit:

    if (pAnchorRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pAnchorRoot);
    }

    return status;
}

static MSTATUS
CERTCHAIN_createFromArray(
    ubyte *pCertArr, sbyte4 certArrLen, certChainPtr *ppRetCertChain)
{
    MSTATUS status;
    ubyte4 i, length, certCount;
    sbyte4 curLen;
    certChain *pCertChain = NULL;
    ubyte *pCertBuffer;
    MemFile certMemFile;
    CStream certCStream;

    if ( (NULL == pCertArr) || (NULL == ppRetCertChain) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certArrLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Calculate the total number of certificates in the chain.
     */
    curLen = certArrLen;
    pCertBuffer = pCertArr;
    certCount = 0;
    while (0 < curLen)
    {
        status = ASN1_getTagLen(0x30, pCertBuffer, &length);
        if (OK != status)
            goto exit;
        
        curLen -= length;
        pCertBuffer += length;
        certCount++;
    }

    /* If the length is not zero then the certificate array contains invalid
     * data or an error occured while parsing the data.
     */
    if (curLen != 0)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Allocate memory for the certificate chain.
     */
    status = DIGI_MALLOC(
        (void **) &pCertChain,
        sizeof(certChain) + (certCount - 1) * sizeof(certChainEntry) + certArrLen);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMSET(
        (ubyte *) (pCertChain->certs), 0x00, certCount * sizeof(certChainEntry));
    if (OK != status)
        goto exit;

    pCertChain->numCerts = certCount;
    pCertBuffer = (ubyte *) (pCertChain->certs + certCount);
    pCertChain->buffer = pCertBuffer;

    /* Loop through the certificates and parse the certificate to ensure that
     * the ASN.1 encoding is valid. Note that this will not perform any
     * certificate validation.
     * 
     * Each certificate will also be placed in the certificate chain.
     */
    for (i = 0; i < certCount; ++i)
    {
        status = ASN1_getTagLen(0x30, pCertArr, &length);
        if (OK != status)
            goto exit;

        MF_attach(&certMemFile, length, pCertArr);
        CS_AttachMemFile(&certCStream, &certMemFile);

        status = X509_parseCertificate(certCStream, &((pCertChain->certs + i)->pRoot));
        if (OK > status)
            goto exit;

        pCertChain->certs[i].certLength = length;

        status = DIGI_MEMCPY(pCertBuffer, pCertArr, length);
        if (OK != status)
            goto exit;
        
        pCertChain->certs[i].cert = pCertBuffer;
        pCertBuffer += length;
        pCertArr += length;
    }

    *ppRetCertChain = pCertChain;
    pCertChain = NULL;

exit:

    if (NULL != pCertChain)
        CERTCHAIN_delete(&pCertChain);

    return status;
}

MOC_EXTERN MSTATUS
CERTCHAIN_validateAll( MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCertArr, sbyte4 certArrLen, ValidationConfig *pConfig,
    certChainPtr *ppRetChain)
{
    MSTATUS status;
    certChainPtr pCertChain = NULL;

    if ( (NULL == pCertArr) || (NULL == pConfig) || (NULL == ppRetChain) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Create a certificate chain from an array. The chain will be created under
     * the assumption that the certificates can be in any order. This function
     * will create the certificate chain as is without validating any
     * signatures.
     */
    status = CERTCHAIN_createFromArray(
        pCertArr, certArrLen, &pCertChain);
    if (OK != status)
        goto exit;

    /* Perform a full validation on the certificates. This will validate all the
     * certificates in the chain.
     */
    status = CERTCHAIN_fullValidate(MOC_ASYM(hwAccelCtx) pCertChain, pConfig);
    if (OK != status)
        goto exit;

    /* If the validation is successful then return the chain to the caller. The
     * caller can determine what to do with the chain once it has been verified.
     */
    *ppRetChain = pCertChain;
    pCertChain = NULL;

exit:

    if (NULL != pCertChain)
        CERTCHAIN_delete(&pCertChain);

    return status;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

MOC_EXTERN MSTATUS
CERTCHAIN_CVC_validate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                   certChainPtr pCertChain,
                   ValidationConfig* config)
{
    MSTATUS status = OK;
    const ubyte* foundAnchor = 0;
    ubyte4 foundAnchorLen = 0;
    CV_CERT *pAnchorRoot = NULL;

    /* if pCertStore provided, try to find either the last certificate in the
     chain or a certificate with the subject name matching the issuer name of
     the last certificate in the chain. */
    if (config->pCertStore)
    {
        intBoolean lastCertFoundInStore = 0; /* last cert in the chain is in store */
        sbyte4 i;
        const certChainEntry *pCurCert = NULL;

        for (i = 0; i < pCertChain->numCerts; i++)
        {
            pCurCert = pCertChain->certs + i;

            if (OK > (status = CERTCHAIN_CVC_findLastCertificateInStore(MOC_ASYM(hwAccelCtx)
                                                                    pCurCert,
                                                                    config->pCertStore,
                                                                    &lastCertFoundInStore)))
            {
                goto exit;
            }

            if (lastCertFoundInStore)
            {
                break;
            }
        }

        if( !lastCertFoundInStore && (pCurCert != NULL))
        {

            if (OK > ( status = CERTCHAIN_CVC_findParentOfLastCertificateInStore( MOC_ASYM(hwAccelCtx)
                                                                             pCurCert,
                                                                             pCertChain,
                                                                             config->pCertStore,
                                                                             &foundAnchor,
                                                                             &foundAnchorLen,
                                                                             &pAnchorRoot)))
            {
                goto exit;
            }

            if (!pAnchorRoot)
            {
                status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                goto exit;
            }
        }
    }

    /* if time is provided, validate all the certificates --including the
     possible newly found root in the stop above -- for that time */
    if (config->td)
    {
        sbyte4 i;

        if (pAnchorRoot)
        {
            /* new anchor found in cert store */
            status = PARSE_CV_CERT_verifyValidityTime(pAnchorRoot, config->td);
            if (OK != status)
                goto exit;
        }

        /* iterate through the chain */
        for (i = 0; i < pCertChain->numCerts; ++i)
        {
            certChainEntry* pCurrCert = pCertChain->certs + i;

            status = PARSE_CV_CERT_verifyValidityTime(pCurrCert->pCertData, config->td);
            if (OK != status)
                goto exit;
        }
    }

    /* If extension checks are added in the future for CVC, this is the time to perform them */

    /* success: return the newly found certificate if any */
    if (pAnchorRoot)
    {
        config->anchorCert = foundAnchor;
        config->anchorCertLen = foundAnchorLen;
    }
    else
    {
        config->anchorCert = 0;
        config->anchorCertLen = 0;
    }

exit:

    if (pAnchorRoot)
    {
        DIGI_FREE((void **) &pAnchorRoot);
    }

    return status;
}

#endif

MOC_EXTERN MSTATUS
CERTCHAIN_validate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                   certChainPtr pCertChain,
                   ValidationConfig* config)
{
    MSTATUS status = OK;
    const ubyte* foundAnchor = 0;
    ubyte4 foundAnchorLen = 0;
    ASN1_ITEMPTR pAnchorRoot = 0;

    /* if pCertStore provided, try to find either the last certificate in the
     chain or a certificate with the subject name matching the issuer name of
     the last certificate in the chain. */
    if (config->pCertStore)
    {
        intBoolean lastCertFoundInStore = 0; /* last cert in the chain is in store */
        sbyte4 i;
        const certChainEntry *pCurCert = NULL;

        for (i = 0; i < pCertChain->numCerts; i++)
        {
            pCurCert = pCertChain->certs + i;

            if (OK > (status = CERTCHAIN_findLastCertificateInStore(MOC_ASYM(hwAccelCtx)
                                                                    pCurCert,
                                                                    config->pCertStore,
                                                                    &lastCertFoundInStore)))
            {
                goto exit;
            }

            if (lastCertFoundInStore)
            {
                break;
            }
        }

        if( !lastCertFoundInStore && (pCurCert != NULL))
        {

            if (OK > ( status = CERTCHAIN_findParentOfLastCertificateInStore( MOC_ASYM(hwAccelCtx)
                                                                             pCurCert,
                                                                             pCertChain,
                                                                             config->pCertStore,
                                                                             &foundAnchor,
                                                                             &foundAnchorLen,
                                                                             &pAnchorRoot)))
            {
                goto exit;
            }

            if (!pAnchorRoot)
            {
                status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                goto exit;
            }
        }
    }

    /* if time is provided, validate all the certificates --including the
     possible newly found root in the stop above -- for that time */
    if (config->td)
    {
        sbyte4 i;

        MemFile mf;
        CStream cs;

        if (pAnchorRoot)
        {
            MF_attach(&mf, foundAnchorLen, (ubyte*) foundAnchor);
            CS_AttachMemFile(&cs, &mf);

            /* new anchor found in cert store */
            if (OK > ( status = X509_verifyValidityTime(ASN1_FIRST_CHILD(pAnchorRoot), cs,
                                                        config->td)))
            {
                goto exit;
            }
        }

        /* iterate through the chain */
        for (i = 0; i < pCertChain->numCerts; ++i)
        {
            certChainEntry* pCurrCert = pCertChain->certs + i;

            MF_attach(&mf, pCurrCert->certLength, (ubyte*) pCurrCert->cert);
            CS_AttachMemFile(&cs, &mf);

            if (OK > ( status = X509_verifyValidityTime(ASN1_FIRST_CHILD(pCurrCert->pRoot), cs,
                                                        config->td)))
            {
                goto exit;
            }
        }
    }

    /* run the leaf cert only tests: commonName, keyUsage, extendedKeyUsage */
    if (OK > ( status = CERTCHAIN_testLeaf(pCertChain->certs, config)))
    {
        goto exit;
    }

    /* success: return the newly found certificate if any */
    if (pAnchorRoot)
    {
        config->anchorCert = foundAnchor;
        config->anchorCertLen = foundAnchorLen;
    }
    else
    {
        config->anchorCert = 0;
        config->anchorCertLen = 0;
    }

exit:

    if (pAnchorRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pAnchorRoot);
    }

    return status;
}

#endif


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CERTCHAIN_delete(certChainPtr* ppCertChain)
{
    sbyte4 i;

    if (!ppCertChain || !(*ppCertChain))
        return ERR_NULL_POINTER;

    for (i = 0; i < (**ppCertChain).numCerts; ++i)
    {
        CERTCHAIN_deleteCertChainEntry( (**ppCertChain).certs + i);
    }

    FREE( *ppCertChain);
    *ppCertChain = 0;

    return OK;
}
