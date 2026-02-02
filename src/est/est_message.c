/**
 * @file  est_message.c
 * @brief EST -- Enrollment over Secure Transport Messages
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
#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EST_CLIENT__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../common/base64.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs10.h"
#include "../crypto/cms.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/asn1cert.h"
#include "../http/http_context.h"
#include "../common/dynarray.h"
#include "../crypto/pki_client_common.h"
#include "../est/est_context.h"
#include "../est/est_message.h"
#include "../est/est_utils.h"
#include "../harness/harness.h"

#include "../common/debug_console.h"
#include <stdio.h>

#define BEGIN_CSR_BLOCK     "-----BEGIN CERTIFICATE REQUEST-----\x0d\x0a"
#define END_CSR_BLOCK       "-----END CERTIFICATE REQUEST-----\x0d\x0a"

/* EST Verisign private OIDs */
const ubyte est_verisign_OID[] =
{ 7, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45}; /*2 16 840 1 113733*/
const ubyte est_verisign_pki_OID[] =
{ 8, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01}; /*2 16 840 1 113733 1*/
const ubyte est_verisign_pkiAttrs_OID[] =
{ 9, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09}; /*2 16 840 1 113733 1 9*/
const ubyte est_verisign_pkiAttrs_messageType_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x02}; /*2 16 840 1 113733 1 9 2*/
const ubyte est_verisign_pkiAttrs_pkiStatus_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x03}; /*2 16 840 1 113733 1 9 3*/
const ubyte est_verisign_pkiAttrs_failInfo_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x04}; /*2 16 840 1 113733 1 9 4*/
const ubyte est_verisign_pkiAttrs_senderNonce_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x05}; /*2 16 840 1 113733 1 9 5*/
const ubyte est_verisign_pkiAttrs_recipientNonce_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x06}; /*2 16 840 1 113733 1 9 6*/
const ubyte est_verisign_pkiAttrs_transId_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x07}; /*2 16 840 1 113733 1 9 7*/
const ubyte est_verisign_pkiAttrs_extensionReq_OID[] =
{ 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x08}; /*2 16 840 1 113733 1 9 8*/

/* enum has to be in same order as AttributeOIDs */
typedef enum {
    contentType, signingTime, messageDigest, messageType, pkiStatus, failInfo, senderNonce, recipientNonce, transId
} attributeType;


typedef struct envelopeSignParams
{
    ubyte *pPayLoad;
    ubyte4 payLoadLen;
    AsymmetricKey *pRecipientKey;
    ASN1_ITEM *pRecipientCert;
    CStream rCS;
    const ubyte *encryptAlgoOID;
    RNGFun rngFun;
    void* rngFunArg;
    AsymmetricKey *pSignerKey;
    ASN1_ITEM *pSignerCert;
    CStream sCS;
    transactionAttributes *pTransAttrs;
    const ubyte *digestAlgoOID;
} envelopeSignParams;

static MSTATUS
EST_MESSAGE_parseCsrAttrsDataToBuffer(ubyte* pCertRep, ubyte4 certRepLen, ubyte **pPReceivedData, ubyte4 *pReceivedDataLength);

/*------------------------------------------------------------------*/

#define CSR_LINE_LENGTH     64
#define PEM_ARMOR		    1

static MSTATUS
EST_MESSAGE_breakIntoLines(ubyte* pLineCsr, ubyte4 lineCsrLength,
        ubyte **ppRetCsr, ubyte4 *p_retCsrLength)
{
    ubyte*  pBlockCSR = NULL;
    ubyte*  pTempLineCsr;
    ubyte4  numLines;

    /* break the data up into (CSR_LINE_LENGTH) sized blocks */
    numLines     = ((lineCsrLength + (CSR_LINE_LENGTH - 1)) / CSR_LINE_LENGTH);
    pTempLineCsr = pLineCsr;

    /* calculate the new block length */
#if PEM_ARMOR
    *p_retCsrLength = (sizeof(BEGIN_CSR_BLOCK) - 1) + lineCsrLength + numLines + numLines + (sizeof(END_CSR_BLOCK) - 1);
#else
    *p_retCsrLength = (lineCsrLength + numLines + numLines);
#endif

    /* allocate the new csr block */
    if (NULL == (*ppRetCsr = pBlockCSR = MALLOC(*p_retCsrLength)))
    {
        return ERR_MEM_ALLOC_FAIL;
    }

#if PEM_ARMOR
    /* copy the start of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)BEGIN_CSR_BLOCK, (sizeof(BEGIN_CSR_BLOCK) - 1));
    pBlockCSR += (sizeof(BEGIN_CSR_BLOCK) - 1);
#endif

    /* copy contiguous blocks of data */
    while (1 < numLines)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, CSR_LINE_LENGTH);
        pBlockCSR[CSR_LINE_LENGTH] = MOC_CR;
        pBlockCSR[CSR_LINE_LENGTH + 1] = LF;

        pBlockCSR += CSR_LINE_LENGTH + 2;
        pTempLineCsr += CSR_LINE_LENGTH;
        lineCsrLength -= CSR_LINE_LENGTH;

        numLines--;
    }

    /* copy any remaining bytes */
    if (lineCsrLength)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, lineCsrLength);
        pBlockCSR += lineCsrLength;

        *pBlockCSR = MOC_CR; pBlockCSR++;
        *pBlockCSR = LF; pBlockCSR++;
    }

#if PEM_ARMOR
    /* copy the end of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)END_CSR_BLOCK, (sizeof(END_CSR_BLOCK) - 1));
#endif

    return OK;
}

MOC_EXTERN MSTATUS
EST_MESSAGE_CertReqToCSR( const ubyte* pCertReq, ubyte4 certReqLen,
        ubyte** ppCsr, ubyte4* pCsrLength)
{
    MSTATUS status;
    ubyte* pLineCsr = 0;
    ubyte4 lineCsrLength;

    if (OK > (status = BASE64_encodeMessage(pCertReq, certReqLen,
                    &pLineCsr, &lineCsrLength)))
    {
        goto exit;
    }

    if (OK > (status = EST_MESSAGE_breakIntoLines(pLineCsr, lineCsrLength,
                    ppCsr, pCsrLength)))
    {
        goto exit;
    }

exit:

    if (pLineCsr)
    {
        FREE(pLineCsr);
    }

    return status;
}

/*------------------------------------------------------------------*/

/* NOTE: selfcert can be either self-signed or ca-issued */

extern MSTATUS
EST_MESSAGE_parseResponse(EST_responseType type, ubyte* pCertRep, ubyte4 certRepLen, ubyte **pResp, ubyte4 *respLen)
{
    MSTATUS status = OK;

    ubyte*  pRetBuffer = NULL;
    ubyte4  retLength;

    switch (type)
    {
        /* cacerts command response */
        case x_pkcs7_cert:
            {
                if (OK > (status = BASE64_decodeMessage(pCertRep, certRepLen, pResp, respLen)))
                {
                    goto exit;
                }
                return status;
            }
            /* csrattrs command response */
        case x_csrattrs:
            {
                if (OK > (status = BASE64_decodeMessage(pCertRep, certRepLen, &pRetBuffer, &retLength)))
                {
                    goto exit;
                }
                if (OK > (status = EST_MESSAGE_parseCsrAttrsDataToBuffer(pRetBuffer, retLength, pResp, respLen)))
                {
                    goto exit;
                }
                if(pRetBuffer)
                {
                    FREE(pRetBuffer);
                }
                return status;
            }
            /* simpleenroll/simplereenroll command response */
        case x_pkcs7_simple_cert:
        case x_pkcs7_fullcmc_response:
            {
                if (OK > (status = BASE64_decodeMessage(pCertRep, certRepLen, pResp, respLen)))
                {
                    goto exit;
                }
                return status;
            }
        case x_pkcs7_multipart_mixed:
        default:
            return ERR_EST_NOT_SUPPORTED;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS
EST_MESSAGE_parseCsrAttrsDataToBuffer(ubyte* pCertRep, ubyte4 certRepLen,
        ubyte **pPReceivedData, ubyte4 *pReceivedDataLength)
{
    MSTATUS status = OK;

    if (!pPReceivedData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*pPReceivedData = (ubyte*) MALLOC(certRepLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    *pReceivedDataLength = certRepLen;
    DIGI_MEMCPY(*pPReceivedData, pCertRep, *pReceivedDataLength);

exit:
    if (OK > status)
    {
        if (pPReceivedData != NULL && (*pPReceivedData) != NULL)
        {
            FREE(*pPReceivedData);
            *pPReceivedData = NULL;
            *pReceivedDataLength = 0;
        }
    }
    return status;
}

#endif /* #ifdef __ENABLE_DIGICERT_EST_CLIENT__ */
