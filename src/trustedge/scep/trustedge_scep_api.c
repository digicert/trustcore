/*
 * trustedge_scep_api.c
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */
#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/debug_console.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/datetime.h"
#include "../../common/msg_logger.h"
#include "../../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../../crypto/dsa.h"
#endif
#include "../../common/uri.h"
#include "../../asn1/oiddefs.h"
#include "../../crypto/crypto.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../common/base64.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/keyblob.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/derencoder.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/cert_store.h"
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../http/http_common.h"
#include "../../http/client/http_request.h"
#include "../../common/mtcp.h"
#include "../../asn1/parsecert.h"
#include "../../cert_enroll/cert_enroll.h"
#include "../../trustedge/scep/trustedge_scep_defn.h"
#include "../../trustedge/scep/trustedge_scep_context.h"
#include "../../trustedge/scep/trustedge_scep_client.h"
#include "../../trustedge/scep/trustedge_scep_message.h"
#include "../../trustedge/agent/trustedge_agent_policy.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/cryptointerface.h"
#endif

#ifdef __ENABLE_DIGICERT_TAP__
#include "../../tap/tap.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../trustedge/utils/trustedge_tap.h"
#endif

#include "../../trustedge/scep/trustedge_scep_api.h"
#include <string.h>

#define SCEP_TCP_READ_BUFFER 512
/*------------------------------------------------------------------*/

/* Local callback variable to get the Scep data from the application */
pFuncPtrGetScepData g_pFuncPtrGetScepData = NULL;

/*------------------------------------------------------------------*/
    /* PKCS7 Callbacks */
/*------------------------------------------------------------------*/
static MSTATUS myValCertFun(const void* arg,
							CStream cs,
							struct ASN1_ITEM* pCertificate,
							sbyte4 chainLength)
{
    MOC_UNUSED(arg);
    MOC_UNUSED(cs);
    MOC_UNUSED(pCertificate);
    MOC_UNUSED(chainLength);

    return OK;
}

/*------------------------------------------------------------------*/

/* this callback is used to load CA certificates */
/* ppCertificate will be released by the PKCS7 stack */
static MSTATUS myGetCertFun(const void* arg,CStream cs,
                            ASN1_ITEM* pSerialNumber,
                            ASN1_ITEM* pIssuerName,
                            ubyte  **ppCertificate,
                            ubyte4 *pcertificateLen)
{
    MOC_UNUSED(arg);
    MOC_UNUSED(cs);
    MOC_UNUSED(pSerialNumber);
    MOC_UNUSED(pIssuerName);
    MSTATUS status = OK;
    SCEP_data *pScepData = NULL;

    if (OK > (status = g_pFuncPtrGetScepData(&pScepData)))
    {
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void**)ppCertificate, 1, pScepData->exchangerCertLen)))
    {
        goto exit;
    }
    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppCertificate, pScepData->pExchangerCertificate, pScepData->exchangerCertLen)))
    {
        goto exit;
    }
    *pcertificateLen = pScepData->exchangerCertLen;
exit:
    return status;
}

/*------------------------------------------------------------------*/

#if 0
static MSTATUS deserializePemKey(ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen, AsymmetricKey *pKey)
{
    MSTATUS  status = OK;
    ubyte *pDatKeyBlob = NULL;


    if ( (NULL == pPemKeyBlob) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (OK > (status = CRYPTO_initAsymmetricKey (pKey)))
    {
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(
        pPemKeyBlob, pemKeyBlobLen, NULL, pKey);
    if (OK != status)
        goto exit;

exit:
    if (pDatKeyBlob != NULL) DIGI_FREE((void**)&pDatKeyBlob);
    if (OK != status)
        CRYPTO_uninitAsymmetricKey(pKey, NULL);
    return status;
}
#endif

/*------------------------------------------------------------------*/

static MSTATUS myGetPrivateKeyFun(const void* arg,CStream cs,
                                  ASN1_ITEM* pSerialNumber,
                                  ASN1_ITEM* pIssuerName,
                                  AsymmetricKey* pKey)
{
    MOC_UNUSED(arg);
    MOC_UNUSED(cs);
    MOC_UNUSED(pSerialNumber);
    MOC_UNUSED(pIssuerName);
    MSTATUS status = OK;
    SCEP_data *pScepData = NULL;

    if (OK > (status = g_pFuncPtrGetScepData(&pScepData)))
    {
        goto exit;
    }

    if (NULL != pScepData->pKeyPw && pScepData->keyPwLen > 0)
    {
        status = CRYPTO_deserializeAsymKeyWithCreds(pScepData->pPemKeyBlob, pScepData->pemKeyBlobLen, NULL, pScepData->pKeyPw, pScepData->keyPwLen, NULL, pKey);
    }
    else
    {
        status = CRYPTO_deserializeAsymKey(pScepData->pPemKeyBlob, pScepData->pemKeyBlobLen, NULL, pKey);
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
    /* Static Functions */
/*------------------------------------------------------------------*/
#if 0
static MSTATUS
SCEP_SAMPLE_updateCertDistinguishedName(nameAttr** pPnameAttr, int nameAttrLen, certDistinguishedName **ppDest)
{
	MSTATUS    status         = OK;
	ubyte4     rdnOffset      = 0;
	ubyte4     tempRdnOffset  = 0;
	relativeDN *pRDN          = NULL;
    nameAttr   *pNameAttr     = NULL;
    ubyte4 found = 0;
	relativeDN *newRDN = NULL;
	certDistinguishedName *pDest = NULL;

    if (ppDest == NULL)
    {
        status = ERR_NULL_POINTER;
        return status;
    }

    if (nameAttrLen == 0 || pPnameAttr == NULL)
    {
        return OK;
    }
    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pDest)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_CALLOC((void**)&(pDest->pDistinguishedName), 1, nameAttrLen * sizeof(relativeDN))))
    {
        goto exit;
    }

	rdnOffset = 0;
    /**
     * Override the pDest values(default values) with pPnameAttr(Attributes from configuration file).
     * If some attributes were missing in configuration file, use default values.
     * If both contains the same attribute then use the attributes values from configuration file.
     *
     */
	for (pNameAttr = pPnameAttr[rdnOffset]; rdnOffset < nameAttrLen; pNameAttr = pPnameAttr[rdnOffset])
	{
        /* Outer  loop to loop through the attributes from configuration file */
        tempRdnOffset = 0;
	    for (pRDN = pDest->pDistinguishedName+tempRdnOffset; tempRdnOffset < pDest->dnCount; pRDN = pDest->pDistinguishedName+tempRdnOffset)
        {
            /* This loop is to find if the match is found from the default attributes (pDest)
             * If match is found then free it and assign the attributes from configuration file */
            nameAttr *pNameComponent;
            ubyte4 j = 0;
            found = 0;
            for (pNameComponent = pRDN->pNameAttr;
                j < pRDN->nameAttrCount; pNameComponent = pRDN->pNameAttr + j)
            {
                /* This loop is to verify if same attribute oid is present */
                if (0 == DIGI_STRCMP((const sbyte *)pNameComponent->oid, (const sbyte *)pNameAttr->oid))
                {
                    found = 1;
                    break;
                }
                j = j + 1;
            }
            if (found == 1)
            {
                /* if match is found then clean the memory and override the default one
                 * with the one specified in the configuration file
                 */
                j = 0;
                for (pNameComponent = pRDN->pNameAttr;
                    j < pRDN->nameAttrCount; pNameComponent = pRDN->pNameAttr + j)
                {
                    /* Don't free oid since oid is not an allocated memory */
			         if (pNameComponent->value && pNameComponent->valueLen > 0)
                     {
                         FREE(pNameComponent->value);
                     }
                     j = j + 1;
                }
                FREE(pRDN->pNameAttr);
                pRDN->pNameAttr = pNameAttr;
                pRDN->nameAttrCount = 1;
                break;
            }
            tempRdnOffset = tempRdnOffset +1;
        }
        if (0 == found)
        {
            /* No match found */
            pRDN = pDest->pDistinguishedName;
            newRDN = MALLOC((pDest->dnCount + 1)*sizeof(relativeDN));
            if (NULL == newRDN)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(newRDN, 0x00, (pDest->dnCount + 1)*sizeof(relativeDN));
            DIGI_MEMCPY((void*)newRDN, (void*)pDest->pDistinguishedName, (pDest->dnCount)*sizeof(relativeDN));
            (&newRDN[pDest->dnCount])->pNameAttr = pNameAttr;
            (&newRDN[pDest->dnCount])->nameAttrCount = 1;
            FREE(pDest->pDistinguishedName);
            pDest->pDistinguishedName = newRDN;
            pDest->dnCount = pDest->dnCount + 1;
        }
		rdnOffset = rdnOffset + 1;
	}
	*ppDest = pDest;

exit:
	return status;

}

/*------------------------------------------------------------------*/

static MSTATUS
setSubjAltNameExtension(SubjectAltNameAttr *pAttrs, int numSans, extensions *pSubAltNameExt)
{
    MSTATUS          status     =  OK;
    DER_ITEMPTR      pRoot      =  NULL;
    ubyte           *pEncoded    =  NULL;
    ubyte4           encodedLen =  0;
    int              pos        =  0;
    ubyte           *pIps       = NULL;
    ubyte4           numIps     = 0;
    ubyte           *pIpPtr     = NULL;
    ubyte4           ipLen      = 0;

    if (OK > (status = DER_AddSequence(NULL, &pRoot)))
    {
        goto exit;
    }

    /* Form of ip addresses need conversion, first get a count of how many ip addresses */
    for (pos = 0; pos < numSans; pos++)
    {
        if (SubjectAltName_iPAddress == pAttrs[pos].subjectAltNameType)
        {
            numIps++;
        }
    }

    if (numIps)
    {
        /* allocate enough space for all v6 ips, 16 bytes each */
        status = DIGI_MALLOC((void **) &pIps, 16 * numIps);
        if (OK != status)
            goto exit;

        pIpPtr = pIps;
    }

    for (pos = 0; pos < numSans; pos++)
    {
        /* Convert IP addresses to raw byte form */
        if (SubjectAltName_iPAddress == pAttrs[pos].subjectAltNameType)
        {
            if (OK > (status = CA_MGMT_convertIpAddress(pAttrs[pos].subjectAltNameValue.data, pIpPtr, &ipLen)))
                goto exit;

            if (OK > (status = DER_AddItem(pRoot, (PRIMITIVE|CONTEXT|(&(pAttrs[pos]))->subjectAltNameType),
                                           ipLen, pIpPtr, NULL)))
                goto exit;

            /* move to the next spot in the array */
            pIpPtr += ipLen;
        }
        else
        {
            if (OK > (status = DER_AddItem(pRoot, (PRIMITIVE|CONTEXT|(&(pAttrs[pos]))->subjectAltNameType),
                                        (&(pAttrs[pos]))->subjectAltNameValue.dataLen,
                                        (&(pAttrs[pos]))->subjectAltNameValue.data, NULL)))
            {
                goto exit;
            }
        }
    }

    if (OK > (status = DER_Serialize(pRoot, &pEncoded, &encodedLen)))
    {
        goto exit;
    }
    pSubAltNameExt->oid = (ubyte*)subjectAltName_OID;
    pSubAltNameExt->isCritical = FALSE;
    pSubAltNameExt->value = pEncoded;
    pSubAltNameExt->valueLen = encodedLen;

exit:

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }


    if (pIps)
    {
        (void) DIGI_MEMSET_FREE(&pIps, 16 * numIps);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_SAMPLE_createNameAttr(ubyte* oid, ubyte type, ubyte* value, ubyte4 valueLen, nameAttr **pPNameAttr)
{
    nameAttr *pNameAttr     = NULL;
    int      actualValueLen = 0;
    MSTATUS status = ERR_MEM_ALLOC_FAIL;

    pNameAttr = (nameAttr*)MALLOC(sizeof(nameAttr));
    if (pNameAttr)
    {
        DIGI_MEMSET((ubyte*) pNameAttr, 0x00, sizeof(nameAttr));
        pNameAttr->oid = oid;
        pNameAttr->type = type;

        if ('\n' == value[valueLen-1])
            actualValueLen = valueLen -1;
        else
            actualValueLen = valueLen;

        pNameAttr->value = (ubyte*)MALLOC(actualValueLen);
        DIGI_MEMCPY((void*)pNameAttr->value, (void*)value, actualValueLen);
        pNameAttr->valueLen = actualValueLen;

        *pPNameAttr = pNameAttr;
        status = OK;
    }

    return status;
}
#endif

/*------------------------------------------------------------------*/

static
MSTATUS SCEP_SAMPLE_initContext(scepContext **ppScepContext, void *pCookie,
                                  byteBoolean useTap,
                                  const ubyte *pEncAlgoOid, const ubyte *pHashOid,
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pKeyPw, ubyte4 keyPwLen,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  ubyte *pOldKeyPw, ubyte4 oldKeyPwLen,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert)
{
    MOC_UNUSED(pCookie);
    MOC_UNUSED(numCaCerts);
    MOC_UNUSED(numRaCerts);
    MSTATUS status = OK;
    pkcsCtxInternal *pPkcsCtxInt;

    if (OK > (status = SCEP_CONTEXT_createContext(ppScepContext, SCEP_CLIENT)))
        goto exit;

    pPkcsCtxInt = (*ppScepContext)->pPkcsCtx;

    /* initialize random generator and crypto algorithms */
    pPkcsCtxInt->rngFun = RANDOM_rngFun;
    pPkcsCtxInt->rngFunArg = g_pRandomContext;
    /* PKCS7 Callbacks */
    pPkcsCtxInt->callbacks.getPrivKeyFun = myGetPrivateKeyFun;
    pPkcsCtxInt->callbacks.valCertFun = myValCertFun;
    pPkcsCtxInt->callbacks.getCertFun = myGetCertFun;

    pPkcsCtxInt->digestAlgoOID = pHashOid;
    pPkcsCtxInt->encryptAlgoOID = pEncAlgoOid;

    pPkcsCtxInt->isOaep = isOaep;
    pPkcsCtxInt->pOaepLabel = pOaepLabel;
    pPkcsCtxInt->oaepHashAlgo = oaepHashAlgo;

    pPkcsCtxInt->isTap = useTap;
    pPkcsCtxInt->isTapPw = useTap && (NULL != pKeyPw) && (keyPwLen > 0);

    status = DIGI_MALLOC((void **) &pPkcsCtxInt->pKey, sizeof(AsymmetricKey));
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(pPkcsCtxInt->pKey);
    if (OK != status)
        goto exit;

    if (NULL != pKeyPw && keyPwLen > 0)
    {
        status = CRYPTO_deserializeAsymKeyWithCreds ( pPemKeyBlob, pemKeyBlobLen, NULL, pKeyPw, keyPwLen, NULL, pPkcsCtxInt->pKey);
    }
    else
    {
        status = CRYPTO_deserializeAsymKey(pPemKeyBlob, pemKeyBlobLen, NULL, pPkcsCtxInt->pKey);
    }
    if (OK != status)
        goto exit;

    if (NULL != pOldPemKeyBlob && (uintptr) pOldPemKeyBlob != (uintptr) pPemKeyBlob)
    {
        status = DIGI_MALLOC((void **) &pPkcsCtxInt->pSignKey, sizeof(AsymmetricKey));
        if (OK != status)
            goto exit;

        status = CRYPTO_initAsymmetricKey(pPkcsCtxInt->pSignKey);
        if (OK != status)
            goto exit;

        if (NULL != pOldKeyPw && oldKeyPwLen > 0)
        {
            status = CRYPTO_deserializeAsymKeyWithCreds ( pOldPemKeyBlob, oldPemKeyBlobLen, NULL, pOldKeyPw, oldKeyPwLen, NULL, pPkcsCtxInt->pSignKey);
        }
        else
        {
            status = CRYPTO_deserializeAsymKey(pOldPemKeyBlob, oldPemKeyBlobLen, NULL, pPkcsCtxInt->pSignKey);
        }
        if (OK != status)
            goto exit;
    }
    else
    {
        pPkcsCtxInt->pSignKey = pPkcsCtxInt->pKey;
    }

    /* retrieve CA/RA certificate */
    pPkcsCtxInt->RACertDescriptor.pCertificate = pRACerts[0].pCertificate;
    pPkcsCtxInt->RACertDescriptor.certLength = pRACerts[0].certLength;
    pPkcsCtxInt->RACertDescriptor.cookie = 1;
    MF_attach(&(pPkcsCtxInt->RAMemFile), pPkcsCtxInt->RACertDescriptor.certLength, pPkcsCtxInt->RACertDescriptor.pCertificate);
    CS_AttachMemFile(&(pPkcsCtxInt->RACertStream), &(pPkcsCtxInt->RAMemFile) );

    if (OK > (status = X509_parseCertificate( pPkcsCtxInt->RACertStream, &(pPkcsCtxInt->pRACertificate))))
        goto exit;

    /* retrieve CA certificate if different from that of RA */
    pPkcsCtxInt->CACertDescriptor.pCertificate = pCACerts[0].pCertificate;
    pPkcsCtxInt->CACertDescriptor.certLength = pCACerts[0].certLength;
    if (!pPkcsCtxInt->CACertDescriptor.pCertificate)
    {
        status = ERR_SCEP_INIT_FAIL;
        goto exit;
    }
    pPkcsCtxInt->CACertDescriptor.cookie = 1;

    MF_attach(&(pPkcsCtxInt->CAMemFile), pPkcsCtxInt->CACertDescriptor.certLength, pPkcsCtxInt->CACertDescriptor.pCertificate);
    CS_AttachMemFile(&(pPkcsCtxInt->CACertStream), &(pPkcsCtxInt->CAMemFile) );
    if (OK > (status = X509_parseCertificate( pPkcsCtxInt->CACertStream, &(pPkcsCtxInt->pCACertificate))))
        goto exit;

    /* initialize self-cert, either self-signed or CA issued */
    /* first see if self cert can be retrived through callback functions */
    /* ignoring error if can't not be retrieved */
    if (pRequesterCert != NULL)
    {
        pPkcsCtxInt->requesterCertDescriptor.pCertificate = pRequesterCert->pCertificate;
        pPkcsCtxInt->requesterCertDescriptor.certLength = pRequesterCert->certLength;
        if (pPkcsCtxInt->requesterCertDescriptor.pCertificate)
        {
            pPkcsCtxInt->requesterCertDescriptor.cookie = 1;
            /* parse the certificate, also cache selfcert for future use */
            MF_attach(&(pPkcsCtxInt->requesterCertMemFile), pPkcsCtxInt->requesterCertDescriptor.certLength, pPkcsCtxInt->requesterCertDescriptor.pCertificate);
            CS_AttachMemFile(&(pPkcsCtxInt->requesterCertStream), &(pPkcsCtxInt->requesterCertMemFile) );
            if (OK > (status = X509_parseCertificate( pPkcsCtxInt->requesterCertStream, &(pPkcsCtxInt->pRequesterCert))))
                goto exit;
        }
    }

    SCEP_CLIENT_STATE(*ppScepContext) = certNonExistant;

exit:

    if (status < OK)
    {
        SCEP_CONTEXT_releaseContext(ppScepContext);
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS SCEP_SAMPLE_registerScepDataCallback(void *pCallback)
{
    g_pFuncPtrGetScepData = pCallback;
    return OK;
}

/*------------------------------------------------------------------*/

MSTATUS
SCEP_SAMPLE_generateCSRRequest(byteBoolean useTap, ubyte4 hashId,
                               ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                               ubyte *pKeyPw, ubyte4 keyPwLen,
                               ubyte *pCsrAttributes, ubyte4 csrAttrsLen,
                               sbyte *pChallengePass, ubyte4 passwordLen,
                               ubyte **ppCsrBuffer, ubyte4 *pCsrBufferLen,
                               requestInfo **ppReqInfo, byteBoolean serviceMode)
{
    MOC_UNUSED(useTap);
    MSTATUS status = OK;
    requestInfo  *pReqInfo = NULL;
    AsymmetricKey asymKey = {0};
    byteBoolean unloadKey = FALSE;

    /*validate input parameters */
    if ( (NULL == pPemKeyBlob) || (NULL == pCsrAttributes) ||
         (NULL == pChallengePass) || (NULL == ppCsrBuffer) || (NULL == pCsrBufferLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if (useTap && NULL != pKeyPw && keyPwLen > 0)
    {
        unloadKey = TRUE;
    }
#endif

    /* Initialize asymmetric key */
    if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
    {
        goto exit;
    }

    if (NULL != pKeyPw && keyPwLen > 0)
    {
        status = CRYPTO_deserializeAsymKeyWithCreds ( pPemKeyBlob, pemKeyBlobLen, NULL, pKeyPw, keyPwLen, NULL, &asymKey);
    }
    else
    {
        status = CRYPTO_deserializeAsymKey(pPemKeyBlob, pemKeyBlobLen, NULL, &asymKey);
    }
    if (OK != status)
        goto exit;

    /* Initialize requesterInfo */
    if (OK > (status = DIGI_CALLOC((void**)&pReqInfo, 1, sizeof(requestInfo))))
    {
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void**)&(pReqInfo->value.certInfoAndReqAttrs.pCsrCtx), 1, sizeof(CertCsrCtx))))
    {
        goto exit;
    }

    if (OK > (status = CERT_ENROLL_addCsrAttributes(pReqInfo->value.certInfoAndReqAttrs.pCsrCtx,
                           (TRUE == serviceMode) ? JSON : TOML, 0/*unused*/, (TRUE == serviceMode) ? TRUSTEDGE_evalFunction : NULL, NULL,
                           &asymKey, certEnrollAlgUndefined, FALSE, hashId, pCsrAttributes, csrAttrsLen, NULL, EXT_ENROLL_FLOW_NONE)))
    {
        goto exit;
    }

    /* initialize requestInfo depending on messageType */
    pReqInfo->type = scep_PKCSReq;

    if (pChallengePass != NULL)
    {

        if (OK > (status = CERT_ENROLL_addReqAttribute(pReqInfo->value.certInfoAndReqAttrs.pCsrCtx,
                                challengePassword, (ubyte *) pChallengePass, passwordLen)))
        {
            goto exit;
        }
    }

    if (OK > (status = SCEP_MESSAGE_generatePayLoad(&asymKey, unloadKey, pReqInfo, ppCsrBuffer, pCsrBufferLen)))
        goto exit;

    *ppReqInfo = pReqInfo;
    pReqInfo = NULL;

exit:

    if (NULL != pReqInfo)
    {
        if (NULL != pReqInfo->value.certInfoAndReqAttrs.pCsrCtx)
        {
            (void) CERT_ENROLL_cleanupCsrCtx(pReqInfo->value.certInfoAndReqAttrs.pCsrCtx);
            (void) DIGI_FREE((void **) &pReqInfo->value.certInfoAndReqAttrs.pCsrCtx);
        }

        (void) DIGI_FREE((void **) &pReqInfo);
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if (useTap)
    {
        (void) TRUSTEDGE_TAP_unloadKey(&asymKey);
    }
#endif

    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS
SCEP_SAMPLE_sendEnrollmentRequest(byteBoolean useTap,
                                  const ubyte *pEncAlgoOid, const ubyte *pHashOid,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pKeyPw, ubyte4 keyPwLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo **ppReqInfo,
                                  byteBoolean usePost, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  ubyte *pOldKeyPw, ubyte4 oldKeyPwLen,
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
                                  ubyte **ppCert, ubyte4 *pCertLen,
                                  sbyte **ppOutTransactionId, ubyte4 *pOutTransactionIdLen,
                                  ubyte4 *pOutStatus, SCEP_failInfo *pFailInfo)
{
    MSTATUS status = OK;
    scepContext *pScepContext = NULL;
    ubyte        *pQuery = NULL;
    ubyte4       queryLen;
    sbyte        *completeUri = NULL;
    ubyte4       completeUriLen;
    ubyte        *pHttpResp = NULL;
    ubyte4       httpRespLen;
    void*        pCookie = NULL;
    void*        pCachedCookie = NULL;
    sbyte        tcpBuffer[SCEP_TCP_READ_BUFFER];
    sbyte4       nRet;
    sbyte        *respFile = NULL;
    ubyte4       bodyLen;

    /*validate input parameters */
    if ( (NULL == pPemKeyBlob) || (NULL == pPkcs10Csr) ||
        (NULL == ppCert) || (NULL == pCertLen) ||
        (NULL == pServerUrl) || (NULL == ppReqInfo) || (NULL == *ppReqInfo) || (NULL == pHttpContext) ||
        (0 == numCaCerts) || (0 == numRaCerts) ||
        ((requestType == 3 || requestType == 2) && (NULL == pOldPemKeyBlob)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = SCEP_SAMPLE_initContext(&pScepContext, NULL,
                                               useTap,
                                               pEncAlgoOid, pHashOid,
                                               isOaep, pOaepLabel, oaepHashAlgo,
                                               pPemKeyBlob, pemKeyBlobLen,
                                               pKeyPw, keyPwLen,
                                               pOldPemKeyBlob, oldPemKeyBlobLen,
                                               pOldKeyPw, oldKeyPwLen,
                                               pCACerts, numCaCerts,
                                               pRACerts, numRaCerts,
                                               pRequesterCert)))
    {
        goto exit;
    }

    if (OK > (status = SCEP_CLIENT_setRequestInfo(pScepContext, ppReqInfo)))
        goto exit;

    /* NOTE: win20xx scep addon doesn't support POST mode */

    if (pScepContext->pPkcsCtx != NULL)
    {
        pScepContext->pPkcsCtx->pPayLoad = pPkcs10Csr;
        pScepContext->pPkcsCtx->payLoadLen = pkcs10CsrLen;
    }

    if (!usePost)
    {
        if (OK > (status = SCEP_CLIENT_generateRequest(pScepContext, &pQuery, &queryLen)))
            goto exit;
    }
    else
    {
        if (OK > (status = SCEP_CLIENT_generateRequestEx(pScepContext, TRUE,
                                                      &pQuery, &queryLen, &bodyLen, &pCookie)))
            goto exit;
        if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
            goto exit;
        if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[POST])))
            goto exit;
        if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
            goto exit;

        HTTP_httpSettings()->funcPtrRequestBodyCallback = SCEP_CLIENT_http_requestBodyCallback;
    }

    completeUriLen = DIGI_STRLEN((sbyte*)pServerUrl) + 1 + queryLen;
    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY((void *)completeUri, (const void *)pServerUrl, DIGI_STRLEN((sbyte*)pServerUrl));
    *(completeUri+DIGI_STRLEN((sbyte*)pServerUrl)) = '?';
    DIGI_MEMCPY((void *) (completeUri+DIGI_STRLEN((sbyte*)pServerUrl)+1), (const void *) pQuery, queryLen);
    *(completeUri+completeUriLen) = '\0';

    /* set request URI */
    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
        goto exit;

    /* send request */
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
        goto exit;

    /* finish sending the request via transport... */
    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
            goto exit;
    }
    MSG_LOG_print(MSG_LOG_DEBUG,"Sent request......\n%s","");

    while (1)
    {
        status = TCP_READ_AVL(pHttpContext->socket, tcpBuffer, SCEP_TCP_READ_BUFFER, (ubyte4 *) &nRet, 50000);

        if (status == ERR_TCP_READ_TIMEOUT)
        {
            MSG_LOG_print(MSG_LOG_DEBUG, "readtimeout......\n%s","");
            continue;
        }
        else if (status < OK)
            goto exit;

        if (nRet <= 0)
            continue;

        /* process response */
        if (OK > (status = HTTP_recv(pHttpContext, (ubyte*)tcpBuffer, nRet)))
            goto exit;

        if (HTTP_isDone(pHttpContext))
        {
            ubyte4 statusCode;
            if (pHttpResp)
            {
                FREE(pHttpResp);
                pHttpResp = NULL;
                httpRespLen = 0;
            }
            if (OK > (status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode)))
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pHttpContext, &pHttpResp, &httpRespLen)))
            {
                goto exit;
            }
            if (statusCode < 300)
            {
                const ubyte *pContentType;
                ubyte4 contentTypeLen;
                if (OK > (status = HTTP_REQUEST_getContentType(pHttpContext, &pContentType, &contentTypeLen)))
                {
                    goto exit;
                }

                if (OK > (status = SCEP_CLIENT_recvResponse(pScepContext, (ubyte*)pContentType, contentTypeLen, pHttpResp, httpRespLen))){

                    goto exit;
                }

                if (SCEP_CLIENT_getStatus(pScepContext) == scep_SUCCESS)
                {
                    ubyte* respBody;
                    ubyte4 respBodyLen;
                    SCEP_CLIENT_getResponseContent(pScepContext, &respBody, &respBodyLen);

                    if (respBodyLen == 0)
                    {
                        MSG_LOG_print(MSG_LOG_WARNING,"WARNING: SCEP_EXAMPLE: Received response 0 length.\n%s","");
                        goto exit;
                    }
                    *ppCert = respBody;
                    *pCertLen = respBodyLen;

                    if (respFile)
                    {
                        FREE (respFile);
                        respFile = NULL;
                    }
                    break;
                }
                else if (SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
                {
                    if (OK > (status = DIGI_CALLOC((void**)ppOutTransactionId, 1, pScepContext->pTransAttrs->transactionIDLen)))
                    {
                        goto exit;
                    }
                    if (OK > (status = DIGI_MEMCPY((ubyte*)*ppOutTransactionId, pScepContext->pTransAttrs->transactionID, pScepContext->pTransAttrs->transactionIDLen)))
                    {
                        goto exit;
                    }
                    *pOutTransactionIdLen = pScepContext->pTransAttrs->transactionIDLen;
                    *pOutStatus = pScepContext->pTransAttrs->pkiStatus;
                    goto exit;
                }
                else
                {
                    /* failed reason: check failInfo*/
                    SCEP_CLIENT_getFailInfo(pScepContext, pFailInfo);
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response with FAILURE status: \n%s","");
                    switch (*pFailInfo)
                    {
                        case scep_badAlg:
                            MSG_LOG_print(MSG_LOG_INFO,"badAlg\n%s","");
                            break;
                        case scep_badMessageCheck:
                            MSG_LOG_print(MSG_LOG_INFO,"badMessageCheck\n%s","");
                            break;
                        case scep_badRequest:
                            MSG_LOG_print(MSG_LOG_INFO,"badRequest\n%s","");
                            break;
                        case scep_badTime:
                            MSG_LOG_print(MSG_LOG_INFO,"badTime\n%s","");
                            break;
                        case scep_badCertId:
                            MSG_LOG_print(MSG_LOG_INFO,"badCertId\n%s","");
                            break;
                        default:
                            MSG_LOG_print(MSG_LOG_INFO,"Unknown\n%s","");
                            break;
                    }
                    break;
                }
            }
            else
            {
                /* print out http response reason phrase */
                const ubyte* reasonPhrase;
                ubyte4 reasonPhraseLength;
                sbyte* str = NULL;
                if (OK > (status = HTTP_REQUEST_getStatusPhrase(pHttpContext,
                                &reasonPhrase, &reasonPhraseLength)))
                    goto exit;
                str = MALLOC(reasonPhraseLength+1);
                if (str)
                {
                    DIGI_MEMCPY(str, reasonPhrase, reasonPhraseLength);
                    *(str+reasonPhraseLength) = '\0';
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response: %s\n", str);
                    FREE(str);
                    str = NULL;
                }
                status = ERR_HTTP;
                break;
            }
        }
    }

exit:
    if (pQuery)
    {
        FREE(pQuery);
        pQuery = NULL;
    }
    if (completeUri)
    {
        FREE(completeUri);
        completeUri = NULL;
    }
    if (pHttpResp)
    {
        FREE(pHttpResp);
        pHttpResp = NULL;
    }
    if (pCookie)
    {
        SCEP_CLIENT_releaseCookie(pCookie);
    }
    if (pCachedCookie)
    {
        SCEP_CLIENT_releasePollCookie(pCachedCookie);
    }

    if (pScepContext && SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
    {
        /* Same requestInfo will be used at the time of pending enrollment
           so don't free requestInfo.*/
        pScepContext->pReqInfo = NULL;
    }
    if (pScepContext)
        SCEP_CLIENT_releaseContext(&pScepContext);

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS
SCEP_SAMPLE_retryPendingEnrollmentRequest(byteBoolean useTap,
                                  const ubyte *pEncAlgoOid, const ubyte *pHashOid,
                                  httpContext *pHttpContext,
                                  ubyte *pPemKeyBlob, ubyte4 pemKeyBlobLen,
                                  ubyte *pKeyPw, ubyte4 keyPwLen,
                                  ubyte *pPkcs10Csr, ubyte4 pkcs10CsrLen,
                                  requestInfo **ppReqInfo,
                                  byteBoolean usePost, ubyte *pServerUrl,
                                  struct certDescriptor pCACerts[], ubyte4 numCaCerts,
                                  struct certDescriptor pRACerts[], ubyte4 numRaCerts,
                                  struct certDescriptor *pRequesterCert, ubyte4 requestType,
                                  ubyte *pOldPemKeyBlob, ubyte4 oldPemKeyBlobLen,
                                  ubyte *pOldKeyPw, ubyte4 oldKeyPwLen,
                                  sbyte* pTransactionID, ubyte4 transactionIdLen,
                                  const ubyte4 pollInterval, const ubyte4 pollCount,
                                  ubyte isOaep, sbyte *pOaepLabel, ubyte4 oaepHashAlgo,
                                  ubyte **ppCert, ubyte4 *pCertLen, SCEP_failInfo *pFailInfo)
{
    MOC_UNUSED(pkcs10CsrLen);
    MSTATUS status = OK;
    scepContext *pScepContext = NULL;
    ubyte        *pQuery = NULL;
    ubyte4       queryLen;
    sbyte        *completeUri = NULL;
    ubyte4       completeUriLen=0;
    ubyte        *pHttpResp = NULL;
    ubyte4       httpRespLen;
    void*        pCookie = NULL;
    void*        pCachedCookie = NULL;
    sbyte        tcpBuffer[SCEP_TCP_READ_BUFFER];
    sbyte4       nRet;
    sbyte        *respFile = NULL;
    ubyte4       bodyLen;

    /*validate input parameters */
    if ((NULL == pPemKeyBlob) || (NULL == pPkcs10Csr) ||
        (NULL == ppCert) || (NULL == pCertLen) ||
        (NULL == pServerUrl) || (NULL == ppReqInfo) || (NULL == *ppReqInfo) || (NULL == pHttpContext) ||
        (NULL == pRequesterCert) || (0 == numCaCerts) || (0 == numRaCerts)  ||
        (NULL == pTransactionID) || (0 == transactionIdLen) ||
        ((requestType == 3 || requestType == 2) && (NULL == pOldPemKeyBlob)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK != (status = SCEP_SAMPLE_initContext(&pScepContext, NULL,
                                               useTap,
                                               pEncAlgoOid, pHashOid,
                                               isOaep, pOaepLabel, oaepHashAlgo,
                                               pPemKeyBlob, pemKeyBlobLen,
                                               pKeyPw, keyPwLen,
                                               pOldPemKeyBlob, oldPemKeyBlobLen,
                                               pOldKeyPw, oldKeyPwLen,
                                               pCACerts, numCaCerts,
                                               pRACerts, numRaCerts,
                                               pRequesterCert)))
    {
        goto exit;
    }

    status = SCEP_CLIENT_setRequestInfo(pScepContext, ppReqInfo);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pScepContext->pTransAttrs, sizeof(transactionAttributes));
    if (OK != status)
	{
		goto exit;
	}

	DIGI_MEMSET((ubyte*)pScepContext->pTransAttrs, 0x00, sizeof(transactionAttributes));

    pScepContext->pTransAttrs->messageType = scep_PKCSReq;
    if (OK != (status = DIGI_CALLOC((void**)&(pScepContext->pTransAttrs->transactionID), 1, transactionIdLen)))
    {
        goto exit;
    }
    if (OK != (status = DIGI_MEMCPY((ubyte*)pScepContext->pTransAttrs->transactionID, pTransactionID, transactionIdLen)))
    {
        goto exit;
    }
    pScepContext->pTransAttrs->transactionIDLen = transactionIdLen;
    pScepContext->pTransAttrs->pkiStatus = scep_PENDING;

    /* TODO resetContext should be done here or in application ? */
	HTTP_CONTEXT_resetContext(pHttpContext);

     /* Incase of Pending Retry also use the generateRequest API - inorder to handle HTTP
      POST related initializations*/
     if (!usePost)
     {
       if (OK > (status = SCEP_CLIENT_generateRequest(pScepContext, &pQuery, &queryLen)))
          goto exit;
     }
     else
     {
       if (OK > (status = SCEP_CLIENT_generateRequestEx(pScepContext, TRUE,
                                                  &pQuery, &queryLen, &bodyLen, &pCookie)))
          goto exit;
       if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
         goto exit;
       if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[POST])))
            goto exit;
       if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
          goto exit;
      }


    /* set request method to GET if not set already */
    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext,
                    &mHttpMethods[GET])))
       goto exit;

    completeUriLen = (ubyte4) DIGI_STRLEN((sbyte*)pServerUrl) + 1 + queryLen;
    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY((void *) completeUri, (const void *) pServerUrl, (sbyte4)DIGI_STRLEN((sbyte*)pServerUrl));
    *(completeUri+DIGI_STRLEN((sbyte*)pServerUrl)) = '?';
    DIGI_MEMCPY((void *) (completeUri+(sbyte4)DIGI_STRLEN((void *)pServerUrl)+1),
            (const void *) pQuery, queryLen);
    *(completeUri+completeUriLen) = '\0';

    /* set request URI */
    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
        goto exit;

    /* send request */
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
        goto exit;

    /* finish sending the request via transport... */
    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
            goto exit;
    }
    MSG_LOG_print(MSG_LOG_INFO,"Sent request......\n%s","");

    int retryCount = pollCount;
    while (retryCount)
    {
        status = TCP_READ_AVL(pHttpContext->socket, tcpBuffer, SCEP_TCP_READ_BUFFER, (ubyte4 *) &nRet, 50000);

        if (status == ERR_TCP_READ_TIMEOUT)
        {
            MSG_LOG_print(MSG_LOG_INFO, "readtimeout......\n%s","");
            continue;
        }
        else if (status < OK)
            goto exit;

        if (nRet <= 0)
            continue;

        /* process response */
        if (OK > (status = HTTP_recv(pHttpContext, (ubyte*)tcpBuffer, nRet)))
            goto exit;

        if (HTTP_isDone(pHttpContext))
        {
            ubyte4 statusCode;
            if (pHttpResp)
            {
                FREE(pHttpResp);
                pHttpResp = NULL;
                httpRespLen = 0;
            }
            if (OK > (status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode)))
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pHttpContext, &pHttpResp, &httpRespLen)))
            {
                goto exit;
            }
            if (statusCode < 300)
            {
                const ubyte *pContentType;
                ubyte4 contentTypeLen;
                if (OK > (status = HTTP_REQUEST_getContentType(pHttpContext, &pContentType, &contentTypeLen)))
                {
                    goto exit;
                }

                if (OK > (status = SCEP_CLIENT_recvResponse(pScepContext, (ubyte*)pContentType, contentTypeLen, pHttpResp, httpRespLen))){

                    goto exit;
                }

                if (SCEP_CLIENT_getStatus(pScepContext) == scep_SUCCESS)
                {
                    ubyte* respBody;
                    ubyte4 respBodyLen;
                    SCEP_CLIENT_getResponseContent(pScepContext, &respBody, &respBodyLen);
                    if (respBodyLen == 0)
                    {
                        MSG_LOG_print(MSG_LOG_WARNING,"WARNING: SCEP_EXAMPLE: Received response 0 length.\n%s","");
                        goto exit;
                    }
                    *ppCert = respBody;
                    *pCertLen = respBodyLen;

                    if (respFile)
                    {
                        FREE (respFile);
                        respFile = NULL;
                    }
                    break;
                }
                else if (SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
                {
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response with PENDING status.\n%s","");
                    retryCount--;
                    if (completeUri)
                    {
                        FREE(completeUri);
                        completeUri = NULL;
                    }
                    if (pQuery)
                    {
                        FREE(pQuery);
                        pQuery = NULL;
                    }
                    if (pCookie)
                    {
                        SCEP_CLIENT_releaseCookie(pCookie);
                        pCookie = NULL;
                    }
                    /* EJBCA doesn't support polling */
                    RTOS_sleepMS(pollInterval); /* sleep for one minute etc */
                    /* pCachedCookie is an opaque cookie that once obtained,
                     * can be saved to resume with SCEP_CLIENT_pollServer later on */
                    HTTP_CONTEXT_resetContext(pHttpContext);
                    if (OK > (status = SCEP_CLIENT_generatePollServerRequest(pScepContext,
                                    &pQuery, &queryLen, &bodyLen, &pCookie, &pCachedCookie)))
                        goto exit;

                    /* send polling request */
                    if (pScepContext->useHttpPOST)
                    {
                        if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
                            goto exit;
                        if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext,
                                        &mHttpMethods[POST])))
                            goto exit;
                        if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
                            goto exit;
                    }

                    /* set request method to GET if not set already */
                    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext,
                                    &mHttpMethods[GET])))
                        goto exit;
                    completeUriLen = (ubyte4) DIGI_STRLEN((sbyte *)pServerUrl) + 1 + queryLen;
                    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }
                    DIGI_MEMCPY((void *) completeUri, (const void *) pServerUrl, (sbyte4)DIGI_STRLEN((sbyte*)pServerUrl));
                    *(completeUri+DIGI_STRLEN((sbyte *)pServerUrl)) = '?';
                    DIGI_MEMCPY((void *) (completeUri+(sbyte4)DIGI_STRLEN((void *)pServerUrl)+1),
                            (const void *) pQuery, queryLen);
                    *(completeUri+completeUriLen) = '\0';

                    /* set request URI */
                    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
                        goto exit;

                    /* send request */
                    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
                        goto exit;
                    /* finish sending the request via transport... */
                    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
                    {
                        if (OK > (status = HTTP_continue(pHttpContext)))
                            goto exit;
                    }
                }
                else
                {
                    /* failed reason: check failInfo*/
                    SCEP_CLIENT_getFailInfo(pScepContext, pFailInfo);
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response with FAILURE status: \n%s","");
                    switch (*pFailInfo)
                    {
                        case scep_badAlg:
                            MSG_LOG_print(MSG_LOG_INFO,"badAlg\n%s","");
                            break;
                        case scep_badMessageCheck:
                            MSG_LOG_print(MSG_LOG_INFO,"badMessageCheck\n%s","");
                            break;
                        case scep_badRequest:
                            MSG_LOG_print(MSG_LOG_INFO,"badRequest\n%s","");
                            break;
                        case scep_badTime:
                            MSG_LOG_print(MSG_LOG_INFO,"badTime\n%s","");
                            break;
                        case scep_badCertId:
                            MSG_LOG_print(MSG_LOG_INFO,"badCertId\n%s","");
                            break;
                        default:
                            MSG_LOG_print(MSG_LOG_INFO,"Unknown\n%s","");
                            break;
                    }
                    break;
                }
            }
            else
            {
                /* print out http response reason phrase */
                const ubyte* reasonPhrase;
                ubyte4 reasonPhraseLength;
                sbyte* str = NULL;
                if (OK > (status = HTTP_REQUEST_getStatusPhrase(pHttpContext,
                                &reasonPhrase, &reasonPhraseLength)))
                    goto exit;
                str = MALLOC(reasonPhraseLength+1);
                if (str)
                {
                    DIGI_MEMCPY(str, reasonPhrase, reasonPhraseLength);
                    *(str+reasonPhraseLength) = '\0';
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response: %s\n", str);
                    DIGI_FREE((void**)&str);
                }
                status = ERR_HTTP;
                break;
            }
        }
    }

exit:
    if (pQuery)
    {
        FREE(pQuery);
        pQuery = NULL;
    }
    if (completeUri)
    {
        FREE(completeUri);
        completeUri = NULL;
    }
    if (pHttpResp)
    {
        FREE(pHttpResp);
        pHttpResp = NULL;
    }
    if (pCookie)
    {
        SCEP_CLIENT_releaseCookie(pCookie);
    }
    if (pCachedCookie)
    {
        SCEP_CLIENT_releasePollCookie(pCachedCookie);
    }
    if (pScepContext && SCEP_CLIENT_getStatus(pScepContext) == scep_PENDING)
    {
        /* Same requestInfo will be used at the time of pending enrollment
           so don't free requestInfo.*/
        pScepContext->pReqInfo = NULL;
    }
    if (pScepContext)
        SCEP_CLIENT_releaseContext(&pScepContext);
    return status;

}

/*------------------------------------------------------------------*/

MSTATUS
SCEP_SAMPLE_fetchCertCRLCapsRequest(httpContext *pHttpContext,
                                    byteBoolean usePost,
                                    ubyte *pServerUrl, ubyte **ppCert,
                                    ubyte4 *pCertLen,
                                    ubyte4 *pOutStatus,
                                    SCEP_messageType messageType,
                                    SCEP_failInfo *pFailInfo)
{
    MSTATUS status = OK;
    scepContext *pScepContext = NULL;
    ubyte        *pQuery = NULL;
    ubyte4       queryLen;
    sbyte        *completeUri = NULL;
    ubyte4       completeUriLen;
    ubyte        *pHttpResp = NULL;
    ubyte4       httpRespLen;
    void*        pCookie = NULL;
    sbyte        tcpBuffer[SCEP_TCP_READ_BUFFER];
    sbyte4       nRet;
    sbyte        *respFile = NULL;
    ubyte4       bodyLen;

    /*validate input parameters */
    if ((NULL == pHttpContext) || (NULL == pServerUrl) ||
        (NULL == ppCert) || (NULL == pCertLen) || (NULL == pOutStatus))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = SCEP_CONTEXT_createContext(&pScepContext, SCEP_CLIENT)))
    {
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void**)&pScepContext->pReqInfo, 1, sizeof(requestInfo))))
    {
        goto exit;
    }

    pScepContext->pReqInfo->type = messageType;

    if (!usePost)
    {
        if (OK > (status = SCEP_CLIENT_generateRequest(pScepContext, &pQuery, &queryLen)))
            goto exit;
    }
    else
    {
        if (OK > (status = SCEP_CLIENT_generateRequestEx(pScepContext, TRUE,
                                                      &pQuery, &queryLen, &bodyLen, &pCookie)))
            goto exit;
        if (OK > (status = HTTP_setCookie(pHttpContext, pCookie)))
            goto exit;
        if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[POST])))
            goto exit;
        if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, bodyLen)))
            goto exit;

        HTTP_httpSettings()->funcPtrRequestBodyCallback = SCEP_CLIENT_http_requestBodyCallback;
    }

    completeUriLen = DIGI_STRLEN((sbyte*)pServerUrl) + 1 + queryLen;
    if (NULL == (completeUri = MALLOC(completeUriLen+1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY((void *)completeUri, (const void *)pServerUrl, DIGI_STRLEN((sbyte*)pServerUrl));
    *(completeUri+DIGI_STRLEN((sbyte*)pServerUrl)) = '?';
    DIGI_MEMCPY((void *) (completeUri+DIGI_STRLEN((sbyte*)pServerUrl)+1), (const void *) pQuery, queryLen);
    *(completeUri+completeUriLen) = '\0';

    /* set request URI */
    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, completeUri)))
        goto exit;

    /* send request */
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
        goto exit;

    /* finish sending the request via transport... */
    while (!HTTP_REQUEST_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
            goto exit;
    }
    MSG_LOG_print(MSG_LOG_DEBUG,"Sent request......\n%s","");

    while (1)
    {
        status = TCP_READ_AVL(pHttpContext->socket, tcpBuffer, SCEP_TCP_READ_BUFFER, (ubyte4 *) &nRet, 50000);

        if (status == ERR_TCP_READ_TIMEOUT)
        {
            MSG_LOG_print(MSG_LOG_DEBUG, "readtimeout......\n%s","");
            continue;
        }
        else if (status < OK)
            goto exit;

        if (nRet <= 0)
            continue;

        /* process response */
        if (OK > (status = HTTP_recv(pHttpContext, (ubyte*)tcpBuffer, nRet)))
            goto exit;

        if (HTTP_isDone(pHttpContext))
        {
            ubyte4 statusCode;
            if (pHttpResp)
            {
                FREE(pHttpResp);
                pHttpResp = NULL;
                httpRespLen = 0;
            }
            if (OK > (status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode)))
            {
                goto exit;
            }

            if (OK > (status = HTTP_REQUEST_getResponseContent(pHttpContext, &pHttpResp, &httpRespLen)))
            {
                goto exit;
            }
            if (statusCode < 300)
            {
                const ubyte *pContentType;
                ubyte4 contentTypeLen;
                if (OK > (status = HTTP_REQUEST_getContentType(pHttpContext, &pContentType, &contentTypeLen)))
                {
                    goto exit;
                }

                if (OK > (status = SCEP_CLIENT_recvResponse(pScepContext, (ubyte*)pContentType, contentTypeLen, pHttpResp, httpRespLen))){

                    goto exit;
                }

                if (SCEP_CLIENT_getStatus(pScepContext) == scep_SUCCESS)
                {
                    ubyte* respBody;
                    ubyte4 respBodyLen;
                    SCEP_CLIENT_getResponseContent(pScepContext, &respBody, &respBodyLen);

                    if (respBodyLen == 0)
                    {
                        MSG_LOG_print(MSG_LOG_WARNING,"WARNING: SCEP_EXAMPLE: Received response 0 length.\n%s","");
                        goto exit;
                    }
                    *ppCert = respBody;
                    *pCertLen = respBodyLen;

                    if (respFile)
                    {
                        FREE (respFile);
                        respFile = NULL;
                    }
                    break;
                }
                else
                {
                    /* failed reason: check failInfo*/
                    SCEP_CLIENT_getFailInfo(pScepContext, pFailInfo);
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response with FAILURE status: \n%s","");
                    switch (*pFailInfo)
                    {
                        case scep_badAlg:
                            MSG_LOG_print(MSG_LOG_INFO,"badAlg\n%s","");
                            break;
                        case scep_badMessageCheck:
                            MSG_LOG_print(MSG_LOG_INFO,"badMessageCheck\n%s","");
                            break;
                        case scep_badRequest:
                            MSG_LOG_print(MSG_LOG_INFO,"badRequest\n%s","");
                            break;
                        case scep_badTime:
                            MSG_LOG_print(MSG_LOG_INFO,"badTime\n%s","");
                            break;
                        case scep_badCertId:
                            MSG_LOG_print(MSG_LOG_INFO,"badCertId\n%s","");
                            break;
                        default:
                            MSG_LOG_print(MSG_LOG_INFO,"Unknown\n%s","");
                            break;
                    }
                    break;
                }
            }
            else
            {
                /* print out http response reason phrase */
                const ubyte* reasonPhrase;
                ubyte4 reasonPhraseLength;
                sbyte* str = NULL;
                if (OK > (status = HTTP_REQUEST_getStatusPhrase(pHttpContext,
                                &reasonPhrase, &reasonPhraseLength)))
                    goto exit;
                str = MALLOC(reasonPhraseLength+1);
                if (str)
                {
                    DIGI_MEMCPY(str, reasonPhrase, reasonPhraseLength);
                    *(str+reasonPhraseLength) = '\0';
                    MSG_LOG_print(MSG_LOG_INFO,"SCEP_EXAMPLE: Received response: %s\n", str);
                    FREE(str);
                    str = NULL;
                }
                status = ERR_HTTP;
                break;
            }
        }
    }

exit:
    if (pQuery)
    {
        FREE(pQuery);
        pQuery = NULL;
    }
    if (completeUri)
    {
        FREE(completeUri);
        completeUri = NULL;
    }
    if (pHttpResp)
    {
        FREE(pHttpResp);
        pHttpResp = NULL;
    }
    if (pCookie)
    {
        SCEP_CLIENT_releaseCookie(pCookie);
    }
    if (pScepContext)
    {
        SCEP_CLIENT_releaseContext(&pScepContext);
    }

    return status;
}

/*------------------------------------------------------------------*/
